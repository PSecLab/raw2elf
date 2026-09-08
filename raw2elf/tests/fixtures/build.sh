#!/usr/bin/env bash
# Build the raw2elf fixture firmwares.
#
# The generated ELFs are committed, so the test suite does not need a
# toolchain; re-run this only when the fixture sources change.
set -euo pipefail

CC=${CC:-arm-none-eabi-gcc}
OBJCOPY=${OBJCOPY:-arm-none-eabi-objcopy}
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
OUT="$HERE"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CFLAGS="-mcpu=cortex-m4 -mthumb -Os -ffreestanding -fno-builtin -fno-common
        -ffunction-sections -fdata-sections -Wall"
LDFLAGS="-nostdlib -nostartfiles -Wl,--gc-sections -Wl,--build-id=none"

# build <name> <flash base> <flash size> <ram base> <ram size> [extra sources...]
build() {
  local name=$1 flash_base=$2 flash_size=$3 ram_base=$4 ram_size=$5
  shift 5
  sed -e "s|@FLASH_BASE@|$flash_base|" -e "s|@FLASH_SIZE@|$flash_size|" \
      -e "s|@RAM_BASE@|$ram_base|"     -e "s|@RAM_SIZE@|$ram_size|" \
      "$SRC/firmware.ld.in" > "$WORK/$name.ld"
  # shellcheck disable=SC2086
  $CC $CFLAGS $LDFLAGS -T "$WORK/$name.ld" -o "$OUT/$name.elf" "$SRC/firmware.c" "$@"
  $OBJCOPY -O binary "$OUT/$name.elf" "$WORK/$name.bin"
  printf '%-22s %s  %s bytes\n' "$name.elf" "$flash_base" "$(stat -c%s "$WORK/$name.bin")"
}

# A conventional STM32F4-style image: Flash at 0x08000000, SRAM at 0x20000000.
build stm32f4_standard 0x08000000 1M 0x20000000 128K

# An unusual Flash base, to make sure nothing assumes 0x08000000 or zero.
build nonstandard_base 0x10000000 512K 0x20000000 64K

# Linked to run from the second half of Flash: dropped into a dump after a
# bootloader, its vector table is at a non-zero file offset.
build application_high 0x08008000 480K 0x20000000 128K

# A small image to act as the bootloader in a two-image dump.
build bootloader 0x08000000 32K 0x20000000 128K

# A second RAM bank in the architectural code region, as vendors do for CCM.
sed -e 's|\*(.bss) \*(.bss\*) \*(COMMON)|*(.bss) *(.bss*) *(COMMON)|' \
    "$SRC/firmware.ld.in" > "$WORK/bank.ld.in"
cat > "$WORK/two_bank.ld.in" <<'INNER'
INNER
python3 - "$SRC/firmware.ld.in" "$WORK/two_bank.ld.in" <<'PYEOF'
import sys
source, destination = sys.argv[1], sys.argv[2]
text = open(source).read()
text = text.replace(
    "  RAM  (rwx) : ORIGIN = @RAM_BASE@,   LENGTH = @RAM_SIZE@",
    "  RAM  (rwx) : ORIGIN = @RAM_BASE@,   LENGTH = @RAM_SIZE@\n"
    "  CCM  (rwx) : ORIGIN = 0x10000000,   LENGTH = 64K",
)
text = text.replace(
    "  .bss : {",
    "  .ccmram (NOLOAD) : { . = ALIGN(4); KEEP(*(.ccmram)) . = ALIGN(4); } > CCM\n"
    "  .bss : {",
)
open(destination, "w").write(text)
PYEOF
name=two_ram_banks
sed -e "s|@FLASH_BASE@|0x08000000|" -e "s|@FLASH_SIZE@|1M|" \
    -e "s|@RAM_BASE@|0x20000000|"   -e "s|@RAM_SIZE@|128K|" \
    "$WORK/two_bank.ld.in" > "$WORK/$name.ld"
# shellcheck disable=SC2086
$CC $CFLAGS $LDFLAGS -DHAVE_SECOND_RAM_BANK -T "$WORK/$name.ld" -o "$OUT/$name.elf" \
    "$SRC/firmware.c" "$SRC/extra_bank.c"
printf '%-22s %s\n' "$name.elf" "0x08000000"

echo "fixtures written to $OUT"
