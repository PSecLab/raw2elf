# Reference firmwares

Purpose-built Cortex-M firmwares with known ground truth, used by the test
suite and by `.venv/bin/python -m raw2elf.eval`. The ELFs are committed so that neither
needs a cross toolchain; re-run `./build.sh` (needs `arm-none-eabi-gcc`) only
when `src/` changes.

| Firmware | Flash | RAM | Exercises |
| --- | --- | --- | --- |
| `stm32f4_standard.elf` | `0x08000000` | `0x20000000`, 128K | The conventional case. |
| `nonstandard_base.elf` | `0x10000000` | `0x20000000`, 64K | A Flash base in the architectural code region, where vendors also put SRAM. |
| `application_high.elf` | `0x08008000` | `0x20000000`, 128K | An image whose vector table lands at a non-zero file offset in a dump. |
| `bootloader.elf` | `0x08000000` | `0x20000000`, 128K | The first image of a two-image dump. |
| `two_ram_banks.elf` | `0x08000000` | `0x20000000` + `0x10000000` | Two RAM banks that must not be merged. |

All five are built from `src/firmware.c`: a conventional vector table with
named exception handlers and 82 device interrupts, a reset handler whose
`.data` copy and `.bss` clear are ordinary C loops, real STM32F4 peripheral
registers across six peripherals, a constant table and a string in `.rodata`,
and a function-pointer table so that absolute code references exist to recover.

Ground truth is read back out of the ELFs by `raw2elf.eval.corpus`, which also
derives the raw, Intel HEX, S-Record, `xxd`, `hexdump -C`, bare-hex and C-array
representations, plus the awkward variants: dumps wrapped in terminal noise,
truncated dumps, squeezed dumps, and multi-image flash layouts with padding.
