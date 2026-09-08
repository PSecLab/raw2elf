"""Corpus generation: turn a firmware image into the formats analysts get.

Given an ELF with known ground truth, this produces the same firmware as a
flat binary, Intel HEX, S-Records, ``xxd`` output, ``hexdump -C`` output and a
bare hex stream, plus the awkward variants that break naive parsers: dumps
wrapped in terminal noise, truncated dumps, squeezed dumps, and flash images
with padding, a bootloader and a second firmware slot.

Generating the inputs here rather than shelling out to ``xxd`` and ``hexdump``
keeps the corpus reproducible, but the parsers are also tested against real
output from those tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import elfread

#: Byte an erased NOR flash cell reads as.
ERASED = 0xFF


# -- ground truth ----------------------------------------------------------


@dataclass
class GroundTruth:
    """What the original ELF says, for grading a reconstruction."""

    name: str
    path: str
    machine: int
    base: int
    entry: int
    image: bytes
    chunks: list[tuple[int, bytes]] = field(default_factory=list)
    vector_offset: Optional[int] = None
    initial_stack_pointer: Optional[int] = None
    data_load: Optional[int] = None
    data_start: Optional[int] = None
    data_end: Optional[int] = None
    bss_start: Optional[int] = None
    bss_end: Optional[int] = None
    function_addresses: set[int] = field(default_factory=set)
    #: Handler addresses held in the reference ELF's vector table.  Unlike
    #: functions in general, these are guaranteed to exist in the firmware as
    #: absolute pointers, so they are the set a reference-recovery recall
    #: figure can fairly be measured against.
    vector_handlers: set[int] = field(default_factory=set)
    ram_ranges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def data_size(self) -> Optional[int]:
        if self.data_start is None or self.data_end is None:
            return None
        return self.data_end - self.data_start

    def is_ram(self, address: int) -> bool:
        return any(low <= address < high for low, high in self.ram_ranges)


def ground_truth(path: str | Path, name: Optional[str] = None) -> GroundTruth:
    """Extract ground truth from an ELF."""
    elf = elfread.read(path)
    base, image = elf.flat_image()

    def symbol(*candidates: str) -> Optional[int]:
        for candidate in candidates:
            found = elf.symbol(candidate)
            if found is not None and found.value:
                return found.value
        return None

    ram: list[tuple[int, int]] = []
    for section in elf.sections:
        if section.allocated and section.flags & elfread.SHF_WRITE and section.size:
            ram.append((section.address, section.address + section.size))

    vector = None
    vector_bytes = b""
    for candidate in (".isr_vector", ".vectors", ".vector_table", ".intvec"):
        section = elf.section(candidate)
        if section is not None and section.size:
            vector = section.address - base
            vector_bytes = section.data
            break
    order = "little" if elf.little_endian else "big"
    if vector is None and image[:4]:
        # No named vector section, so the table's extent has to be inferred.
        # It is bounded by the ELF's own load extent -- entries are zero or
        # point inside the image -- rather than by a fixed word count, which
        # would otherwise adopt whatever code follows the table as handlers.
        vector = 0
        vector_bytes = image[:4]
        for offset in range(4, min(len(image), 256 * 4), 4):
            word = int.from_bytes(image[offset : offset + 4], order)
            inside = base <= (word & ~1) < base + len(image)
            if word != 0 and not (word & 1 and inside):
                break
            vector_bytes += image[offset : offset + 4]

    handlers = {
        int.from_bytes(vector_bytes[offset : offset + 4], order) & ~1
        for offset in range(4, len(vector_bytes) - 3, 4)
        if int.from_bytes(vector_bytes[offset : offset + 4], order) & 1
    }

    return GroundTruth(
        name=name or Path(path).stem,
        path=str(path),
        machine=elf.machine,
        base=base,
        entry=elf.entry & ~1,
        image=image,
        chunks=elf.addressed_chunks(),
        vector_offset=vector,
        initial_stack_pointer=symbol("_estack", "__StackTop", "_stack_top"),
        data_load=symbol("_sidata", "__data_load", "__etext"),
        data_start=symbol("_sdata", "__data_start__", "__data_start"),
        data_end=symbol("_edata", "__data_end__", "__data_end"),
        bss_start=symbol("_sbss", "__bss_start__", "__bss_start"),
        bss_end=symbol("_ebss", "__bss_end__", "__bss_end"),
        function_addresses=elf.function_addresses(),
        vector_handlers=handlers,
        ram_ranges=ram,
    )


# -- format generation -----------------------------------------------------


def to_raw(image: bytes) -> bytes:
    return image


def to_ihex(chunks: Sequence[tuple[int, bytes]], record_length: int = 32) -> bytes:
    """Render addressed chunks as Intel HEX with linear address records."""
    lines: list[str] = []
    upper = None
    for address, payload in chunks:
        for offset in range(0, len(payload), record_length):
            piece = payload[offset : offset + record_length]
            here = address + offset
            high = here >> 16
            if high != upper:
                lines.append(_ihex_record(0, 0x04, high.to_bytes(2, "big")))
                upper = high
            lines.append(_ihex_record(here & 0xFFFF, 0x00, piece))
    lines.append(_ihex_record(0, 0x01, b""))
    return ("\n".join(lines) + "\n").encode("ascii")


def _ihex_record(address: int, kind: int, payload: bytes) -> str:
    body = bytes((len(payload), (address >> 8) & 0xFF, address & 0xFF, kind)) + payload
    checksum = (-sum(body)) & 0xFF
    return ":" + (body + bytes((checksum,))).hex().upper()


def to_srec(
    chunks: Sequence[tuple[int, bytes]], record_length: int = 32, name: str = "RAW2ELF"
) -> bytes:
    """Render addressed chunks as S-Records, using S3 for 32-bit addresses."""
    lines = [_srec_record(0, b"S0", name.encode("ascii")[:16], 2)]
    count = 0
    for address, payload in chunks:
        for offset in range(0, len(payload), record_length):
            piece = payload[offset : offset + record_length]
            lines.append(_srec_record(address + offset, b"S3", piece, 4))
            count += 1
    lines.append(_srec_record(min((item[0] for item in chunks), default=0), b"S7", b"", 4))
    return ("\n".join(lines) + "\n").encode("ascii")


def _srec_record(address: int, kind: bytes, payload: bytes, address_width: int) -> str:
    body = address.to_bytes(address_width, "big") + payload
    count = len(body) + 1
    checksum = 0xFF - ((count + sum(body)) & 0xFF)
    return kind.decode() + bytes((count,)).hex().upper() + body.hex().upper() + f"{checksum:02X}"


def to_xxd(image: bytes, columns: int = 16, group: int = 2, start: int = 0) -> bytes:
    """Render ``image`` the way ``xxd`` does."""
    lines: list[str] = []
    for offset in range(0, len(image), columns):
        row = image[offset : offset + columns]
        groups = [
            row[index : index + group].hex()
            for index in range(0, len(row), group)
        ]
        hex_field = " ".join(groups)
        width = (columns // group) * (group * 2 + 1) - 1
        ascii_field = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in row)
        lines.append(f"{start + offset:08x}: {hex_field:<{width}}  {ascii_field}")
    return ("\n".join(lines) + "\n").encode("ascii")


def to_hexdump(image: bytes, squeeze: bool = False) -> bytes:
    """Render ``image`` the way ``hexdump -C`` does, optionally squeezed."""
    lines: list[str] = []
    previous: Optional[bytes] = None
    squeezing = False
    for offset in range(0, len(image), 16):
        row = image[offset : offset + 16]
        if squeeze and row == previous and len(row) == 16:
            if not squeezing:
                lines.append("*")
                squeezing = True
            continue
        squeezing = False
        previous = row
        left = " ".join(f"{byte:02x}" for byte in row[:8])
        right = " ".join(f"{byte:02x}" for byte in row[8:])
        hex_field = f"{left:<23}  {right:<23}"
        ascii_field = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in row)
        lines.append(f"{offset:08x}  {hex_field} |{ascii_field}|")
    lines.append(f"{len(image):08x}")
    return ("\n".join(lines) + "\n").encode("ascii")


def to_plainhex(image: bytes, columns: int = 30) -> bytes:
    """Render ``image`` as a bare hex stream, the way ``xxd -p`` does."""
    lines = [image[offset : offset + columns].hex() for offset in range(0, len(image), columns)]
    return ("\n".join(lines) + "\n").encode("ascii")


def to_c_array(image: bytes, columns: int = 12) -> bytes:
    """Render ``image`` as comma-separated ``0x``-prefixed bytes."""
    lines = [
        ", ".join(f"0x{byte:02x}" for byte in image[offset : offset + columns]) + ","
        for offset in range(0, len(image), columns)
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


#: Every format a corpus entry is rendered into, by name.
FORMATS: dict[str, str] = {
    "raw": "raw",
    "ihex": "ihex",
    "srec": "srec",
    "xxd": "xxd",
    "hexdump": "hexdump",
    "plainhex": "plainhex",
    "c_array": "plainhex",
    "xxd_noisy": "xxd",
    "hexdump_squeezed": "hexdump",
}


def render(truth: GroundTruth, form: str) -> bytes:
    """Render one corpus entry in the named form."""
    if form == "raw":
        return to_raw(truth.image)
    if form == "ihex":
        return to_ihex(truth.chunks)
    if form == "srec":
        return to_srec(truth.chunks)
    if form == "xxd":
        return to_xxd(truth.image)
    if form == "hexdump":
        return to_hexdump(truth.image)
    if form == "hexdump_squeezed":
        return to_hexdump(truth.image, squeeze=True)
    if form == "plainhex":
        return to_plainhex(truth.image)
    if form == "c_array":
        return to_c_array(truth.image)
    if form == "xxd_noisy":
        return wrap_in_terminal_noise(to_xxd(truth.image))
    raise ValueError(f"unknown corpus form {form!r}")


def wrap_in_terminal_noise(dump: bytes) -> bytes:
    """Surround a dump with the log lines a real capture picks up."""
    header = (
        b"$ openocd -f board/stm32f4discovery.cfg\n"
        b"Open On-Chip Debugger 0.12.0\n"
        b"Info : clock speed 2000 kHz\n"
        b"target halted due to debug-request\n"
        b"$ xxd firmware.bin\n"
    )
    footer = b"$ \nConnection closed by foreign host.\n"
    return header + dump + footer


def truncate(dump: bytes, keep: float = 0.6) -> bytes:
    """Cut a text dump short, mid-line, the way a lost session does."""
    return dump[: int(len(dump) * keep)]


# -- synthetic flash layouts ----------------------------------------------


def flash_dump(
    images: Iterable[tuple[int, bytes]], size: int, fill: int = ERASED
) -> bytes:
    """Place images at offsets in an erased flash of ``size`` bytes."""
    buffer = bytearray(bytes((fill,)) * size)
    for offset, payload in images:
        buffer[offset : offset + len(payload)] = payload
    return bytes(buffer)


def with_padding(image: bytes, trailing: int, fill: int = ERASED) -> bytes:
    """Append an erased tail, as reading a whole flash bank produces."""
    return image + bytes((fill,)) * trailing
