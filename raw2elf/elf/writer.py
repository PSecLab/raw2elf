"""A small native ELF writer.

Writing the ELF directly rather than generating a linker script and shelling
out to binutils keeps the tool dependency-light and, more importantly, keeps
the recovered addresses under our control: there is no linker deciding to
insert padding, drop a section or place a segment somewhere else.

Both ELF32 and ELF64 in either byte order are supported so that a future
64-bit backend needs no changes here.  Loadable sections get one ``PT_LOAD``
each with ``p_align`` of four: these ELFs are read by disassemblers, not
mapped by an operating system, and page-aligning every segment would inflate
the file with padding for no benefit.  Discontiguous inputs therefore produce
several small segments instead of one segment with an enormous zero-filled
hole.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .symbols import FUNC, NOTYPE, OBJECT, Symbol

ET_EXEC = 2
EV_CURRENT = 1
ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA2LSB, ELFDATA2MSB = 1, 2

PT_LOAD = 1
PF_X, PF_W, PF_R = 1, 2, 4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHN_UNDEF = 0
#: Symbols with an absolute value rather than a location in a section.
SHN_ABS = 0xFFF1

STB_LOCAL, STB_GLOBAL = 0, 1
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2

_SYMBOL_TYPES = {NOTYPE: STT_NOTYPE, OBJECT: STT_OBJECT, FUNC: STT_FUNC}

#: PT_LOAD alignment.  See the module docstring.
SEGMENT_ALIGNMENT = 4


@dataclass
class Section:
    """One output section."""

    name: str
    section_type: int
    flags: int
    address: int = 0
    data: bytes = b""
    #: Memory size; differs from ``len(data)`` only for ``SHT_NOBITS``.
    memory_size: Optional[int] = None
    alignment: int = 4
    link: int = 0
    info: int = 0
    entry_size: int = 0
    #: Emit a ``PT_LOAD`` for this section.
    loadable: bool = False
    #: Physical load address, when it differs from the runtime address --
    #: initialized data lives in Flash but runs from RAM.
    load_address: Optional[int] = None
    index: int = 0
    offset: int = 0

    @property
    def size(self) -> int:
        return self.memory_size if self.memory_size is not None else len(self.data)

    @property
    def file_size(self) -> int:
        return 0 if self.section_type == SHT_NOBITS else len(self.data)

    @property
    def segment_flags(self) -> int:
        flags = PF_R
        if self.flags & SHF_WRITE:
            flags |= PF_W
        if self.flags & SHF_EXECINSTR:
            flags |= PF_X
        return flags


class StringTable:
    """A deduplicating ELF string table."""

    def __init__(self) -> None:
        self._payload = bytearray(b"\x00")
        self._offsets: dict[str, int] = {"": 0}

    def add(self, text: str) -> int:
        if text in self._offsets:
            return self._offsets[text]
        offset = len(self._payload)
        self._payload += text.encode("utf-8") + b"\x00"
        self._offsets[text] = offset
        return offset

    @property
    def payload(self) -> bytes:
        return bytes(self._payload)


@dataclass
class ElfImage:
    """Everything needed to write one ELF."""

    machine: int
    entry: int
    flags: int = 0
    pointer_width: int = 32
    little_endian: bool = True
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    def add_section(self, section: Section) -> Section:
        self.sections.append(section)
        return section


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return value + (-value % alignment)


class ElfWriter:
    """Serializes an :class:`ElfImage`."""

    def __init__(self, image: ElfImage) -> None:
        self.image = image
        self.wide = image.pointer_width == 64
        self.order = "<" if image.little_endian else ">"
        self.header_size = 64 if self.wide else 52
        self.phdr_size = 56 if self.wide else 32
        self.shdr_size = 64 if self.wide else 40
        self.symbol_size = 24 if self.wide else 16

    # -- public -----------------------------------------------------------

    def build(self) -> bytes:
        image = self.image
        loadable = [section for section in image.sections if section.loadable]

        shstrtab = StringTable()
        strtab = StringTable()

        sections: list[Section] = [Section(name="", section_type=SHT_NULL, flags=0, alignment=0)]
        sections.extend(image.sections)

        symtab_index = len(sections)
        symbol_payload, first_global = self._encode_symbols(sections, strtab)
        sections.append(
            Section(
                name=".symtab",
                section_type=SHT_SYMTAB,
                flags=0,
                data=symbol_payload,
                alignment=8 if self.wide else 4,
                link=symtab_index + 1,
                info=first_global,
                entry_size=self.symbol_size,
            )
        )
        sections.append(
            Section(name=".strtab", section_type=SHT_STRTAB, flags=0, data=strtab.payload, alignment=1)
        )
        sections.append(
            Section(name=".shstrtab", section_type=SHT_STRTAB, flags=0, data=b"", alignment=1)
        )
        shstrtab_index = len(sections) - 1

        for index, section in enumerate(sections):
            section.index = index
            shstrtab.add(section.name)
        sections[shstrtab_index].data = shstrtab.payload

        cursor = self.header_size + len(loadable) * self.phdr_size
        for section in sections:
            if section.section_type in (SHT_NULL, SHT_NOBITS):
                section.offset = cursor
                continue
            cursor = _align_up(cursor, max(section.alignment, 1))
            if section.flags & SHF_ALLOC:
                # PT_LOAD requires p_offset and p_vaddr to be congruent
                # modulo p_align.
                cursor += (section.address - cursor) % SEGMENT_ALIGNMENT
            section.offset = cursor
            cursor += len(section.data)

        section_header_offset = _align_up(cursor, 8 if self.wide else 4)

        output = bytearray()
        output += self._encode_header(
            section_header_offset=section_header_offset,
            phnum=len(loadable),
            shnum=len(sections),
            shstrndx=shstrtab_index,
        )
        for section in loadable:
            output += self._encode_program_header(section)
        for section in sections:
            if section.section_type in (SHT_NULL, SHT_NOBITS) or not section.data:
                continue
            if len(output) < section.offset:
                output += b"\x00" * (section.offset - len(output))
            output[section.offset : section.offset + len(section.data)] = section.data
        if len(output) < section_header_offset:
            output += b"\x00" * (section_header_offset - len(output))
        for section in sections:
            output += self._encode_section_header(section, shstrtab)
        return bytes(output)

    # -- encoding ---------------------------------------------------------

    def _encode_header(
        self, section_header_offset: int, phnum: int, shnum: int, shstrndx: int
    ) -> bytes:
        identity = bytearray(16)
        identity[0:4] = b"\x7fELF"
        identity[4] = ELFCLASS64 if self.wide else ELFCLASS32
        identity[5] = ELFDATA2LSB if self.image.little_endian else ELFDATA2MSB
        identity[6] = EV_CURRENT
        layout = (
            f"{self.order}16sHHIQQQIHHHHHH" if self.wide else f"{self.order}16sHHIIIIIHHHHHH"
        )
        return struct.pack(
            layout,
            bytes(identity),
            ET_EXEC,
            self.image.machine,
            EV_CURRENT,
            self.image.entry,
            self.header_size if phnum else 0,
            section_header_offset,
            self.image.flags,
            self.header_size,
            self.phdr_size,
            phnum,
            self.shdr_size,
            shnum,
            shstrndx,
        )

    def _encode_program_header(self, section: Section) -> bytes:
        if self.wide:
            return struct.pack(
                f"{self.order}IIQQQQQQ",
                PT_LOAD,
                section.segment_flags,
                section.offset,
                section.address,
                section.load_address if section.load_address is not None else section.address,
                section.file_size,
                section.size,
                SEGMENT_ALIGNMENT,
            )
        return struct.pack(
            f"{self.order}IIIIIIII",
            PT_LOAD,
            section.offset,
            section.address,
            section.load_address if section.load_address is not None else section.address,
            section.file_size,
            section.size,
            section.segment_flags,
            SEGMENT_ALIGNMENT,
        )

    def _encode_section_header(self, section: Section, shstrtab: StringTable) -> bytes:
        name_offset = shstrtab.add(section.name)
        if self.wide:
            return struct.pack(
                f"{self.order}IIQQQQIIQQ",
                name_offset,
                section.section_type,
                section.flags,
                section.address,
                section.offset,
                section.size if section.section_type == SHT_NOBITS else len(section.data),
                section.link,
                section.info,
                section.alignment,
                section.entry_size,
            )
        return struct.pack(
            f"{self.order}IIIIIIIIII",
            name_offset,
            section.section_type,
            section.flags,
            section.address,
            section.offset,
            section.size if section.section_type == SHT_NOBITS else len(section.data),
            section.link,
            section.info,
            section.alignment,
            section.entry_size,
        )

    def _encode_symbols(self, sections: list[Section], strtab: StringTable) -> tuple[bytes, int]:
        """Encode ``.symtab``, locals first, and return the first global index."""
        # Indices, not the section objects: sections compare by field value,
        # so two identically shaped sections would test as the same one.
        allocated = [
            index
            for index, section in enumerate(sections)
            if section.flags & SHF_ALLOC and section.section_type != SHT_NULL
        ]

        def section_index(symbol: Symbol) -> int:
            if symbol.absolute:
                return SHN_ABS
            if symbol.section:
                for index, section in enumerate(sections):
                    if section.name == symbol.section:
                        return index
            for index in allocated:
                section = sections[index]
                if section.address <= symbol.value < section.address + max(section.size, 1):
                    return index
            return SHN_ABS

        ordered = [symbol for symbol in self.image.symbols if symbol.local]
        ordered += [symbol for symbol in self.image.symbols if not symbol.local]
        first_global = 1 + sum(1 for symbol in self.image.symbols if symbol.local)

        payload = bytearray(self._encode_symbol(0, 0, 0, 0, 0, 0))
        for symbol in ordered:
            info = ((STB_LOCAL if symbol.local else STB_GLOBAL) << 4) | _SYMBOL_TYPES.get(
                symbol.kind, STT_NOTYPE
            )
            payload += self._encode_symbol(
                strtab.add(symbol.name),
                symbol.value,
                symbol.size,
                info,
                0,
                section_index(symbol),
            )
        return bytes(payload), first_global

    def _encode_symbol(
        self, name: int, value: int, size: int, info: int, other: int, shndx: int
    ) -> bytes:
        if self.wide:
            return struct.pack(f"{self.order}IBBHQQ", name, info, other, shndx, value, size)
        return struct.pack(f"{self.order}IIIBBH", name, value, size, info, other, shndx)
