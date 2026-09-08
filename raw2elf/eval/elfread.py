"""A minimal ELF reader, used to grade reconstructions.

Only what the evaluation harness needs: the machine and entry point, the
loadable segments with their virtual and physical addresses, the section
table and the symbol table.  Written with ``struct`` rather than pulling in
an ELF library so that the evaluation harness has the same dependency
footprint as the tool it grades, and so that a reconstruction can be checked
without trusting the same code that produced it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

PT_LOAD = 1
SHT_SYMTAB = 2
SHT_NOBITS = 8
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_WRITE = 0x1
STT_FUNC = 2
STT_OBJECT = 1
SHN_ABS = 0xFFF1


@dataclass(frozen=True)
class Segment:
    kind: int
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int
    data: bytes = b""

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def writable(self) -> bool:
        return bool(self.flags & 0x2)


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    entry_size: int
    link: int
    info: int = 0
    data: bytes = b""

    @property
    def allocated(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int
    section_index: int

    @property
    def kind(self) -> int:
        return self.info & 0xF

    @property
    def is_function(self) -> bool:
        return self.kind == STT_FUNC

    @property
    def is_absolute(self) -> bool:
        return self.section_index == SHN_ABS


@dataclass
class ElfFile:
    """A parsed ELF."""

    path: str
    machine: int
    entry: int
    flags: int
    pointer_width: int
    little_endian: bool
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)

    @property
    def loads(self) -> list[Segment]:
        return [item for item in self.segments if item.kind == PT_LOAD and item.memory_size]

    def section(self, name: str) -> Optional[Section]:
        return next((item for item in self.sections if item.name == name), None)

    def symbol(self, name: str) -> Optional[Symbol]:
        return next((item for item in self.symbols if item.name == name), None)

    def function_addresses(self) -> set[int]:
        """Thumb bit removed, so recovered pointers can be compared directly."""
        return {
            item.value & ~1
            for item in self.symbols
            if item.is_function and item.value and not item.is_absolute
        }

    def flat_image(self) -> tuple[int, bytes]:
        """The Flash image as a programmer would write it, plus its base.

        Segments are placed by physical address, which is where initialized
        data lives before startup copies it, and gaps are filled with the
        erased-flash byte.
        """
        loads = [item for item in self.loads if item.file_size]
        if not loads:
            return 0, b""
        base = min(item.physical_address for item in loads)
        end = max(item.physical_address + item.file_size for item in loads)
        buffer = bytearray(b"\xff" * (end - base))
        for segment in sorted(loads, key=lambda item: item.physical_address):
            start = segment.physical_address - base
            buffer[start : start + segment.file_size] = segment.data
        return base, bytes(buffer)

    def addressed_chunks(self) -> list[tuple[int, bytes]]:
        """Loadable content as ``(physical address, bytes)`` runs."""
        return [
            (item.physical_address, item.data)
            for item in sorted(self.loads, key=lambda entry: entry.physical_address)
            if item.file_size
        ]


def read(path: str | Path) -> ElfFile:
    """Parse the ELF at ``path``."""
    raw = Path(path).read_bytes()
    if raw[:4] != b"\x7fELF":
        raise ValueError(f"{path} is not an ELF file")
    wide = raw[4] == 2
    order = "<" if raw[5] == 1 else ">"

    if wide:
        layout = f"{order}16sHHIQQQIHHHHHH"
    else:
        layout = f"{order}16sHHIIIIIHHHHHH"
    size = struct.calcsize(layout)
    (
        _identity,
        _kind,
        machine,
        _version,
        entry,
        phoff,
        shoff,
        flags,
        _ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = struct.unpack(layout, raw[:size])

    elf = ElfFile(
        path=str(path),
        machine=machine,
        entry=entry,
        flags=flags,
        pointer_width=64 if wide else 32,
        little_endian=order == "<",
    )

    for index in range(phnum):
        chunk = raw[phoff + index * phentsize : phoff + (index + 1) * phentsize]
        if wide:
            kind, pflags, offset, vaddr, paddr, filesz, memsz, align = struct.unpack(
                f"{order}IIQQQQQQ", chunk[:56]
            )
        else:
            kind, offset, vaddr, paddr, filesz, memsz, pflags, align = struct.unpack(
                f"{order}IIIIIIII", chunk[:32]
            )
        elf.segments.append(
            Segment(
                kind=kind,
                offset=offset,
                virtual_address=vaddr,
                physical_address=paddr,
                file_size=filesz,
                memory_size=memsz,
                flags=pflags,
                alignment=align,
                data=raw[offset : offset + filesz],
            )
        )

    raw_sections = []
    for index in range(shnum):
        chunk = raw[shoff + index * shentsize : shoff + (index + 1) * shentsize]
        if wide:
            name, kind, sflags, addr, offset, ssize, link, info, align, entsize = struct.unpack(
                f"{order}IIQQQQIIQQ", chunk[:64]
            )
        else:
            name, kind, sflags, addr, offset, ssize, link, info, align, entsize = struct.unpack(
                f"{order}IIIIIIIIII", chunk[:40]
            )
        raw_sections.append((name, kind, sflags, addr, offset, ssize, link, info, entsize))

    names = b""
    if shnum and shstrndx < shnum:
        _n, _k, _f, _a, offset, ssize, _l, _i, _e = raw_sections[shstrndx]
        names = raw[offset : offset + ssize]

    for name, kind, sflags, addr, offset, ssize, link, info, entsize in raw_sections:
        elf.sections.append(
            Section(
                name=_string(names, name),
                kind=kind,
                flags=sflags,
                address=addr,
                offset=offset,
                size=ssize,
                entry_size=entsize,
                link=link,
                info=info,
                data=b"" if kind == SHT_NOBITS else raw[offset : offset + ssize],
            )
        )

    for section in elf.sections:
        if section.kind != SHT_SYMTAB or not section.entry_size:
            continue
        strings = elf.sections[section.link].data if section.link < len(elf.sections) else b""
        count = section.size // section.entry_size
        for index in range(count):
            chunk = section.data[index * section.entry_size : (index + 1) * section.entry_size]
            if wide:
                name, info, _other, shndx, value, symsize = struct.unpack(f"{order}IBBHQQ", chunk[:24])
            else:
                name, value, symsize, info, _other, shndx = struct.unpack(f"{order}IIIBBH", chunk[:16])
            elf.symbols.append(
                Symbol(
                    name=_string(strings, name),
                    value=value,
                    size=symsize,
                    info=info,
                    section_index=shndx,
                )
            )
    return elf


def _string(table: bytes, offset: int) -> str:
    if offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    return table[offset : end if end >= 0 else len(table)].decode("utf-8", errors="replace")
