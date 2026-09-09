"""ELF reconstruction.

Sections stay conservative on purpose.  A single ``.flash`` per input segment
is correct and useful; inventing ``.text``/``.rodata`` boundaries that the
evidence does not support makes an ELF that looks more authoritative than it
is.  The split is available with ``--split-sections`` and only happens when
code discovery actually covered a meaningful part of the segment.

``.data`` and ``.bss`` are emitted only when startup analysis recovered them.
``.data`` carries the Flash bytes at its RAM runtime address with the Flash
address as its physical load address, mirroring what the original linker did,
so code that references initialized globals resolves in a disassembler.
"""

from __future__ import annotations

from typing import Optional

from ..core.evidence import Evidence
from ..core.hypothesis import InconsistentPlacementError
from ..core.memory import InitKind, LoadedSegment, StartupState
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.util import human_size
from ..elf.symbols import SymbolTable
from ..elf.writer import (
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_WRITE,
    SHT_NOBITS,
    SHT_PROGBITS,
    ElfImage,
    ElfWriter,
    Section,
)

#: Code discovery must cover at least this share of a segment before its
#: boundaries are trusted enough to split sections.
SPLIT_COVERAGE = 0.25


class ElfReconstruction(AnalysisPass):
    """Assemble and serialize the output ELF."""

    name = "ElfReconstruction"
    requires = frozenset({"loadable_segments", "runtime_base"})
    after = frozenset({"SymbolRecovery", "MemoryRegionRecovery"})
    provides = frozenset({"elf", "elf_sections"})
    optional = False

    def _check_placement(self, context: AnalysisContext) -> None:
        """Refuse to write an ELF whose own description contradicts itself.

        These are assertions, not scores. Each one compares two numbers that
        must agree by construction, so a disagreement means a stage assembled
        an image out of parts rather than selecting one -- and the resulting
        ELF would load, disassemble, and be wrong.
        """
        selected = context.get("selected_image")
        placement = context.get("selected_placement")
        if selected is None or placement is None:
            return

        # These assertions catch *our* mistakes -- an image assembled out of
        # parts. An analyst who supplies --base or --entry may knowingly
        # contradict what the image says about itself, which is their call;
        # that is reported as a warning rather than refused.
        forced = context.options.base is not None or context.options.entry is not None

        problems: list[str] = []
        if placement is not selected.placement:
            problems.append("the reported placement is not the selected image's own")

        base = placement.runtime_base
        if base is None:
            problems.append("the selected image has no load address")
        else:
            structure = placement.entry_structure
            if structure is not None and not placement.contains_address(structure):
                problems.append(
                    f"the entry structure {structure:#010x} is outside the selected image "
                    f"{base:#010x}..{placement.runtime_end:#010x}"
                )
            entry = context.get("entry")
            if (
                entry is not None
                and placement.entry is not None
                and context.backend.normalize_code_pointer(entry)
                != context.backend.normalize_code_pointer(placement.entry)
            ):
                problems.append(
                    f"the entry point {entry:#010x} is not the selected image's "
                    f"{placement.entry:#010x}"
                )
            if entry is not None and not placement.contains_address(
                context.backend.normalize_code_pointer(entry)
            ):
                complaint = (
                    f"the entry point {entry:#010x} is outside the selected image "
                    f"{base:#010x}..{placement.runtime_end:#010x}"
                )
                if forced:
                    context.warn(
                        complaint + "; the supplied base or entry disagrees with what the "
                        "image says about itself"
                    )
                else:
                    problems.append(complaint)

            segments = context.get("loadable_segments") or []
            # A container that declares its own layout describes discontiguous
            # memory on purpose, so its segments are checked against their
            # own declarations rather than against one contiguous extent.
            contiguous = (
                len(context.image.segments) == 1 and not context.image.addresses_declared
            )
            if contiguous:
                for segment in segments:
                    end = segment.address + segment.size
                    if forced:
                        continue
                    if segment.address < base or end > placement.runtime_end:
                        problems.append(
                            f"segment {segment.name} at {segment.address:#010x}..{end:#010x} "
                            f"is not inside the selected image "
                            f"{base:#010x}..{placement.runtime_end:#010x}"
                        )
                emitted = sum(segment.size for segment in segments)
                if not forced and emitted > placement.image_size:
                    problems.append(
                        f"{emitted} bytes would be emitted for an image of "
                        f"{placement.image_size}"
                    )
            else:
                for segment in segments:
                    declared = context.image.declared_address_for(segment.image_offset)
                    if declared is not None and declared != segment.address:
                        problems.append(
                            f"segment {segment.name} would be written at "
                            f"{segment.address:#010x}, but the input declares "
                            f"{declared:#010x}"
                        )
            if placement.file_offset != context.file_offset_of(placement.image_offset):
                problems.append("the file offset does not describe the selected image")

        if problems:
            raise InconsistentPlacementError(problems)

    def run(self, context: AnalysisContext) -> None:
        self._check_placement(context)
        backend = context.backend
        target = backend.elf_target_info()
        entry = context.get("entry")
        image = ElfImage(
            machine=target.elf_machine,
            entry=backend.encode_code_pointer(entry) if entry is not None else context.runtime_base,
            flags=target.elf_flags,
            pointer_width=target.pointer_width,
            little_endian=target.little_endian,
        )

        segments: list[LoadedSegment] = context.require("loadable_segments")
        for section in self._firmware_sections(context, segments):
            image.add_section(section)
        for section in self._runtime_sections(context):
            image.add_section(section)
        for extra in backend.elf_extra_sections(context):
            image.add_section(
                Section(
                    name=extra.name,
                    section_type=extra.section_type,
                    flags=extra.flags,
                    data=extra.payload,
                    alignment=extra.alignment,
                )
            )

        symbols: Optional[SymbolTable] = context.get("symbols")
        if symbols is not None:
            image.symbols = list(symbols)

        payload = ElfWriter(image).build()
        context.provide("elf", payload)
        context.provide(
            "elf_sections",
            [
                {
                    "name": section.name,
                    "address": f"0x{section.address:08x}",
                    "size": section.size,
                    "type": "nobits" if section.section_type == SHT_NOBITS else "progbits",
                    "loadable": section.loadable,
                }
                for section in image.sections
                if section.flags & SHF_ALLOC
            ],
        )
        loadable = sum(1 for section in image.sections if section.loadable)
        context.log(
            f"elf: {len(payload)} bytes, {loadable} loadable segment(s), "
            f"{len(image.symbols)} symbol(s)",
            level=1,
        )

    # -- firmware ---------------------------------------------------------

    def _firmware_sections(
        self, context: AnalysisContext, segments: list[LoadedSegment]
    ) -> list[Section]:
        sections: list[Section] = []
        code_regions = context.get("code_regions") or []
        for index, segment in enumerate(segments):
            parts = self._split(context, segment, code_regions) if context.options.split_sections else None
            if not parts:
                parts = [(segment.name if index == 0 else f"{segment.name}", segment.address, segment.data, True)]
            for name, address, data, executable in parts:
                if not data:
                    continue
                sections.append(
                    Section(
                        name=f".{name}" if not name.startswith(".") else name,
                        section_type=SHT_PROGBITS,
                        flags=SHF_ALLOC | (SHF_EXECINSTR if executable else 0),
                        address=address,
                        data=data,
                        alignment=4,
                        loadable=True,
                    )
                )
        return sections

    def _split(
        self, context: AnalysisContext, segment: LoadedSegment, code_regions
    ) -> Optional[list[tuple[str, int, bytes, bool]]]:
        """Split one segment into vectors/text/rodata, if evidence allows."""
        start = segment.address
        end = segment.address + segment.size
        inside = [
            (region_start, size)
            for region_start, size in code_regions
            if start <= region_start < end
        ]
        if not inside:
            return None
        covered = sum(size for _address, size in inside)
        if covered / max(segment.size, 1) < SPLIT_COVERAGE:
            context.note(
                Evidence(
                    kind="sections",
                    source=self.name,
                    explanation=(
                        f"code discovery covered only {human_size(covered)} of "
                        f"{human_size(segment.size)}; keeping one conservative section"
                    ),
                    value=covered,
                    weight=0.0,
                    supports=False,
                )
            )
            return None

        low = min(address for address, _size in inside)
        high = max(address + size for address, size in inside)
        low = max(low - (low % 4), start)
        high = min(high + (-high % 4), end)

        parts: list[tuple[str, int, bytes, bool]] = []
        if low > start:
            parts.append((".vectors", start, segment.data[: low - start], False))
        parts.append((".text", low, segment.data[low - start : high - start], True))
        if high < end:
            parts.append((".rodata", high, segment.data[high - start :], False))
        context.note(
            Evidence(
                kind="sections",
                source=self.name,
                explanation=(
                    f"split {segment.name} into {len(parts)} sections from discovered code "
                    f"covering {human_size(covered)}"
                ),
                value=covered,
            )
        )
        return parts

    # -- runtime ----------------------------------------------------------

    def _runtime_sections(self, context: AnalysisContext) -> list[Section]:
        state: Optional[StartupState] = context.get("startup_state")
        if state is None:
            return []
        sections: list[Section] = []
        counts: dict[InitKind, int] = {}
        for item in state.initializations:
            size = item.resolved_size
            if not size:
                continue
            ordinal = counts.get(item.kind, 0)
            counts[item.kind] = ordinal + 1
            suffix = "" if ordinal == 0 else str(ordinal + 1)
            if item.kind == InitKind.COPY and item.source is not None:
                payload = context.read_address(item.source, size)
                if len(payload) != size:
                    context.warn(
                        f"cannot read {size} bytes of initialized data from {item.source:#010x}; "
                        "omitting .data from the ELF"
                    )
                    continue
                sections.append(
                    Section(
                        name=f".data{suffix}",
                        section_type=SHT_PROGBITS,
                        flags=SHF_ALLOC | SHF_WRITE,
                        address=item.destination,
                        data=payload,
                        alignment=4,
                        loadable=True,
                        load_address=item.source,
                    )
                )
            elif item.kind == InitKind.ZERO:
                sections.append(
                    Section(
                        name=f".bss{suffix}",
                        section_type=SHT_NOBITS,
                        flags=SHF_ALLOC | SHF_WRITE,
                        address=item.destination,
                        data=b"",
                        memory_size=size,
                        alignment=4,
                        loadable=True,
                    )
                )
        return sections
