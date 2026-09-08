"""Memory region and startup state recovery.

Regions are built only from addresses with real provenance: destinations of
recovered load/store instructions, boundaries recovered from startup
initialization code, and the initial stack pointer.  Sorting every aligned
32-bit integer in the image and calling the gaps "RAM" produces far more false
positives than useful regions, so it is not done.

Multiple RAM banks are expected rather than merged: a single contiguous RAM
range is an assumption that plenty of real parts break.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..arch.base import ArchCapability
from ..core.evidence import Evidence
from ..core.memory import (
    InitKind,
    LoadedSegment,
    MemoryMap,
    MemoryRegion,
    RegionKind,
    StartupState,
)
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.reference import Access, ReferenceKind, ReferenceSet
from ..core.util import align_down, align_up, human_size

#: Addresses further apart than this belong to different RAM banks.
RAM_BANK_GAP = 0x10000
#: RAM region boundaries are reported at this granularity.
RAM_GRANULARITY = 0x400
#: Peripheral windows further apart than this are reported separately.
MMIO_GAP = 0x10000
MMIO_GRANULARITY = 0x400
#: A RAM cluster needs at least this many distinct addresses to stand on
#: read references alone.  A recovered *store* needs no such corroboration:
#: the instruction wrote there, so the memory exists and is writable.
MIN_RAM_REFERENCES = 3
#: Trailing erased flash at least this large is left out of the ELF.
PADDING_TRIM_THRESHOLD = 0x10000


class StartupAnalysis(AnalysisPass):
    """Recover ``.data`` and ``.bss`` initialization from startup code."""

    name = "StartupAnalysis"
    requires = frozenset({"runtime_base"})
    after = frozenset({"MemoryAccessRecovery"})
    capabilities = frozenset({ArchCapability.STARTUP_ANALYSIS})
    provides = frozenset({"startup_state"})

    def run(self, context: AnalysisContext) -> None:
        state = context.backend.recover_startup_state(context)
        context.provide("startup_state", state or StartupState())
        if state is None:
            return
        context.note(*state.evidence)
        for initialization in state.initializations:
            context.note(*initialization.evidence)
        copies = [item for item in state.initializations if item.kind == InitKind.COPY]
        zeros = [item for item in state.initializations if item.kind == InitKind.ZERO]
        context.log(
            f"startup: {len(copies)} data initializer(s), {len(zeros)} cleared range(s)", level=1
        )
        if not state.initializations:
            context.note(
                Evidence(
                    kind="startup",
                    source=self.name,
                    explanation=(
                        "no data-copy or bss-clear loop was recovered; the runtime may use a "
                        "table-driven initializer, which is not recovered"
                    ),
                    weight=0.0,
                    supports=False,
                )
            )


@dataclass
class _Cluster:
    addresses: list[int]
    write_count: int = 0
    read_count: int = 0

    @property
    def low(self) -> int:
        return min(self.addresses)

    @property
    def high(self) -> int:
        return max(self.addresses)


def cluster(addresses: Iterable[int], gap: int) -> list[list[int]]:
    """Group sorted addresses wherever the spacing exceeds ``gap``."""
    ordered = sorted(set(addresses))
    if not ordered:
        return []
    groups: list[list[int]] = [[ordered[0]]]
    for address in ordered[1:]:
        if address - groups[-1][-1] > gap:
            groups.append([address])
        else:
            groups[-1].append(address)
    return groups


class MemoryRegionRecovery(AnalysisPass):
    """Build the recovered memory map and the loadable firmware segments."""

    name = "MemoryRegionRecovery"
    requires = frozenset({"runtime_base"})
    after = frozenset({"StartupAnalysis", "MemoryAccessRecovery"})
    provides = frozenset({"memory_map", "loadable_segments"})

    def run(self, context: AnalysisContext) -> None:
        # Loadable segments first, so the reported Flash regions describe the
        # bytes that actually reach the ELF rather than the whole input.
        segments = self._segments(context)
        context.provide("loadable_segments", segments)

        memory_map = MemoryMap()
        for region in self._flash(segments):
            memory_map.add(region)
        for region in self._ram(context):
            memory_map.add(region)
        for region in self._mmio(context):
            memory_map.add(region)
        for region in context.backend.memory_region_hints(context):
            memory_map.add(region)
        context.provide("memory_map", memory_map)
        context.log(
            "memory map: "
            + ", ".join(
                f"{len(memory_map.of_kind(kind))} {kind.value}"
                for kind in (RegionKind.FLASH, RegionKind.RAM, RegionKind.MMIO)
            ),
            level=1,
        )

    # -- flash ------------------------------------------------------------

    def _flash(self, segments: list[LoadedSegment]) -> list[MemoryRegion]:
        return [
            MemoryRegion(
                kind=RegionKind.FLASH,
                start=segment.address,
                size=segment.size,
                name=segment.name,
                executable=True,
                loadable=True,
                confidence=1.0,
                evidence=(
                    Evidence(
                        kind="image_segment",
                        source=self.name,
                        explanation=(
                            f"{human_size(segment.size)} of firmware bytes at "
                            f"{segment.address:#010x}"
                        ),
                        value=segment.address,
                    ),
                ),
            )
            for segment in segments
        ]

    # -- ram --------------------------------------------------------------

    def _ram(self, context: AnalysisContext) -> list[MemoryRegion]:
        references: ReferenceSet = context.get("references") or ReferenceSet()
        startup: Optional[StartupState] = context.get("startup_state")

        anchors: dict[int, list[Evidence]] = {}

        def anchor(address: int, evidence: Evidence) -> None:
            anchors.setdefault(address, []).append(evidence)

        writes: set[int] = set()
        for reference in references.of_kind(ReferenceKind.RAM):
            anchor(
                reference.value,
                Evidence(
                    kind="ram_reference",
                    source=self.name,
                    explanation=(
                        f"{reference.access.value.lower()} of {reference.width or 32} bits at "
                        f"{reference.value:#010x} ({reference.derivation})"
                    ),
                    value=reference.value,
                    confidence=reference.confidence,
                ),
            )
            if reference.access == Access.WRITE:
                writes.add(reference.value)

        required: set[int] = set()
        if startup is not None:
            for initialization in startup.initializations:
                size = initialization.resolved_size or 0
                for address in (initialization.destination, initialization.destination + max(size - 1, 0)):
                    anchor(
                        address,
                        Evidence(
                            kind="startup_init",
                            source=self.name,
                            explanation=(
                                f"startup {initialization.kind.value} initializes "
                                f"{initialization.destination:#010x}..{initialization.destination + size:#010x}"
                            ),
                            value=initialization.destination,
                            confidence=initialization.confidence,
                        ),
                    )
                    required.add(address)
            if startup.initial_stack_pointer is not None:
                pointer = startup.initial_stack_pointer
                anchor(
                    pointer - 1,
                    Evidence(
                        kind="stack_pointer",
                        source=self.name,
                        explanation=f"initial stack pointer {pointer:#010x} sits at the top of this bank",
                        value=pointer,
                    ),
                )
                required.add(pointer - 1)

        regions: list[MemoryRegion] = []
        for index, group in enumerate(cluster(anchors, RAM_BANK_GAP)):
            distinct = len(group)
            members = set(group)
            anchored = bool(required & members) or bool(writes & members)
            if not anchored and distinct < MIN_RAM_REFERENCES:
                continue
            start = align_down(min(group), RAM_GRANULARITY)
            end = align_up(max(group) + 1, RAM_GRANULARITY)
            evidence: list[Evidence] = []
            for address in group:
                evidence.extend(anchors[address][:2])
            confidence = 0.9 if anchored else min(0.5 + 0.05 * distinct, 0.85)
            regions.append(
                MemoryRegion(
                    kind=RegionKind.RAM,
                    start=start,
                    size=end - start,
                    name="ram" if index == 0 else f"ram{index}",
                    writable=True,
                    confidence=confidence,
                    evidence=tuple(evidence[:6]),
                )
            )
        return regions

    # -- mmio -------------------------------------------------------------

    def _mmio(self, context: AnalysisContext) -> list[MemoryRegion]:
        accesses = context.get("peripheral_accesses") or context.get("mmio_accesses") or []
        if not accesses:
            return []
        by_address: dict[int, list] = {}
        for reference in accesses:
            by_address.setdefault(reference.value, []).append(reference)

        regions: list[MemoryRegion] = []
        for index, group in enumerate(cluster(by_address, MMIO_GAP)):
            start = align_down(min(group), MMIO_GRANULARITY)
            end = align_up(max(group) + 1, MMIO_GRANULARITY)
            hits = sum(len(by_address[address]) for address in group)
            regions.append(
                MemoryRegion(
                    kind=RegionKind.MMIO,
                    start=start,
                    size=end - start,
                    name=f"mmio{index}",
                    writable=True,
                    confidence=0.9,
                    evidence=(
                        Evidence(
                            kind="mmio_access",
                            source=self.name,
                            explanation=(
                                f"{hits} recovered access(es) to {len(group)} distinct register(s) "
                                f"in {start:#010x}..{end - 1:#010x}"
                            ),
                            value=hits,
                        ),
                    ),
                )
            )
        return regions

    # -- loadable segments ------------------------------------------------

    def _segments(self, context: AnalysisContext) -> list[LoadedSegment]:
        """Firmware bytes paired with the addresses they occupy."""
        segments: list[LoadedSegment] = []
        padding = context.get("padding") or []
        trim = bool(context.options.extra.get("trim_padding", True))

        for index, segment in enumerate(context.image.iter_segments()):
            address = segment.address
            if address is None:
                address = context.runtime_base + segment.image_offset
            data = segment.data
            if trim:
                data, removed = _trim_tail(segment, padding)
                if removed:
                    context.note(
                        Evidence(
                            kind="padding",
                            source=self.name,
                            explanation=(
                                f"omitted {human_size(removed)} of trailing erased flash from "
                                f"the ELF (offsets {segment.image_offset + len(data):#x}.."
                                f"{segment.image_end:#x})"
                            ),
                            value=removed,
                            weight=0.0,
                        )
                    )
            if not data:
                continue
            segments.append(
                LoadedSegment(
                    address=address,
                    data=data,
                    name="flash" if index == 0 else f"flash{index}",
                    executable=True,
                    writable=False,
                    image_offset=segment.image_offset,
                )
            )
        return segments


def _trim_tail(segment, padding) -> tuple[bytes, int]:
    """Remove a large erased run at the end of ``segment``."""
    for run in padding:
        if run.end != segment.image_end:
            continue
        if run.size < PADDING_TRIM_THRESHOLD:
            continue
        keep = run.image_offset - segment.image_offset
        return segment.data[:keep], segment.size - keep
    return segment.data, 0
