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

from dataclasses import dataclass, field, replace
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
from ..core.provenance import CodeProvenance
from ..core.reference import Access, ReferenceKind, ReferenceSet
from .devices import layout_for
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
#: Below this a region is not worth reporting at all.
MIN_REGION_CONFIDENCE = 0.25
#: At or above this a region counts as established rather than speculative.
ESTABLISHED_CONFIDENCE = 0.6
#: A region below this architectural plausibility stays speculative however
#: good its other evidence: memory that needs a controller configured before
#: it answers is not established by a handful of stores.
PLAUSIBLE_ENOUGH = 0.5
#: The most that untrusted code can contribute to a region's score, no matter
#: how many accesses it makes. Weak evidence repeated is still weak evidence,
#: and a linear sweep over a compressed asset produces a great deal of it.
UNTRUSTED_CEILING = 0.6


@dataclass
class AccessEvidence:
    """What one cluster of addresses rests on, kept apart by trust.

    Trusted and untrusted accesses are counted separately rather than summed,
    because they differ in kind. Ten stores from a function the reset path
    reaches say the memory is there; ten stores from bytes that merely
    decoded say the bytes decoded.
    """

    #: Addresses reached by code something is known to reach, by an access
    #: whose base value could actually address memory.
    trusted_addresses: set = field(default_factory=set)
    #: Instruction offsets in trusted code that reached them.
    trusted_sites: set = field(default_factory=set)
    #: Distinct discovered functions those instructions belong to.
    functions: set = field(default_factory=set)
    #: Addresses trusted code writes to.
    writes: set = field(default_factory=set)
    #: Every address in the cluster, trusted or not.
    addresses: set = field(default_factory=set)
    #: Summed weight of the untrusted accesses, before the ceiling.
    untrusted_weight: float = 0.0
    untrusted_sites: set = field(default_factory=set)
    #: Instruction offsets whose recovered address was built from a value
    #: that could not address memory.
    incredible_sites: set = field(default_factory=set)
    #: The best reason any contributing instruction is believed to be code.
    best_provenance: Optional[CodeProvenance] = None
    #: The strongest reference that establishes memory here, kept so the
    #: region can show why it is believed rather than only assert it.
    witness: Optional[object] = None

    def record(self, reference) -> None:
        self.addresses.add(reference.value)
        provenance = reference.code_provenance
        if self.best_provenance is None or provenance.rank < self.best_provenance.rank:
            self.best_provenance = provenance
        if not reference.base_credible:
            # Reached, decoded, and computing nothing. Counted as weak so it
            # is visible, never as support.
            self.incredible_sites.add(reference.source_offset)
            return
        if reference.trusted:
            if self.witness is None or provenance.rank < self.witness.code_provenance.rank:
                self.witness = reference
            self.trusted_addresses.add(reference.value)
            self.trusted_sites.add(reference.source_offset)
            if reference.source_function is not None:
                self.functions.add(reference.source_function)
            if reference.access == Access.WRITE:
                self.writes.add(reference.value)
        else:
            self.untrusted_weight += provenance.weight
            self.untrusted_sites.add(reference.source_offset)

    def restricted_to(self, addresses: set) -> "AccessEvidence":
        """The part of this evidence concerning ``addresses``."""
        return AccessEvidence(
            trusted_addresses=self.trusted_addresses & addresses,
            trusted_sites=set(self.trusted_sites),
            functions=set(self.functions),
            writes=self.writes & addresses,
            addresses=self.addresses & addresses,
            untrusted_weight=self.untrusted_weight,
            untrusted_sites=set(self.untrusted_sites),
            incredible_sites=set(self.incredible_sites),
            best_provenance=self.best_provenance,
        )


def _region_confidence(
    name: str,
    evidence: "AccessEvidence",
    anchored: bool,
    layout,
    plausibility: float = 0.5,
) -> tuple:
    """How much a cluster of accesses is worth believing.

    Weighted by what the evidence *is*, not how much of it there is. The
    largest single factor is whether the instructions making the accesses are
    known to be executed at all: a valid instruction encoding is not the same
    thing as known executable code, and a page of compressed data decodes into
    plenty of well-formed stores whose effective addresses look exactly like
    real ones.

    Untrusted accesses are not ignored -- they are capped, at a level that
    cannot on its own carry a region past ``ESTABLISHED_CONFIDENCE``, however
    many of them there are.
    """
    from ..core.evidence import Evidence
    from ..core.util import logistic

    notes = []
    score = 0.0

    if anchored:
        score += 3.0
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation="a startup boundary or the reset stack pointer falls in this range",
                weight=3.0,
            )
        )

    if evidence.writes:
        score += 1.5
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=(
                    f"{len(evidence.writes)} address(es) in this range are written by "
                    "code that is reached"
                ),
                value=len(evidence.writes),
                weight=1.5,
            )
        )

    if evidence.trusted_sites:
        score += min(len(evidence.trusted_sites) * 0.4, 2.0)
        score += min(len(evidence.trusted_addresses) * 0.3, 1.5)
        provenance = evidence.best_provenance
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=(
                    f"{len(evidence.trusted_sites)} instruction(s) in reachable code "
                    f"({provenance.value.lower().replace('_', ' ')}) reach "
                    f"{len(evidence.trusted_addresses)} distinct {name} address(es)"
                ),
                value=len(evidence.trusted_sites),
            )
        )

    # Independently reached functions are much better evidence than the same
    # number of accesses from one block: two functions agreeing that memory
    # is here is a corroboration, twenty stores in a row is one opinion.
    independent = len(evidence.functions)
    if independent > 1:
        score += min((independent - 1) * 0.6, 1.8)
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=f"{independent} independently reached functions access this range",
                value=independent,
                weight=min((independent - 1) * 0.6, 1.8),
            )
        )

    if evidence.untrusted_weight:
        contribution = min(evidence.untrusted_weight, UNTRUSTED_CEILING)
        score += contribution
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=(
                    f"{len(evidence.untrusted_sites)} further access(es) come from bytes that "
                    "decode as instructions but that nothing is known to execute"
                ),
                value=len(evidence.untrusted_sites),
                weight=contribution,
                supports=bool(evidence.trusted_sites),
            )
        )

    if layout and any(
        origin <= address < origin + LAYOUT_WINDOW
        for origin in layout
        for address in evidence.addresses
    ):
        score += 1.5
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation="the range agrees with where the named part maps memory",
                weight=1.5,
            )
        )

    if evidence.incredible_sites:
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=(
                    f"{len(evidence.incredible_sites)} access(es) reach this range only by "
                    "indexing a register whose recovered value could not address memory, so "
                    "the address is a displacement rather than a pointer"
                ),
                value=len(evidence.incredible_sites),
                supports=False,
            )
        )

    if plausibility < PLAUSIBLE_ENOUGH:
        # This keeps the region speculative -- see the establishment test in
        # MemoryRegionRecovery._region -- rather than reducing its score. The
        # two are different questions: the score says how sure we are these
        # accesses happened, and establishment says whether this target is
        # known to have memory where they point. Subtracting here would push
        # a well-evidenced bank below the reporting floor and lose it, when
        # what is wanted is to report it and withhold the claim.
        notes.append(
            Evidence(
                kind="region",
                source="MemoryRegionRecovery",
                explanation=(
                    "this target is not known to have memory in this window, so the region "
                    "is reported without being claimed as recovered"
                ),
                weight=0.0,
                supports=False,
            )
        )

    return logistic(score, midpoint=2.5, steepness=0.9), notes


#: How far past a family's memory origin still counts as that memory.
LAYOUT_WINDOW = 0x00100000


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

        evidence_at: dict[int, AccessEvidence] = {}
        for reference in references.of_kind(ReferenceKind.RAM):
            if not reference.access.touches_memory:
                # A constant that looks like a RAM address is not a RAM bank.
                continue
            evidence_at.setdefault(reference.value, AccessEvidence()).record(reference)

        anchors: dict[int, list[Evidence]] = {
            address: [
                Evidence(
                    kind="ram_access",
                    source=self.name,
                    explanation=(
                        f"{len(item.trusted_sites) + len(item.untrusted_sites)} instruction(s) "
                        f"access {address:#010x}"
                        + (" including a write" if address in item.writes else "")
                    ),
                    value=address,
                )
            ]
            for address, item in evidence_at.items()
        }

        required: set[int] = set()
        if startup is not None:
            for initialization in startup.initializations:
                size = initialization.resolved_size or 0
                for address in (
                    initialization.destination,
                    initialization.destination + max(size - 1, 0),
                ):
                    anchors.setdefault(address, []).append(
                        Evidence(
                            kind="startup_init",
                            source=self.name,
                            explanation=(
                                f"startup {initialization.kind.value} initializes "
                                f"{initialization.destination:#010x}.."
                                f"{initialization.destination + size:#010x}"
                            ),
                            value=initialization.destination,
                            confidence=initialization.confidence,
                        )
                    )
                    required.add(address)
            if startup.initial_stack_pointer is not None:
                pointer = startup.initial_stack_pointer
                anchors.setdefault(pointer - 1, []).append(
                    Evidence(
                        kind="stack_pointer",
                        source=self.name,
                        explanation=(
                            f"initial stack pointer {pointer:#010x} sits at the top of this bank"
                        ),
                        value=pointer,
                    )
                )
                required.add(pointer - 1)

        layout = layout_for(context.options.mcu) if context.options.mcu else None
        regions: list[MemoryRegion] = []
        for group in cluster(anchors, RAM_BANK_GAP):
            region = self._region(
                context,
                kind=RegionKind.RAM,
                label="RAM",
                group=group,
                evidence_at=evidence_at,
                anchored=bool(required & set(group)),
                layout=layout.ram if layout else (),
                granularity=RAM_GRANULARITY,
                name=f"ram{len(regions)}" if regions else "ram",
                extra={address: anchors[address][:1] for address in sorted(group)[:4]},
            )
            if region is not None:
                regions.append(region)
        return regions

    # -- mmio -------------------------------------------------------------

    def _mmio(self, context: AnalysisContext) -> list[MemoryRegion]:
        accesses = context.get("peripheral_accesses") or context.get("mmio_accesses") or []
        evidence_at: dict[int, AccessEvidence] = {}
        for reference in accesses:
            if not reference.access.touches_memory:
                continue
            evidence_at.setdefault(reference.value, AccessEvidence()).record(reference)
        if not evidence_at:
            return []

        regions: list[MemoryRegion] = []
        for group in cluster(evidence_at, MMIO_GAP):
            region = self._region(
                context,
                kind=RegionKind.MMIO,
                label="peripheral",
                group=group,
                evidence_at=evidence_at,
                anchored=False,
                layout=(),
                granularity=MMIO_GRANULARITY,
                name=f"mmio{len(regions)}",
            )
            if region is not None:
                regions.append(region)
        return regions

    # -- one region, and what it rests on ---------------------------------

    def _region(
        self,
        context: AnalysisContext,
        kind: RegionKind,
        label: str,
        group,
        evidence_at: dict,
        anchored: bool,
        layout,
        granularity: int,
        name: str,
        extra: Optional[dict] = None,
    ) -> Optional[MemoryRegion]:
        """Score one cluster and turn it into a region, or reject it."""
        members = set(group)
        combined = AccessEvidence()
        for address in members:
            item = evidence_at.get(address)
            if item is None:
                continue
            combined.trusted_addresses |= item.trusted_addresses
            combined.trusted_sites |= item.trusted_sites
            combined.functions |= item.functions
            combined.writes |= item.writes
            combined.addresses |= item.addresses
            combined.untrusted_weight += item.untrusted_weight
            combined.untrusted_sites |= item.untrusted_sites
            combined.incredible_sites |= item.incredible_sites
            if item.witness is not None and (
                combined.witness is None
                or item.witness.code_provenance.rank < combined.witness.code_provenance.rank
            ):
                combined.witness = item.witness
            if item.best_provenance is not None and (
                combined.best_provenance is None
                or item.best_provenance.rank < combined.best_provenance.rank
            ):
                combined.best_provenance = item.best_provenance

        # How likely this target is to have memory here at all. The backend
        # knows its own address map; this code does not and must not. The
        # question is asked about read/write memory for RAM, because a window
        # that plausibly holds image bytes is not therefore a plausible place
        # to find a RAM bank.
        layout = layout_for(context.options.mcu) if context.options.mcu else None
        known_ram = tuple(layout.ram) if layout else ()
        plausibility = min(
            (
                context.backend.region_plausibility(
                    address, writable=kind is RegionKind.RAM, known_ram=known_ram
                )
                for address in members
            ),
            default=0.5,
        )
        confidence, notes = _region_confidence(
            name=label,
            evidence=combined,
            anchored=anchored,
            layout=layout,
            plausibility=plausibility,
        )
        if confidence < MIN_REGION_CONFIDENCE:
            return None

        # Established means three things at once: reachable code made the
        # accesses, there is enough of that evidence, and the target
        # plausibly has memory here. Any one of them missing leaves the
        # region reported but speculative.
        established = (
            confidence >= ESTABLISHED_CONFIDENCE
            and (anchored or bool(combined.trusted_sites))
            and plausibility >= PLAUSIBLE_ENOUGH
        )
        # An established region must be able to answer "why do we believe an
        # instruction that touches this executes?". If it cannot, it is not
        # established, whatever its score.
        trust_path: tuple[str, ...] = ()
        if combined.witness is not None:
            trust_path = tuple(context.backend.trust_path(context, combined.witness))
        if established and not anchored and not trust_path:
            established = False

        evidence: list[Evidence] = list(notes)
        for items in (extra or {}).values():
            evidence.extend(items)
        return MemoryRegion(
            kind=kind,
            start=align_down(min(group), granularity),
            size=align_up(max(group) + 1, granularity) - align_down(min(group), granularity),
            name=name,
            writable=True,
            confidence=confidence,
            speculative=not established,
            trust_path=trust_path,
            evidence=tuple(evidence[:6]),
        )

    # -- loadable segments ------------------------------------------------

    def _segments(self, context: AnalysisContext) -> list[LoadedSegment]:
        """Firmware bytes paired with the addresses they occupy.

        The bytes that reach the ELF are the program's, which is not always
        the whole input: a dump may hold erased flash, a configuration block
        or a second program before the one being reconstructed. Emitting
        those as part of it places the program at an address it does not
        occupy.
        """
        segments: list[LoadedSegment] = []
        padding = context.get("padding") or []
        trim = bool(context.options.extra.get("trim_padding", True))
        placement = context.get("selected_placement")

        # Clipping applies to a dump with a program inside it, not to a
        # container that declares its own layout: every segment an Intel HEX
        # file describes is part of the program.
        clips = (
            placement is not None
            and placement.image_size
            and len(context.image.segments) == 1
            and not context.image.addresses_declared
        )

        for segment in context.image.iter_segments():
            data = segment.data
            image_offset = segment.image_offset
            if clips:
                # The bytes that reach the ELF are the selected image's. A
                # dump may hold erased flash, a configuration block or a
                # second program; emitting those as part of this one places
                # it at an address it does not occupy.
                low = max(image_offset, placement.image_offset)
                high = min(segment.image_end, placement.image_offset + placement.image_size)
                if low >= high:
                    continue
                dropped = (high - low) - segment.size
                data = data[low - image_offset : high - image_offset]
                image_offset = low
                if dropped:
                    erased = any(
                        run.image_offset <= high and run.end >= segment.image_end
                        for run in padding
                    )
                    what = (
                        "trailing erased flash"
                        if erased
                        else "bytes outside the selected image"
                    )
                    context.note(
                        Evidence(
                            kind="image_extent",
                            source=self.name,
                            explanation=(
                                f"omitted {human_size(-dropped)} of {what} from the ELF "
                                f"(kept offsets {low:#x}..{high:#x} of "
                                f"{segment.image_offset:#x}..{segment.image_end:#x})"
                            ),
                            value=-dropped,
                            weight=0.0,
                        )
                    )
            address = segment.address
            if address is None:
                address = context.runtime_base + image_offset
            else:
                address += image_offset - segment.image_offset
            segment = replace(segment, image_offset=image_offset, data=data)
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
                    name="flash" if not segments else f"flash{len(segments)}",
                    executable=True,
                    writable=False,
                    image_offset=image_offset,
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
