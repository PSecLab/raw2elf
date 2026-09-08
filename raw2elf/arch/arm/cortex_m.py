"""ARM Cortex-M architecture backend.

Everything Cortex-M specific lives behind the
:class:`~raw2elf.arch.base.ArchitectureBackend` interface: the ARMv7-M address
map, the Thumb code-pointer representation, exception vector tables, the reset
convention, PC-relative address construction and startup initialization
patterns.  The generic core sees only entry candidates, references, evidence
and base assessments.
"""

from __future__ import annotations

import struct
from typing import Optional

from ...core.evidence import Evidence
from ...core.hypothesis import EntryCandidate
from ...core.image import FirmwareImage
from ...core.memory import MemoryRegion, RegionKind, StartupState
from ...core.reference import Access, AddressClass, Reference, ReferenceKind
from ...core.util import logistic
from ..base import (
    ArchCapability,
    ArchitectureBackend,
    BaseAssessment,
    BaseConstraints,
    BaseSeed,
    CodeScore,
    ExtraSection,
    InterruptEntry,
    InterruptTable,
    ProbeResult,
    SymbolRequest,
    TargetInfo,
)
from . import references as arm_references
from . import startup as arm_startup
from . import vectors as arm_vectors
from .decoder import Decoder

#: ARMv7-M address map.  Vendors also place SRAM in the code region (CCM on
#: STM32F4, main SRAM on LPC17xx), which is why the ``CODE`` class means
#: "executable, not necessarily Flash" rather than "definitely Flash".
_ADDRESS_MAP: tuple[tuple[int, int, AddressClass], ...] = (
    (0x00000000, 0x20000000, AddressClass.CODE),
    (0x20000000, 0x40000000, AddressClass.RAM),
    (0x40000000, 0x60000000, AddressClass.MMIO),
    (0x60000000, 0xA0000000, AddressClass.RAM),
    (0xA0000000, 0xE0000000, AddressClass.MMIO),
    (0xE0000000, 0xE0100000, AddressClass.SYSTEM),
    (0xE0100000, 0x100000000, AddressClass.RESERVED),
)

#: Ranges the image itself can plausibly be linked into.
_EXECUTION_WINDOWS: tuple[tuple[int, int], ...] = (
    (0x00000000, 0x1FFFFFFF),
    (0x20000000, 0x3FFFFFFF),
    (0x60000000, 0x9FFFFFFF),
)

#: How far past its own vector table a handler may plausibly live.  Handlers
#: belong to the image the table heads, and images are not this large.
HANDLER_LOCALITY = 0x40000
#: Vector tables examined when scoring a candidate base.  A dump may hold
#: several images, and the real base is the one that satisfies all of them.
MAX_TABLES_CHECKED = 6

EM_ARM = 40
EF_ARM_EABI_VER5 = 0x05000000
#: Cortex-M is Thumb-only, so the ELF must say so or disassemblers guess ARM.
EF_ARM_ABI_FLOAT_SOFT = 0x00000200

_SOURCE = "arm-cortex-m"


class CortexMBackend(ArchitectureBackend):
    """Recovery for ARM Cortex-M (ARMv6-M / ARMv7-M / ARMv8-M) firmware."""

    name = "arm-cortex-m"
    description = "ARM Cortex-M (Thumb-2, little endian)"
    instruction_alignment = 2
    entry_scan_alignment = 4

    def __init__(self, big_endian: bool = False) -> None:
        self.big_endian = big_endian
        self.decoder = Decoder(big_endian=big_endian)

    # -- identity ---------------------------------------------------------

    def capabilities(self) -> frozenset[ArchCapability]:
        return frozenset(
            (
                ArchCapability.ENTRY_DISCOVERY,
                ArchCapability.BASE_CONSTRAINTS,
                ArchCapability.REFERENCE_RECOVERY,
                ArchCapability.MMIO_REFERENCE_RECOVERY,
                ArchCapability.STARTUP_ANALYSIS,
                ArchCapability.INTERRUPT_TABLE_RECOVERY,
                ArchCapability.CODE_VALIDATION,
                ArchCapability.CODE_DISCOVERY,
            )
        )

    def elf_target_info(self) -> TargetInfo:
        return TargetInfo(
            architecture="arm",
            subarchitecture="cortex-m",
            instruction_mode="thumb",
            endianness="big" if self.big_endian else "little",
            pointer_width=32,
            elf_machine=EM_ARM,
            elf_flags=EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_SOFT,
            display_name="ARM Cortex-M",
        )

    # -- address space ----------------------------------------------------

    def classify_address(self, address: int) -> AddressClass:
        address &= 0xFFFFFFFF
        for low, high, kind in _ADDRESS_MAP:
            if low <= address < high:
                return kind
        return AddressClass.UNKNOWN

    def normalize_code_pointer(self, value: int) -> int:
        """Drop the Thumb interworking bit."""
        return value & ~1

    def encode_code_pointer(self, address: int) -> int:
        """Set the Thumb interworking bit."""
        return address | 1

    def is_plausible_code_pointer(self, value: int) -> bool:
        return arm_vectors.plausible_handler(value, self.classify_address)

    # -- probing ----------------------------------------------------------

    def probe(self, image: FirmwareImage) -> ProbeResult:
        tables = self._tables(image)
        evidence: list[Evidence] = []
        score = 0.0

        if tables:
            best = tables[0]
            score += 4.0 * best.confidence
            evidence.append(
                Evidence(
                    kind="vector_table",
                    source=_SOURCE,
                    explanation=(
                        f"candidate Cortex-M vector table at image offset {best.image_offset:#x} "
                        f"(MSP {best.initial_sp:#010x}, reset {best.reset_handler:#010x})"
                    ),
                    value=best.image_offset,
                    confidence=best.confidence,
                    weight=4.0,
                )
            )
            if len(tables) > 1:
                evidence.append(
                    Evidence(
                        kind="vector_table",
                        source=_SOURCE,
                        explanation=f"{len(tables)} candidate vector tables found",
                        value=len(tables),
                        weight=0.0,
                    )
                )

        if self._looks_like_a32_reset_table(image):
            score -= 6.0
            evidence.append(
                Evidence(
                    kind="a32_vectors",
                    source=_SOURCE,
                    explanation=(
                        "the image begins with the classic ARM exception table convention "
                        "(a run of branches or 'ldr pc, [pc, #imm]'), which Cortex-M does not use"
                    ),
                    weight=6.0,
                    supports=False,
                )
            )

        density, a32_density, samples = self._code_density(image)
        score += 3.0 * density
        evidence.append(
            Evidence(
                kind="code_density",
                source=_SOURCE,
                explanation=f"{samples} sampled window(s) decode as Thumb with mean confidence {density:.2f}",
                value=round(density, 3),
                confidence=density,
                weight=3.0,
            )
        )
        if a32_density > density:
            penalty = 6.0 * (a32_density - density)
            score -= penalty
            evidence.append(
                Evidence(
                    kind="code_density",
                    source=_SOURCE,
                    explanation=(
                        f"the same windows decode better as classic ARM ({a32_density:.2f}) than as "
                        "Thumb, so this is more likely an A-profile or classic ARM image"
                    ),
                    value=round(a32_density, 3),
                    weight=penalty,
                    supports=False,
                )
            )

        confidence = logistic(score, midpoint=2.0, steepness=1.1)
        return ProbeResult(
            backend=self.name,
            confidence=confidence,
            target=self.elf_target_info(),
            evidence=tuple(evidence),
            details={
                "vector_tables": len(tables),
                "thumb_density": round(density, 3),
                "a32_density": round(a32_density, 3),
            },
        )

    def _code_density(self, image: FirmwareImage, samples: int = 12) -> tuple[float, float, int]:
        """Mean Thumb and A32 plausibility over windows across the image.

        Padding and uniform runs are skipped: they decode "successfully" as
        degenerate instructions and would otherwise inflate both scores.
        """
        thumb: list[float] = []
        a32: list[float] = []
        for segment in image.iter_segments():
            if segment.size < 64:
                continue
            step = max(64, segment.size // samples)
            for offset in range(0, segment.size - 64, step):
                window = segment.data[offset : offset + 256]
                if len(set(window)) <= 2:
                    continue
                address = segment.image_offset + offset
                thumb.append(self.decoder.score_code(window, address).confidence)
                a32.append(self.decoder.score_a32(window, address))
                if len(thumb) >= samples:
                    break
            if len(thumb) >= samples:
                break
        if not thumb:
            return 0.0, 0.0, 0
        return sum(thumb) / len(thumb), sum(a32) / len(a32), len(thumb)

    def _looks_like_a32_reset_table(self, image: FirmwareImage) -> bool:
        """Detect the classic ARM reset convention at the image start.

        ARM7/ARM9/A-profile images open with eight A32 words that branch or
        load PC -- ``e59ff018`` repeated, or a run of ``b`` instructions.
        Cortex-M puts a stack pointer and Thumb handler addresses there
        instead, so finding one rules this backend out rather than being a
        detail to score.
        """
        from capstone import arm as csarm

        head = image.read(0, 32)
        if len(head) < 32:
            return False
        matches = 0
        for index in range(8):
            word = head[index * 4 : index * 4 + 4]
            decoded = None
            for instruction in self.decoder.a32.disasm(word, index * 4, count=1):
                decoded = instruction
            if decoded is None:
                continue
            if decoded.id == csarm.ARM_INS_B:
                matches += 1
            elif decoded.id == csarm.ARM_INS_LDR and "pc," in decoded.op_str.replace(" ", ""):
                matches += 1
        return matches >= 6

    def validate_code(self, data: bytes, address: int) -> CodeScore:
        return self.decoder.score_code(data, address)

    # -- entry discovery --------------------------------------------------

    def _tables(self, image: FirmwareImage) -> list[arm_vectors.VectorTable]:
        # Cached against the image, because probing and entry discovery both
        # want the scan and a carved sub-image needs its own.
        return image.derived(
            "cortexm_vector_tables",
            lambda: arm_vectors.find_tables(
                image,
                self.classify_address,
                byte_order=self.elf_target_info().byte_order,
                alignment=self.entry_scan_alignment,
            ),
        )

    def discover_entry_candidates(self, context) -> list[EntryCandidate]:
        override = context.options.vector_offset
        if override is not None:
            forced = self._forced_table(context.image, override)
            tables = [forced] if forced is not None else []
            if forced is None:
                context.warn(
                    f"--vector-offset {override:#x} does not hold a readable vector table"
                )
        else:
            tables = self._tables(context.image)

        candidates: list[EntryCandidate] = []
        for table in tables:
            remaining = context.image.size - table.image_offset
            candidate = EntryCandidate(
                kind="vector_table",
                image_offset=table.image_offset,
                entry_value=table.reset_address,
                entry_base_relative=False,
                confidence=table.confidence,
                evidence=list(table.evidence),
                details={
                    "initial_sp": table.initial_sp,
                    "reset_handler": table.reset_handler,
                    "words": table.word_count,
                    "handler_slots": list(table.handler_slots),
                    "default_handler": table.default_handler,
                    "score": round(table.score, 3),
                    "base_seeds": table.base_seeds(remaining),
                    "base_range": table.base_range(remaining),
                    "table": table,
                },
            )
            candidates.append(candidate)
        return candidates

    def _forced_table(self, image: FirmwareImage, offset: int) -> Optional[arm_vectors.VectorTable]:
        """Build a vector table candidate at an analyst-specified offset."""
        byte_order = self.elf_target_info().byte_order
        payload = image.read(offset, arm_vectors.MAX_TABLE_WORDS * 4)
        if len(payload) < 32:
            return None
        available = len(payload) // 4
        words = [
            int.from_bytes(payload[index * 4 : index * 4 + 4], byte_order)
            for index in range(available)
        ]
        length = max(16, arm_vectors._table_length(words, self.classify_address))
        words = words[:length]
        table = arm_vectors.VectorTable(
            image_offset=offset,
            initial_sp=words[0],
            reset_handler=words[1],
            words=words,
            handler_slots=[
                index
                for index in range(1, len(words))
                if arm_vectors.plausible_handler(words[index], self.classify_address)
            ],
        )
        arm_vectors.score_table(table, image.size - offset, self.classify_address)
        table.confidence = 1.0
        table.evidence.insert(
            0,
            Evidence(
                kind="override",
                source=_SOURCE,
                explanation=f"analyst specified the vector table at image offset {offset:#x}",
                value=offset,
                weight=0.0,
            ),
        )
        return table

    # -- base recovery ----------------------------------------------------

    def generate_base_constraints(self, context) -> BaseConstraints:
        candidates = context.get("entry_candidates") or []
        seeds: list[BaseSeed] = []
        ranges: list[tuple[int, int]] = []
        evidence: list[Evidence] = []

        for candidate in candidates[:4]:
            for base, weight in candidate.details.get("base_seeds", ()):
                seeds.append(
                    BaseSeed(
                        runtime_base=base,
                        weight=weight,
                        evidence=Evidence(
                            kind="base_seed",
                            source=_SOURCE,
                            explanation=(
                                f"vector table at offset {candidate.image_offset:#x} allows base "
                                f"{base:#010x} with its handlers inside the image"
                            ),
                            value=base,
                            weight=weight,
                        ),
                    )
                )
            bounds = candidate.details.get("base_range")
            if bounds:
                ranges.append(bounds)

        if ranges:
            low = min(item[0] for item in ranges)
            high = max(item[1] for item in ranges)
            plausible = ((low, high),)
            evidence.append(
                Evidence(
                    kind="base_range",
                    source=_SOURCE,
                    explanation=(
                        f"vector table handlers constrain the base to {low:#010x}..{high:#010x}"
                    ),
                    value=(low, high),
                )
            )
        else:
            plausible = _EXECUTION_WINDOWS

        return BaseConstraints(
            seeds=tuple(seeds),
            alignments=arm_vectors.BASE_ALIGNMENTS,
            required_alignment=4,
            plausible_ranges=plausible,
            evidence=tuple(evidence),
        )

    def evaluate_base(self, context, runtime_base: int) -> BaseAssessment:
        """Verify a candidate base with instruction semantics.

        Every vector table found in the input is checked, not just the one
        chosen as the entry point.  In a dump holding a bootloader and an
        application, each table on its own is consistent with a base that
        happens to line its handlers up with the *other* image's code; only
        the real base satisfies all of them at once.

        The other decisive test is agreement between absolute code pointers
        and the function starts that direct calls identified.  Call targets
        are relocation-invariant image offsets, so they cannot pick a base by
        themselves; but a wrong base shifts every absolute code pointer off
        those offsets, and a right one lines them up.
        """
        image = context.image
        size = image.size
        sweep = self._sweep(context)
        evidence: list[Evidence] = []
        score = 0.0

        def offset_of(address: int) -> Optional[int]:
            offset = address - runtime_base
            return offset if 0 <= offset < size else None

        tables = [
            candidate.details["table"]
            for candidate in (context.get("entry_candidates") or [])[:MAX_TABLES_CHECKED]
            if candidate.details.get("table") is not None
        ]
        for index, table in enumerate(tables):
            # The chosen entry structure carries full weight; further tables
            # corroborate at a discount, so one spurious candidate cannot
            # outvote the real one.
            weight = 1.0 if index == 0 else 0.6
            delta, notes = self._assess_table(table, runtime_base, offset_of, image, len(tables) > 1)
            score += weight * delta
            evidence.extend(notes)

        # Call targets, not every branch target: an absolute code pointer
        # names a function, while a plain branch usually names a label inside
        # one.
        starts = sweep.call_locations or sweep.code_locations
        pool = context.get("references")
        pool = list(pool) if pool is not None else list(sweep.references)

        agreeing = 0
        in_image = 0
        outside = 0.0
        pointers = 0
        for reference in pool:
            if reference.base_relative or reference.address_class not in (
                AddressClass.CODE,
                AddressClass.RAM,
            ):
                continue
            value = reference.value
            if value & 1:
                offset = offset_of(value & ~1)
                if offset is None:
                    # Weighted by how much the reference is trusted: a
                    # literal pool in the middle of a constant table produces
                    # plenty of odd words that are not pointers at all.
                    outside += reference.confidence
                    continue
                pointers += 1
                if offset in starts:
                    agreeing += 1
                else:
                    in_image += 1
            elif offset_of(value) is not None:
                in_image += 1

        # A resynchronizing sweep also walks data, so some of its "call
        # targets" are noise and a wrong base picks up coincidental hits.
        # Only agreement beyond what that noise explains counts: with a
        # fraction `density` of all instruction slots marked as a call target,
        # `density * pointers` hits are expected by chance alone.
        density = len(starts) / max(size // 2, 1)
        expected = density * pointers
        excess = agreeing - expected
        if excess > 0.5:
            weight = min(excess * 0.6, 6.0)
            score += weight
            evidence.append(
                Evidence(
                    kind="code_pointers",
                    source=_SOURCE,
                    explanation=(
                        f"{agreeing} absolute code pointer(s) land exactly on recovered function "
                        f"starts, against {expected:.1f} expected by chance"
                    ),
                    value=agreeing,
                    weight=weight,
                )
            )
        if in_image:
            weight = min(in_image * 0.03, 1.5)
            score += weight
            evidence.append(
                Evidence(
                    kind="references_resolve",
                    source=_SOURCE,
                    explanation=f"{in_image} other absolute reference(s) resolve inside the image",
                    value=in_image,
                    weight=weight,
                )
            )
        if outside >= 1.0:
            weight = min(outside * 0.2, 3.0)
            score -= weight
            evidence.append(
                Evidence(
                    kind="references_resolve",
                    source=_SOURCE,
                    explanation=(
                        f"the equivalent of {outside:.0f} trusted Thumb code pointer(s) "
                        "fall outside the image"
                    ),
                    value=round(outside, 1),
                    weight=weight,
                    supports=False,
                )
            )

        return BaseAssessment(score=score, evidence=tuple(evidence))

    def _assess_table(
        self, table, runtime_base: int, offset_of, image, several: bool
    ) -> tuple[float, list[Evidence]]:
        """Score one vector table against a candidate base."""
        evidence: list[Evidence] = []
        score = 0.0
        where = f" at image offset {table.image_offset:#x}" if several else ""

        table_address = runtime_base + table.image_offset
        required = table.required_alignment
        if table_address % required:
            score -= 5.0
            evidence.append(
                Evidence(
                    kind="vtor_alignment",
                    source=_SOURCE,
                    explanation=(
                        f"vector table{where} would sit at {table_address:#010x}, which VTOR "
                        f"cannot address: a {table.word_count}-word table requires "
                        f"{required:#x}-byte alignment"
                    ),
                    value=table_address,
                    weight=5.0,
                    supports=False,
                )
            )
        else:
            # Beyond the architectural minimum, a strongly aligned table
            # address is what linkers actually produce; the extra alignment
            # separates the true base from its near neighbours.
            alignment = arm_vectors.alignment_of(table_address)
            bits = alignment.bit_length() - 1 if alignment else 32
            bonus = min(max(bits - 6, 0) * 0.35, 4.0)
            score += bonus
            evidence.append(
                Evidence(
                    kind="vtor_alignment",
                    source=_SOURCE,
                    explanation=(
                        f"vector table{where} lands at {table_address:#010x}, aligned to "
                        + (f"{alignment:#x}" if alignment else "the start of memory")
                    ),
                    value=table_address,
                    weight=bonus,
                )
            )

        reset_offset = offset_of(table.reset_address)
        if reset_offset is None:
            score -= 3.0
            evidence.append(
                Evidence(
                    kind="entry_decodes",
                    source=_SOURCE,
                    explanation=(
                        f"reset vector{where} {table.reset_address:#010x} falls outside the image"
                    ),
                    value=table.reset_address,
                    weight=3.0,
                    supports=False,
                )
            )
        else:
            code = self.decoder.score_code(image.read(reset_offset, 256), table.reset_address)
            if code.confidence >= 0.5:
                score += 4.0
                evidence.append(
                    Evidence(
                        kind="entry_decodes",
                        source=_SOURCE,
                        explanation=(
                            f"reset vector{where} "
                            f"{self.encode_code_pointer(table.reset_address):#010x} maps to "
                            f"executable bytes ({code.explanation})"
                        ),
                        value=table.reset_address,
                        confidence=code.confidence,
                        weight=4.0,
                    )
                )
            else:
                score -= 2.0
                evidence.append(
                    Evidence(
                        kind="entry_decodes",
                        source=_SOURCE,
                        explanation=(
                            f"reset vector{where} {table.reset_address:#010x} maps to bytes that "
                            f"do not decode as Thumb code ({code.explanation})"
                        ),
                        value=table.reset_address,
                        weight=2.0,
                        supports=False,
                    )
                )

        # A table heads its own image, so its handlers lie after it and near
        # it.  This is what separates the real base from one that happens to
        # line a table's handlers up with a *different* image's code, which
        # any dump holding a bootloader and an application slot offers.
        handlers = table.handler_addresses
        if handlers:
            lowest = min(handlers) - table_address
            highest = max(handlers) - table_address
            if lowest < 0:
                score -= 3.0
                evidence.append(
                    Evidence(
                        kind="table_locality",
                        source=_SOURCE,
                        explanation=(
                            f"handlers{where} would lie {-lowest:#x} bytes *before* their own "
                            f"vector table at {table_address:#010x}"
                        ),
                        value=lowest,
                        weight=3.0,
                        supports=False,
                    )
                )
            elif highest > HANDLER_LOCALITY:
                score -= 2.0
                evidence.append(
                    Evidence(
                        kind="table_locality",
                        source=_SOURCE,
                        explanation=(
                            f"handlers{where} would lie up to {highest / (1 << 20):.1f} MiB past "
                            f"their own vector table at {table_address:#010x}"
                        ),
                        value=highest,
                        weight=2.0,
                        supports=False,
                    )
                )
            else:
                score += 2.0
                evidence.append(
                    Evidence(
                        kind="table_locality",
                        source=_SOURCE,
                        explanation=(
                            f"all handlers{where} lie within {highest:#x} bytes after their own "
                            f"vector table at {table_address:#010x}"
                        ),
                        value=highest,
                        weight=2.0,
                    )
                )

        others = [
            address
            for slot, address in zip(table.handler_slots, table.handler_addresses)
            if slot != 1
        ]
        distinct = sorted(set(others))
        resolved = [address for address in distinct if offset_of(address) is not None]
        if not distinct:
            return score, evidence

        score += min(len(resolved) * 0.3, 3.0)
        evidence.append(
            Evidence(
                kind="vectors_resolve",
                source=_SOURCE,
                explanation=(
                    f"{len(resolved)} of {len(distinct)} distinct exception vectors{where} "
                    "resolve inside the image"
                ),
                value=len(resolved),
                weight=min(len(resolved) * 0.3, 3.0),
                supports=bool(resolved),
            )
        )
        unresolved = len(distinct) - len(resolved)
        if unresolved:
            score -= min(unresolved * 0.4, 3.0)
            evidence.append(
                Evidence(
                    kind="vectors_resolve",
                    source=_SOURCE,
                    explanation=(
                        f"{unresolved} exception vector(s){where} point outside the image"
                    ),
                    value=unresolved,
                    weight=min(unresolved * 0.4, 3.0),
                    supports=False,
                )
            )

        decoding = 0
        for address in resolved[:8]:
            offset = offset_of(address)
            if offset is None:
                continue
            if self.decoder.score_code(image.read(offset, 128), address).confidence >= 0.5:
                decoding += 1
        if decoding:
            score += min(decoding * 0.4, 3.0)
            evidence.append(
                Evidence(
                    kind="vectors_decode",
                    source=_SOURCE,
                    explanation=(
                        f"{decoding} exception handler target(s){where} decode as Thumb code"
                    ),
                    value=decoding,
                    weight=min(decoding * 0.4, 3.0),
                )
            )
        elif resolved:
            score -= 2.0
            evidence.append(
                Evidence(
                    kind="vectors_decode",
                    source=_SOURCE,
                    explanation=(
                        f"none of the {len(resolved)} resolvable exception handlers{where} "
                        "decode as Thumb code"
                    ),
                    value=len(resolved),
                    weight=2.0,
                    supports=False,
                )
            )
        return score, evidence

    # -- references -------------------------------------------------------

    def _sweep(self, context) -> arm_references.SweepResult:
        return context.cache(
            "cortexm_sweep",
            lambda: arm_references.sweep_image(
                context.image,
                self.decoder,
                self.classify_address,
                byte_order=self.elf_target_info().byte_order,
                max_instructions=context.options.max_instructions,
            ),
        )

    def extract_references(self, context) -> list[Reference]:
        sweep = self._sweep(context)
        references = list(sweep.references)
        context.log(
            f"cortex-m sweep: {sweep.instructions} instructions, {len(references)} absolute "
            f"references, {len(sweep.code_locations)} branch-target code starts",
            level=1,
        )
        for candidate in context.get("entry_candidates") or []:
            table = candidate.details.get("table")
            if table is None:
                continue
            for slot in table.handler_slots:
                value = table.words[slot]
                references.append(
                    Reference(
                        value=value,
                        source_offset=candidate.image_offset + slot * 4,
                        derivation="exception vector table entry",
                        kind=ReferenceKind.CODE,
                        access=Access.EXECUTE,
                        width=32,
                        confidence=0.9,
                        source_text=f"vector[{slot}]",
                        address_class=self.classify_address(value),
                    )
                )
        return references

    def recover_memory_accesses(self, context) -> list[Reference]:
        recovery = self._recovery(context)
        return list(recovery.references)

    def _recovery(self, context) -> arm_references.AccessRecovery:
        def build() -> arm_references.AccessRecovery:
            base = context.runtime_base
            sweep = self._sweep(context)
            seeds: list[int] = []
            entry = context.get("entry")
            if entry is not None:
                seeds.append(self.normalize_code_pointer(entry))
            selected = context.get("selected_entry_candidate")
            if selected is not None:
                table = selected.details.get("table")
                if table is not None:
                    seeds.extend(table.handler_addresses)
            seeds.extend(base + offset for offset in sweep.call_locations)
            return arm_references.recover_accesses(
                context,
                self.decoder,
                self.classify_address,
                seeds=seeds,
                max_instructions=context.options.max_instructions,
            )

        return context.cache("cortexm_recovery", build)

    def _code_addresses(self, context) -> frozenset[int]:
        """Addresses known to be the start of an instruction.

        The Thumb bit makes a code pointer look distinctive, but plenty of
        ordinary constants are odd, and a literal pointing one byte into a
        string is not a function.  Requiring the target to be an address that
        was actually decoded as an instruction -- or a call target a sweep
        found -- is what keeps the ``CODE`` class meaningful.
        """

        def build() -> frozenset[int]:
            addresses: set[int] = set()
            graph = self._recovery(context).graph
            if graph is not None:
                addresses |= graph.visited
            base = context.runtime_base
            addresses |= {base + offset for offset in self._sweep(context).call_locations}
            return frozenset(addresses)

        return context.cache("cortexm_code_addresses", build)

    def classify_reference(self, reference: Reference, context) -> ReferenceKind:
        address_class = reference.address_class or self.classify_address(reference.value)
        if address_class == AddressClass.RAM:
            return ReferenceKind.RAM
        if address_class in (AddressClass.MMIO, AddressClass.SYSTEM):
            return ReferenceKind.MMIO
        if address_class != AddressClass.CODE:
            return ReferenceKind.UNKNOWN

        normalized = self.normalize_code_pointer(reference.value)
        if context.address_to_offset(normalized) is None:
            # Outside the image, but the architectural code region is also
            # where vendors put SRAM (CCM on STM32F4, main SRAM on LPC17xx).
            # A store settles it: Flash is not written by ordinary stores, so
            # a write target here is writable memory.
            if reference.access == Access.WRITE:
                return ReferenceKind.RAM
            return ReferenceKind.UNKNOWN
        if reference.access == Access.EXECUTE:
            return ReferenceKind.CODE
        if reference.value & 1 and normalized in self._code_addresses(context):
            return ReferenceKind.CODE
        return ReferenceKind.FLASH_DATA

    def discover_code(self, context) -> list[tuple[int, int]]:
        return list(self._recovery(context).code_regions)

    # -- startup ----------------------------------------------------------

    def recover_startup_state(self, context) -> Optional[StartupState]:
        selected = context.get("selected_entry_candidate")
        initial_sp = None
        if selected is not None:
            initial_sp = selected.details.get("initial_sp")
        return arm_startup.recover(
            context,
            self._recovery(context),
            self.classify_address,
            initial_stack_pointer=initial_sp,
        )

    def memory_region_hints(self, context) -> list[MemoryRegion]:
        """Report the ARMv7-M private peripheral block when it is used.

        Nothing else is asserted from the address map alone; regions come from
        recovered references, not from the architecture's reservations.
        """
        references = context.get("references")
        if references is None:
            return []
        system = [
            reference
            for reference in references
            if reference.address_class == AddressClass.SYSTEM
        ]
        if not system:
            return []
        return [
            MemoryRegion(
                kind=RegionKind.MMIO,
                start=0xE0000000,
                size=0x00100000,
                name="ppb",
                writable=True,
                confidence=0.9,
                evidence=(
                    Evidence(
                        kind="mmio_access",
                        source=_SOURCE,
                        explanation=(
                            f"{len(system)} access(es) to the ARMv7-M private peripheral block"
                        ),
                        value=len(system),
                    ),
                ),
            )
        ]

    # -- interrupts -------------------------------------------------------

    def recover_interrupt_table(self, context) -> Optional[InterruptTable]:
        selected = context.get("selected_entry_candidate")
        if selected is None:
            return None
        table = selected.details.get("table")
        if table is None:
            return None
        base = context.runtime_base
        entries: list[InterruptEntry] = []
        for slot in table.handler_slots:
            raw = table.words[slot]
            name = arm_vectors.CORE_VECTORS.get(slot)
            irq = None
            if name is None:
                if slot in arm_vectors.RESERVED_SLOTS:
                    continue
                irq = slot - arm_vectors.FIRST_DEVICE_IRQ
                if irq < 0:
                    continue
                name = self.irq_symbol_name(irq)
            entries.append(
                InterruptEntry(
                    index=slot,
                    name=name,
                    raw_value=raw,
                    address=self.normalize_code_pointer(raw),
                    core=slot in arm_vectors.CORE_VECTORS,
                    irq=irq,
                )
            )
        return InterruptTable(
            image_offset=table.image_offset,
            entries=entries,
            runtime_address=base + table.image_offset,
        )

    # -- ELF enrichment ---------------------------------------------------

    def elf_extra_sections(self, context) -> list[ExtraSection]:
        # Only name the core if something actually identified it; the profile
        # and Thumb-only ISA are enough for a disassembler to pick the right
        # decoder, and inventing a core name would be a claim we cannot back.
        cpu = core_name(context.get("svd_cpu_name"))
        return [
            ExtraSection(
                name=".ARM.attributes",
                section_type=0x70000003,  # SHT_ARM_ATTRIBUTES
                flags=0,
                payload=build_arm_attributes(cpu),
                alignment=1,
            )
        ]

    def elf_symbols(self, context) -> list[SymbolRequest]:
        """The vector table symbol plus ARM mapping symbols.

        Mapping symbols matter more than they look: ``$d`` over the vector
        table and ``$t`` at each code start are what make objdump and Ghidra
        decode Thumb instead of guessing ARM.
        """
        symbols: list[SymbolRequest] = []
        selected = context.get("selected_entry_candidate")
        base = context.runtime_base
        if selected is not None:
            table = selected.details.get("table")
            symbols.append(
                SymbolRequest(
                    name="__vector_table",
                    address=base + selected.image_offset,
                    size=(table.word_count * 4) if table is not None else 0,
                    kind="object",
                    literal_value=True,
                )
            )
            symbols.append(
                SymbolRequest(
                    name="$d",
                    address=base + selected.image_offset,
                    kind="notype",
                    is_local=True,
                    literal_value=True,
                )
            )
        regions = context.get("code_regions") or []
        for start, _size in sorted(regions)[:512]:
            symbols.append(
                SymbolRequest(
                    name="$t",
                    address=start,
                    kind="notype",
                    is_local=True,
                    literal_value=True,
                )
            )
        return symbols


    # -- reporting --------------------------------------------------------

    def report_rows(self, context) -> list[tuple[str, str]]:
        selected = context.get("selected_entry_candidate")
        if selected is None:
            return []
        rows: list[tuple[str, str]] = []
        base = context.get("runtime_base")
        if base is not None:
            rows.append(("Vector table", f"0x{base + selected.image_offset:08x}"))
        initial_sp = selected.details.get("initial_sp")
        if initial_sp is not None:
            rows.append(("Initial MSP", f"0x{initial_sp:08x}"))
        return rows

    def manifest_fields(self, context) -> dict[str, object]:
        selected = context.get("selected_entry_candidate")
        if selected is None:
            return {}
        base = context.get("runtime_base")
        fields: dict[str, object] = {}
        if base is not None:
            fields["vector_table"] = f"0x{base + selected.image_offset:08x}"
        initial_sp = selected.details.get("initial_sp")
        if initial_sp is not None:
            fields["initial_sp"] = f"0x{initial_sp:08x}"
        table = selected.details.get("table")
        if table is not None:
            fields["vector_table_entries"] = table.word_count
            if table.default_handler is not None:
                fields["default_handler"] = f"0x{table.default_handler:08x}"
        return fields


def core_name(svd_cpu: Optional[str]) -> Optional[str]:
    """Turn a CMSIS-SVD ``<cpu><name>`` such as ``CM4`` into ``Cortex-M4``."""
    if not svd_cpu:
        return None
    import re

    match = re.fullmatch(r"CM(\d+)(PLUS)?", svd_cpu.strip().upper())
    if match:
        return f"Cortex-M{match.group(1)}{'+' if match.group(2) else ''}"
    return svd_cpu


def build_arm_attributes(cpu_name: Optional[str] = None) -> bytes:
    """Build a minimal ``.ARM.attributes`` section.

    Declaring the M profile and Thumb-only ISA is what makes ``objdump`` and
    Ghidra choose the right decoder without being told on the command line.
    ``Tag_CPU_name`` is emitted only when the core is actually known.
    """
    attributes = bytearray()
    if cpu_name:
        attributes += b"\x05" + cpu_name.encode("ascii") + b"\x00"  # Tag_CPU_name
    attributes += b"\x06\x0a"  # Tag_CPU_arch = ARM v7
    attributes += b"\x07\x4d"  # Tag_CPU_arch_profile = 'M'
    attributes += b"\x08\x00"  # Tag_ARM_ISA_use = none
    attributes += b"\x09\x02"  # Tag_THUMB_ISA_use = Thumb-2

    file_subsection = b"\x01" + struct.pack("<I", 5 + len(attributes)) + bytes(attributes)
    vendor = b"aeabi\x00" + file_subsection
    return b"A" + struct.pack("<I", 4 + len(vendor)) + vendor
