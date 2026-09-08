"""Reference recovery passes.

Two passes, matching the two things references are for.  The first runs before
a load address exists and collects the absolute values instructions
construct -- the raw material for base recovery.  The second runs afterwards,
when value propagation can produce effective addresses, and classifies
everything against the now-known memory map.
"""

from __future__ import annotations

from ..arch.base import ArchCapability
from ..core.evidence import Evidence
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.reference import Access, AddressClass, Reference, ReferenceKind, ReferenceSet


class ReferenceRecovery(AnalysisPass):
    """Collect absolute references before the base is known."""

    name = "ReferenceRecovery"
    requires = frozenset({"entry_candidates"})
    capabilities = frozenset({ArchCapability.REFERENCE_RECOVERY})
    provides = frozenset({"references"})

    def run(self, context: AnalysisContext) -> None:
        references = ReferenceSet(context.backend.extract_references(context))
        context.provide("references", references)
        usable = len(references.base_discriminating())
        context.note(
            Evidence(
                kind="references",
                source=self.name,
                explanation=(
                    f"recovered {len(references)} reference(s), {usable} of which are absolute "
                    "and can discriminate between candidate load addresses"
                ),
                value=len(references),
                weight=0.0,
            )
        )
        context.log(f"references: {len(references)} recovered, {usable} base-discriminating", level=1)


class MemoryAccessRecovery(AnalysisPass):
    """Recover effective load/store addresses and classify every reference.

    Classification waits until here because the same literal can be a code
    pointer, a RAM pointer, a peripheral address or an ordinary integer, and
    telling them apart needs the load address.
    """

    name = "MemoryAccessRecovery"
    requires = frozenset({"runtime_base"})
    capabilities = frozenset({ArchCapability.MMIO_REFERENCE_RECOVERY})
    provides = frozenset({"references", "mmio_accesses", "peripheral_accesses", "code_regions"})

    def run(self, context: AnalysisContext) -> None:
        references: ReferenceSet = context.get("references") or ReferenceSet()
        context.provide("references", references)
        backend = context.backend

        recovered = backend.recover_memory_accesses(context)
        references.extend(recovered)

        classified = [
            reference.with_kind(backend.classify_reference(reference, context))
            for reference in references
        ]
        references.replace_all(classified)

        if ArchCapability.CODE_DISCOVERY in backend.capabilities():
            context.provide("code_regions", backend.discover_code(context))
        else:
            context.provide("code_regions", [])

        accesses = [
            reference
            for reference in references
            if reference.kind == ReferenceKind.MMIO
            and reference.access in (Access.READ, Access.WRITE)
        ]
        accesses.sort(key=lambda item: (item.value, item.source_offset))
        context.provide("mmio_accesses", accesses)

        # The architectural system region (NVIC, SysTick, SCB on Cortex-M) is
        # identical on every part in a family, so it says nothing about which
        # part this is and only adds noise to MCU ranking and region
        # clustering.  It is still reported as recovered MMIO.
        context.provide(
            "peripheral_accesses",
            [item for item in accesses if item.address_class == AddressClass.MMIO],
        )

        counts = references.counts_by_kind()
        context.note(
            Evidence(
                kind="references",
                source=self.name,
                explanation=(
                    "reference classification: "
                    + ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items()))
                ),
                value=counts,
                weight=0.0,
            )
        )
        context.log(
            f"memory accesses: {len(recovered)} recovered from value propagation, "
            f"{len(accesses)} peripheral access(es)",
            level=1,
        )
