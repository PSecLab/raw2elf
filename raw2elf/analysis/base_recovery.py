"""Runtime load address recovery.

Candidate bases come from three places: the analyst, the input container
(Intel HEX and SREC state their addresses outright) and inference.  Inference
combines a cheap generic filter with the backend's semantic verification:

1.  The backend seeds candidates it can justify structurally and states the
    alignments and ranges the architecture permits.
2.  Every absolute reference value is truncated to each permitted alignment,
    which is how the real base gets proposed even when no structure named it.
3.  Candidates are pre-ranked by how many references resolve inside the image
    -- cheap, and enough to discard the great majority.
4.  The survivors go to :meth:`ArchitectureBackend.evaluate_base`, which
    checks them with instruction semantics.

Relative branches are never used to *choose* a base.  Their targets move with
the image, so every candidate satisfies them equally; the backend may use them
to identify where code starts, and it is the absolute references that pick a
winner.
"""

from __future__ import annotations

import math
from collections import Counter

from ..core.evidence import Evidence, confidence_label
from ..core.hypothesis import BaseCandidate, resolve
from ..core.interaction import Choice
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.reference import ReferenceSet
from ..core.util import align_down, logistic
from .devices import layout_for

#: How many pre-ranked candidates get the backend's expensive verification.
VERIFY_LIMIT = 24
#: Cap on distinct reference values used to synthesize candidates.
SYNTHESIS_LIMIT = 4000
#: Softmax temperature used to turn scores into candidate confidences.
TEMPERATURE = 1.5
#: How much a supplied part number's Flash origin counts for. Comparable to a
#: reset vector decoding as code, so it can settle a close call without
#: overruling an image that clearly says otherwise.
DEVICE_LAYOUT_WEIGHT = 4.0


class BaseRecovery(AnalysisPass):
    """Recover the runtime load address and finalize the entry point."""

    name = "BaseRecovery"
    # Deliberately requires nothing: an analyst-supplied base, or an input
    # container that states its own addresses, needs no analysis at all, and a
    # backend that cannot recover references should still produce an ELF.
    after = frozenset({"ReferenceRecovery", "EntryDiscovery"})
    provides = frozenset({"runtime_base", "base_candidates", "entry", "base_confidence"})
    optional = False

    def run(self, context: AnalysisContext) -> None:
        candidates = self._candidates(context)
        context.provide("base_candidates", candidates)

        base = resolve(
            "runtime base address",
            [
                Choice(
                    value=candidate.runtime_base,
                    label=f"0x{candidate.runtime_base:08x}",
                    origin=candidate.origin,
                    confidence=candidate.confidence,
                    evidence=[str(item) for item in candidate.supporting[:4]]
                    + [str(item) for item in candidate.contradicting[:3]],
                    flag=f"--base 0x{candidate.runtime_base:08x}",
                )
                for candidate in candidates
            ],
            context.options,
            custom="enter a load address",
        )
        # An analyst may answer with an address the analysis never proposed,
        # which is the whole point of being able to answer: they know
        # something the image does not say.
        chosen = next(
            (item for item in candidates if item.runtime_base == base),
            None,
        )
        if chosen is None:
            chosen = BaseCandidate(
                runtime_base=base,
                score=math.inf,
                confidence=1.0,
                origin="supplied during analysis",
                supporting=[
                    Evidence(
                        kind="override",
                        source=self.name,
                        explanation=f"analyst chose base {base:#010x}, which was not a candidate",
                        value=base,
                    )
                ],
            )
            candidates.insert(0, chosen)
        context.provide("runtime_base", base)
        context.provide("base_confidence", chosen.confidence)
        context.note(*chosen.supporting, *chosen.contradicting)
        context.log(
            f"base: {base:#010x} confidence {chosen.confidence:.2f} "
            f"({confidence_label(chosen.confidence)}) via {chosen.origin}",
            level=1,
        )
        self._resolve_entry(context, base)

    # -- candidate generation --------------------------------------------

    def _candidates(self, context: AnalysisContext) -> list[BaseCandidate]:
        options = context.options
        if options.base is not None:
            return [
                BaseCandidate(
                    runtime_base=options.base,
                    score=math.inf,
                    confidence=1.0,
                    origin="analyst override",
                    supporting=[
                        Evidence(
                            kind="override",
                            source=self.name,
                            explanation=f"analyst specified base {options.base:#010x}",
                            value=options.base,
                        )
                    ],
                )
            ]

        image = context.image
        if image.addresses_declared:
            span = image.declared_span
            assert span is not None
            return [
                BaseCandidate(
                    runtime_base=span[0],
                    score=math.inf,
                    confidence=1.0,
                    origin=f"declared by the {image.source_format} container",
                    supporting=[
                        Evidence(
                            kind="declared_address",
                            source=self.name,
                            explanation=(
                                f"the {image.metadata.get('label', image.source_format)} input "
                                f"declares addresses {span[0]:#010x}..{span[1] - 1:#010x}"
                            ),
                            value=span[0],
                        )
                    ],
                )
            ]

        return self._infer(context)

    def _infer(self, context: AnalysisContext) -> list[BaseCandidate]:
        backend = context.backend
        options = context.options
        image = context.image
        references: ReferenceSet = context.get("references") or ReferenceSet()
        constraints = backend.generate_base_constraints(context)
        context.note(*constraints.evidence)

        usable = references.base_discriminating()
        values = Counter(backend.normalize_code_pointer(item.value) for item in usable)

        proposals: dict[int, str] = {}
        for seed in constraints.seeds:
            if constraints.permits(seed.runtime_base) and seed.runtime_base >= 0:
                proposals.setdefault(seed.runtime_base, "backend seed")
        for value, _count in values.most_common(SYNTHESIS_LIMIT):
            for alignment in constraints.alignments:
                candidate = align_down(value, alignment)
                if candidate < 0 or not constraints.permits(candidate):
                    continue
                proposals.setdefault(candidate, f"reference value aligned to {alignment:#x}")

        if not proposals:
            context.warn(
                "no candidate load addresses could be synthesized; supply one with --base"
            )
            return []

        # A part number the analyst supplied is the one piece of evidence the
        # image cannot contain. It is scored, not obeyed: a firmware linked
        # somewhere unusual still wins on its own evidence.
        layout = layout_for(options.mcu) if options.mcu else None
        if layout is not None:
            for address in layout.flash:
                if constraints.permits(address):
                    proposals.setdefault(address, f"{layout.family} Flash origin")
            context.note(
                Evidence(
                    kind="device_layout",
                    source=self.name,
                    explanation=f"{options.mcu} was supplied, and {layout.describe()}",
                    value=layout.flash[0] if layout.flash else None,
                )
            )
        elif options.mcu:
            context.log(
                f"no memory layout is known for {options.mcu}; it will still be used "
                "for peripheral matching",
                level=1,
            )

        seed_weights = {seed.runtime_base: seed.weight for seed in constraints.seeds}
        seed_evidence = {
            seed.runtime_base: seed.evidence for seed in constraints.seeds if seed.evidence
        }

        # Cheap pre-ranking: how much reference weight resolves inside the
        # image at this base.  Wrong-by-a-lot candidates die here so the
        # semantic verification only runs a couple of dozen times.
        size = image.size
        prescored: list[tuple[float, int]] = []
        for candidate in proposals:
            total = 0.0
            for value, count in values.items():
                offset = value - candidate
                if 0 <= offset < size:
                    total += count
            total += 3.0 * seed_weights.get(candidate, 0.0)
            prescored.append((total, candidate))
        prescored.sort(key=lambda item: (-item[0], item[1]))
        shortlist = [candidate for _score, candidate in prescored[:VERIFY_LIMIT]]
        context.log(
            f"base recovery: {len(proposals)} candidate(s) proposed, verifying {len(shortlist)}",
            level=1,
        )

        results: list[BaseCandidate] = []
        for candidate in shortlist:
            assessment = backend.evaluate_base(context, candidate)
            resolved = sum(count for value, count in values.items() if 0 <= value - candidate < size)
            generic = min(resolved * 0.02, 2.0)
            score = assessment.score + generic + 1.5 * seed_weights.get(candidate, 0.0)
            supporting = [item for item in assessment.evidence if item.supports]
            contradicting = [item for item in assessment.evidence if not item.supports]

            if layout is not None and candidate in layout.flash:
                # Enough to settle a close call, not enough to overrule an
                # image whose own evidence points elsewhere.
                preference = DEVICE_LAYOUT_WEIGHT * (1.0 if candidate == layout.flash[0] else 0.6)
                score += preference
                supporting.insert(
                    0,
                    Evidence(
                        kind="device_layout",
                        source=self.name,
                        explanation=(
                            f"{candidate:#010x} is where {layout.family} maps Flash, "
                            f"as {layout.matched} indicates"
                        ),
                        value=candidate,
                        weight=preference,
                    ),
                )
            if candidate in seed_evidence:
                supporting.insert(0, seed_evidence[candidate])
            if resolved:
                supporting.append(
                    Evidence(
                        kind="references_resolve",
                        source=self.name,
                        explanation=f"{resolved} absolute reference value(s) resolve inside the image",
                        value=resolved,
                        weight=generic,
                    )
                )
            results.append(
                BaseCandidate(
                    runtime_base=candidate,
                    score=score,
                    origin=proposals[candidate],
                    supporting=supporting,
                    contradicting=contradicting,
                )
            )

        results.sort(key=lambda item: (-item.score, item.runtime_base))
        _assign_confidence(results)
        return results

    # -- entry ------------------------------------------------------------

    def _resolve_entry(self, context: AnalysisContext, base: int) -> None:
        options = context.options
        if options.entry is not None:
            context.provide("entry", options.entry)
            context.provide("entry_confidence", 1.0)
            context.note(
                Evidence(
                    kind="override",
                    source=self.name,
                    explanation=f"analyst specified entry {options.entry:#010x}",
                    value=options.entry,
                )
            )
            return

        candidate = context.get("selected_entry_candidate")
        if candidate is not None:
            entry = candidate.entry_address(base)
            if entry is not None:
                context.provide("entry", entry)
                context.provide("entry_confidence", candidate.confidence)
                return

        hint = context.image.entry_hint
        if hint is not None:
            context.provide("entry", hint)
            context.provide("entry_confidence", 0.8)
            context.note(
                Evidence(
                    kind="declared_entry",
                    source=self.name,
                    explanation=f"the input container declares entry {hint:#010x}",
                    value=hint,
                )
            )
            return

        context.provide("entry", None)
        context.provide("entry_confidence", 0.0)
        context.warn("no entry point recovered; the ELF will use the load address as its entry")


def _assign_confidence(candidates: list[BaseCandidate]) -> None:
    """Turn scores into per-candidate confidences.

    Two things matter and are kept separate: whether the evidence for a
    candidate is strong in absolute terms, and whether it is clearly better
    than the alternatives.  A candidate that scores well but ties with another
    does not get to look certain.
    """
    if not candidates:
        return
    best = candidates[0].score
    weights = [math.exp((item.score - best) / TEMPERATURE) for item in candidates]
    total = sum(weights)
    for candidate, weight in zip(candidates, weights):
        plausibility = logistic(candidate.score, midpoint=6.0, steepness=0.45)
        share = weight / total if total else 0.0
        candidate.confidence = round(plausibility * (0.4 + 0.6 * share), 4)
