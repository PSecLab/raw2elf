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
from ..core.hypothesis import BaseCandidate, ImageHypothesis, resolve
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
    after = frozenset({"ReferenceRecovery", "EntryDiscovery", "ImageDiscovery"})
    provides = frozenset(
        {
            "runtime_base",
            "program_base",
            "base_candidates",
            "entry",
            "base_confidence",
            "selected_image",
            "selected_placement",
        }
    )
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
        self._place(context, base)

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

    def _place(self, context: AnalysisContext, base: int) -> None:
        """Choose the one image every later stage works from.

        This *selects* an image; it does not build one. Base, entry, entry
        structure, stack pointer and extent are recovered by different means,
        and a stage that picks the best of each and combines them produces a
        tuple in which every number is defensible and which describes no image
        that exists. So the candidate images -- each already internally
        consistent -- are the only things offered, one is chosen, and if the
        recovered base differs from the one it was built with, the whole
        object moves together.
        """
        candidates = context.get("candidate_images") or []
        entry_candidate = context.get("selected_entry_candidate")

        selected = self._choose(context, candidates, entry_candidate, base)
        if selected is None:
            # No candidate image at all: a single-image input the discovery
            # pass had nothing to say about. Describing the whole input is
            # then the only honest option, and it is still one object.
            selected = ImageHypothesis(
                architecture=context.backend.name,
                placement=context.placement_for(
                    image_offset=0,
                    image_size=context.image.size,
                    runtime_base=base,
                    entry_structure_offset=(
                        None if entry_candidate is None else entry_candidate.image_offset
                    ),
                    entry=context.get("entry"),
                    initial_stack_pointer=(
                        None
                        if entry_candidate is None
                        else entry_candidate.details.get("initial_sp")
                    ),
                    confidence=context.get("base_confidence", 0.0) or 0.0,
                ),
                details={"origin": "the whole input"},
            )
        elif selected.runtime_base is None:
            selected = selected.rebased(base + selected.image_offset)
        elif selected.runtime_base != base + selected.image_offset:
            # The analyst or the reference evidence chose a different base.
            # Move the image, all of it, rather than overwriting one field.
            context.note(
                Evidence(
                    kind="placement",
                    source=self.name,
                    explanation=(
                        f"moving the selected image from {selected.runtime_base:#010x} to the "
                        f"recovered base {base + selected.image_offset:#010x}"
                    ),
                    value=base,
                    weight=0.0,
                )
            )
            selected = selected.rebased(base + selected.image_offset)

        # An analyst who supplies --entry knows something the bytes do not
        # say. That is applied to the selected image rather than kept beside
        # it, so there is still exactly one answer.
        resolved_entry = context.get("entry")
        if context.options.entry is not None or selected.entry is None:
            selected = selected.with_entry(resolved_entry)

        # An extent is inferred; an entry structure and an entry are read out
        # of the image itself. When they disagree the extent gives way.
        selected = selected.grown_to_contain(
            selected.entry_structure,
            None
            if selected.entry is None
            else context.backend.normalize_code_pointer(selected.entry),
        )

        context.provide("selected_image", selected)
        context.provide("selected_placement", selected.placement)

        # Everything downstream reads these, so they are *derived from* the
        # selected image rather than standing alongside it. A later pass
        # cannot disagree with the selection because there is nothing else to
        # agree with.
        if selected.entry is not None:
            context.provide("entry", selected.entry)
        context.provide(
            "runtime_base", selected.runtime_base - selected.image_offset
        )
        context.provide("program_base", selected.runtime_base)

        # Compared by where they are, not by object identity: the selected
        # image is a moved copy of the one in this list by now.
        others = [
            item
            for item in candidates
            if item.image_size
            and item.confidence >= 0.6
            and not (
                item.file_offset < selected.file_end
                and selected.file_offset < item.file_offset + item.image_size
            )
        ]
        if others and context.options.image is None:
            # The ELF describes one program. If the input holds more than
            # one, saying which was chosen -- and how to ask for the other --
            # matters more than quietly reconstructing the first.
            where = ", ".join(
                f"{item.file_offset:#08x} ({item.image_size} bytes)" for item in others[:4]
            )
            context.warn(
                f"this input holds {len(others) + 1} programs; reconstructing the one at "
                f"file offset {selected.file_offset:#08x} ({selected.image_size} bytes). "
                f"The other(s) are at {where} -- use --image to select one"
            )

        if selected.image_offset:
            context.note(
                Evidence(
                    kind="placement",
                    source=self.name,
                    explanation=(
                        f"the program occupies {selected.image_size} bytes from file offset "
                        f"{selected.file_offset:#x} and loads at {selected.runtime_base:#010x}; "
                        "the bytes before it are not part of it"
                    ),
                    value=selected.runtime_base,
                    weight=0.0,
                )
            )

    def _choose(self, context, candidates, entry_candidate, base):
        """The candidate image the rest of the run describes.

        The entry structure is what identifies it: an image is the thing its
        own reset vector belongs to.
        """
        if not candidates:
            return None

        already = context.get("selected_image")
        if already is not None:
            # An explicit --image, or a carve. The choice is made.
            return already

        if len(context.image.segments) > 1 or context.image.addresses_declared:
            # A container that describes its own layout -- Intel HEX, SREC --
            # is not a dump with programs hidden in it. Every segment it
            # declares is part of the program, so carving an extent out of
            # one entry structure would throw the rest away.
            return None

        if entry_candidate is not None:
            match = next(
                (
                    item
                    for item in candidates
                    if item.image_offset == entry_candidate.image_offset
                ),
                None,
            )
            if match is not None:
                return match

        # No entry structure to go on: the most credible image, which is what
        # the candidate list is already ordered by.
        return candidates[0]

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
