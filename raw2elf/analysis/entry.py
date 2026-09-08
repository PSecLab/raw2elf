"""Entry point discovery and selection."""

from __future__ import annotations

from dataclasses import replace

from ..arch.base import ArchCapability
from ..core.evidence import Evidence, confidence_label
from ..core.hypothesis import resolve
from ..core.interaction import Choice
from ..core.pipeline import AnalysisContext, AnalysisPass


class EntryDiscovery(AnalysisPass):
    """Ask the backend for entry candidates and pick one.

    The backend decides what an entry candidate *is* -- a vector table, a
    reset trampoline, a header field.  This pass only ranks them and applies
    the analyst's overrides.
    """

    name = "EntryDiscovery"
    capabilities = frozenset({ArchCapability.ENTRY_DISCOVERY})
    provides = frozenset({"entry_candidates", "selected_entry_candidate"})

    def run(self, context: AnalysisContext) -> None:
        candidates = context.backend.discover_entry_candidates(context)
        candidates.sort(key=lambda item: item.confidence, reverse=True)
        context.provide("entry_candidates", candidates)

        if not candidates:
            context.warn(
                "no entry structures found; the entry point will have to be supplied with --entry"
            )
            context.provide("selected_entry_candidate", None)
            return

        # Selecting the entry structure is separate from trusting its entry
        # value: --entry overrides the value, but the structure still supplies
        # the interrupt table and initial stack pointer.
        # A lower bar than the rest of the run: an entry structure that is
        # merely plausible is still worth carrying forward, because the base
        # scoring that follows will test it properly.
        relaxed = replace(
            context.options,
            minimum_confidence=min(context.options.minimum_confidence, 0.35),
        )
        selected = resolve(
            "entry structure",
            [
                Choice(
                    value=candidate,
                    label=f"{candidate.kind} at file offset 0x{candidate.image_offset:06x}",
                    confidence=candidate.confidence,
                    evidence=[str(item) for item in candidate.evidence[:4]],
                    flag=f"--vector-offset 0x{candidate.image_offset:x}",
                )
                for candidate in candidates
            ],
            relaxed,
            custom=None,
        )
        context.provide("selected_entry_candidate", selected)
        context.provide("entry_confidence", selected.confidence)
        context.note(*selected.evidence)
        context.log(
            f"entry: {selected.kind} at image offset {selected.image_offset:#x}, "
            f"confidence {selected.confidence:.2f} ({confidence_label(selected.confidence)})",
            level=1,
        )
        if len(candidates) > 1:
            context.note(
                Evidence(
                    kind="entry_candidates",
                    source=self.name,
                    explanation=(
                        f"{len(candidates)} entry structures found; "
                        f"selected the one at offset {selected.image_offset:#x}"
                    ),
                    value=len(candidates),
                    weight=0.0,
                )
            )
