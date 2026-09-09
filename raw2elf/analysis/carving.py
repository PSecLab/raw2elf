"""Padding detection and candidate firmware image discovery.

A flash dump is not the same thing as a firmware image.  One dump may hold a
bootloader, an application, two OTA slots, a configuration block and a lot of
erased flash.  These passes find the erased regions and, using whatever entry
structures the backend can locate, propose the executable images inside the
input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..arch.base import ArchCapability
from ..core.evidence import Evidence
from ..core.hypothesis import ImageHypothesis
from ..core.interaction import Choice
from ..core.options import OptionError
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.util import human_size


#: Confidence a candidate needs before it is worth putting to a person.
OFFER_CONFIDENCE = 0.9
#: Smaller than this is not a program worth reconstructing on its own. Real
#: bootloaders get down to a few hundred bytes; the stray matches that turn up
#: in constant tables are smaller still.
MIN_OFFERABLE_IMAGE = 512
#: More options than this is not a question anyone can answer.
MAX_OFFERED = 6


def _span(offset: int, size: int) -> str:
    """The byte range a program occupies, so it can be carved by hand."""
    return f"0x{offset:06x}-0x{offset + size - 1:06x}"


def credible(hypothesis) -> bool:
    """Whether a candidate is solid enough to act as a boundary or an option.

    Weak candidates are still reported, because a wrong rejection should be
    visible. They must not shape anything, though: a stray match inside a
    program would otherwise cut that program short at the point where the
    noise happened to land.
    """
    return (
        hypothesis.confidence >= OFFER_CONFIDENCE
        and hypothesis.image_size >= MIN_OFFERABLE_IMAGE
    )


def _where(offset: int, total: int) -> str:
    """Describe a position in a dump without requiring hex to be read."""
    if offset == 0:
        return "the program at the very start of the dump"
    return f"the program {human_size(offset)} into the dump"


@dataclass(frozen=True)
class PaddingRun:
    """A run of one repeated byte."""

    image_offset: int
    size: int
    byte: int

    @property
    def end(self) -> int:
        return self.image_offset + self.size

    def as_dict(self) -> dict[str, Any]:
        return {
            "offset": f"0x{self.image_offset:06x}",
            "size": self.size,
            "size_human": human_size(self.size),
            "byte": f"0x{self.byte:02x}",
        }


def find_padding(image, threshold: int) -> list[PaddingRun]:
    """Locate runs of a single repeated byte at least ``threshold`` long.

    Only ``0xff`` (erased NOR flash) and ``0x00`` are reported: a long run of
    any other byte is more likely to be a real constant table than padding.
    """
    runs: list[PaddingRun] = []
    for segment in image.iter_segments():
        data = segment.data
        size = len(data)
        start = 0
        while start < size:
            byte = data[start]
            end = start + 1
            while end < size and data[end] == byte:
                end += 1
            if end - start >= threshold and byte in (0x00, 0xFF):
                runs.append(
                    PaddingRun(
                        image_offset=segment.image_offset + start,
                        size=end - start,
                        byte=byte,
                    )
                )
            start = end
    return runs


class PaddingDetection(AnalysisPass):
    """Find erased and zero-filled regions."""

    name = "PaddingDetection"
    provides = frozenset({"padding"})

    def run(self, context: AnalysisContext) -> None:
        runs = find_padding(context.image, context.options.padding_threshold)
        context.provide("padding", runs)
        total = sum(run.size for run in runs)
        if total:
            share = total / max(context.image.size, 1)
            context.note(
                Evidence(
                    kind="padding",
                    source=self.name,
                    explanation=(
                        f"{len(runs)} padding run(s) covering {human_size(total)} "
                        f"({share * 100:.0f}% of the input)"
                    ),
                    value=total,
                    weight=0.0,
                )
            )
        context.log(f"padding: {len(runs)} run(s), {human_size(total)} total", level=1)


class ImageDiscovery(AnalysisPass):
    """Propose the firmware images contained in the input.

    Each entry structure the backend finds anchors a candidate image, which
    runs from that structure to the next one (or to the end of the enclosing
    segment, minus any erased tail).  When ``--image`` selects one, analysis
    continues on that window alone.
    """

    name = "ImageDiscovery"
    capabilities = frozenset({ArchCapability.ENTRY_DISCOVERY})
    provides = frozenset({"candidate_images"})

    def run(self, context: AnalysisContext) -> None:
        candidates = context.backend.discover_entry_candidates(context)
        hypotheses = self._build(context, candidates)
        context.provide("candidate_images", hypotheses)
        context.log(f"image discovery: {len(hypotheses)} candidate image(s)", level=1)

        selection = context.options.image
        if selection is None:
            selection = self._ask(context, hypotheses)
        if selection is None:
            return
        if not 0 <= selection < len(hypotheses):
            raise OptionError(
                f"--image {selection} is out of range; {len(hypotheses)} candidate image(s) found"
            )
        chosen = hypotheses[selection]
        context.image = context.root_image.subimage(chosen.image_offset, chosen.image_size)
        context.provide("selected_image", chosen)
        context.note(
            Evidence(
                kind="image_selection",
                source=self.name,
                explanation=(
                    f"analysing candidate image {selection} at input offset "
                    f"{chosen.image_offset:#x} ({human_size(chosen.image_size)})"
                ),
                value=chosen.image_offset,
            )
        )

    def _ask(self, context: AnalysisContext, hypotheses) -> Optional[int]:
        """Offer the programs found, in terms someone can answer.

        Which program an analyst wants is not something the bytes can say, so
        it is worth asking. But "pick a candidate image" is a question about
        binaries, and the answer they need to give is about intent, so the
        options are described by where they sit and how big they are, and
        analysing everything together leads and is the default.
        """
        interaction = context.options.interaction
        if interaction is None:
            return None

        offerable = [
            (index, item) for index, item in enumerate(hypotheses) if credible(item)
        ]
        if len(offerable) < 2 or len(offerable) > MAX_OFFERED:
            # Nothing worth asking about, or too many to be a real question;
            # the whole dump is the right default either way.
            if len(offerable) > MAX_OFFERED:
                interaction.note(
                    f"  {len(offerable)} separate programs look possible; analysing the whole "
                    "dump. Use --list-images to see them."
                )
            return None

        total = context.image.size
        choices = [
            Choice(
                value=None,
                label=f"analyse the whole dump together  [{_span(0, total)}]",
                origin="recommended",
                flag="",
            )
        ]
        choices.extend(
            Choice(
                value=index,
                label=(
                    f"just {_where(item.image_offset, total)}, {human_size(item.image_size)}"
                    f"  [{_span(item.image_offset, item.image_size)}]"
                ),
                confidence=item.confidence,
                flag=f"--image {index}",
            )
            for index, item in offerable
        )
        picked = interaction.choose(
            "which program to reconstruct",
            choices,
            prompt=(
                f"This dump appears to contain {len(offerable)} separate programs.\n"
                "If you are not sure, press Enter and the whole dump will be used."
            ),
        )
        return None if picked is None else picked.value

    def _build(self, context: AnalysisContext, candidates) -> list[ImageHypothesis]:
        image = context.image
        padding = context.get("padding") or []
        offsets = sorted({candidate.image_offset for candidate in candidates})
        best_at: dict[int, Any] = {}
        for candidate in candidates:
            existing = best_at.get(candidate.image_offset)
            if existing is None or candidate.confidence > existing.confidence:
                best_at[candidate.image_offset] = candidate

        # A program runs until the next *credible* program starts, not until
        # the next thing that resembled one. Otherwise a stray match inside a
        # program truncates it at the point the noise landed.
        boundaries = sorted(
            offset
            for offset in offsets
            if best_at[offset].confidence >= OFFER_CONFIDENCE
        )

        hypotheses: list[ImageHypothesis] = []
        for offset in offsets:
            candidate = best_at[offset]
            following = next(
                (item for item in boundaries if item > offset),
                image.size,
            )
            end = self._trim(offset, following, padding)
            # Each image's base comes from its own entry structure, so every
            # field below describes the same image.
            seeds = candidate.details.get("base_seeds") or ()
            own_base = seeds[0][0] if seeds else None
            hypotheses.append(
                ImageHypothesis(
                    architecture=context.backend.name,
                    image_offset=offset,
                    image_size=max(end - offset, 0),
                    runtime_base=own_base,
                    entry=candidate.entry_value,
                    entry_structure=None if own_base is None else own_base + offset,
                    initial_stack_pointer=candidate.details.get("initial_sp"),
                    score=candidate.details.get("score", 0.0),
                    confidence=candidate.confidence,
                    evidence=list(candidate.evidence),
                    details={"entry_kind": candidate.kind},
                )
            )
        hypotheses.sort(key=lambda item: item.confidence, reverse=True)
        return hypotheses

    @staticmethod
    def _trim(start: int, end: int, padding: list[PaddingRun]) -> int:
        """Drop an erased tail from a candidate image's extent."""
        for run in padding:
            if run.image_offset < start or run.end < end:
                continue
            if run.end >= end and run.image_offset > start:
                end = min(end, run.image_offset)
        return end
