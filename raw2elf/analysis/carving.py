"""Padding detection and candidate firmware image discovery.

A flash dump is not the same thing as a firmware image.  One dump may hold a
bootloader, an application, two OTA slots, a configuration block and a lot of
erased flash.  These passes find the erased regions and, using whatever entry
structures the backend can locate, propose the executable images inside the
input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..arch.base import ArchCapability
from ..core.evidence import Evidence
from ..core.hypothesis import ImageHypothesis
from ..core.options import OptionError
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.util import human_size


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

    def _build(self, context: AnalysisContext, candidates) -> list[ImageHypothesis]:
        image = context.image
        padding = context.get("padding") or []
        offsets = sorted({candidate.image_offset for candidate in candidates})
        best_at: dict[int, Any] = {}
        for candidate in candidates:
            existing = best_at.get(candidate.image_offset)
            if existing is None or candidate.confidence > existing.confidence:
                best_at[candidate.image_offset] = candidate

        hypotheses: list[ImageHypothesis] = []
        for index, offset in enumerate(offsets):
            candidate = best_at[offset]
            following = offsets[index + 1] if index + 1 < len(offsets) else image.size
            end = self._trim(offset, following, padding)
            hypotheses.append(
                ImageHypothesis(
                    architecture=context.backend.name,
                    image_offset=offset,
                    image_size=max(end - offset, 0),
                    entry=candidate.entry_value,
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
