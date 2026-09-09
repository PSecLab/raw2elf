"""Candidate hypotheses: entry points, load addresses and firmware images.

raw2elf never commits to a single answer while several are plausible.  Each
stage produces ranked candidates carrying their own evidence, and the choice
is made once, explicitly, against a confidence threshold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from .evidence import Evidence, confidence_label
from .placement import ImagePlacement
from .util import hexs

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .interaction import Choice


@dataclass
class EntryCandidate:
    """A possible execution entry point.

    Backends discover these however their architecture dictates -- a Cortex-M
    backend from an exception vector table, another from a reset trampoline or
    a header.  The core only ever sees "an entry candidate".
    """

    #: Backend-defined label for the structure that produced this candidate.
    kind: str
    #: Image offset of the producing structure (not of the entry itself).
    image_offset: int
    entry_value: Optional[int] = None
    #: When true ``entry_value`` is in image-offset space, not absolute.
    entry_base_relative: bool = False
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    #: Backend-specific extras (handler tables, stack pointers, ...).
    details: dict[str, Any] = field(default_factory=dict)

    def entry_address(self, runtime_base: int) -> Optional[int]:
        if self.entry_value is None:
            return None
        return runtime_base + self.entry_value if self.entry_base_relative else self.entry_value

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "image_offset": hexs(self.image_offset, 6),
            "entry": hexs(self.entry_value, 8),
            "base_relative": self.entry_base_relative,
            "confidence": round(self.confidence, 3),
            "evidence": [item.explanation for item in self.evidence],
        }


@dataclass
class BaseCandidate:
    """One candidate runtime load address for the image under analysis."""

    runtime_base: int
    score: float = 0.0
    confidence: float = 0.0
    supporting: list[Evidence] = field(default_factory=list)
    contradicting: list[Evidence] = field(default_factory=list)
    origin: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "base": hexs(self.runtime_base, 8),
            "score": round(self.score, 3),
            "confidence": round(self.confidence, 3),
            "origin": self.origin,
            "evidence": [str(item) for item in self.supporting + self.contradicting],
        }


@dataclass
class ImageHypothesis:
    """A complete guess at one firmware image inside the input.

    The geometry and the recovered facts live together in one
    :class:`~raw2elf.core.placement.ImagePlacement`, so a hypothesis cannot
    be built with a base from one image and an entry from another without
    that being visible.  A dump holding a bootloader and an application has
    two of these, each fully describing its own image.
    """

    architecture: str
    placement: ImagePlacement
    score: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    contradictions: list[Evidence] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    # -- the placement is the hypothesis; these read through to it --------

    @property
    def file_offset(self) -> int:
        return self.placement.file_offset

    @property
    def image_offset(self) -> int:
        return self.placement.image_offset

    @property
    def image_size(self) -> int:
        return self.placement.image_size

    @property
    def runtime_base(self) -> Optional[int]:
        return self.placement.runtime_base

    @property
    def entry(self) -> Optional[int]:
        return self.placement.entry

    @property
    def entry_structure(self) -> Optional[int]:
        return self.placement.entry_structure

    @property
    def initial_stack_pointer(self) -> Optional[int]:
        return self.placement.initial_stack_pointer

    @property
    def confidence(self) -> float:
        return self.placement.confidence

    @property
    def label(self) -> str:
        return confidence_label(self.confidence)

    def as_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            **self.placement.as_dict(),
            "score": round(self.score, 3),
            "evidence": [str(item) for item in self.evidence],
            "contradictions": [str(item) for item in self.contradictions],
            "details": self.details,
        }


class RecoveryRefused(RuntimeError):
    """Base class for a refusal to guess.

    Carries the analysis context that produced it so the caller can report
    the candidates and their evidence, rather than only the verdict.  A
    refusal that does not say what the alternatives were leaves the analyst
    with nothing to act on.
    """

    subject: str = ""
    #: Set by the driver once the run unwinds; ``None`` if unavailable.
    context: Any = None


class AmbiguityError(RecoveryRefused):
    """Raised when candidates are too close to choose between safely."""

    def __init__(self, subject: str, candidates: list[tuple[int | str, float]]) -> None:
        self.subject = subject
        self.candidates = candidates
        leaders = ", ".join(
            f"{value if isinstance(value, str) else hexs(value, 8)} ({confidence:.2f})"
            for value, confidence in candidates[:2]
        )
        super().__init__(
            f"cannot choose a {subject}: {leaders} are too close to separate"
        )


class LowConfidenceError(RecoveryRefused):
    """Raised when the best candidate does not meet the required confidence."""

    def __init__(self, subject: str, value: Any, confidence: float, threshold: float) -> None:
        self.subject = subject
        self.value = value
        self.confidence = confidence
        self.threshold = threshold
        super().__init__(
            f"best {subject} candidate "
            f"{value if isinstance(value, str) else hexs(value, 8)} has confidence "
            f"{confidence:.2f}, below the required {threshold:.2f}"
        )


def resolve(
    subject: str,
    choices: list["Choice"],
    options,
    ambiguity_margin: float = 0.15,
    custom: Optional[str] = None,
) -> Any:
    """Pick a candidate, asking a person only if the evidence will not.

    The unattended path is unchanged: rank, apply the threshold, and refuse
    rather than guess. An interaction is consulted only once that refusal has
    already been decided on, so being able to ask never lowers the bar for
    deciding automatically -- it only changes what happens when the bar is
    not met.
    """
    ranked = [(item.value, item.confidence or 0.0) for item in choices]
    try:
        return choose(
            subject,
            ranked,
            minimum_confidence=options.minimum_confidence,
            fail_on_ambiguity=options.fail_on_ambiguity,
            ambiguity_margin=ambiguity_margin,
        )
    except RecoveryRefused as refusal:
        interaction = getattr(options, "interaction", None)
        if interaction is None:
            raise
        picked = interaction.choose(subject, choices, prompt=str(refusal), custom=custom)
        if picked is None:
            raise
        return picked.value


def choose(
    subject: str,
    ranked: list[tuple[Any, float]],
    minimum_confidence: float,
    fail_on_ambiguity: bool,
    ambiguity_margin: float = 0.15,
) -> Any:
    """Pick the best ranked candidate, or refuse to guess.

    ``ranked`` must be sorted best-first as ``(value, confidence)`` pairs.
    Refusing is the point: silently emitting a confidently wrong ELF is worse
    than telling the analyst to supply the answer.
    """
    if not ranked:
        raise LowConfidenceError(subject, "none", 0.0, minimum_confidence)
    best_value, best_confidence = ranked[0]
    if best_confidence < minimum_confidence:
        raise LowConfidenceError(subject, best_value, best_confidence, minimum_confidence)
    if fail_on_ambiguity and len(ranked) > 1:
        runner_up = ranked[1][1]
        if best_confidence - runner_up < ambiguity_margin:
            raise AmbiguityError(subject, ranked[:5])
    return best_value
