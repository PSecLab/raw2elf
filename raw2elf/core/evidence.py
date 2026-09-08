"""Evidence and confidence primitives.

Every non-trivial conclusion raw2elf reaches is accompanied by the evidence
that produced it.  This exists so that a wrong reconstruction can be traced
back to the specific observation that caused it, not just so reports look
tidy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from .util import fmt_value

HIGH = 0.85
MEDIUM = 0.6
LOW = 0.3


def confidence_label(confidence: float) -> str:
    """Map a 0..1 confidence onto the coarse label used in reports."""
    if confidence >= HIGH:
        return "HIGH"
    if confidence >= MEDIUM:
        return "MEDIUM"
    if confidence >= LOW:
        return "LOW"
    return "NONE"


@dataclass(frozen=True)
class Evidence:
    """One observation that supports or contradicts a conclusion."""

    kind: str
    source: str
    explanation: str
    value: Any = None
    confidence: float = 1.0
    weight: float = 1.0
    supports: bool = True

    @property
    def signed_weight(self) -> float:
        return self.weight * self.confidence * (1.0 if self.supports else -1.0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.kind,
            "source": self.source,
            "explanation": self.explanation,
            "value": fmt_value(self.value),
            "confidence": round(self.confidence, 4),
            "weight": self.weight,
            "supports": self.supports,
        }

    def __str__(self) -> str:
        return f"{'+' if self.supports else '-'} {self.explanation}"


class EvidenceLog:
    """An append-only, iterable collection of :class:`Evidence`."""

    def __init__(self, items: Iterable[Evidence] = ()) -> None:
        self._items: list[Evidence] = list(items)

    def add(self, *args: Any, **kwargs: Any) -> Evidence:
        item = args[0] if args and isinstance(args[0], Evidence) else Evidence(*args, **kwargs)
        self._items.append(item)
        return item

    def extend(self, items: Iterable[Evidence]) -> None:
        self._items.extend(items)

    def of_kind(self, kind: str) -> list[Evidence]:
        return [item for item in self._items if item.kind == kind]

    def from_source(self, source: str) -> list[Evidence]:
        return [item for item in self._items if item.source == source]

    @property
    def supporting(self) -> list[Evidence]:
        return [item for item in self._items if item.supports]

    @property
    def contradicting(self) -> list[Evidence]:
        return [item for item in self._items if not item.supports]

    def score(self) -> float:
        return sum(item.signed_weight for item in self._items)

    def as_list(self) -> list[dict[str, Any]]:
        return [item.as_dict() for item in self._items]

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)
