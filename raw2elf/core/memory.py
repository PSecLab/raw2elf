"""Generic memory regions, address mapping and memory-initialization records."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator, Optional

from .evidence import Evidence
from .util import hexs, human_size


class RegionKind(str, Enum):
    FLASH = "flash"
    RAM = "ram"
    MMIO = "mmio"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class MemoryRegion:
    """A recovered runtime memory region."""

    kind: RegionKind
    start: int
    size: int
    name: str = ""
    readable: bool = True
    writable: bool = False
    executable: bool = False
    loadable: bool = False
    confidence: float = 0.5
    evidence: tuple[Evidence, ...] = ()

    @property
    def end(self) -> int:
        """Inclusive end address."""
        return self.start + self.size - 1

    def contains(self, address: int) -> bool:
        return self.start <= address < self.start + self.size

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.kind.value,
            "name": self.name,
            "start": hexs(self.start, 8),
            "end": hexs(self.end, 8),
            "size": self.size,
            "size_human": human_size(self.size),
            "permissions": ("r" if self.readable else "-")
            + ("w" if self.writable else "-")
            + ("x" if self.executable else "-"),
            "loadable": self.loadable,
            "confidence": round(self.confidence, 3),
            "evidence": [item.explanation for item in self.evidence],
        }


class MemoryMap:
    """The set of recovered regions, keyed by nothing in particular."""

    def __init__(self, regions: Iterable[MemoryRegion] = ()) -> None:
        self._regions: list[MemoryRegion] = sorted(regions, key=lambda region: region.start)

    def add(self, region: MemoryRegion) -> None:
        self._regions.append(region)
        self._regions.sort(key=lambda item: item.start)

    def of_kind(self, *kinds: RegionKind) -> list[MemoryRegion]:
        wanted = set(kinds)
        return [region for region in self._regions if region.kind in wanted]

    def region_for(self, address: int) -> Optional[MemoryRegion]:
        for region in self._regions:
            if region.contains(address):
                return region
        return None

    def as_list(self) -> list[dict[str, Any]]:
        return [region.as_dict() for region in self._regions]

    def __iter__(self) -> Iterator[MemoryRegion]:
        return iter(self._regions)

    def __len__(self) -> int:
        return len(self._regions)


@dataclass(frozen=True)
class LoadedSegment:
    """Firmware bytes placed at a runtime address, ready for ELF emission."""

    address: int
    data: bytes
    name: str
    executable: bool = True
    writable: bool = False
    image_offset: int = 0

    @property
    def size(self) -> int:
        return len(self.data)


class InitKind(str, Enum):
    COPY = "copy"
    ZERO = "zero"


@dataclass(frozen=True)
class MemoryInitialization:
    """A recovered startup memory-initialization action.

    ``COPY`` records a load-address to run-address copy (a ``.data``-style
    initializer); ``ZERO`` records a cleared range (a ``.bss``-style
    initializer).  Startup conventions are architecture-specific, so backends
    recover these and report them through this generic record.
    """

    kind: InitKind
    destination: int
    size: Optional[int] = None
    source: Optional[int] = None
    destination_end: Optional[int] = None
    confidence: float = 0.5
    evidence: tuple[Evidence, ...] = ()
    detected_at: Optional[int] = None

    @property
    def resolved_size(self) -> Optional[int]:
        if self.size is not None:
            return self.size
        if self.destination_end is not None:
            return self.destination_end - self.destination
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "source": hexs(self.source, 8),
            "destination": hexs(self.destination, 8),
            "destination_end": hexs(self.destination_end, 8),
            "size": self.resolved_size,
            "confidence": round(self.confidence, 3),
            "detected_at": hexs(self.detected_at, 8),
            "evidence": [item.explanation for item in self.evidence],
        }


@dataclass
class StartupState:
    """Everything a backend recovered about startup memory initialization."""

    initializations: list[MemoryInitialization] = field(default_factory=list)
    initial_stack_pointer: Optional[int] = None
    evidence: list[Evidence] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "initial_stack_pointer": hexs(self.initial_stack_pointer, 8),
            "initializations": [item.as_dict() for item in self.initializations],
        }
