"""Architecture-neutral representation of a recovered address reference.

A reference is a value that some instruction constructed or used as an
address, together with the provenance that lets a later analysis decide what
it actually is.  Recovering references is the architecture backend's job;
storing, correlating and scoring them is the core's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Iterator, Optional

from .util import fmt_value, hexs


class ReferenceKind(str, Enum):
    """What a reference value appears to denote."""

    CODE = "CODE"
    FLASH_DATA = "FLASH_DATA"
    RAM = "RAM"
    MMIO = "MMIO"
    UNKNOWN = "UNKNOWN"


class Access(str, Enum):
    """How the referenced location is used by the producing instruction."""

    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    ADDRESS_ONLY = "ADDRESS_ONLY"


class AddressClass(str, Enum):
    """A backend's opinion about an address, from the target memory map alone.

    This is a *hint*: it says what the architecture's address space reserves a
    range for, not what this particular firmware puts there.
    """

    CODE = "CODE"
    RAM = "RAM"
    MMIO = "MMIO"
    SYSTEM = "SYSTEM"
    RESERVED = "RESERVED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Reference:
    """One recovered reference and everything known about where it came from."""

    value: int
    source_offset: int
    derivation: str
    kind: ReferenceKind = ReferenceKind.UNKNOWN
    access: Access = Access.ADDRESS_ONLY
    width: Optional[int] = None
    confidence: float = 0.5
    source_text: str = ""
    #: When true, ``value`` lives in image-offset space and the runtime value
    #: is ``runtime_base + value``.  Such references cannot discriminate
    #: between candidate load addresses because they move with the image.
    base_relative: bool = False
    #: Whether this reference is admissible as base-recovery evidence.
    useful_for_base: bool = True
    #: For load/store references, the recovered base register value and the
    #: literal displacement applied to it.
    base_value: Optional[int] = None
    offset_value: Optional[int] = None
    #: Backend-supplied address-space opinion for ``value``.
    address_class: AddressClass = AddressClass.UNKNOWN

    def runtime_value(self, runtime_base: int) -> int:
        return runtime_base + self.value if self.base_relative else self.value

    def with_kind(self, kind: ReferenceKind) -> "Reference":
        from dataclasses import replace

        return replace(self, kind=kind)

    def as_dict(self, runtime_base: Optional[int] = None) -> dict[str, Any]:
        value = self.value if runtime_base is None else self.runtime_value(runtime_base)
        return {
            "value": hexs(value, 8),
            "kind": self.kind.value,
            "access": self.access.value,
            "width": self.width,
            "derivation": self.derivation,
            "source_offset": hexs(self.source_offset, 6),
            "source": self.source_text,
            "base": hexs(self.base_value, 8),
            "offset": fmt_value(self.offset_value),
            "confidence": round(self.confidence, 3),
        }


class ReferenceSet:
    """A queryable collection of recovered references."""

    def __init__(self, references: Iterable[Reference] = ()) -> None:
        self._references: list[Reference] = list(references)

    def add(self, reference: Reference) -> None:
        self._references.append(reference)

    def extend(self, references: Iterable[Reference]) -> None:
        self._references.extend(references)

    def of_kind(self, *kinds: ReferenceKind) -> list[Reference]:
        wanted = set(kinds)
        return [ref for ref in self._references if ref.kind in wanted]

    def base_discriminating(self) -> list[Reference]:
        """References whose value does not move with the image load address."""
        return [ref for ref in self._references if ref.useful_for_base and not ref.base_relative]

    def replace_all(self, references: Iterable[Reference]) -> None:
        self._references = list(references)

    def counts_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ref in self._references:
            counts[ref.kind.value] = counts.get(ref.kind.value, 0) + 1
        return counts

    def __iter__(self) -> Iterator[Reference]:
        return iter(self._references)

    def __len__(self) -> int:
        return len(self._references)
