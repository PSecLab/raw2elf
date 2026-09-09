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

from .provenance import CodeProvenance
from .util import fmt_value, hexs


class ReferenceKind(str, Enum):
    """What a reference value appears to denote.

    ``CONSTANT`` is the honest default for a value an instruction merely
    loaded. A literal pool holds integers, masks, floating-point bit patterns
    and string data as well as pointers, and every one of those can fall
    inside a plausible address range. A value is only promoted out of
    ``CONSTANT`` when something is seen to use it as an address.
    """

    CONSTANT = "CONSTANT"
    CODE = "CODE"
    FLASH_DATA = "FLASH_DATA"
    RAM = "RAM"
    MMIO = "MMIO"
    UNKNOWN = "UNKNOWN"


class Access(str, Enum):
    """How the referenced location is used by the producing instruction.

    ``ADDRESS_ONLY`` means a value was produced and nothing more: the
    instruction did not touch the memory it might name. Only ``READ``,
    ``WRITE`` and ``EXECUTE`` are evidence that the address exists.
    """

    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    ADDRESS_ONLY = "ADDRESS_ONLY"

    @property
    def touches_memory(self) -> bool:
        """Whether the instruction actually used the address."""
        return self in (Access.READ, Access.WRITE, Access.EXECUTE)


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
    #: Why the instruction that produced this is believed to be code. An
    #: address computed by bytes that merely decoded is not evidence that the
    #: address exists, however well-formed the encoding.
    code_provenance: CodeProvenance = CodeProvenance.LINEAR_SWEEP
    #: Start address of the discovered function the instruction belongs to.
    #: Accesses from several independently reached functions are much better
    #: evidence than the same number of accesses from one block.
    source_function: Optional[int] = None
    #: Whether the value this address was *built from* is credible as a
    #: memory base. An instruction can be perfectly reachable, correctly
    #: decoded, and still compute a meaningless address, because the base
    #: register held something that was never a pointer -- a loop counter, a
    #: flag, a function argument the analysis could not resolve. The
    #: effective address is then just the displacement wearing a base's
    #: clothes, and it is not evidence about memory.
    base_credible: bool = True

    @property
    def establishes_memory(self) -> bool:
        """Whether this reference is evidence that its address is real memory.

        Three independent things have to hold, and they are genuinely
        different questions:

        - the instruction is reached (``trusted``),
        - the address it computed means something (``base_credible``),
        - and it actually touched that address (``access.touches_memory``).
        """
        return self.trusted and self.base_credible and self.access.touches_memory

    @property
    def trusted(self) -> bool:
        """Whether this came from code something is known to reach."""
        return self.code_provenance.trusted

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
            "code_provenance": self.code_provenance.value,
            "source_function": hexs(self.source_function, 8),
            "base_credible": self.base_credible,
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

    def accesses(self) -> list[Reference]:
        """References where an instruction actually touched the address."""
        return [ref for ref in self._references if ref.access.touches_memory]

    def trusted_accesses(self) -> list[Reference]:
        """Accesses made by code something is known to reach."""
        return [ref for ref in self.accesses() if ref.trusted]

    def establishing(self) -> list[Reference]:
        """References that are evidence their address is real memory."""
        return [ref for ref in self._references if ref.establishes_memory]

    def counts_by_provenance(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for ref in self._references:
            key = ref.code_provenance.value
            counts[key] = counts.get(key, 0) + 1
        return counts

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
