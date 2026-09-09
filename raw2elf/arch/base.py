"""The architecture backend interface.

This module is the boundary between generic analysis and per-ISA knowledge.
It imports only from :mod:`raw2elf.core` and contains no knowledge of any
particular instruction set.  Everything an architecture knows -- how code
pointers are encoded, where reset conventions put the entry point, which
address ranges mean what, how startup code initializes memory -- is expressed
through these methods.

Backends are not required to implement everything.  A backend advertises what
it can do through :meth:`ArchitectureBackend.capabilities`, and the pipeline
runs only the analyses whose capabilities are available.  This is why the
interface has no mandatory notion of a vector table, a mode bit or a stack
pointer: those are Cortex-M concepts, not universal ones.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional

from ..core.evidence import Evidence
from ..core.hypothesis import EntryCandidate
from ..core.image import FirmwareImage
from ..core.memory import MemoryRegion, StartupState
from ..core.reference import AddressClass, Reference, ReferenceKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..core.pipeline import AnalysisContext


class ArchCapability(Enum):
    """Optional abilities a backend may advertise."""

    #: Can propose execution entry points from image contents.
    ENTRY_DISCOVERY = auto()
    #: Can seed and constrain runtime load-address candidates.
    BASE_CONSTRAINTS = auto()
    #: Can recover absolute address references from instructions.
    REFERENCE_RECOVERY = auto()
    #: Can attribute recovered references to memory-mapped I/O accesses.
    MMIO_REFERENCE_RECOVERY = auto()
    #: Can recover startup memory initialization (data copy, bss clear).
    STARTUP_ANALYSIS = auto()
    #: Can recover a table of interrupt/exception handlers with names.
    INTERRUPT_TABLE_RECOVERY = auto()
    #: Can score whether a byte range plausibly decodes as code.
    CODE_VALIDATION = auto()
    #: Can propose architectural RAM/peripheral regions from evidence.
    MEMORY_REGION_HINTS = auto()
    #: Can report which parts of the image are executable code.
    CODE_DISCOVERY = auto()


@dataclass(frozen=True)
class TargetInfo:
    """The target description an ELF writer needs.

    These stay separate rather than collapsing into one architecture string,
    because they vary independently: the same ``architecture`` can appear with
    different instruction modes, endiannesses and ELF flags.
    """

    architecture: str
    subarchitecture: str = ""
    instruction_mode: str = ""
    endianness: str = "little"
    pointer_width: int = 32
    elf_machine: int = 0
    elf_flags: int = 0
    elf_osabi: int = 0
    #: Human-readable label used in reports.
    display_name: str = ""

    @property
    def little_endian(self) -> bool:
        return self.endianness == "little"

    @property
    def byte_order(self) -> str:
        return "little" if self.little_endian else "big"

    def as_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "subarchitecture": self.subarchitecture,
            "instruction_mode": self.instruction_mode,
            "endianness": self.endianness,
            "pointer_width": self.pointer_width,
            "elf_machine": self.elf_machine,
            "elf_flags": hex(self.elf_flags),
        }


@dataclass(frozen=True)
class ProbeResult:
    """A backend's opinion on whether an image is its architecture."""

    backend: str
    confidence: float
    target: Optional[TargetInfo] = None
    evidence: tuple[Evidence, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CodeScore:
    """How plausibly a byte range decodes as instructions."""

    confidence: float
    instructions: int = 0
    decoded_bytes: int = 0
    total_bytes: int = 0
    explanation: str = ""

    @property
    def coverage(self) -> float:
        return self.decoded_bytes / self.total_bytes if self.total_bytes else 0.0


@dataclass(frozen=True)
class BaseSeed:
    """A strong architecture-derived candidate load address."""

    runtime_base: int
    weight: float = 1.0
    evidence: Optional[Evidence] = None


@dataclass(frozen=True)
class BaseConstraints:
    """Architecture-supplied inputs to generic base recovery.

    The generic pass synthesizes further candidates by truncating recovered
    reference values to each granularity in ``alignments``, then scores every
    candidate against the reference set.  ``required_alignment`` and
    ``plausible_ranges`` prune candidates the architecture cannot support.
    """

    seeds: tuple[BaseSeed, ...] = ()
    alignments: tuple[int, ...] = (0x1000,)
    required_alignment: int = 1
    plausible_ranges: tuple[tuple[int, int], ...] = ()
    #: Evidence a backend wants recorded regardless of which base wins.
    evidence: tuple[Evidence, ...] = ()

    def permits(self, runtime_base: int) -> bool:
        if self.required_alignment > 1 and runtime_base % self.required_alignment:
            return False
        if not self.plausible_ranges:
            return True
        return any(low <= runtime_base <= high for low, high in self.plausible_ranges)


@dataclass(frozen=True)
class BaseAssessment:
    """An architecture's verdict on one candidate load address.

    The generic pass counts how references land; the backend performs the
    checks that need instruction semantics -- whether handlers point at code,
    whether absolute code pointers agree with the relocation-invariant code
    starts that direct branches identified.
    """

    score: float = 0.0
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class ExtraSection:
    """A raw section a backend wants in the output ELF."""

    name: str
    #: ELF ``SHT_*`` value.
    section_type: int
    #: ELF ``SHF_*`` flags.
    flags: int
    payload: bytes
    alignment: int = 1


@dataclass(frozen=True)
class SymbolRequest:
    """A symbol a backend contributes to the output ELF."""

    name: str
    address: int
    size: int = 0
    #: ``"function"``, ``"object"`` or ``"notype"``.
    kind: str = "function"
    is_local: bool = False
    #: Skip the architecture's code-pointer encoding for this symbol.
    literal_value: bool = False


@dataclass(frozen=True)
class InterruptEntry:
    """One recovered interrupt or exception handler."""

    index: int
    name: str
    #: Handler address as encoded in the table (mode bits still present).
    raw_value: int
    #: Handler address normalized for symbol emission.
    address: int
    #: True for architecture-defined vectors, false for device-specific IRQs.
    core: bool = False
    #: Device IRQ number, when this entry is a device interrupt.
    irq: Optional[int] = None


@dataclass
class InterruptTable:
    """A recovered handler table."""

    image_offset: int
    entries: list[InterruptEntry] = field(default_factory=list)
    #: Image offset of the table's runtime address anchor, if distinct.
    runtime_address: Optional[int] = None

    def device_entries(self) -> list[InterruptEntry]:
        return [entry for entry in self.entries if not entry.core]


class ArchitectureBackend(ABC):
    """Base class for every architecture backend."""

    #: Stable identifier used by ``--arch``.
    name: str = ""
    #: One-line description for ``--list-arch``.
    description: str = ""
    #: Byte alignment instructions must satisfy.
    instruction_alignment: int = 4
    #: Step used when scanning for entry structures.
    entry_scan_alignment: int = 4

    # -- identity ---------------------------------------------------------

    @abstractmethod
    def capabilities(self) -> frozenset[ArchCapability]:
        """The optional analyses this backend supports."""

    @abstractmethod
    def elf_target_info(self) -> TargetInfo:
        """Architecture, endianness, pointer width and ELF machine fields."""

    @abstractmethod
    def probe(self, image: FirmwareImage) -> ProbeResult:
        """Score how likely ``image`` is this architecture."""

    # -- address space ----------------------------------------------------

    def classify_address(self, address: int) -> AddressClass:
        """What the architecture's address map reserves ``address`` for."""
        return AddressClass.UNKNOWN

    def region_plausibility(self, address: int) -> float:
        """How plausible it is that this target has memory at ``address``.

        Distinct from :meth:`classify_address`, which says what the address
        map *reserves* a range for.  A range can be reserved for memory that
        a given part does not fit: an address in a window that needs an
        external controller configured before it responds is far less likely
        to be real memory than one in on-chip SRAM, and evidence for a region
        there should have to be correspondingly better.

        Returns a weight in ``[0, 1]``.  The default abstains.
        """
        return 0.5

    def normalize_code_pointer(self, value: int) -> int:
        """Strip any instruction-mode encoding from a code pointer."""
        return value

    def encode_code_pointer(self, address: int) -> int:
        """Re-apply instruction-mode encoding to a code address."""
        return address

    def is_plausible_code_pointer(self, value: int) -> bool:
        """Whether ``value`` could be a code pointer at all."""
        return value != 0 and value != (1 << self.elf_target_info().pointer_width) - 1

    def elf_symbol_value(self, address: int, is_function: bool) -> int:
        """The value to store in an ELF symbol for ``address``."""
        return self.encode_code_pointer(address) if is_function else address

    # -- optional analyses ------------------------------------------------

    def validate_code(self, data: bytes, address: int) -> CodeScore:
        """Score ``data`` as instructions located at ``address``."""
        return CodeScore(confidence=0.0, total_bytes=len(data), explanation="not implemented")

    def discover_entry_candidates(self, context: "AnalysisContext") -> list[EntryCandidate]:
        """Propose entry points, best first."""
        return []

    def generate_base_constraints(self, context: "AnalysisContext") -> BaseConstraints:
        """Seed and constrain the generic base-recovery search."""
        return BaseConstraints()

    def evaluate_base(self, context: "AnalysisContext", runtime_base: int) -> BaseAssessment:
        """Score one candidate load address using instruction semantics."""
        return BaseAssessment()

    def extract_references(self, context: "AnalysisContext") -> list[Reference]:
        """Recover absolute address references before the base is known.

        Called before base recovery, so anything returned must either be an
        absolute value or be flagged ``base_relative``.
        """
        return []

    def recover_memory_accesses(self, context: "AnalysisContext") -> list[Reference]:
        """Recover effective load/store addresses once the base is known."""
        return []

    def discover_code(self, context: "AnalysisContext") -> list[tuple[int, int]]:
        """Executable ``(runtime address, size)`` ranges, best effort."""
        return []

    def classify_reference(self, reference: Reference, context: "AnalysisContext") -> ReferenceKind:
        """Decide what a recovered reference denotes, once the base is known."""
        return reference.kind

    def recover_startup_state(self, context: "AnalysisContext") -> Optional[StartupState]:
        """Recover startup memory initialization, if the convention is known."""
        return None

    def recover_interrupt_table(self, context: "AnalysisContext") -> Optional[InterruptTable]:
        """Recover a handler table with architecture-defined names."""
        return None

    def memory_region_hints(self, context: "AnalysisContext") -> list[MemoryRegion]:
        """Architectural regions worth recording even without references."""
        return []

    def irq_symbol_name(self, index: int) -> str:
        """Placeholder symbol name for device interrupt ``index``."""
        return f"IRQ{index}_Handler"

    # -- ELF enrichment ---------------------------------------------------

    def elf_extra_sections(self, context: "AnalysisContext") -> list[ExtraSection]:
        """Architecture metadata sections, such as ARM build attributes."""
        return []

    def elf_symbols(self, context: "AnalysisContext") -> list[SymbolRequest]:
        """Architecture-specific symbols, such as ARM mapping symbols."""
        return []

    # -- reporting --------------------------------------------------------

    def report_rows(self, context: "AnalysisContext") -> list[tuple[str, str]]:
        """Extra ``(label, value)`` rows for the console report.

        The report has no way to know what an architecture's entry structure
        contains, so the backend formats those lines itself.  Without this the
        reporting code would have to reach into backend-defined details and
        name them, which is exactly the coupling the interface exists to
        prevent.
        """
        return []

    def manifest_fields(self, context: "AnalysisContext") -> dict[str, Any]:
        """Extra top-level fields for the JSON manifest.

        Called after analysis, so a backend can publish values that depend on
        the recovered base -- the runtime address of an entry structure, for
        instance.  Keys become part of the manifest's stable interface, so
        they should be named for the architecture's own vocabulary.
        """
        return {}

    # -- plumbing ---------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover - diagnostics
        return f"<{type(self).__name__} {self.name}>"
