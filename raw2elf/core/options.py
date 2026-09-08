"""Analysis options, including every analyst override.

Explicit analyst input always wins over inference.  Each override is stored
separately from the inferred value so reports can say which is which.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .interaction import Interaction


class OptionError(ValueError):
    """Raised when an analyst-supplied option cannot be honoured.

    Distinct from an analysis failure: a pass that cannot do its job is
    skipped and reported, but an option the analyst got wrong has to stop the
    run, or they will be handed an ELF that answers a different question.
    """


@dataclass
class Options:
    """Knobs for one reconstruction run."""

    #: Architecture backend name, or ``"auto"`` to probe.
    arch: str = "auto"
    #: Analyst-supplied runtime load address for the selected image.
    base: Optional[int] = None
    #: Analyst-supplied entry point.
    entry: Optional[int] = None
    #: Analyst-supplied image offset of the entry structure (vector table).
    vector_offset: Optional[int] = None
    #: Index into the discovered candidate image list.
    image: Optional[int] = None
    #: Analyst-supplied MCU name, bypassing SVD ranking.
    mcu: Optional[str] = None
    #: Explicit SVD file, or a directory to search.
    svd: Optional[str] = None
    enable_svd: bool = True
    #: Download the CMSIS-SVD database when no local copy is found.
    #:
    #: Off by default, because a library call should never reach the network
    #: on its own. The command line turns it on, since a person running the
    #: tool should not have to go and find the database first.
    fetch_svd: bool = False
    svd_symbols: str = "peripherals"  # none | peripherals | registers
    minimum_confidence: float = 0.5
    fail_on_ambiguity: bool = False
    verbose: int = 0
    #: Upper bound on instructions decoded during reference recovery.
    max_instructions: int = 400_000
    #: Runs of an identical byte at least this long count as padding.
    padding_threshold: int = 256
    #: Force a source format instead of sniffing.
    input_format: Optional[str] = None
    #: Emit ``.text``/``.rodata``-style splits when evidence justifies it.
    split_sections: bool = False
    #: Someone to ask when the evidence does not decide. ``None`` means run
    #: unattended: an undecidable point refuses rather than blocking.
    interaction: Optional["Interaction"] = None
    extra: dict[str, object] = field(default_factory=dict)

    @property
    def has_base_override(self) -> bool:
        return self.base is not None
