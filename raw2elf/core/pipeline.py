"""Analysis-pass framework and the shared analysis context.

Passes declare what they require and provide; the pipeline orders them and
skips any whose requirements cannot be satisfied -- either because an earlier
pass failed or because the selected architecture backend lacks the capability
the pass needs.  Adding an analysis means adding a pass, not editing the
pipeline.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Optional

from .evidence import Evidence, EvidenceLog
from .image import FirmwareImage
from .options import OptionError, Options
from .placement import ImagePlacement

if TYPE_CHECKING:  # pragma: no cover - typing only, no runtime dependency
    from ..arch.base import ArchitectureBackend


class AnalysisContext:
    """Everything a pass may read or contribute to.

    Artifacts are addressed by the same names passes use in ``provides`` and
    ``requires``, which keeps the dependency declarations honest.
    """

    def __init__(
        self,
        image: FirmwareImage,
        backend: "ArchitectureBackend",
        options: Options,
        root_image: Optional[FirmwareImage] = None,
    ) -> None:
        self.image = image
        self.root_image = root_image if root_image is not None else image
        self.backend = backend
        self.options = options
        self.evidence = EvidenceLog()
        self.artifacts: dict[str, Any] = {}
        self.warnings: list[str] = []
        self.timings: dict[str, float] = {}
        self._caches: dict[str, Any] = {}

    # -- artifacts --------------------------------------------------------

    def provide(self, name: str, value: Any) -> None:
        self.artifacts[name] = value

    def get(self, name: str, default: Any = None) -> Any:
        return self.artifacts.get(name, default)

    def require(self, name: str) -> Any:
        if name not in self.artifacts:
            raise KeyError(f"analysis artifact {name!r} is not available")
        return self.artifacts[name]

    def has(self, name: str) -> bool:
        return name in self.artifacts

    def cache(self, key: str, factory: Any) -> Any:
        """Memoize an expensive derived object for the life of the run."""
        if key not in self._caches:
            self._caches[key] = factory()
        return self._caches[key]

    # -- diagnostics ------------------------------------------------------

    def note(self, *evidence: Evidence) -> None:
        self.evidence.extend(evidence)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.log(f"warning: {message}", level=1)

    def log(self, message: str, level: int = 1) -> None:
        if self.options.verbose >= level:
            print(f"[raw2elf] {message}", file=sys.stderr)

    # -- convenience ------------------------------------------------------

    @property
    def runtime_base(self) -> int:
        """The chosen load address, or zero while it is still unknown."""
        return self.get("runtime_base", 0) or 0

    def file_offset_of(self, image_offset: int) -> int:
        """Where an image offset was in the input the analyst supplied.

        A carved image restarts its offsets at zero, so reporting one back
        unchanged would tell the analyst to look in the wrong place in their
        own file.  Segments keep the provenance; this converts with it.
        """
        segment = self.image.segment_at_offset(image_offset)
        if segment is not None and segment.file_offset is not None:
            return segment.file_offset + (image_offset - segment.image_offset)
        return image_offset + int(self.image.metadata.get("carved_from_offset", 0) or 0)

    def placement_for(
        self,
        image_offset: int,
        image_size: int,
        runtime_base: Optional[int] = None,
        **facts: Any,
    ) -> "ImagePlacement":
        """Assemble a placement for one image in this analysis."""
        return ImagePlacement(
            file_offset=self.file_offset_of(image_offset),
            image_offset=image_offset,
            image_size=image_size,
            runtime_base=runtime_base,
            **facts,
        )

    def offset_to_address(self, offset: int) -> Optional[int]:
        declared = self.image.declared_address_for(offset)
        if declared is not None:
            return declared
        if self.has("runtime_base"):
            return self.runtime_base + offset
        return None

    def read_address(self, address: int, size: int) -> bytes:
        """Read ``size`` bytes from the runtime address ``address``."""
        offset = self.address_to_offset(address)
        if offset is None:
            return b""
        return self.image.read(offset, size)

    def read_word(self, address: int) -> Optional[int]:
        """Read one pointer-width word from a runtime address."""
        target = self.backend.elf_target_info()
        size = target.pointer_width // 8
        payload = self.read_address(address, size)
        if len(payload) != size:
            return None
        return int.from_bytes(payload, target.byte_order)

    def address_to_offset(self, address: int) -> Optional[int]:
        segment = self.image.segment_at_address(address)
        if segment is not None:
            return segment.image_offset + (address - segment.address)
        if self.has("runtime_base"):
            offset = address - self.runtime_base
            if 0 <= offset < self.image.size:
                return offset
        return None


class AnalysisPass:
    """One unit of analysis.

    ``requires`` names artifacts that must already exist; ``capabilities``
    names architecture capabilities the backend must advertise.  A pass whose
    prerequisites are unmet is skipped, not failed.
    """

    name: str = "pass"
    requires: frozenset[str] = frozenset()
    provides: frozenset[str] = frozenset()
    capabilities: frozenset[Any] = frozenset()
    #: Pass names that should run first when they are present.  Unlike
    #: ``requires`` this only affects ordering: a pass is not skipped because
    #: something it lists here was skipped.
    after: frozenset[str] = frozenset()
    optional: bool = True

    def enabled(self, context: AnalysisContext) -> bool:
        return True

    def run(self, context: AnalysisContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass
class PassOutcome:
    name: str
    status: str  # "ok" | "skipped" | "failed"
    detail: str = ""
    duration: float = 0.0


@dataclass
class PipelineResult:
    context: AnalysisContext
    outcomes: list[PassOutcome] = field(default_factory=list)

    @property
    def failures(self) -> list[PassOutcome]:
        return [outcome for outcome in self.outcomes if outcome.status == "failed"]


class Pipeline:
    """Orders and runs analysis passes."""

    def __init__(self, passes: Iterable[AnalysisPass]) -> None:
        self.passes = list(passes)

    def ordered(self) -> list[AnalysisPass]:
        """Topologically order passes by artifact dependencies.

        Ties keep registration order, which makes runs reproducible.
        """
        remaining = list(self.passes)
        produced: set[str] = set()
        ordered: list[AnalysisPass] = []
        while remaining:
            pending_names = {item.name for item in remaining}
            ready = [
                item
                for item in remaining
                if item.requires <= produced and not (item.after & pending_names)
            ]
            if not ready:
                # Unsatisfiable requirements: keep registration order and let
                # the runner skip them, rather than deadlocking here.
                ordered.extend(remaining)
                break
            for item in ready:
                ordered.append(item)
                produced |= item.provides
                remaining.remove(item)
        return ordered

    def run(self, context: AnalysisContext) -> PipelineResult:
        result = PipelineResult(context=context)
        backend_capabilities = set(context.backend.capabilities())
        for analysis in self.ordered():
            missing = sorted(str(item) for item in analysis.requires - set(context.artifacts))
            if missing:
                result.outcomes.append(
                    PassOutcome(analysis.name, "skipped", f"missing {', '.join(missing)}")
                )
                continue
            unmet = analysis.capabilities - backend_capabilities
            if unmet:
                names = ", ".join(sorted(item.name for item in unmet))
                result.outcomes.append(
                    PassOutcome(analysis.name, "skipped", f"backend lacks {names}")
                )
                continue
            if not analysis.enabled(context):
                result.outcomes.append(PassOutcome(analysis.name, "skipped", "disabled"))
                continue
            started = time.monotonic()
            try:
                analysis.run(context)
            except OptionError:
                # The analyst asked for something impossible; say so instead
                # of quietly analysing something else.
                raise
            except Exception as error:  # noqa: BLE001 - a pass must not kill the run
                if not analysis.optional:
                    raise
                context.warn(f"{analysis.name} failed: {error}")
                result.outcomes.append(
                    PassOutcome(analysis.name, "failed", str(error), time.monotonic() - started)
                )
                continue
            duration = time.monotonic() - started
            context.timings[analysis.name] = duration
            context.log(f"{analysis.name} completed in {duration * 1000:.0f}ms", level=2)
            result.outcomes.append(PassOutcome(analysis.name, "ok", duration=duration))
        return result
