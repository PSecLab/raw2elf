"""Top-level reconstruction driver.

Selects an architecture backend, then runs the analysis pipeline against the
normalized image.  This is the entry point for programmatic use; the CLI is a
thin layer over it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .analysis import default_pipeline
from .arch.base import ArchitectureBackend, ProbeResult
from .arch.registry import get_backend, probe_all
from .core.evidence import Evidence
from .core.hypothesis import LowConfidenceError, choose
from .core.image import FirmwareImage
from .core.options import Options
from .core.pipeline import AnalysisContext, PipelineResult

#: Below this, architecture detection refuses to guess.
ARCHITECTURE_FLOOR = 0.2


@dataclass
class Reconstruction:
    """Everything one reconstruction run produced."""

    image: FirmwareImage
    backend: ArchitectureBackend
    context: AnalysisContext
    result: PipelineResult
    probes: list[ProbeResult] = field(default_factory=list)
    architecture_confidence: float = 1.0

    @property
    def elf(self) -> Optional[bytes]:
        return self.context.get("elf")

    @property
    def runtime_base(self) -> Optional[int]:
        return self.context.get("runtime_base")

    @property
    def entry(self) -> Optional[int]:
        return self.context.get("entry")


def select_backend(
    image: FirmwareImage, options: Options
) -> tuple[ArchitectureBackend, float, list[ProbeResult]]:
    """Pick an architecture backend, by override or by probing."""
    if options.arch and options.arch != "auto":
        return get_backend(options.arch), 1.0, []

    hint = image.architecture_hint
    if hint:
        try:
            return get_backend(hint), 1.0, []
        except KeyError:
            pass

    probes = probe_all(image)
    ranked = [(probe.backend, probe.confidence) for probe in probes]
    if not ranked or ranked[0][1] < ARCHITECTURE_FLOOR:
        raise LowConfidenceError(
            "architecture",
            ranked[0][0] if ranked else "none",
            ranked[0][1] if ranked else 0.0,
            ARCHITECTURE_FLOOR,
        )
    name = choose(
        "architecture",
        ranked,
        minimum_confidence=ARCHITECTURE_FLOOR,
        fail_on_ambiguity=options.fail_on_ambiguity,
    )
    confidence = next(probe.confidence for probe in probes if probe.backend == name)
    return get_backend(name), confidence, probes


def reconstruct(image: FirmwareImage, options: Optional[Options] = None) -> Reconstruction:
    """Run the full pipeline against ``image``."""
    options = options or Options()
    backend, confidence, probes = select_backend(image, options)

    context = AnalysisContext(image=image, backend=backend, options=options)
    context.provide("architecture_confidence", confidence)
    probe = next((item for item in probes if item.backend == backend.name), None)
    if probe is not None:
        context.note(*probe.evidence)
    elif options.arch != "auto":
        context.note(
            Evidence(
                kind="override",
                source="reconstruct",
                explanation=f"analyst selected the {backend.name} backend",
                value=backend.name,
            )
        )
    context.log(
        f"architecture: {backend.name} confidence {confidence:.2f}; "
        f"input format {image.source_format}, {image.size} bytes in {len(image.segments)} segment(s)",
        level=1,
    )

    result = default_pipeline().run(context)
    return Reconstruction(
        image=image,
        backend=backend,
        context=context,
        result=result,
        probes=probes,
        architecture_confidence=confidence,
    )
