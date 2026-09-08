"""Generic analysis passes and the default pipeline.

Passes declare the artifacts they need and produce; the pipeline orders them
and skips those whose requirements or architecture capabilities are missing.
Adding an analysis means adding it to :func:`default_passes`, not editing the
pipeline.
"""

from __future__ import annotations

from ..core.pipeline import AnalysisPass, Pipeline
from .base_recovery import BaseRecovery
from .carving import ImageDiscovery, PaddingDetection
from .elf_build import ElfReconstruction
from .entry import EntryDiscovery
from .interrupts import InterruptAnnotation, SymbolRecovery
from .memory_recovery import MemoryRegionRecovery, StartupAnalysis
from .references import MemoryAccessRecovery, ReferenceRecovery
from .svd import SvdMatcher


def default_passes() -> list[AnalysisPass]:
    """The standard reconstruction pipeline, in dependency order."""
    return [
        PaddingDetection(),
        ImageDiscovery(),
        EntryDiscovery(),
        ReferenceRecovery(),
        BaseRecovery(),
        MemoryAccessRecovery(),
        StartupAnalysis(),
        MemoryRegionRecovery(),
        SvdMatcher(),
        InterruptAnnotation(),
        SymbolRecovery(),
        ElfReconstruction(),
    ]


def default_pipeline() -> Pipeline:
    return Pipeline(default_passes())


__all__ = [
    "BaseRecovery",
    "ElfReconstruction",
    "EntryDiscovery",
    "ImageDiscovery",
    "InterruptAnnotation",
    "MemoryAccessRecovery",
    "MemoryRegionRecovery",
    "PaddingDetection",
    "ReferenceRecovery",
    "StartupAnalysis",
    "SvdMatcher",
    "SymbolRecovery",
    "default_passes",
    "default_pipeline",
]
