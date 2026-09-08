"""Shared fixtures for the raw2elf test suite.

The tests import ``raw2elf`` as a package, so the directory holding it goes on
``sys.path`` here rather than relying on how pytest was invoked.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
PACKAGE = TESTS.parent
ROOT = PACKAGE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = TESTS / "fixtures"

#: The bundled reference firmwares, by name.
FIRMWARES = {
    "stm32f4_standard": FIXTURES / "stm32f4_standard.elf",
    "nonstandard_base": FIXTURES / "nonstandard_base.elf",
    "application_high": FIXTURES / "application_high.elf",
    "bootloader": FIXTURES / "bootloader.elf",
    "two_ram_banks": FIXTURES / "two_ram_banks.elf",
}


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def truth():
    """Ground truth for every bundled firmware, keyed by name."""
    from raw2elf.eval import corpus

    return {name: corpus.ground_truth(path, name) for name, path in FIRMWARES.items()}


@pytest.fixture(scope="session")
def standard(truth):
    """Ground truth for the conventional STM32F4-style firmware."""
    return truth["stm32f4_standard"]


@pytest.fixture
def options():
    """Options that accept whatever confidence the analysis reaches."""
    from raw2elf.core.options import Options

    return Options(minimum_confidence=0.0, enable_svd=False)


def reconstruct_bytes(payload: bytes, options=None, **overrides):
    """Normalize and reconstruct ``payload`` in one step."""
    from raw2elf import input as ingest
    from raw2elf.core.options import Options
    from raw2elf.reconstruct import reconstruct

    if options is None:
        options = Options(minimum_confidence=0.0, enable_svd=False)
    for name, value in overrides.items():
        setattr(options, name, value)
    return reconstruct(ingest.parse(payload), options)


class MinimalBackend:
    """A backend that implements only the mandatory interface.

    Exists to prove that the generic pipeline works against a backend with
    almost no capabilities -- which is the shape a new architecture starts
    out in -- and to keep the core tests free of Cortex-M behaviour.
    """

    name = "minimal-test"
    description = "test backend with no optional capabilities"
    instruction_alignment = 4
    entry_scan_alignment = 4

    def __init__(self, confidence: float = 0.5) -> None:
        self._confidence = confidence

    def capabilities(self):
        return frozenset()

    def elf_target_info(self):
        from raw2elf.arch.base import TargetInfo

        return TargetInfo(
            architecture="test",
            subarchitecture="minimal",
            endianness="little",
            pointer_width=32,
            elf_machine=0xFE,
            display_name="Minimal Test Architecture",
        )

    def probe(self, image):
        from raw2elf.arch.base import ProbeResult

        return ProbeResult(backend=self.name, confidence=self._confidence, target=self.elf_target_info())

    # Everything else comes from the abstract base class's defaults, which is
    # the point: a partial backend must not need to stub out concepts it has
    # no equivalent for.
    def __getattr__(self, name):
        from raw2elf.arch.base import ArchitectureBackend

        attribute = getattr(ArchitectureBackend, name, None)
        if attribute is None or not callable(attribute):
            raise AttributeError(name)
        return attribute.__get__(self, type(self))


@pytest.fixture
def minimal_backend():
    return MinimalBackend()
