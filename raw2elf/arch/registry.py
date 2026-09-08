"""Architecture backend registry.

Backends are imported lazily from here so that the generic core never pulls in
a concrete ISA implementation.  Adding an architecture means adding an entry to
:data:`_BACKEND_MODULES` and implementing
:class:`~raw2elf.arch.base.ArchitectureBackend`.
"""

from __future__ import annotations

from importlib import import_module
from typing import Iterable

from ..core.image import FirmwareImage
from .base import ArchitectureBackend, ProbeResult

#: ``backend name -> "relative.module:attribute"``, resolved against this
#: package so raw2elf works under any top-level import name.
_BACKEND_MODULES: dict[str, str] = {
    "arm-cortex-m": ".arm.cortex_m:CortexMBackend",
}

_INSTANCES: dict[str, ArchitectureBackend] = {}


def backend_names() -> list[str]:
    return sorted(_BACKEND_MODULES)


def get_backend(name: str) -> ArchitectureBackend:
    """Instantiate a backend by name."""
    if name not in _BACKEND_MODULES:
        known = ", ".join(backend_names())
        raise KeyError(f"unknown architecture {name!r}; known backends: {known}")
    if name not in _INSTANCES:
        target = _BACKEND_MODULES[name]
        module_name, _, attribute = target.partition(":")
        package = __package__ if module_name.startswith(".") else None
        module = import_module(module_name, package=package)
        _INSTANCES[name] = getattr(module, attribute)()
    return _INSTANCES[name]


def all_backends() -> list[ArchitectureBackend]:
    return [get_backend(name) for name in backend_names()]


def probe_all(image: FirmwareImage) -> list[ProbeResult]:
    """Probe every backend and return results best-first."""
    results = [backend.probe(image) for backend in all_backends()]
    return sorted(results, key=lambda result: result.confidence, reverse=True)


def register(name: str, target: str) -> None:
    """Register a backend as ``"module:attribute"`` (absolute or relative)."""
    _BACKEND_MODULES[name] = target
    _INSTANCES.pop(name, None)


def describe() -> Iterable[tuple[str, str]]:
    for backend in all_backends():
        yield backend.name, backend.description
