"""The ``*.raw2elf.json`` reconstruction manifest.

The manifest is the stable machine-readable interface to a reconstruction.  It
records not only what was recovered but the evidence behind it and the
alternatives that were rejected, because a wrong reconstruction has to be
debuggable after the fact.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from ..core.evidence import confidence_label
from ..core.memory import InitKind
from ..core.reference import ReferenceKind
from ..core.util import hexs
from ..reconstruct import Reconstruction

#: Bumped when the manifest layout changes incompatibly.
MANIFEST_VERSION = 1
#: Caps keeping the manifest usable as a file rather than a dump.
MAX_REFERENCES = 2000
MAX_EVIDENCE = 400


def build(reconstruction: Reconstruction) -> dict[str, Any]:
    """Assemble the manifest for one reconstruction."""
    context = reconstruction.context
    target = reconstruction.backend.elf_target_info()
    image = reconstruction.image
    base = context.get("runtime_base")
    entry = context.get("entry")
    candidate = context.get("selected_entry_candidate")
    references = context.get("references")
    memory_map = context.get("memory_map")
    startup = context.get("startup_state")
    mcu = context.get("mcu")

    manifest: dict[str, Any] = {
        "raw2elf": {
            "manifest_version": MANIFEST_VERSION,
            "tool_version": _tool_version(),
        },
        "input": {
            "path": image.metadata.get("source_path"),
            "format": image.source_format,
            "format_label": image.metadata.get("label", image.source_format),
            "detection": image.metadata.get("detection"),
            "detection_confidence": image.metadata.get("detection_confidence"),
            "detection_ranking": image.metadata.get("detection_ranking"),
            "bytes": image.metadata.get("source_bytes"),
            "normalized_bytes": image.size,
            "segments": [
                {
                    "image_offset": hexs(segment.image_offset, 6),
                    "file_offset": hexs(segment.file_offset, 6),
                    "declared_address": hexs(segment.address, 8),
                    "size": segment.size,
                }
                for segment in image.iter_segments()
            ],
            "addresses_declared": image.addresses_declared,
            "notes": image.metadata.get("notes", []),
        },
        "architecture": target.architecture
        + ("-" + target.subarchitecture if target.subarchitecture else ""),
        "backend": reconstruction.backend.name,
        "target": target.as_dict(),
        "endianness": target.endianness,
        "pointer_width": target.pointer_width,
        "base": hexs(base, 8),
        "entry": hexs(entry, 8),
        "elf_entry": hexs(
            reconstruction.backend.encode_code_pointer(entry) if entry is not None else None, 8
        ),
        "confidence": {
            "architecture": round(reconstruction.architecture_confidence, 4),
            "base": round(context.get("base_confidence") or 0.0, 4),
            "entry": round(context.get("entry_confidence") or 0.0, 4),
        },
        "confidence_labels": {
            "architecture": confidence_label(reconstruction.architecture_confidence),
            "base": confidence_label(context.get("base_confidence") or 0.0),
            "entry": confidence_label(context.get("entry_confidence") or 0.0),
        },
    }

    if candidate is not None:
        manifest["entry_structure"] = {
            "kind": candidate.kind,
            "image_offset": hexs(candidate.image_offset, 6),
            "runtime_address": hexs(
                (base + candidate.image_offset) if base is not None else None, 8
            ),
            "confidence": round(candidate.confidence, 4),
        }

    # Fields only the architecture can name -- the runtime address of its
    # entry structure, its reset-time stack pointer -- come from the backend
    # so that this code never has to know what they mean.
    manifest.update(reconstruction.backend.manifest_fields(context))

    manifest["architecture_candidates"] = [
        {
            "backend": probe.backend,
            "confidence": round(probe.confidence, 4),
            "details": probe.details,
        }
        for probe in reconstruction.probes
    ]

    manifest["base_candidates"] = [
        candidate.as_dict() for candidate in (context.get("base_candidates") or [])[:10]
    ]

    manifest["images"] = [
        item.as_dict() for item in (context.get("candidate_images") or [])[:32]
    ]

    manifest["entry_candidates"] = [
        item.as_dict() for item in (context.get("entry_candidates") or [])[:32]
    ]

    manifest["regions"] = memory_map.as_list() if memory_map is not None else []
    manifest["elf_sections"] = context.get("elf_sections") or []

    manifest["padding"] = [run.as_dict() for run in (context.get("padding") or [])[:64]]

    if references is not None:
        counts = references.counts_by_kind()
        by_access: dict[str, int] = {}
        for reference in references:
            by_access[reference.access.value] = by_access.get(reference.access.value, 0) + 1
        manifest["references"] = {
            "total": len(references),
            "by_kind": counts,
            "by_access": by_access,
            "code": [
                reference.as_dict()
                for reference in references.of_kind(ReferenceKind.CODE)[:MAX_REFERENCES]
            ],
            "ram": [
                reference.as_dict()
                for reference in references.of_kind(ReferenceKind.RAM)[:MAX_REFERENCES]
            ],
            "flash_data": [
                reference.as_dict()
                for reference in references.of_kind(ReferenceKind.FLASH_DATA)[:MAX_REFERENCES]
            ],
        }

    accesses = context.get("mmio_accesses") or []
    manifest["mmio_accesses"] = [reference.as_dict() for reference in accesses[:MAX_REFERENCES]]

    if startup is not None:
        manifest["startup"] = startup.as_dict()
        manifest["data_initialization"] = [
            item.as_dict() for item in startup.initializations if item.kind == InitKind.COPY
        ]
        manifest["bss"] = [
            item.as_dict() for item in startup.initializations if item.kind == InitKind.ZERO
        ]

    interrupt_table = context.get("interrupt_table")
    if interrupt_table is not None:
        names = context.get("handler_names") or {}
        manifest["interrupts"] = [
            {
                "index": entry.index,
                "irq": entry.irq,
                "name": names.get(entry.index, entry.name),
                "handler": hexs(entry.raw_value, 8),
                "core": entry.core,
            }
            for entry in interrupt_table.entries
        ]

    if mcu is not None:
        match = mcu["match"]
        manifest["candidate_mcu"] = mcu["label"]
        manifest["mcu"] = {
            "label": mcu["label"],
            "exact": mcu["exact"],
            "confidence": round(match.confidence, 4),
            "device": match.device.name,
            "vendor": match.device.vendor,
            "cpu": match.device.cpu,
        }
        manifest["confidence"]["mcu"] = round(match.confidence, 4)
    candidates = context.get("mcu_candidates") or []
    if candidates:
        manifest["mcu_candidates"] = [item.as_dict() for item in candidates[:10]]

    annotations = context.get("svd_annotations") or {}
    if annotations.get("peripherals"):
        manifest["peripherals"] = annotations["peripherals"]
    if annotations.get("registers"):
        manifest["peripheral_registers"] = annotations["registers"][:MAX_REFERENCES]

    symbols = context.get("symbols")
    if symbols is not None:
        manifest["symbols"] = [
            {
                "name": symbol.name,
                "value": hexs(symbol.value, 8),
                "size": symbol.size,
                "kind": symbol.kind,
                "origin": symbol.origin,
            }
            for symbol in symbols.named()
        ]

    manifest["evidence"] = context.evidence.as_list()[:MAX_EVIDENCE]
    manifest["warnings"] = context.warnings
    manifest["passes"] = [
        {
            "name": outcome.name,
            "status": outcome.status,
            "detail": outcome.detail,
            "milliseconds": round(outcome.duration * 1000, 2),
        }
        for outcome in reconstruction.result.outcomes
    ]
    return manifest


def dumps(reconstruction: Reconstruction, indent: int = 2) -> str:
    return json.dumps(build(reconstruction), indent=indent, sort_keys=False)


def _tool_version() -> Optional[str]:
    try:
        from .. import __version__

        return __version__
    except Exception:  # pragma: no cover
        return None
