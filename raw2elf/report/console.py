"""Human-readable reporting."""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

from ..core.evidence import confidence_label
from ..core.memory import InitKind
from ..core.reference import Access, ReferenceKind
from ..core.util import human_size
from ..reconstruct import Reconstruction

_LABEL_WIDTH = 20


def _row(label: str, value: object) -> str:
    return f"{label + ':':<{_LABEL_WIDTH}}{value}"


def summary(reconstruction: Reconstruction, outputs: Sequence[str] = ()) -> str:
    """The standard report for one reconstruction."""
    context = reconstruction.context
    image = reconstruction.image
    target = reconstruction.backend.elf_target_info()
    base = context.get("runtime_base")
    entry = context.get("entry")
    candidate = context.get("selected_entry_candidate")
    references = context.get("references")
    accesses = context.get("mmio_accesses") or []
    memory_map = context.get("memory_map")
    startup = context.get("startup_state")
    mcu = context.get("mcu")

    lines: list[str] = []
    lines.append(_row("Input format", image.metadata.get("label", image.source_format)))
    if image.metadata.get("detection"):
        lines.append(_row("  detected as", image.metadata["detection"]))
    lines.append(
        _row(
            "Input size",
            f"{human_size(image.size)} in {len(image.segments)} segment(s)"
            + (" with declared addresses" if image.addresses_declared else ""),
        )
    )
    lines.append(_row("Architecture", target.display_name or reconstruction.backend.name))
    if candidate is not None:
        carved = image.metadata.get("carved_from_offset", 0)
        where = f"0x{carved + candidate.image_offset:06x}"
        if carved:
            where += f" (0x{candidate.image_offset:06x} within the selected image)"
        lines.append(_row("Entry structure", f"{candidate.kind} at file offset {where}"))
    # Whatever else the architecture wants to report about its entry
    # structure: this code does not know, and does not need to.
    for label, value in reconstruction.backend.report_rows(context):
        lines.append(_row(label, value))
    if base is not None:
        lines.append(_row("Load base", f"0x{base:08x}"))
    if entry is None:
        lines.append(_row("Entry point", "not recovered"))
    else:
        encoded = reconstruction.backend.encode_code_pointer(entry)
        suffix = f"  (ELF e_entry 0x{encoded:08x})" if encoded != entry else ""
        lines.append(_row("Entry point", f"0x{entry:08x}{suffix}"))

    if references is not None:
        counts = references.counts_by_kind()
        ram = references.of_kind(ReferenceKind.RAM)
        # A recovered load or store is much stronger evidence than a literal
        # that merely happens to look like a RAM address, and a constant table
        # produces a great many of the latter.  Reporting one total for both
        # would make the weak evidence look like the strong kind.
        ram_accessed = sum(1 for item in ram if item.access in (Access.READ, Access.WRITE))
        ram_literals = len(ram) - ram_accessed
        lines.append("")
        lines.append("Recovered:")
        lines.append(f"  Code references:   {counts.get(ReferenceKind.CODE.value, 0)}")
        lines.append(f"  Flash references:  {counts.get(ReferenceKind.FLASH_DATA.value, 0)}")
        lines.append(
            f"  RAM references:    {ram_accessed} accessed"
            + (f", {ram_literals} as address literals" if ram_literals else "")
        )
        lines.append(f"  MMIO accesses:     {len(accesses)}")

    if memory_map is not None and len(memory_map):
        lines.append("")
        lines.append("Memory regions:")
        for region in memory_map:
            lines.append(
                f"  {region.kind.value:<6} 0x{region.start:08x}-0x{region.end:08x}"
                f"  {human_size(region.size):>7}  {region.name}"
            )

    if startup is not None and startup.initializations:
        lines.append("")
        lines.append("Startup initialization:")
        for item in startup.initializations:
            size = item.resolved_size or 0
            if item.kind == InitKind.COPY:
                lines.append(
                    f"  .data  0x{item.source or 0:08x} -> 0x{item.destination:08x}"
                    f"  {human_size(size)}"
                )
            else:
                lines.append(
                    f"  .bss   0x{item.destination:08x}-0x{item.destination + size:08x}"
                    f"  {human_size(size)}"
                )

    lines.append("")
    lines.append("Likely MCU:")
    if mcu is None:
        lines.append("  not identified")
    else:
        match = mcu["match"]
        lines.append(f"  {mcu['label']}  (confidence {match.confidence:.2f})")
        candidates = context.get("mcu_candidates") or []
        for other in candidates[1:3]:
            lines.append(f"    also matches {other.device.name} ({other.confidence:.2f})")

    lines.append("")
    lines.append("Confidence:")
    for label, value in (
        ("Architecture", reconstruction.architecture_confidence),
        ("Base", context.get("base_confidence") or 0.0),
        ("Entry", context.get("entry_confidence") or 0.0),
    ):
        lines.append(f"  {label + ':':<14}{confidence_label(value):<7} ({value:.2f})")

    if context.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in context.warnings:
            lines.append(f"  - {warning}")

    if outputs:
        lines.append("")
        lines.append("Generated:")
        for path in outputs:
            lines.append(f"  {path}")
    return "\n".join(lines)


def evidence(reconstruction: Reconstruction, limit: int = 60) -> str:
    """Why the reconstruction reached its conclusions."""
    context = reconstruction.context
    lines: list[str] = []
    base = context.get("runtime_base")
    if base is not None:
        confidence = context.get("base_confidence") or 0.0
        lines.append(f"Recovered base: 0x{base:08x}")
        lines.append(f"Confidence: {confidence_label(confidence)} ({confidence:.2f})")
        lines.append("")
    lines.append("Evidence:")
    for item in list(context.evidence)[:limit]:
        lines.append(f"  {item}")
    remaining = len(context.evidence) - limit
    if remaining > 0:
        lines.append(f"  ... {remaining} more (see the JSON manifest)")
    return "\n".join(lines)


def base_candidates(reconstruction: Reconstruction, limit: int = 5) -> str:
    candidates = reconstruction.context.get("base_candidates") or []
    if not candidates:
        return ""
    lines = ["Candidate load addresses:"]
    for index, candidate in enumerate(candidates[:limit], start=1):
        lines.append(
            f"  {index}. 0x{candidate.runtime_base:08x}    confidence {candidate.confidence:.2f}"
            f"    ({candidate.origin})"
        )
        for item in candidate.supporting[:4]:
            lines.append(f"       {item}")
        for item in candidate.contradicting[:2]:
            lines.append(f"       {item}")
    return "\n".join(lines)


def images(candidates: Iterable, backend_name: str) -> str:
    """The ``--list-images`` listing."""
    listing = list(candidates)
    if not listing:
        return "No candidate firmware images were found."
    lines: list[str] = []
    for index, item in enumerate(listing):
        lines.append(f"Image {index}")
        lines.append(f"  Offset:        0x{item.image_offset:06x}")
        lines.append(f"  Size:          {human_size(item.image_size)} ({item.image_size} bytes)")
        lines.append(f"  Architecture:  {item.architecture}")
        if item.entry is not None:
            lines.append(f"  Entry:         0x{item.entry:08x}")
        lines.append(f"  Confidence:    {item.confidence:.2f} ({confidence_label(item.confidence)})")
        for evidence_item in item.evidence[:4]:
            lines.append(f"    {evidence_item}")
        lines.append("")
    lines.append(f"Reconstruct one with: --image <n> -o <output>.elf")
    return "\n".join(lines)


def architectures(probes: Sequence, selected: Optional[str] = None) -> str:
    if not probes:
        return ""
    lines = ["Architecture probes:"]
    for probe in probes:
        marker = " <-" if selected and probe.backend == selected else ""
        lines.append(f"  {probe.backend:<20} {probe.confidence:.2f}{marker}")
    return "\n".join(lines)
