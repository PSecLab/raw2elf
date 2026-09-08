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
        end = item.image_offset + item.image_size - 1
        lines.append(f"  Range:         0x{item.image_offset:06x}-0x{end:06x}")
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


#: Which context artifact holds the candidates for each refusal subject.
_CANDIDATE_SOURCES = {
    "runtime base address": "base_candidates",
    "entry structure": "entry_candidates",
    "architecture": "architecture_candidates",
}


def refusal(error) -> str:
    """Explain a refusal: the candidates, their evidence, and what to supply.

    A refusal that only announces a verdict leaves the analyst with nothing
    to act on. What they need is the list the tool was choosing between, why
    each one scored as it did, and the exact flag that would settle it.
    """
    context = getattr(error, "context", None)
    subject = getattr(error, "subject", "")
    lines: list[str] = [f"raw2elf: {error}", ""]

    body = _candidate_listing(error, context, subject)
    if body:
        lines.extend(body)
        lines.append("")

    lines.append("raw2elf will not emit an ELF it cannot justify. Any of these settles it:")
    lines.append("")
    suggestions = _suggested_flags(error, context, subject)
    width = max((len(flag) for flag, _why in suggestions), default=0) + 3
    for flag, why in suggestions:
        lines.append(f"  {flag.ljust(width)}{why}")
    return "\n".join(lines)


def _candidate_listing(error, context, subject: str) -> list[str]:
    """The ranked candidates for whatever could not be decided."""
    if subject == "architecture":
        probes = getattr(error, "probes", None)
        if probes is None and context is not None:
            probes = context.get("architecture_candidates")
        if not probes:
            return []
        lines = ["Candidate architectures:"]
        for index, probe in enumerate(probes[:5], start=1):
            lines.append(f"  {index}. {probe.backend:<20} confidence {probe.confidence:.2f}")
            for item in list(probe.evidence)[:4]:
                lines.append(f"       {item}")
        return lines

    if context is None:
        return []

    if subject == "entry structure":
        candidates = context.get("entry_candidates") or []
        if not candidates:
            return []
        lines = ["Candidate entry structures:"]
        for index, candidate in enumerate(candidates[:5], start=1):
            lines.append(
                f"  {index}. {candidate.kind} at file offset 0x{candidate.image_offset:06x}"
                f"    confidence {candidate.confidence:.2f}"
            )
            for item in candidate.evidence[:4]:
                lines.append(f"       {item}")
        return lines

    candidates = context.get("base_candidates") or []
    if not candidates:
        return []
    lines = ["Candidate load addresses:"]
    for index, candidate in enumerate(candidates[:5], start=1):
        lines.append(
            f"  {index}. 0x{candidate.runtime_base:08x}    confidence {candidate.confidence:.2f}"
            f"    ({candidate.origin})"
        )
        for item in candidate.supporting[:4]:
            lines.append(f"       {item}")
        for item in candidate.contradicting[:3]:
            lines.append(f"       {item}")
    return lines


def _suggested_flags(error, context, subject: str) -> list[tuple[str, str]]:
    """Concrete flags that would resolve this particular refusal."""
    if subject == "architecture":
        # The architecture floor is fixed, so --minimum-confidence would not
        # move it; naming the backend is the only way through.
        return [
            ("--arch <name>", "name the architecture (--list-arch)"),
            ("--probe", "show every backend's score and evidence"),
        ]

    flags: list[tuple[str, str]] = []
    if subject == "entry structure":
        flags.append(("--vector-offset <offset>", "name the entry structure"))
        flags.append(("--entry <address>", "name the entry point outright"))

    best = None
    if context is not None and subject == "runtime base address":
        candidates = context.get("base_candidates") or []
        if candidates:
            best = candidates[0]
            flags.append((f"--base 0x{best.runtime_base:08x}", "take the best candidate"))

    from ..core.hypothesis import AmbiguityError

    if isinstance(error, AmbiguityError):
        # Raising the threshold cannot separate two candidates that tie;
        # either name one, or stop asking for a clear winner.
        flags.append(("(drop --fail-on-ambiguity)", "accept the best of a close call"))
    else:
        confidence = getattr(error, "confidence", None)
        if confidence:
            # A threshold that would actually admit the best candidate,
            # rather than "lower it" to some unspecified value.
            flags.append(
                (
                    f"--minimum-confidence {max(confidence - 0.01, 0.0):.2f}",
                    "accept it as it stands",
                )
            )
        else:
            flags.append(("--minimum-confidence <float>", "accept the best candidate"))

    if not any(flag.startswith("--base") for flag, _why in flags):
        flags.append(("--base <address>", "supply the load address directly"))
    return flags


def architectures(probes: Sequence, selected: Optional[str] = None) -> str:
    if not probes:
        return ""
    lines = ["Architecture probes:"]
    for probe in probes:
        marker = " <-" if selected and probe.backend == selected else ""
        lines.append(f"  {probe.backend:<20} {probe.confidence:.2f}{marker}")
    return "\n".join(lines)
