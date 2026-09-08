"""``raw2elf`` command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

if __package__ in (None, ""):  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "raw2elf"

from . import __version__, input as ingest
from .analysis import PaddingDetection
from .analysis.carving import ImageDiscovery
from .arch.registry import backend_names, describe, probe_all
from .core.hypothesis import AmbiguityError, LowConfidenceError
from .core.options import Options
from .core.pipeline import AnalysisContext, Pipeline
from .reconstruct import reconstruct
from .report import console, manifest

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AMBIGUOUS = 3


def _integer(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raw2elf",
        description=(
            "Reconstruct an analysis-ready ELF from a raw firmware extraction. "
            "Recovers the architecture, load address, entry point, memory regions "
            "and symbols, and records the evidence for every conclusion."
        ),
        epilog=(
            "Analyst-supplied values always override inference. When recovery is "
            "ambiguous, raw2elf reports the candidates instead of guessing."
        ),
    )
    parser.add_argument("firmware", nargs="?", help="firmware dump to reconstruct")
    parser.add_argument("-o", "--output", help="ELF to write (default: <firmware>.elf)")
    parser.add_argument("--report", help="manifest to write (default: <firmware>.raw2elf.json)")
    parser.add_argument("--no-report", action="store_true", help="do not write a JSON manifest")

    recovery = parser.add_argument_group("recovery overrides")
    recovery.add_argument(
        "--arch", default="auto", help=f"architecture backend: auto, {', '.join(backend_names())}"
    )
    recovery.add_argument("--base", type=_integer, help="runtime load address of the image")
    recovery.add_argument("--entry", type=_integer, help="entry point address")
    recovery.add_argument(
        "--vector-offset", type=_integer, help="file offset of the entry/vector structure"
    )
    recovery.add_argument("--image", type=int, help="index of the candidate image to reconstruct")
    recovery.add_argument(
        "--input-format",
        choices=ingest.format_names(),
        help="force an input format instead of detecting one",
    )

    peripherals = parser.add_argument_group("MCU identification")
    peripherals.add_argument("--mcu", help="assume this MCU instead of ranking SVD candidates")
    peripherals.add_argument("--svd", help="CMSIS-SVD file or data directory to match against")
    peripherals.add_argument(
        "--no-svd", action="store_true", help="skip MCU identification entirely"
    )
    peripherals.add_argument(
        "--svd-symbols",
        choices=("none", "peripherals", "registers"),
        default="peripherals",
        help="how much SVD detail to turn into ELF symbols (default: peripherals)",
    )

    policy = parser.add_argument_group("confidence policy")
    policy.add_argument(
        "--minimum-confidence",
        type=float,
        default=0.5,
        help="refuse to emit an ELF below this confidence (default: 0.5)",
    )
    policy.add_argument(
        "--fail-on-ambiguity",
        action="store_true",
        help="fail when the best candidate is not clearly ahead of the next",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--split-sections",
        action="store_true",
        help="emit .text/.rodata instead of one conservative .flash, where evidence allows",
    )
    output.add_argument(
        "--keep-padding",
        action="store_true",
        help="keep large trailing erased-flash regions in the ELF",
    )
    output.add_argument(
        "--max-instructions",
        type=_integer,
        default=400_000,
        help="cap on instructions decoded during analysis (default: 400000)",
    )
    output.add_argument(
        "--padding-threshold",
        type=_integer,
        default=256,
        help="shortest run of a repeated byte reported as padding (default: 256)",
    )

    queries = parser.add_argument_group("queries")
    queries.add_argument(
        "--list-images", action="store_true", help="list candidate firmware images and exit"
    )
    queries.add_argument(
        "--list-arch", action="store_true", help="list architecture backends and exit"
    )
    queries.add_argument(
        "--detect", action="store_true", help="report input format detection and exit"
    )
    queries.add_argument(
        "--probe", action="store_true", help="report architecture probe scores and exit"
    )

    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="explain the analysis (repeatable)"
    )
    parser.add_argument("--version", action="version", version=f"raw2elf {__version__}")
    return parser


def options_from(arguments: argparse.Namespace) -> Options:
    options = Options(
        arch=arguments.arch,
        base=arguments.base,
        entry=arguments.entry,
        vector_offset=arguments.vector_offset,
        image=arguments.image,
        mcu=arguments.mcu,
        svd=arguments.svd,
        enable_svd=not arguments.no_svd,
        svd_symbols=arguments.svd_symbols,
        minimum_confidence=arguments.minimum_confidence,
        fail_on_ambiguity=arguments.fail_on_ambiguity,
        verbose=arguments.verbose,
        max_instructions=arguments.max_instructions,
        padding_threshold=arguments.padding_threshold,
        input_format=arguments.input_format,
        split_sections=arguments.split_sections,
    )
    options.extra["trim_padding"] = not arguments.keep_padding
    return options


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.list_arch:
        for name, description in describe():
            print(f"{name:<20} {description}")
        return EXIT_OK

    if not arguments.firmware:
        parser.error("a firmware file is required")

    path = Path(arguments.firmware)
    if not path.is_file():
        print(f"raw2elf: {path} is not a file", file=sys.stderr)
        return EXIT_USAGE

    try:
        image = ingest.load(path, input_format=arguments.input_format)
    except ingest.ParseError as error:
        print(f"raw2elf: cannot read {path}: {error}", file=sys.stderr)
        return EXIT_USAGE

    if arguments.detect:
        raw = path.read_bytes()
        print(f"Selected: {image.source_format} ({image.metadata.get('label')})")
        print(f"Normalized: {image.size} bytes in {len(image.segments)} segment(s)")
        for note in image.metadata.get("notes", []):
            print(f"  note: {note}")
        print("\nParser opinions:")
        for detection in ingest.detect(raw):
            print(f"  {detection.parser.name:<12} {detection.sniff.confidence:.2f}  {detection.sniff.detail}")
        return EXIT_OK

    if arguments.probe:
        probes = probe_all(image)
        print(console.architectures(probes))
        for probe in probes:
            for item in probe.evidence:
                print(f"  {probe.backend}: {item}")
        return EXIT_OK

    options = options_from(arguments)

    if arguments.list_images:
        return _list_images(image, options)

    try:
        reconstruction = reconstruct(image, options)
    except (AmbiguityError, LowConfidenceError) as error:
        return _report_uncertainty(error)

    outputs: list[str] = []
    payload = reconstruction.elf
    if payload is None:
        print("raw2elf: no ELF was produced", file=sys.stderr)
        print(console.evidence(reconstruction), file=sys.stderr)
        return EXIT_AMBIGUOUS

    elf_path = Path(arguments.output) if arguments.output else path.with_suffix(".elf")
    elf_path.write_bytes(payload)
    outputs.append(str(elf_path))

    if not arguments.no_report:
        report_path = (
            Path(arguments.report)
            if arguments.report
            else elf_path.with_suffix("").with_suffix(".raw2elf.json")
        )
        report_path.write_text(manifest.dumps(reconstruction) + "\n")
        outputs.append(str(report_path))

    print(console.summary(reconstruction, outputs))
    if arguments.verbose:
        print()
        print(console.evidence(reconstruction))
        candidates = console.base_candidates(reconstruction)
        if candidates:
            print()
            print(candidates)
    return EXIT_OK


def _list_images(image, options: Options) -> int:
    """Run only as far as image discovery, then list what was found."""
    from .reconstruct import select_backend

    try:
        backend, _confidence, _probes = select_backend(image, options)
    except LowConfidenceError as error:
        return _report_uncertainty(error)
    context = AnalysisContext(image=image, backend=backend, options=options)
    Pipeline([PaddingDetection(), ImageDiscovery()]).run(context)
    print(console.images(context.get("candidate_images") or [], backend.name))
    return EXIT_OK


def _report_uncertainty(error: Exception) -> int:
    print(f"raw2elf: {error}", file=sys.stderr)
    print(
        "\nraw2elf will not emit an ELF it cannot justify. Supply the answer explicitly\n"
        "(--arch / --base / --entry / --vector-offset / --image), or lower\n"
        "--minimum-confidence to accept the best candidate.",
        file=sys.stderr,
    )
    return EXIT_AMBIGUOUS


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
