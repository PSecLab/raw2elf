"""``python -m raw2elf.eval`` -- grade reconstructions against reference ELFs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

if __package__ in (None, ""):  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    __package__ = "raw2elf.eval"

from ..core.options import Options
from . import corpus, metrics

#: Default fixture directory, relative to the package.
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raw2elf.eval",
        description=(
            "Render each reference ELF into every supported input format, "
            "reconstruct it, and grade the result against the original."
        ),
    )
    parser.add_argument(
        "elf",
        nargs="*",
        help="reference ELF files (default: the bundled fixture firmwares)",
    )
    parser.add_argument(
        "--formats",
        default=",".join(corpus.FORMATS),
        help="comma-separated input formats to test",
    )
    parser.add_argument("--json", help="write the full report to this path")
    parser.add_argument("--svd", action="store_true", help="include MCU identification")
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="only print the summary table"
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = build_parser().parse_args(argv)
    paths = [Path(item) for item in arguments.elf] or sorted(FIXTURES.glob("*.elf"))
    if not paths:
        print("raw2elf.eval: no reference ELFs to grade", file=sys.stderr)
        return 2

    forms = [item.strip() for item in arguments.formats.split(",") if item.strip()]
    unknown = [item for item in forms if item not in corpus.FORMATS]
    if unknown:
        print(f"raw2elf.eval: unknown format(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    options = Options(minimum_confidence=0.0, enable_svd=arguments.svd)
    summary = metrics.Summary()

    for path in paths:
        try:
            truth = corpus.ground_truth(path)
        except Exception as error:  # noqa: BLE001
            print(f"{path}: cannot read reference ELF: {error}", file=sys.stderr)
            continue
        for form in forms:
            grade = metrics.grade(truth, form, options)
            summary.add(grade)
            if not arguments.quiet:
                status = "ok" if grade.ok else "FAIL"
                print(
                    f"{truth.name:22} {form:18} {status:4} "
                    f"{grade.passed} passed, {grade.failed} failed, "
                    f"{grade.skipped} n/a  ({grade.seconds * 1000:.0f}ms)"
                )
                if grade.error:
                    print(f"    error: {grade.error}")

    print()
    print(f"{'check':32} {'pass':>5} {'fail':>5} {'n/a':>5}")
    for name, (passed, failed, skipped) in sorted(summary.by_check().items()):
        print(f"{name:32} {passed:5} {failed:5} {skipped:5}")

    failures = summary.failures()
    if failures:
        print(f"\n{len(failures)} failing check(s):")
        for grade, check in failures[:40]:
            print(
                f"  {grade.firmware}/{grade.form}: {check.name} "
                f"expected {check.as_dict()['expected']} got {check.as_dict()['actual']}"
                + (f" -- {check.detail}" if check.detail else "")
            )

    print(
        f"\n{summary.as_dict()['clean_runs']}/{len(summary.grades)} runs clean; "
        f"slowest {summary.as_dict()['slowest_seconds']}s, "
        f"peak {summary.as_dict()['peak_bytes'] / (1 << 20):.1f} MiB"
    )

    if arguments.json:
        Path(arguments.json).write_text(json.dumps(summary.as_dict(), indent=2) + "\n")
        print(f"report written to {arguments.json}")

    return 0 if not failures else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
