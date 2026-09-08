"""Grade a reconstruction against the ELF the firmware came from.

Every metric is reported per input format, because a tool that recovers a
firmware perfectly from a flat binary and mangles it from a squeezed hexdump
is not finished.  Metrics that have no ground truth in a given ELF are
reported as "not applicable" rather than as passes.
"""

from __future__ import annotations

import time
import tracemalloc
from dataclasses import dataclass, field
from typing import Any, Optional

from .. import input as ingest
from ..core.options import Options
from ..core.reference import Access, ReferenceKind
from ..reconstruct import Reconstruction, reconstruct
from . import corpus, elfread
from .corpus import GroundTruth

#: ELF machine number for ARM, used to grade architecture detection.
EM_ARM = 40


@dataclass
class Check:
    """One graded question."""

    name: str
    #: ``True`` pass, ``False`` fail, ``None`` no ground truth to grade.
    passed: Optional[bool]
    expected: Any = None
    actual: Any = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "result": "n/a" if self.passed is None else ("pass" if self.passed else "fail"),
            "expected": _render(self.expected),
            "actual": _render(self.actual),
            "detail": self.detail,
        }


def _render(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 0xFFFF:
        return f"0x{value:08x}"
    return value


@dataclass
class Grade:
    """The result of grading one firmware in one input format."""

    firmware: str
    form: str
    checks: list[Check] = field(default_factory=list)
    seconds: float = 0.0
    peak_bytes: int = 0
    error: str = ""

    def add(self, name: str, passed: Optional[bool], expected: Any = None, actual: Any = None,
            detail: str = "") -> None:
        self.checks.append(Check(name, passed, expected, actual, detail))

    @property
    def passed(self) -> int:
        return sum(1 for item in self.checks if item.passed is True)

    @property
    def failed(self) -> int:
        return sum(1 for item in self.checks if item.passed is False)

    @property
    def skipped(self) -> int:
        return sum(1 for item in self.checks if item.passed is None)

    @property
    def ok(self) -> bool:
        return not self.error and self.failed == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "firmware": self.firmware,
            "form": self.form,
            "error": self.error,
            "seconds": round(self.seconds, 3),
            "peak_bytes": self.peak_bytes,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "checks": [item.as_dict() for item in self.checks],
        }


def grade(truth: GroundTruth, form: str, options: Optional[Options] = None) -> Grade:
    """Reconstruct ``truth`` from the given input form and grade the result."""
    result = Grade(firmware=truth.name, form=form)
    payload = corpus.render(truth, form)
    options = options or Options(minimum_confidence=0.0, enable_svd=False)

    tracemalloc.start()
    started = time.monotonic()
    try:
        image = ingest.parse(payload)
        reconstruction = reconstruct(image, options)
    except Exception as error:  # noqa: BLE001 - a failure is a result, not a crash
        result.error = f"{type(error).__name__}: {error}"
        result.seconds = time.monotonic() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        result.peak_bytes = peak
        return result
    result.seconds = time.monotonic() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result.peak_bytes = peak

    _grade_input(result, truth, form, image)
    _grade_architecture(result, truth, reconstruction)
    _grade_addresses(result, truth, reconstruction)
    _grade_startup(result, truth, reconstruction)
    _grade_references(result, truth, reconstruction)
    _grade_elf(result, truth, reconstruction)
    return result


# -- individual metric groups ---------------------------------------------


def _grade_input(result: Grade, truth: GroundTruth, form: str, image) -> None:
    """Did normalization recover the exact bytes and declared addresses?"""
    recovered = image.stream
    result.add(
        "input.bytes",
        recovered == truth.image,
        len(truth.image),
        len(recovered),
        detail="" if recovered == truth.image else _first_difference(truth.image, recovered),
    )
    declares = form in ("ihex", "srec")
    if declares:
        span = image.declared_span
        result.add(
            "input.declared_base",
            span is not None and span[0] == truth.base,
            truth.base,
            span[0] if span else None,
        )
    else:
        result.add("input.declared_base", None, detail=f"{form} carries no addresses")
    result.add("input.format", image.source_format == corpus.FORMATS[form],
               corpus.FORMATS[form], image.source_format)


def _first_difference(expected: bytes, actual: bytes) -> str:
    for index, (left, right) in enumerate(zip(expected, actual)):
        if left != right:
            return f"first difference at offset 0x{index:x}: {left:#04x} != {right:#04x}"
    return f"length differs: {len(expected)} vs {len(actual)}"


def _grade_architecture(result: Grade, truth: GroundTruth, reconstruction: Reconstruction) -> None:
    target = reconstruction.backend.elf_target_info()
    result.add(
        "architecture.machine",
        target.elf_machine == truth.machine,
        truth.machine,
        target.elf_machine,
    )
    result.add(
        "architecture.confidence",
        reconstruction.architecture_confidence >= 0.5,
        ">= 0.50",
        round(reconstruction.architecture_confidence, 3),
    )


def _grade_addresses(result: Grade, truth: GroundTruth, reconstruction: Reconstruction) -> None:
    context = reconstruction.context
    base = context.get("runtime_base")
    result.add("base.top1", base == truth.base, truth.base, base)

    candidates = context.get("base_candidates") or []
    top3 = [item.runtime_base for item in candidates[:3]]
    result.add("base.top3", truth.base in top3, truth.base, [f"0x{item:08x}" for item in top3])

    entry = context.get("entry")
    result.add("entry", entry == truth.entry, truth.entry, entry)

    candidate = context.get("selected_entry_candidate")
    offset = candidate.image_offset if candidate is not None else None
    if truth.vector_offset is None:
        result.add("vector_offset", None, detail="no vector section in the reference ELF")
    else:
        result.add("vector_offset", offset == truth.vector_offset, truth.vector_offset, offset)

    if truth.initial_stack_pointer is None:
        result.add("initial_sp", None, detail="no stack symbol in the reference ELF")
    else:
        actual = candidate.details.get("initial_sp") if candidate is not None else None
        result.add(
            "initial_sp",
            actual == truth.initial_stack_pointer,
            truth.initial_stack_pointer,
            actual,
        )


def _grade_startup(result: Grade, truth: GroundTruth, reconstruction: Reconstruction) -> None:
    state = reconstruction.context.get("startup_state")
    copies = []
    zeros = []
    if state is not None:
        from ..core.memory import InitKind

        copies = [item for item in state.initializations if item.kind == InitKind.COPY]
        zeros = [item for item in state.initializations if item.kind == InitKind.ZERO]

    for name, expected, actual in (
        ("startup.data_load", truth.data_load, copies[0].source if copies else None),
        ("startup.data_start", truth.data_start, copies[0].destination if copies else None),
        ("startup.data_size", truth.data_size, copies[0].resolved_size if copies else None),
        ("startup.bss_start", truth.bss_start, zeros[0].destination if zeros else None),
        (
            "startup.bss_end",
            truth.bss_end,
            (zeros[0].destination + (zeros[0].resolved_size or 0)) if zeros else None,
        ),
    ):
        if expected is None:
            result.add(name, None, detail="not in the reference ELF")
        elif name == "startup.data_size" and expected == 0:
            result.add(name, None, detail="reference ELF has no initialized data")
        else:
            result.add(name, expected == actual, expected, actual)


def _grade_references(result: Grade, truth: GroundTruth, reconstruction: Reconstruction) -> None:
    """Precision and recall for the three reference classes."""
    references = reconstruction.context.get("references")
    if references is None:
        result.add("references.code_precision", None, detail="no references recovered")
        return

    backend = reconstruction.backend
    code = {
        backend.normalize_code_pointer(item.value)
        for item in references.of_kind(ReferenceKind.CODE)
    }
    if truth.function_addresses:
        correct = code & truth.function_addresses
        precision = len(correct) / len(code) if code else 0.0
        result.add(
            "references.code_precision",
            precision >= 0.8,
            ">= 0.80",
            round(precision, 3),
            detail=f"{len(correct)} of {len(code)} recovered code pointers are known functions",
        )
        # Reported, never graded: most functions are only ever reached by a
        # direct branch, so no amount of absolute-reference recovery can name
        # them.  A threshold here would be a threshold on how the firmware was
        # compiled.
        result.add(
            "references.function_coverage",
            None,
            actual=round(len(correct) / len(truth.function_addresses), 3),
            detail=(
                f"{len(correct)} of {len(truth.function_addresses)} functions have a recovered "
                "absolute pointer"
            ),
        )
    else:
        result.add("references.code_precision", None, detail="reference ELF has no function symbols")
        result.add("references.function_coverage", None, detail="reference ELF has no function symbols")

    if truth.vector_handlers:
        found = code & truth.vector_handlers
        recall = len(found) / len(truth.vector_handlers)
        result.add(
            "references.vector_recall",
            recall >= 0.95,
            ">= 0.95",
            round(recall, 3),
            detail=(
                f"{len(found)} of {len(truth.vector_handlers)} handler addresses from the "
                "reference vector table were recovered as code pointers"
            ),
        )
    else:
        result.add("references.vector_recall", None, detail="no vector table in the reference ELF")

    ram = [item for item in references.of_kind(ReferenceKind.RAM)]
    if truth.ram_ranges and ram:
        inside = sum(1 for item in ram if truth.is_ram(item.value))
        precision = inside / len(ram)
        result.add(
            "references.ram_precision",
            precision >= 0.7,
            ">= 0.70",
            round(precision, 3),
            detail=f"{inside} of {len(ram)} RAM references fall in a writable section",
        )
    else:
        result.add("references.ram_precision", None, detail="no writable sections or no RAM refs")

    accesses = reconstruction.context.get("mmio_accesses") or []
    directed = sum(1 for item in accesses if item.access in (Access.READ, Access.WRITE))
    result.add(
        "references.mmio_directed",
        None if not accesses else directed == len(accesses),
        len(accesses),
        directed,
        detail="every recovered MMIO access carries a direction and width",
    )


def _grade_elf(result: Grade, truth: GroundTruth, reconstruction: Reconstruction) -> None:
    """Is the emitted ELF parseable, correctly addressed and byte-faithful?"""
    payload = reconstruction.elf
    if not payload:
        result.add("elf.produced", False, "an ELF", None)
        return
    result.add("elf.produced", True, "an ELF", f"{len(payload)} bytes")

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as handle:
        handle.write(payload)
        handle.flush()
        try:
            emitted = elfread.read(handle.name)
        except Exception as error:  # noqa: BLE001
            result.add("elf.parses", False, "parseable", str(error))
            return
    result.add("elf.parses", True, "parseable", "yes")
    result.add("elf.machine", emitted.machine == truth.machine, truth.machine, emitted.machine)
    result.add(
        "elf.entry",
        (emitted.entry & ~1) == truth.entry,
        truth.entry,
        emitted.entry & ~1,
    )

    # Every byte of the original Flash image must appear at its address.
    faithful = True
    detail = ""
    for segment in emitted.loads:
        if not segment.file_size or segment.writable:
            continue
        start = segment.physical_address - truth.base
        if start < 0 or start + segment.file_size > len(truth.image):
            faithful = False
            detail = f"segment at 0x{segment.physical_address:08x} lies outside the reference image"
            break
        expected = truth.image[start : start + segment.file_size]
        if expected != segment.data:
            faithful = False
            detail = _first_difference(expected, segment.data)
            break
    result.add("elf.bytes_faithful", faithful, "identical", "identical" if faithful else "differs",
               detail=detail)


# -- aggregation ----------------------------------------------------------


@dataclass
class Summary:
    grades: list[Grade] = field(default_factory=list)

    def add(self, item: Grade) -> None:
        self.grades.append(item)

    def by_check(self) -> dict[str, tuple[int, int, int]]:
        """``check name -> (passed, failed, skipped)``."""
        totals: dict[str, list[int]] = {}
        for item in self.grades:
            for check in item.checks:
                slot = totals.setdefault(check.name, [0, 0, 0])
                slot[0 if check.passed is True else (1 if check.passed is False else 2)] += 1
        return {name: tuple(counts) for name, counts in totals.items()}

    def failures(self) -> list[tuple[Grade, Check]]:
        return [
            (item, check)
            for item in self.grades
            for check in item.checks
            if check.passed is False
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "runs": len(self.grades),
            "clean_runs": sum(1 for item in self.grades if item.ok),
            "by_check": {
                name: {"passed": counts[0], "failed": counts[1], "skipped": counts[2]}
                for name, counts in sorted(self.by_check().items())
            },
            "slowest_seconds": round(max((item.seconds for item in self.grades), default=0.0), 3),
            "peak_bytes": max((item.peak_bytes for item in self.grades), default=0),
            "grades": [item.as_dict() for item in self.grades],
        }
