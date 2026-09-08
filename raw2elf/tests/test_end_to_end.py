"""The correctness metrics, run over every firmware in every input format.

This is the graded matrix from the evaluation plan: each reference firmware is
rendered into every format an analyst might hand over, reconstructed, and
checked against what the original ELF says.  A regression in ingestion, base
recovery, startup analysis or ELF emission shows up here as a named failing
metric rather than as a mysteriously different byte.
"""

from __future__ import annotations

import pytest

from conftest import FIRMWARES
from raw2elf.core.options import Options
from raw2elf.eval import corpus, metrics

FORMS = sorted(corpus.FORMATS)


@pytest.fixture(scope="module")
def graded(request):
    """Grade every firmware in every format once, then assert against it."""
    truths = {name: corpus.ground_truth(path, name) for name, path in FIRMWARES.items()}
    options = Options(minimum_confidence=0.0, enable_svd=False)
    return {
        (name, form): metrics.grade(truth, form, options)
        for name, truth in truths.items()
        for form in FORMS
    }


@pytest.mark.parametrize("firmware", sorted(FIRMWARES))
@pytest.mark.parametrize("form", FORMS)
def test_reconstruction_is_clean(graded, firmware, form):
    grade = graded[(firmware, form)]
    assert not grade.error, grade.error
    failures = [
        f"{item.name}: expected {item.as_dict()['expected']} got {item.as_dict()['actual']}"
        f"{' -- ' + item.detail if item.detail else ''}"
        for item in grade.checks
        if item.passed is False
    ]
    assert not failures, "\n".join(failures)


def test_every_metric_is_exercised_by_the_corpus(graded):
    """A metric that is never graded is not protecting anything."""
    graded_names = {
        item.name
        for grade in graded.values()
        for item in grade.checks
        if item.passed is not None
    }
    expected = {
        "input.bytes",
        "input.format",
        "input.declared_base",
        "architecture.machine",
        "architecture.confidence",
        "base.top1",
        "base.top3",
        "entry",
        "vector_offset",
        "initial_sp",
        "startup.data_load",
        "startup.data_start",
        "startup.data_size",
        "startup.bss_start",
        "startup.bss_end",
        "references.code_precision",
        "references.vector_recall",
        "references.ram_precision",
        "references.mmio_directed",
        "elf.produced",
        "elf.parses",
        "elf.machine",
        "elf.entry",
        "elf.bytes_faithful",
    }
    assert expected <= graded_names, expected - graded_names


def test_the_recovered_answer_is_identical_across_input_formats(graded):
    """Whichever way the firmware arrived, the reconstruction must agree."""
    for firmware in FIRMWARES:
        answers = set()
        for form in FORMS:
            grade = graded[(firmware, form)]
            by_name = {item.name: item.actual for item in grade.checks}
            answers.add(
                (by_name["base.top1"], by_name["entry"], by_name["vector_offset"])
            )
        assert len(answers) == 1, f"{firmware} reconstructs differently per format: {answers}"


def test_analysis_stays_fast_enough_for_interactive_use(graded):
    slowest = max(graded.values(), key=lambda item: item.seconds)
    assert slowest.seconds < 5.0, f"{slowest.firmware}/{slowest.form} took {slowest.seconds:.1f}s"
    heaviest = max(item.peak_bytes for item in graded.values())
    assert heaviest < 256 << 20, f"peak memory {heaviest / (1 << 20):.0f} MiB"
