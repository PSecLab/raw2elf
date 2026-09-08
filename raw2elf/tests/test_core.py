"""The architecture-neutral core: lattice, evidence, hypotheses, pipeline."""

from __future__ import annotations

import pytest

from raw2elf.core import valueflow
from raw2elf.core.evidence import Evidence, EvidenceLog, confidence_label
from raw2elf.core.hypothesis import (
    AmbiguityError,
    BaseCandidate,
    EntryCandidate,
    LowConfidenceError,
    choose,
)
from raw2elf.core.image import FirmwareImage, FirmwareSegment
from raw2elf.core.options import Options
from raw2elf.core.pipeline import AnalysisContext, AnalysisPass, Pipeline
from raw2elf.core.reference import Reference, ReferenceKind, ReferenceSet
from raw2elf.core.util import align_down, align_up, logistic


# -- lattice ---------------------------------------------------------------


def test_constants_propagate_through_arithmetic():
    lattice = valueflow.Lattice(32)
    base = lattice.constant(0x40020000)
    assert lattice.add(base, lattice.constant(0x14)).constant() == 0x40020014
    assert lattice.sub(base, lattice.constant(0x20)).constant() == 0x4001FFE0
    assert lattice.bit_or(lattice.constant(0xF0), lattice.constant(0x0F)).constant() == 0xFF
    assert lattice.shift_left(lattice.constant(1), lattice.constant(12)).constant() == 0x1000


def test_arithmetic_wraps_at_the_pointer_width():
    lattice = valueflow.Lattice(32)
    result = lattice.add(lattice.constant(0xFFFFFFFF), lattice.constant(2))
    assert result.constant() == 1


def test_unknown_is_absorbing():
    lattice = valueflow.Lattice(32)
    assert lattice.add(lattice.constant(4), valueflow.UNKNOWN) is valueflow.UNKNOWN
    assert lattice.join(lattice.constant(4), valueflow.UNKNOWN) is valueflow.UNKNOWN


def test_joining_constants_yields_a_bounded_set_then_gives_up():
    lattice = valueflow.Lattice(32)
    value = lattice.constant(0)
    for step in range(1, valueflow.MAX_SET_SIZE):
        value = lattice.join(value, lattice.constant(step * 4))
    assert isinstance(value, valueflow.ConstSet)
    assert len(value.constants()) == valueflow.MAX_SET_SIZE
    assert value.constants()[:3] == (0, 4, 8)
    # One member past the cap and the set degrades rather than growing.
    assert lattice.join(value, lattice.constant(0x1000)) is valueflow.UNKNOWN


def test_high_half_insertion_builds_a_full_word():
    lattice = valueflow.Lattice(32)
    low = lattice.constant(0x3800)
    assert lattice.insert_high_half(low, 0x4002).constant() == 0x40023800


def test_symbolic_bases_track_displacements():
    lattice = valueflow.Lattice(32)
    pointer = valueflow.Sym("stack")
    moved = lattice.add(pointer, lattice.constant(8))
    assert moved == valueflow.Sym("stack", 8)
    assert lattice.sub(moved, lattice.constant(4)) == valueflow.Sym("stack", 4)
    # Different displacements of one base join to the base with none.
    assert lattice.join(valueflow.Sym("s", 4), valueflow.Sym("s", 8)) == valueflow.Sym("s")
    assert lattice.join(valueflow.Sym("a"), valueflow.Sym("b")) is valueflow.UNKNOWN


def test_state_join_keeps_only_registers_both_sides_agree_on():
    lattice = valueflow.Lattice(32)
    left = valueflow.State({"r0": valueflow.Const(1), "r1": valueflow.Const(9)})
    right = valueflow.State({"r0": valueflow.Const(1), "r2": valueflow.Const(3)})
    merged = left.join(right, lattice)
    assert merged.get("r0").constant() == 1
    assert merged.get("r1") is valueflow.UNKNOWN
    assert merged.get("r2") is valueflow.UNKNOWN


def test_the_solver_reaches_a_fixpoint_over_a_loop():
    lattice = valueflow.Lattice(32)
    #  0: r0 = 0x100      1: r0 += 4      2: branch back to 1
    def transfer(location, state):
        out = state.copy()
        if location == 0:
            out.set("r0", lattice.constant(0x100))
            return out, [1]
        if location == 1:
            out.set("r0", lattice.add(state.get("r0"), lattice.constant(4)))
            return out, [2]
        return out, [1]

    result = valueflow.solve([(0, valueflow.State())], transfer, lattice)
    assert not result.exhausted
    # The first arrival still knows where the pointer started.
    assert result.first_state_at(1).get("r0").constant() == 0x100
    # The merged state has widened, which is what stops the loop unrolling.
    assert result.state_at(1).get("r0").constants() != (0x100,)


def test_the_solver_respects_its_visit_budget():
    lattice = valueflow.Lattice(32)

    def transfer(location, state):
        out = state.copy()
        out.set("r0", lattice.constant(location))
        return out, [location + 1]

    result = valueflow.solve([(0, valueflow.State())], transfer, lattice, max_visits=50)
    assert result.exhausted
    assert result.visits == 50


# -- evidence --------------------------------------------------------------


def test_evidence_scores_are_signed_by_polarity():
    log = EvidenceLog(
        [
            Evidence("a", "test", "supports", weight=2.0),
            Evidence("b", "test", "contradicts", weight=0.5, supports=False),
        ]
    )
    assert log.score() == pytest.approx(1.5)
    assert [item.kind for item in log.supporting] == ["a"]
    assert [item.kind for item in log.contradicting] == ["b"]


def test_evidence_renders_wide_integers_as_hex():
    item = Evidence("base", "test", "recovered a base", value=0x08000000)
    assert item.as_dict()["value"] == "0x08000000"
    assert str(item) == "+ recovered a base"
    assert str(Evidence("x", "t", "no", supports=False)) == "- no"


@pytest.mark.parametrize(
    ("value", "label"),
    [(0.99, "HIGH"), (0.85, "HIGH"), (0.7, "MEDIUM"), (0.4, "LOW"), (0.1, "NONE")],
)
def test_confidence_labels(value, label):
    assert confidence_label(value) == label


# -- hypotheses ------------------------------------------------------------


def test_choose_returns_the_best_candidate_above_the_threshold():
    assert choose("base", [(0x08000000, 0.9), (0, 0.3)], 0.5, False) == 0x08000000


def test_choose_refuses_when_confidence_is_too_low():
    with pytest.raises(LowConfidenceError) as error:
        choose("base", [(0x08000000, 0.4)], 0.8, False)
    assert "0x08000000" in str(error.value)
    assert error.value.confidence == 0.4


def test_choose_refuses_a_close_call_when_asked_to():
    ranked = [(0x08000000, 0.62), (0x00000000, 0.60)]
    assert choose("base", ranked, 0.5, fail_on_ambiguity=False) == 0x08000000
    with pytest.raises(AmbiguityError) as error:
        choose("base", ranked, 0.5, fail_on_ambiguity=True)
    assert len(error.value.candidates) == 2
    assert "0x08000000" in str(error.value)


def test_choose_with_no_candidates_is_a_low_confidence_failure():
    with pytest.raises(LowConfidenceError):
        choose("base", [], 0.5, False)


def test_entry_candidates_resolve_base_relative_values():
    absolute = EntryCandidate(kind="header", image_offset=0, entry_value=0x1234)
    relative = EntryCandidate(
        kind="header", image_offset=0, entry_value=0x1234, entry_base_relative=True
    )
    assert absolute.entry_address(0x08000000) == 0x1234
    assert relative.entry_address(0x08000000) == 0x08001234


def test_base_candidates_serialize_their_evidence():
    candidate = BaseCandidate(
        runtime_base=0x08000000,
        score=12.0,
        confidence=0.97,
        supporting=[Evidence("x", "t", "reset handler resolves")],
        origin="backend seed",
    )
    rendered = candidate.as_dict()
    assert rendered["base"] == "0x08000000"
    assert rendered["evidence"] == ["+ reset handler resolves"]


# -- images ----------------------------------------------------------------


def test_reads_do_not_cross_a_segment_boundary():
    image = FirmwareImage(
        source_format="ihex",
        segments=(
            FirmwareSegment(0, b"\xaa" * 16, address=0x08000000),
            FirmwareSegment(16, b"\xbb" * 16, address=0x08001000),
        ),
    )
    assert image.read(8, 16) == b"\xaa" * 8
    assert image.read(16, 4) == b"\xbb" * 4
    assert image.declared_address_for(20) == 0x08001004
    assert image.declared_span == (0x08000000, 0x08001010)


def test_a_subimage_restarts_offsets_and_keeps_file_provenance():
    image = FirmwareImage(
        source_format="raw",
        segments=(FirmwareSegment(0, bytes(range(256)), file_offset=0),),
    )
    carved = image.subimage(0x40, 0x20)
    assert carved.size == 0x20
    assert carved.stream == bytes(range(0x40, 0x60))
    assert carved.segments[0].image_offset == 0
    assert carved.segments[0].file_offset == 0x40
    assert carved.metadata["carved_from_offset"] == 0x40


def test_derived_results_are_not_inherited_by_a_subimage():
    image = FirmwareImage(
        source_format="raw", segments=(FirmwareSegment(0, bytes(64)),)
    )
    assert image.derived("tables", lambda: ["parent"]) == ["parent"]
    carved = image.subimage(0, 32)
    assert carved.derived("tables", lambda: ["child"]) == ["child"]


# -- references ------------------------------------------------------------


def test_base_relative_references_are_excluded_from_base_discrimination():
    references = ReferenceSet(
        [
            Reference(value=0x08001234, source_offset=0, derivation="literal"),
            Reference(value=0x1234, source_offset=4, derivation="adr", base_relative=True),
            Reference(
                value=0x40020000, source_offset=8, derivation="literal", useful_for_base=False
            ),
        ]
    )
    assert len(references.base_discriminating()) == 1
    assert references.base_discriminating()[0].value == 0x08001234


def test_base_relative_references_resolve_once_a_base_is_known():
    reference = Reference(value=0x1234, source_offset=0, derivation="adr", base_relative=True)
    assert reference.runtime_value(0x08000000) == 0x08001234


def test_reference_sets_count_by_kind():
    references = ReferenceSet(
        [
            Reference(value=1, source_offset=0, derivation="x", kind=ReferenceKind.CODE),
            Reference(value=2, source_offset=0, derivation="x", kind=ReferenceKind.CODE),
            Reference(value=3, source_offset=0, derivation="x", kind=ReferenceKind.MMIO),
        ]
    )
    assert references.counts_by_kind() == {"CODE": 2, "MMIO": 1}
    assert len(references.of_kind(ReferenceKind.CODE, ReferenceKind.MMIO)) == 3


# -- util ------------------------------------------------------------------


def test_alignment_helpers():
    assert align_down(0x08001234, 0x1000) == 0x08001000
    assert align_up(0x08001234, 0x1000) == 0x08002000
    assert align_up(0x08001000, 0x1000) == 0x08001000


def test_logistic_is_monotone_and_bounded():
    assert logistic(-1000, 5.0) == 0.0
    assert logistic(1000, 5.0) == 1.0
    assert logistic(5.0, 5.0) == pytest.approx(0.5)
    assert logistic(6.0, 5.0) > logistic(5.0, 5.0)


# -- pipeline --------------------------------------------------------------


class _Producer(AnalysisPass):
    name = "Producer"
    provides = frozenset({"thing"})

    def run(self, context):
        context.provide("thing", 42)


class _Consumer(AnalysisPass):
    name = "Consumer"
    requires = frozenset({"thing"})
    provides = frozenset({"result"})

    def run(self, context):
        context.provide("result", context.require("thing") * 2)


class _Unsatisfiable(AnalysisPass):
    name = "Unsatisfiable"
    requires = frozenset({"missing"})

    def run(self, context):  # pragma: no cover - never runs
        raise AssertionError("should have been skipped")


class _Exploding(AnalysisPass):
    name = "Exploding"

    def run(self, context):
        raise RuntimeError("boom")


def _context(backend):
    image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, bytes(64)),))
    return AnalysisContext(image=image, backend=backend, options=Options())


def test_the_pipeline_orders_passes_by_their_dependencies(minimal_backend):
    pipeline = Pipeline([_Consumer(), _Producer()])
    assert [item.name for item in pipeline.ordered()] == ["Producer", "Consumer"]
    context = _context(minimal_backend)
    pipeline.run(context)
    assert context.get("result") == 84


def test_a_pass_with_unmet_requirements_is_skipped_not_failed(minimal_backend):
    result = Pipeline([_Unsatisfiable()]).run(_context(minimal_backend))
    assert [(item.name, item.status) for item in result.outcomes] == [
        ("Unsatisfiable", "skipped")
    ]


def test_a_failing_optional_pass_is_recorded_and_the_run_continues(minimal_backend):
    context = _context(minimal_backend)
    result = Pipeline([_Exploding(), _Producer()]).run(context)
    statuses = {item.name: item.status for item in result.outcomes}
    assert statuses == {"Exploding": "failed", "Producer": "ok"}
    assert context.get("thing") == 42
    assert any("boom" in warning for warning in context.warnings)


def test_soft_ordering_runs_a_pass_after_another_without_requiring_it():
    class _Later(AnalysisPass):
        name = "Later"
        after = frozenset({"Producer"})

        def run(self, context):
            pass

    pipeline = Pipeline([_Later(), _Producer()])
    assert [item.name for item in pipeline.ordered()] == ["Producer", "Later"]
