"""A valid instruction encoding is not the same thing as executable code.

Almost any byte sequence decodes as something. A page of compressed data
decodes into well-formed loads and stores whose effective addresses look
exactly like real ones, and an analysis that treats every decoded instruction
alike reports memory regions built out of a compression dictionary.

These tests pin the distinction: where an instruction came from, how that
travels with the references it produces, and what it is allowed to establish.
"""

from __future__ import annotations

import random
import struct

import pytest

from conftest import reconstruct_bytes
from raw2elf.core.memory import RegionKind
from raw2elf.core.provenance import CodeProvenance
from raw2elf.core.reference import Access, ReferenceKind


# -- the ladder itself -----------------------------------------------------


def test_trust_flows_downhill_only():
    """Being called does not promote a guess."""
    swept = CodeProvenance.LINEAR_SWEEP
    assert swept.demoted_to(CodeProvenance.DIRECT_CALL) is swept
    # ...but code the reset path reaches, calling onwards, stays trusted.
    reached = CodeProvenance.ENTRY_POINT.demoted_to(CodeProvenance.DIRECT_CALL)
    assert reached is CodeProvenance.DIRECT_CALL
    assert reached.trusted


def test_only_reachable_code_is_trusted():
    trusted = (
        CodeProvenance.ENTRY_POINT,
        CodeProvenance.DECLARED_HANDLER,
        CodeProvenance.DIRECT_CALL,
        CodeProvenance.VALIDATED_INDIRECT_CALL,
    )
    for item in trusted:
        assert item.trusted, item
    for item in (
        CodeProvenance.SPECULATIVE_FUNCTION,
        CodeProvenance.LINEAR_SWEEP,
        CodeProvenance.DATA_DECODE,
    ):
        assert not item.trusted, item
    # And the ladder is ordered, so "best" means what it says.
    assert CodeProvenance.best(CodeProvenance.LINEAR_SWEEP, CodeProvenance.ENTRY_POINT) is (
        CodeProvenance.ENTRY_POINT
    )


def test_an_untrusted_access_is_worth_far_less_than_a_trusted_one():
    assert CodeProvenance.LINEAR_SWEEP.weight * 8 < CodeProvenance.DIRECT_CALL.weight


# -- provenance reaches the references -------------------------------------


def test_the_reset_path_is_recorded_as_the_reason_its_code_is_code(standard):
    result = reconstruct_bytes(standard.image)
    graph = result.context.backend._recovery(result.context).graph
    provenances = {function.provenance for function in graph.functions.values()}

    assert CodeProvenance.ENTRY_POINT in provenances
    assert all(item.trusted for item in provenances), provenances


def test_every_recovered_access_says_which_function_made_it(standard):
    result = reconstruct_bytes(standard.image)
    accesses = [
        item
        for item in result.context.get("references")
        if item.access in (Access.READ, Access.WRITE)
    ]
    assert accesses
    assert all(item.source_function is not None for item in accesses)
    assert all(item.trusted for item in accesses)


# -- and decide what may be established ------------------------------------


@pytest.fixture
def dump_with_data(standard):
    """A real image followed by strings and a compressed-looking blob.

    Both are what a linear sweep turns into hundreds of plausible-looking
    memory accesses; neither is code.
    """
    random.seed(11)
    words = ["Latitude", "Longitude", "PASS", "time", "sensor", "calibration",
             "battery", "temperature", "altitude", "config.json"]
    text = bytearray()
    while len(text) < 0x18000:
        text += random.choice(words).encode() + b"\x00"
        if random.random() < 0.25:
            text += b"-" * random.randint(3, 12) + b"\x00"
    entropy = bytes(random.randrange(256) for _ in range(0x18000))
    payload = bytearray(standard.image)
    payload += b"\x00" * ((4 - len(payload) % 4) % 4)
    return bytes(payload) + bytes(text) + entropy


def test_decoded_data_does_not_invent_memory_regions(dump_with_data, standard):
    """The regions must be the ones the real image alone produces."""
    clean = reconstruct_bytes(standard.image)
    noisy = reconstruct_bytes(dump_with_data)

    def banks(result):
        return {
            (region.kind, region.start, region.size)
            for region in result.context.get("memory_map").established
            if region.kind is not RegionKind.FLASH
        }

    assert banks(noisy) == banks(clean)


def test_the_data_does_produce_plenty_of_plausible_accesses(dump_with_data):
    """Guard the test above: it is only meaningful if the noise is there."""
    result = reconstruct_bytes(dump_with_data)
    references = result.context.get("references")
    untrusted = [
        item
        for item in references
        if item.access in (Access.READ, Access.WRITE) and not item.trusted
    ]
    assert len(untrusted) > 200, "expected the decoded data to generate accesses"
    # None of it comes from anything reached.
    assert all(not item.code_provenance.trusted for item in untrusted)


def test_a_region_only_untrusted_code_touches_is_never_established(dump_with_data):
    result = reconstruct_bytes(dump_with_data)
    references = result.context.get("references")
    trusted = {
        item.value
        for item in references
        if item.access in (Access.READ, Access.WRITE) and item.trusted
    }
    for region in result.context.get("memory_map").established:
        if region.kind is RegionKind.FLASH:
            continue
        startup = result.context.get("startup_state")
        anchors = {startup.initial_stack_pointer} if startup else set()
        for item in (startup.initializations if startup else ()):
            anchors |= {item.destination, item.destination + (item.resolved_size or 0)}
        assert any(region.contains(value) for value in trusted) or any(
            value is not None and region.start <= value <= region.end + 1 for value in anchors
        ), f"{region.name} at 0x{region.start:08x} rests only on unreached bytes"


def test_repeating_weak_evidence_does_not_make_it_strong():
    """A thousand accesses from unreached bytes still cannot establish."""
    from raw2elf.analysis.memory_recovery import (
        AccessEvidence,
        ESTABLISHED_CONFIDENCE,
        _region_confidence,
    )

    evidence = AccessEvidence()
    evidence.addresses = {0x20000000 + index * 4 for index in range(500)}
    evidence.untrusted_sites = {0x1000 + index for index in range(500)}
    evidence.untrusted_weight = 500 * CodeProvenance.LINEAR_SWEEP.weight
    evidence.best_provenance = CodeProvenance.LINEAR_SWEEP

    confidence, _notes = _region_confidence(
        name="RAM", evidence=evidence, anchored=False, layout=(), plausibility=1.0
    )
    assert confidence < ESTABLISHED_CONFIDENCE


def test_several_independent_functions_beat_one_busy_block():
    from raw2elf.analysis.memory_recovery import AccessEvidence, _region_confidence

    def score(functions):
        evidence = AccessEvidence()
        evidence.trusted_addresses = {0x20000000 + i * 4 for i in range(4)}
        evidence.trusted_sites = {0x1000 + i * 2 for i in range(6)}
        evidence.addresses = set(evidence.trusted_addresses)
        evidence.functions = set(functions)
        evidence.best_provenance = CodeProvenance.DIRECT_CALL
        return _region_confidence(
            name="RAM", evidence=evidence, anchored=False, layout=(), plausibility=1.0
        )[0]

    assert score({0x1000, 0x2000, 0x3000}) > score({0x1000})


def test_a_window_needing_an_external_controller_is_held_to_a_higher_bar():
    from raw2elf.analysis.memory_recovery import AccessEvidence, _region_confidence

    evidence = AccessEvidence()
    evidence.trusted_addresses = {0x60000000 + i * 4 for i in range(4)}
    evidence.trusted_sites = {0x1000 + i * 2 for i in range(4)}
    evidence.addresses = set(evidence.trusted_addresses)
    evidence.best_provenance = CodeProvenance.DIRECT_CALL

    external, _n = _region_confidence(
        name="RAM", evidence=evidence, anchored=False, layout=(), plausibility=0.15
    )
    internal, _n = _region_confidence(
        name="RAM", evidence=evidence, anchored=False, layout=(), plausibility=1.0
    )
    assert external < internal


def test_the_backend_owns_the_notion_of_a_plausible_range():
    """The neutral core must not know which windows a part has memory in."""
    from raw2elf.arch.registry import get_backend

    backend = get_backend("arm-cortex-m")
    on_chip = backend.region_plausibility(0x20001000)
    external = backend.region_plausibility(0x64757400)
    reserved = backend.region_plausibility(0xF0000000)
    assert on_chip > external > reserved
