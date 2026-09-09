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
    """Implausibility withholds the claim; it does not delete the evidence.

    The two are separate questions: how sure we are these accesses happened,
    and whether this target is known to have memory where they point. So the
    confidence is unchanged and the region is reported -- as speculative.
    """
    from raw2elf.analysis.memory_recovery import (
        PLAUSIBLE_ENOUGH,
        AccessEvidence,
        _region_confidence,
    )

    evidence = AccessEvidence()
    evidence.trusted_addresses = {0x60000000 + i * 4 for i in range(4)}
    evidence.trusted_sites = {0x1000 + i * 2 for i in range(4)}
    evidence.addresses = set(evidence.trusted_addresses)
    evidence.best_provenance = CodeProvenance.DIRECT_CALL

    _confidence, notes = _region_confidence(
        name="RAM", evidence=evidence, anchored=False, layout=(), plausibility=0.15
    )
    assert 0.15 < PLAUSIBLE_ENOUGH
    assert any("not known to have memory in this window" in str(item) for item in notes)
    assert any(not item.supports for item in notes)


def test_an_implausible_window_stays_speculative_on_a_real_run(standard):
    """End to end: a bank the part is not known to have is not claimed."""
    from raw2elf.core.memory import RegionKind

    result = reconstruct_bytes(standard.image)
    memory_map = result.context.get("memory_map")
    for region in memory_map.established:
        if region.kind is RegionKind.RAM:
            # Everything established must be somewhere a part plausibly has
            # writable memory.
            assert result.backend.region_plausibility(
                region.start, writable=True
            ) >= 0.5, hex(region.start)


def test_the_backend_owns_the_notion_of_a_plausible_range():
    """The neutral core must not know which windows a part has memory in."""
    from raw2elf.arch.registry import get_backend

    backend = get_backend("arm-cortex-m")
    on_chip = backend.region_plausibility(0x20001000)
    external = backend.region_plausibility(0x64757400)
    reserved = backend.region_plausibility(0xF0000000)
    assert on_chip > external > reserved


# -- reachable, correctly decoded, and still meaningless -------------------


def test_an_address_built_from_a_loop_counter_is_not_evidence():
    """The failure this catches, from a real STM32G dump.

    ``str r0, [r4, #0x20]`` with ``r4 == 2`` yields "address 0x22". The
    instruction is genuinely reached -- eleven direct calls from an interrupt
    vector -- and correctly decoded. The address is a displacement.

        reachable instruction != correct recovered address != physical memory
    """
    from raw2elf.arch.registry import get_backend

    backend = get_backend("arm-cortex-m")
    for base in (0x00000000, 0x00000001, 0x00000002, 0x000000FF):
        assert not backend.is_credible_base(base), hex(base)
    for base in (0x20000000, 0x40021000, 0x08000000, 0xE000E000):
        assert backend.is_credible_base(base), hex(base)


def test_an_incredible_base_is_kept_out_of_the_region_evidence():
    from raw2elf.analysis.memory_recovery import AccessEvidence
    from raw2elf.core.reference import Access, Reference, ReferenceKind

    evidence = AccessEvidence()
    evidence.record(
        Reference(
            value=0x00000022,
            source_offset=0x1000,
            derivation="recovered base + displacement",
            kind=ReferenceKind.RAM,
            access=Access.WRITE,
            base_value=0x2,
            code_provenance=CodeProvenance.DIRECT_CALL,
            source_function=0x900,
            base_credible=False,
        )
    )
    assert not evidence.trusted_addresses, "must not support a region"
    assert not evidence.writes
    assert evidence.incredible_sites == {0x1000}


def test_such_a_reference_is_not_evidence_but_is_still_recorded():
    from raw2elf.core.reference import Access, Reference, ReferenceKind

    reference = Reference(
        value=0x22,
        source_offset=0x1000,
        derivation="recovered base + displacement",
        kind=ReferenceKind.RAM,
        access=Access.WRITE,
        code_provenance=CodeProvenance.DIRECT_CALL,
        base_credible=False,
    )
    assert reference.trusted, "the instruction really is reached"
    assert reference.access.touches_memory, "and it really does store"
    assert not reference.establishes_memory, "but the address means nothing"
    assert reference.as_dict()["base_credible"] is False


# -- an established region can say why ------------------------------------


def test_every_established_region_can_be_audited(standard):
    """"Why do we believe an instruction that touches this executes?\""""
    from raw2elf.core.memory import RegionKind

    result = reconstruct_bytes(standard.image)
    startup = result.context.get("startup_state")
    anchors = set()
    if startup is not None:
        for item in startup.initializations:
            anchors |= {item.destination, item.destination + (item.resolved_size or 0)}
        if startup.initial_stack_pointer:
            anchors.add(startup.initial_stack_pointer)

    for region in result.context.get("memory_map").established:
        if region.kind is RegionKind.FLASH:
            continue
        anchored = any(region.start <= value <= region.end + 1 for value in anchors)
        assert region.trust_path or anchored, (
            f"{region.name} at 0x{region.start:08x} is established but cannot say why"
        )


def test_the_path_names_a_seed_a_block_and_an_instruction(standard):
    result = reconstruct_bytes(standard.image)
    references = result.context.get("references")
    witness = next(item for item in references.establishing() if item.source_function)
    path = result.backend.trust_path(result.context, witness)

    assert path
    assert any("block" in step for step in path)
    assert any("instruction" in step for step in path)
    assert path[-1].endswith(f"{witness.value:#010x}")
    # And it starts from something the hardware or a reached call reaches.
    assert any(word in path[0] for word in ("vector", "entry point", "direct call"))


def test_a_path_says_when_the_base_was_the_problem(standard):
    from raw2elf.core.reference import Access, Reference, ReferenceKind

    result = reconstruct_bytes(standard.image)
    real = next(
        item for item in result.context.get("references").establishing()
        if item.source_function
    )
    from dataclasses import replace

    doubtful = replace(real, base_credible=False, base_value=0x2, value=0x22)
    path = result.backend.trust_path(result.context, doubtful)
    assert any("cannot address memory" in step for step in path)


# -- blocks, not address ranges -------------------------------------------


def test_a_block_ends_at_every_write_to_pc():
    """Falling through a return into a literal pool is how data gets trusted."""
    import capstone

    from raw2elf.arch.arm.decoder import terminates_flow

    engine = capstone.Cs(
        capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS
    )
    engine.detail = True
    samples = {
        "bx lr": bytes.fromhex("7047"),
        "pop {r4, pc}": bytes.fromhex("10bd"),
        "b.n": bytes.fromhex("fee7"),
        "mov pc, r3": bytes.fromhex("9f46"),
    }
    for name, code in samples.items():
        decoded = list(engine.disasm(code, 0x08000000))
        assert decoded, name
        assert terminates_flow(decoded[0]), f"{name} must end the block"

    # ...while an ordinary instruction does not.
    decoded = list(engine.disasm(bytes.fromhex("0123"), 0x08000000))
    assert not terminates_flow(decoded[0])


def test_trust_is_recorded_per_block_not_per_range(standard):
    """A function's span may contain bytes no block ever covered."""
    result = reconstruct_bytes(standard.image)
    graph = result.context.backend._recovery(result.context).graph
    for function in graph.functions.values():
        assert function.blocks
        # Every block start is an instruction the walk actually decoded.
        for start in function.blocks:
            assert start in function.instructions
        # And every instruction belongs to a block at or before it.
        for address in function.order:
            assert function.block_of(address) is not None
