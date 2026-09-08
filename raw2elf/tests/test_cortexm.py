"""The Cortex-M backend: vector tables, references, base recovery, startup."""

from __future__ import annotations

import struct

import pytest

from conftest import reconstruct_bytes
from raw2elf.arch.arm import references as arm_references
from raw2elf.arch.arm import vectors
from raw2elf.arch.arm.cortex_m import CortexMBackend, build_arm_attributes, core_name
from raw2elf.arch.base import ArchCapability
from raw2elf.core.image import FirmwareImage, FirmwareSegment
from raw2elf.core.memory import InitKind
from raw2elf.core.reference import Access, AddressClass, ReferenceKind
from raw2elf.eval import corpus


@pytest.fixture(scope="module")
def backend():
    return CortexMBackend()


def _image(payload: bytes) -> FirmwareImage:
    return FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, payload),))


def _table(stack: int, reset: int, handlers: list[int]) -> bytes:
    return struct.pack("<%dI" % (2 + len(handlers)), stack, reset, *handlers)


# -- address map -----------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        (0x00000000, AddressClass.CODE),
        (0x08001234, AddressClass.CODE),
        (0x1FFFFFFF, AddressClass.CODE),
        (0x20000000, AddressClass.RAM),
        (0x2001FFFF, AddressClass.RAM),
        (0x40020000, AddressClass.MMIO),
        (0x5FFFFFFF, AddressClass.MMIO),
        (0x60000000, AddressClass.RAM),
        (0xA0000000, AddressClass.MMIO),
        (0xE000E010, AddressClass.SYSTEM),
        (0xF0000000, AddressClass.RESERVED),
    ],
)
def test_the_armv7m_address_map_is_classified(backend, address, expected):
    assert backend.classify_address(address) == expected


def test_code_pointers_carry_the_thumb_bit(backend):
    assert backend.encode_code_pointer(0x08000318) == 0x08000319
    assert backend.normalize_code_pointer(0x08000319) == 0x08000318
    # The ELF entry and function symbols keep the bit; data symbols do not.
    assert backend.elf_symbol_value(0x08000318, True) == 0x08000319
    assert backend.elf_symbol_value(0x20000000, False) == 0x20000000


def test_the_backend_advertises_the_full_capability_set(backend):
    assert backend.capabilities() >= {
        ArchCapability.ENTRY_DISCOVERY,
        ArchCapability.BASE_CONSTRAINTS,
        ArchCapability.REFERENCE_RECOVERY,
        ArchCapability.MMIO_REFERENCE_RECOVERY,
        ArchCapability.STARTUP_ANALYSIS,
        ArchCapability.INTERRUPT_TABLE_RECOVERY,
        ArchCapability.CODE_VALIDATION,
    }


# -- vector table discovery ------------------------------------------------


def test_the_fixture_vector_table_is_found_at_offset_zero(backend, standard):
    found = vectors.find_tables(_image(standard.image), backend.classify_address)
    assert found
    best = found[0]
    assert best.image_offset == 0
    assert best.initial_sp == standard.initial_stack_pointer
    assert best.reset_address == standard.entry
    assert best.confidence > 0.9
    assert best.default_handler is not None


def test_a_table_at_a_nonzero_offset_is_found(backend, standard):
    payload = b"\xff" * 0x8000 + standard.image
    found = vectors.find_tables(_image(payload), backend.classify_address)
    assert [item.image_offset for item in found] == [0x8000]


def test_a_run_of_repeated_characters_is_not_a_vector_table(backend):
    # 0x2d2d2d2d ("----") passes every arithmetic test a vector table applies:
    # eight-byte aligned, odd, and consistent with itself.
    payload = b"-" * 4096
    assert vectors.find_tables(_image(payload), backend.classify_address) == []
    assert vectors.uniform_bytes(0x2D2D2D2D)
    assert not vectors.uniform_bytes(0x08000319)


def test_a_table_whose_handlers_never_vary_is_rejected(backend):
    payload = _table(0x20008000, 0x08000101, [0x08000101] * 30)
    found = vectors.find_tables(_image(payload), backend.classify_address, minimum_confidence=0.0)
    assert not found or found[0].confidence < 0.5


def test_a_word_aligned_stack_pointer_is_accepted_but_scored_lower(backend):
    handlers = [0x08000201, 0x08000301, 0, 0, 0, 0, 0x08000401, 0, 0, 0x08000501, 0x08000601]
    aligned = _table(0x20008000, 0x08000101, handlers)
    misaligned = _table(0x20008004, 0x08000101, handlers)
    strong = vectors.find_tables(_image(aligned), backend.classify_address, minimum_confidence=0.0)
    weak = vectors.find_tables(_image(misaligned), backend.classify_address, minimum_confidence=0.0)
    assert strong and weak
    assert strong[0].score > weak[0].score


def test_an_odd_stack_pointer_is_not_a_vector_table(backend):
    payload = _table(0x20008001, 0x08000101, [0x08000201] * 20)
    assert vectors.find_tables(_image(payload), backend.classify_address) == []


def test_vtor_alignment_scales_with_table_size():
    small = vectors.VectorTable(0, 0x20008000, 0x101, words=[0] * 16, handler_slots=[1])
    large = vectors.VectorTable(
        0, 0x20008000, 0x101, words=[0] * 130, handler_slots=list(range(1, 130))
    )
    assert small.required_alignment == 0x80
    assert large.required_alignment == 0x400


def test_the_probe_rejects_a_classic_arm_image(backend):
    # e59ff018 is "ldr pc, [pc, #24]" -- the A32 reset convention.
    payload = struct.pack("<8I", *([0xE59FF018] * 8)) + bytes(range(256)) * 8
    result = backend.probe(_image(payload))
    assert result.confidence < 0.2
    assert any("classic ARM" in str(item) for item in result.evidence)


def test_the_probe_is_confident_about_real_cortexm_firmware(backend, standard):
    result = backend.probe(_image(standard.image))
    assert result.confidence > 0.9
    assert result.details["thumb_density"] > result.details["a32_density"]
    assert result.target.elf_machine == 40


def test_the_probe_declines_bytes_that_are_not_code(backend):
    assert backend.probe(_image(b"\x00" * 4096)).confidence < 0.2
    assert backend.probe(_image(b"the quick brown fox " * 200)).confidence < 0.5


# -- code validation -------------------------------------------------------


def test_code_validation_separates_code_from_constant_tables(backend, standard):
    entry_offset = standard.entry - standard.base
    code = backend.validate_code(standard.image[entry_offset : entry_offset + 256], standard.entry)
    assert code.confidence > 0.6
    assert code.coverage > 0.9

    # A table of small increasing integers decodes cleanly and is not code.
    table = struct.pack("<64I", *range(64))
    assert backend.validate_code(table, 0x08000000).confidence < 0.4
    assert backend.validate_code(b"\xff" * 256, 0x08000000).confidence < 0.4


# -- references ------------------------------------------------------------


def test_the_sweep_recovers_literal_pool_values(backend, standard):
    from raw2elf.arch.arm.decoder import Decoder

    result = arm_references.sweep_image(
        _image(standard.image), Decoder(), backend.classify_address
    )
    values = {item.value for item in result.references}
    # The startup pointers live in a literal pool and must come back.
    assert standard.data_load in values
    assert standard.data_start in values
    assert standard.bss_end in values
    # Call targets are recorded as relocation-invariant code starts.
    assert result.call_locations
    assert all(0 <= item < len(standard.image) for item in result.call_locations)


def test_literals_are_not_assumed_to_be_pointers(backend, standard):
    reconstruction = reconstruct_bytes(standard.image)
    references = reconstruction.context.get("references")
    # Every recovered reference keeps how it was derived...
    assert all(item.derivation for item in references)
    # ...and a value is only CODE if it points at a decoded instruction.
    for reference in references.of_kind(ReferenceKind.CODE):
        normalized = backend.normalize_code_pointer(reference.value)
        assert standard.base <= normalized < standard.base + len(standard.image)


def test_mmio_accesses_record_address_direction_and_width(standard):
    reconstruction = reconstruct_bytes(standard.image)
    accesses = reconstruction.context.get("mmio_accesses")
    by_address = {item.value: item for item in accesses}

    # From the fixture: "REG(GPIOA_BASE + 0x20) = 0x770" is a 32-bit write to
    # 0x40020020, reached through a base register holding 0x40020000.
    write = by_address[0x40020020]
    assert write.access == Access.WRITE
    assert write.width == 32
    assert write.base_value == 0x40020000
    assert write.offset_value == 0x20
    assert "displacement" in write.derivation

    # And the USART status register is read, not written.
    assert by_address[0x40011000].access == Access.READ

    # Peripherals the fixture touches, all recovered as effective addresses.
    for address in (0x40023800, 0x40023808, 0x40007000, 0x40011008, 0x40020C18, 0x40000028):
        assert address in by_address, hex(address)


def test_system_registers_are_kept_out_of_peripheral_matching(standard):
    reconstruction = reconstruct_bytes(standard.image)
    all_accesses = {item.value for item in reconstruction.context.get("mmio_accesses")}
    peripheral = {item.value for item in reconstruction.context.get("peripheral_accesses")}
    assert 0xE000E010 in all_accesses  # SysTick is reported...
    assert 0xE000E010 not in peripheral  # ...but cannot identify a part.


# -- base recovery ---------------------------------------------------------


def test_base_recovery_finds_the_linked_address(truth):
    for name, expected in (
        ("stm32f4_standard", 0x08000000),
        ("nonstandard_base", 0x10000000),
        ("application_high", 0x08008000),
    ):
        reconstruction = reconstruct_bytes(truth[name].image)
        assert reconstruction.context.get("runtime_base") == expected, name
        assert reconstruction.context.get("base_confidence") > 0.8, name


def test_base_recovery_explains_itself(standard):
    reconstruction = reconstruct_bytes(standard.image)
    candidates = reconstruction.context.get("base_candidates")
    winner = candidates[0]
    assert winner.runtime_base == standard.base
    explanations = " ".join(str(item) for item in winner.supporting)
    assert "reset vector" in explanations
    assert "executable bytes" in explanations
    assert "aligned" in explanations
    assert "exception vectors" in explanations


def test_vtor_misalignment_is_recorded_as_a_contradiction(standard):
    reconstruction = reconstruct_bytes(standard.image)
    candidates = reconstruction.context.get("base_candidates")
    misaligned = [
        item
        for item in candidates
        if any("VTOR cannot address" in str(evidence) for evidence in item.contradicting)
    ]
    assert misaligned
    assert all(item.confidence < candidates[0].confidence for item in misaligned)


def test_an_analyst_supplied_base_overrides_inference(standard):
    reconstruction = reconstruct_bytes(standard.image, base=0x12340000)
    assert reconstruction.context.get("runtime_base") == 0x12340000
    assert reconstruction.context.get("base_confidence") == 1.0
    candidates = reconstruction.context.get("base_candidates")
    assert candidates[0].origin == "analyst override"


def test_declared_addresses_are_used_instead_of_inference(standard):
    reconstruction = reconstruct_bytes(corpus.to_ihex(standard.chunks))
    assert reconstruction.context.get("runtime_base") == standard.base
    assert "declared by" in reconstruction.context.get("base_candidates")[0].origin


# -- startup ---------------------------------------------------------------


def test_startup_recovers_the_data_and_bss_ranges_exactly(standard):
    reconstruction = reconstruct_bytes(standard.image)
    state = reconstruction.context.get("startup_state")
    assert state.initial_stack_pointer == standard.initial_stack_pointer

    copies = [item for item in state.initializations if item.kind == InitKind.COPY]
    zeros = [item for item in state.initializations if item.kind == InitKind.ZERO]
    assert len(copies) == 1 and len(zeros) == 1

    assert copies[0].source == standard.data_load
    assert copies[0].destination == standard.data_start
    assert copies[0].resolved_size == standard.data_size
    assert zeros[0].destination == standard.bss_start
    assert zeros[0].destination + zeros[0].resolved_size == standard.bss_end


def test_startup_reports_nothing_when_there_is_nothing_to_find(standard):
    # Truncating the image to the vector table alone removes the startup code.
    reconstruction = reconstruct_bytes(standard.image[:0x188], base=standard.base)
    state = reconstruction.context.get("startup_state")
    assert state.initializations == []


def test_interrupt_handlers_are_named_from_the_table(standard):
    reconstruction = reconstruct_bytes(standard.image)
    table = reconstruction.context.get("interrupt_table")
    by_index = {entry.index: entry for entry in table.entries}
    assert by_index[1].name == "Reset_Handler"
    assert by_index[1].address == standard.entry
    assert by_index[3].name == "HardFault_Handler"
    assert by_index[15].name == "SysTick_Handler"
    # Device interrupts are numbered until an MCU match can name them.
    assert by_index[16 + 28].name == "IRQ28_Handler"
    assert by_index[16 + 28].irq == 28
    # Architecturally reserved slots are not handlers at all.
    assert 7 not in by_index


# -- ELF metadata ----------------------------------------------------------


def test_arm_build_attributes_declare_the_m_profile():
    payload = build_arm_attributes("Cortex-M4")
    assert payload.startswith(b"A")
    assert b"aeabi\x00" in payload
    assert b"Cortex-M4\x00" in payload
    assert b"\x07\x4d" in payload  # Tag_CPU_arch_profile = 'M'
    assert b"\x09\x02" in payload  # Tag_THUMB_ISA_use = Thumb-2
    # With no identified core, no core is claimed.
    assert b"Cortex" not in build_arm_attributes(None)


@pytest.mark.parametrize(
    ("svd", "expected"),
    [("CM4", "Cortex-M4"), ("CM0PLUS", "Cortex-M0+"), ("CM33", "Cortex-M33"), ("", None)],
)
def test_svd_core_names_are_translated(svd, expected):
    assert core_name(svd) == expected
