"""Guards against inference outrunning its evidence.

A few correct observations must not be allowed to turn arbitrary constants
into a memory map. Each test here corresponds to a way that went wrong on a
real dump.
"""

from __future__ import annotations

import struct

import pytest

from conftest import reconstruct_bytes
from raw2elf import input as ingest
from raw2elf.core.memory import RegionKind
from raw2elf.core.options import Options
from raw2elf.core.reference import Access, ReferenceKind
from raw2elf.eval import corpus
from raw2elf.reconstruct import reconstruct


def _table(base: int, msp: int, entry_offset: int, irqs: int = 82) -> bytes:
    """A conventional vector table for an image linked at ``base``."""
    default = base + 0x1B1
    words = [msp, base + entry_offset + 1] + [base + 0x201 + 2 * index for index in range(5)]
    words += [0, 0, 0, 0, default, default, 0, default, base + 0x301]
    words += [default] * irqs
    return struct.pack(f"<{len(words)}I", *words)


def _image(base: int, msp: int, entry_offset: int) -> bytes:
    table = _table(base, msp, entry_offset)
    code = bytearray(b"\x00" * 0x400)
    thumb = bytes.fromhex("08b5024a1168012911d1")
    for offset in (entry_offset - len(table), 0x1B0 - len(table)):
        if 0 <= offset < len(code) - len(thumb):
            code[offset : offset + len(thumb)] = thumb
    return table + bytes(code)


@pytest.fixture
def two_images():
    """A dump holding a bootloader at 0 and an application at 0x20000."""
    dump = bytearray(b"\xff" * 0x200000)
    first = _image(0x08000000, 0x20000600, 0x2E0)
    second = _image(0x08020000, 0x30000600, 0xDE8)
    dump[0 : len(first)] = first
    dump[0x20000 : 0x20000 + len(second)] = second
    return bytes(dump)


# -- 1. every recovered fact must describe the same image ------------------


def test_base_entry_and_entry_structure_all_describe_one_image(two_images):
    result = reconstruct(
        ingest.parse(two_images), Options(enable_svd=False, minimum_confidence=0.0)
    )
    context = result.context
    selected = context.get("selected_entry_candidate")
    base = context.get("runtime_base")

    # The dump is linked at 0x08000000; both images agree on that.
    assert base == 0x08000000
    # And the entry, table and stack pointer come from the anchor image.
    assert context.get("entry") == selected.entry_value
    assert base + selected.image_offset == 0x08000000
    assert selected.details["initial_sp"] == 0x20000600


def test_a_second_image_cannot_supply_the_base_for_the_first(two_images):
    """The failure this guards against gave a base of 0x07fe0000.

    That is the base which puts the *second* image's table where the first
    image's belongs. Every individual fact looked reasonable and the
    combination was nonsense.
    """
    result = reconstruct(
        ingest.parse(two_images), Options(enable_svd=False, minimum_confidence=0.0)
    )
    assert result.context.get("runtime_base") != 0x07FE0000


def test_each_candidate_image_carries_its_own_whole_tuple(two_images):
    result = reconstruct(
        ingest.parse(two_images), Options(enable_svd=False, minimum_confidence=0.0)
    )
    images = {item.image_offset: item for item in result.context.get("candidate_images")}
    assert set(images) == {0x000000, 0x020000}

    first, second = images[0x000000], images[0x020000]
    assert first.entry_structure == 0x08000000
    assert first.initial_stack_pointer == 0x20000600
    assert first.entry == 0x080002E0
    assert second.entry_structure == 0x08020000
    assert second.initial_stack_pointer == 0x30000600
    assert second.entry == 0x08020DE8

    # Each image's own table sits at its own base plus its own offset.
    for item in (first, second):
        assert item.entry_structure == item.runtime_base + item.image_offset
        assert item.entry > item.entry_structure


# -- 2, 3. a constant is not an address until something dereferences it ----


def test_a_float_constant_is_not_a_ram_pointer(standard):
    """0x3dcccccd is 0.1, and it falls squarely in the SRAM window."""
    floats = struct.pack("<8f", 0.1, 0.25, 0.5, 0.75, 0.125, 0.3, 0.6, 0.9)
    assert struct.unpack("<I", struct.pack("<f", 0.1))[0] == 0x3DCCCCCD

    result = reconstruct_bytes(standard.image + floats + b"\xff" * 0x400)
    references = result.context.get("references")

    ram = {item.value for item in references.of_kind(ReferenceKind.RAM)}
    assert 0x3DCCCCCD not in ram
    for region in result.context.get("memory_map").of_kind(RegionKind.RAM):
        assert not region.contains(0x3DCCCCCD)


def test_a_loaded_value_starts_out_as_a_constant(standard):
    result = reconstruct_bytes(standard.image)
    references = result.context.get("references")
    constants = references.of_kind(ReferenceKind.CONSTANT)
    assert constants, "literals should be recorded, just not as addresses"
    assert all(item.access == Access.ADDRESS_ONLY for item in constants)


def test_a_dereferenced_literal_is_promoted_to_an_address(standard):
    """The fixture loads peripheral bases and then stores through them."""
    result = reconstruct_bytes(standard.image)
    references = result.context.get("references")
    mmio = {item.value for item in references.of_kind(ReferenceKind.MMIO)}
    # 'ldr r3, =0x40020000; str r2, [r3, #0x20]' -- the address is used.
    assert 0x40020020 in mmio


# -- 4. regions come from accesses, not from address-shaped constants ------


def test_every_reported_region_rests_on_an_actual_access(standard):
    result = reconstruct_bytes(standard.image)
    references = result.context.get("references")
    touched = {
        item.value for item in references if item.access.touches_memory
    }
    startup = result.context.get("startup_state")
    boundaries = set()
    for item in startup.initializations:
        boundaries |= {item.destination, item.destination + (item.resolved_size or 0)}
    if startup.initial_stack_pointer:
        boundaries.add(startup.initial_stack_pointer)

    for region in result.context.get("memory_map").established:
        if region.kind is RegionKind.FLASH:
            continue
        covered = any(region.contains(address) for address in touched) or any(
            region.start <= address <= region.end + 1 for address in boundaries
        )
        assert covered, f"{region.name} at 0x{region.start:08x} rests on nothing accessed"


def test_address_only_evidence_does_not_make_an_established_region():
    """A literal pool of plausible-looking addresses, and nothing else."""
    plausible = struct.pack("<16I", *[0x20004000 + index * 0x400 for index in range(16)])
    payload = corpus.ground_truth(
        __import__("conftest").FIRMWARES["stm32f4_standard"]
    ).image + plausible

    result = reconstruct_bytes(payload)
    for region in result.context.get("memory_map").established:
        assert not region.contains(0x20004000) or region.confidence >= 0.6


# -- 5. confidence has to reflect the quality of the evidence --------------


def test_one_literal_does_not_make_a_confident_ram_bank():
    from raw2elf.analysis.memory_recovery import _region_confidence

    lone, _notes = _region_confidence(
        name="RAM", addresses={0x20001000}, instructions={0x100}, writes=set(),
        anchored=False, layout=(),
    )
    solid, _notes = _region_confidence(
        name="RAM",
        addresses={0x20000000 + index * 4 for index in range(8)},
        instructions={0x100 + index * 4 for index in range(10)},
        writes={0x20000000},
        anchored=True,
        layout=(0x20000000,),
    )
    assert lone < 0.5, "a single access is not a memory bank"
    assert solid > 0.9
    assert solid > lone


def test_a_known_part_supports_a_region_that_agrees_with_it():
    from raw2elf.analysis.memory_recovery import _region_confidence

    common = dict(
        name="RAM",
        addresses={0x20000100, 0x20000200},
        instructions={0x100, 0x104},
        writes=set(),
        anchored=False,
    )
    without, _n = _region_confidence(layout=(), **common)
    with_layout, _n = _region_confidence(layout=(0x20000000,), **common)
    assert with_layout > without


# -- 6. instruction semantics settle the obvious cases ---------------------


def test_a_floating_point_literal_load_is_not_a_pointer_load():
    import capstone
    from capstone import arm as csarm

    from raw2elf.arch.arm.decoder import is_float_literal, is_literal_load

    engine = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    engine.detail = True
    # vldr s0, [pc, #4]  followed by  ldr r0, [pc, #4]
    code = bytes.fromhex("9fed01" "0a" "01" "48")
    decoded = list(engine.disasm(code, 0x08000000))
    floats = [item for item in decoded if item.id == csarm.ARM_INS_VLDR]
    assert floats, "expected a VLDR in the sample"
    for item in floats:
        assert is_float_literal(item)
        assert not is_literal_load(item)


# -- 8. a supplied part number is a hint, never an identification ----------


def test_naming_a_part_claims_nothing_on_its_own(standard):
    """With nothing to match against, a supplied name identifies nothing."""
    result = reconstruct_bytes(standard.image, mcu="STM32G474RET6", enable_svd=False)
    assert result.context.get("mcu") is None
    # It still informs the load address, which is what a part number is for.
    assert result.context.get("runtime_base") == standard.base
    assert any(
        "maps Flash" in str(item) for item in result.context.evidence
    )


# -- 9, 10. reject the impossible, keep the plausible ----------------------


def test_a_table_vtor_could_not_address_is_not_a_candidate():
    from raw2elf.arch.arm import vectors
    from raw2elf.arch.arm.cortex_m import CortexMBackend
    from raw2elf.core.image import FirmwareImage, FirmwareSegment

    backend = CortexMBackend()
    table = _table(0x08000000, 0x20000600, 0x2E0)
    for offset, expected in ((0x000000, True), (0x000080, True), (0x000078, False)):
        payload = b"\x00" * offset + table + b"\x00" * 0x400
        image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, payload),))
        found = vectors.find_tables(image, backend.classify_address, minimum_confidence=0.0)
        placed = any(item.image_offset == offset for item in found)
        assert placed is expected, f"offset 0x{offset:x} should {'' if expected else 'not '}survive"


def test_multi_image_detection_survives_the_tightening(two_images):
    """Rejecting coincidences must not cost the real second image."""
    result = reconstruct(
        ingest.parse(two_images), Options(enable_svd=False, minimum_confidence=0.0)
    )
    offsets = {item.image_offset for item in result.context.get("candidate_images")}
    assert offsets == {0x000000, 0x020000}
    assert all(
        item.confidence > 0.9 for item in result.context.get("candidate_images")
    )
