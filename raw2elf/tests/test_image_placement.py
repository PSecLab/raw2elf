"""Every recovered number describes the same image, in stated coordinates.

Base, entry, entry structure, stack pointer and extent only mean anything
together. A dump holding a bootloader and an application can produce an answer
in which each number is individually defensible and the combination describes
no image that exists; these tests are what stops that.
"""

from __future__ import annotations

import struct

import pytest

from raw2elf import input as ingest
from raw2elf.core.options import Options
from raw2elf.core.placement import ImagePlacement
from raw2elf.eval import elfread
from raw2elf.reconstruct import reconstruct


def _table(base: int, msp: int, entry_offset: int, irqs: int = 82) -> bytes:
    default = base + 0x1B1
    words = [msp, base + entry_offset + 1] + [base + 0x201 + 2 * index for index in range(5)]
    words += [0, 0, 0, 0, default, default, 0, default, base + 0x301]
    words += [default] * irqs
    return struct.pack(f"<{len(words)}I", *words)


def _image(base: int, msp: int, entry_offset: int) -> bytes:
    table = _table(base, msp, entry_offset)
    code = bytearray(b"\x00" * 0x1000)
    thumb = bytes.fromhex("08b5024a1168012911d1")
    for offset in (entry_offset - len(table), 0x1B0 - len(table), 0x301 - len(table)):
        if 0 <= offset < len(code) - len(thumb):
            code[offset : offset + len(thumb)] = thumb
    return table + bytes(code)


def _dump(*placements) -> bytes:
    dump = bytearray(b"\xff" * 0x200000)
    for offset, payload in placements:
        dump[offset : offset + len(payload)] = payload
    return bytes(dump)


@pytest.fixture
def staged():
    """One program, stored at file offset 0x20000, linked to run at 0x08000000.

    A staged update looks exactly like this, and it is the case that used to
    produce a load address of 0x07fe0000 -- the address that would put image
    offset zero in the right place if the erased flash in front of the
    program were part of it.
    """
    return _dump((0x20000, _image(0x08000000, 0x20000600, 0x2E0)))


@pytest.fixture
def two_programs():
    return _dump(
        (0x00000, _image(0x08000000, 0x20000600, 0x2E0)),
        (0x20000, _image(0x08020000, 0x30000600, 0xDE8)),
    )


def _run(payload, **overrides):
    return reconstruct(
        ingest.parse(payload), Options(enable_svd=False, minimum_confidence=0.0, **overrides)
    )


# -- the placement type ----------------------------------------------------


def test_a_placement_converts_between_all_three_coordinate_systems():
    placement = ImagePlacement(
        file_offset=0x20000, image_offset=0, runtime_base=0x08000000, image_size=0x1188
    )
    assert placement.address_of(0x100) == 0x08000100
    assert placement.offset_of(0x08000100) == 0x100
    assert placement.file_offset_of(0x100) == 0x20100
    assert placement.offset_of(0x09000000) is None, "outside the image"
    assert placement.runtime_end == 0x08001188


def test_a_placement_knows_when_its_parts_disagree():
    coherent = ImagePlacement(
        file_offset=0, image_offset=0, runtime_base=0x08000000, image_size=0x1000,
        entry_structure_offset=0, entry=0x08000300,
    )
    assert coherent.consistent
    assert coherent.entry_structure == 0x08000000
    # An entry belonging to the *next* image along.
    mixed = ImagePlacement(
        file_offset=0, image_offset=0, runtime_base=0x08000000, image_size=0x1000,
        entry_structure_offset=0, entry=0x08020DE8,
    )
    assert not mixed.consistent


def test_the_entry_structure_address_follows_the_base():
    """Stored as an offset, so it cannot go stale when the image moves."""
    placement = ImagePlacement(
        file_offset=0, image_offset=0, runtime_base=0x08000200, image_size=0x1000,
        entry_structure_offset=0, entry=0x080002B8,
    )
    assert placement.entry_structure == 0x08000200

    # Correcting the belief about where the image loads moves the structure
    # with it, and leaves the entry -- which was read out of that structure,
    # and is what the bytes actually say -- alone.
    corrected = placement.rebased(0x08000000)
    assert corrected.entry_structure == 0x08000000
    assert corrected.entry == 0x080002B8


def test_carving_shifts_every_offset_together():
    placement = ImagePlacement(
        file_offset=0x20000, image_offset=0x20000, runtime_base=0x08020000,
        image_size=0x1000, entry_structure_offset=0x20000, entry=0x08020DE8,
    )
    carved = placement.at_image_offset(0)
    assert carved.entry_structure_offset == 0
    assert carved.entry_structure == 0x08020000, "unchanged address"
    assert carved.file_offset == 0x20000, "still found there in the analyst's file"


# -- one program, stored somewhere other than the start --------------------


def test_a_staged_program_loads_where_it_is_linked_not_where_it_is_stored(staged):
    result = _run(staged)
    placement = result.context.get("selected_placement")

    assert placement.file_offset == 0x20000, "found here in the analyst's file"
    assert placement.runtime_base == 0x08000000, "but it runs here"
    assert placement.entry_structure == 0x08000000
    assert placement.entry == 0x080002E0
    assert placement.consistent


def test_the_erased_flash_in_front_of_a_program_is_not_part_of_it(staged, tmp_path):
    result = _run(staged)
    segments = result.context.get("loadable_segments")

    assert [segment.address for segment in segments] == [0x08000000]
    # And nothing like the whole 2 MiB dump reaches the ELF.
    assert sum(segment.size for segment in segments) < 0x8000

    target = tmp_path / "staged.elf"
    target.write_bytes(result.elf)
    parsed = elfread.read(target)
    assert parsed.entry == 0x080002E1
    assert min(section.address for section in parsed.sections if section.address) == 0x08000000


# -- two programs, each with its own everything ----------------------------


def test_each_program_reports_its_own_load_address(two_programs):
    result = _run(two_programs)
    images = {item.file_offset: item for item in result.context.get("candidate_images")}
    assert set(images) == {0x000000, 0x020000}

    first, second = images[0x000000], images[0x020000]
    assert (first.runtime_base, first.entry) == (0x08000000, 0x080002E0)
    assert (second.runtime_base, second.entry) == (0x08020000, 0x08020DE8)
    for item in (first, second):
        assert item.placement.consistent
        assert item.entry_structure == item.runtime_base


def test_selecting_a_program_keeps_the_offset_it_came_from(two_programs):
    result = _run(two_programs, image=1)
    placement = result.context.get("selected_placement")

    # Offsets restart at zero inside the carved image...
    assert placement.image_offset == 0
    # ...but the analyst is told where in *their* file it was.
    assert placement.file_offset == 0x020000
    assert placement.runtime_base == 0x08020000
    assert placement.entry == 0x08020DE8
    assert placement.initial_stack_pointer == 0x30000600


def test_the_report_never_shows_a_carved_offset_as_a_file_offset(two_programs):
    from raw2elf.report import console

    result = _run(two_programs, image=1)
    text = console.summary(result)
    assert "file offset 0x020000" in text
    assert "0x08020000" in text
