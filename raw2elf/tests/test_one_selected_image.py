"""One image is selected, and nothing later may assemble a different one.

The failure these guard against is a tuple in which every number is
individually defensible: a base belonging to the bootloader, an entry
belonging to the application, an extent belonging to neither. Such an ELF
loads, disassembles, and is wrong in a way nothing downstream can detect.
"""

from __future__ import annotations

import struct

import pytest

from raw2elf import input as ingest
from raw2elf.core.hypothesis import InconsistentPlacementError
from raw2elf.core.options import Options
from raw2elf.eval import elfread
from raw2elf.reconstruct import reconstruct


def _table(base: int, msp: int, entry_offset: int, irqs: int = 82) -> bytes:
    default = base + 0x1B1
    words = [msp, base + entry_offset + 1] + [base + 0x201 + 2 * index for index in range(5)]
    words += [0, 0, 0, 0, default, default, 0, default, base + 0x301]
    words += [default] * irqs
    return struct.pack(f"<{len(words)}I", *words)


def _image(base: int, msp: int, entry_offset: int, size: int = 0x1000) -> bytes:
    table = _table(base, msp, entry_offset)
    code = bytearray(b"\x00" * size)
    thumb = bytes.fromhex("08b5024a1168012911d1")
    for offset in (entry_offset - len(table), 0x1B0 - len(table), 0x301 - len(table)):
        if 0 <= offset < len(code) - len(thumb):
            code[offset : offset + len(thumb)] = thumb
    return table + bytes(code)


@pytest.fixture
def two_programs():
    """A bootloader at 0 and an application at 0x20000, as a real dump has."""
    dump = bytearray(b"\xff" * 0x200000)
    first = _image(0x08000000, 0x20000600, 0x2E0)
    second = _image(0x08020000, 0x30000600, 0xDE8, size=0x4000)
    dump[0 : len(first)] = first
    dump[0x20000 : 0x20000 + len(second)] = second
    return bytes(dump)


def _run(payload, **overrides):
    return reconstruct(
        ingest.parse(payload), Options(enable_svd=False, minimum_confidence=0.0, **overrides)
    )


# -- the selection is one object -------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, 0x000000),
        ({"image": 0}, 0x000000),
        ({"image": 1}, 0x020000),
        ({"vector_offset": 0x20000}, 0x020000),
    ],
)
def test_every_way_of_selecting_yields_one_coherent_image(
    two_programs, overrides, expected
):
    result = _run(two_programs, **overrides)
    selected = result.context.get("selected_image")
    placement = result.context.get("selected_placement")

    # The published placement *is* the selected image's own, not a copy
    # assembled next to it.
    assert placement is selected.placement
    assert placement.file_offset == expected
    assert placement.consistent, placement

    # Every field describes the same program.
    base = placement.runtime_base
    assert placement.entry_structure == base
    assert base <= placement.entry < placement.runtime_end
    assert result.context.get("entry") == placement.entry
    assert result.context.get("program_base") == base


def test_the_two_programs_are_never_mixed(two_programs):
    boot = _run(two_programs, image=0).context.get("selected_placement")
    app = _run(two_programs, image=1).context.get("selected_placement")

    assert (boot.runtime_base, boot.entry, boot.initial_stack_pointer) == (
        0x08000000, 0x080002E0, 0x20000600,
    )
    assert (app.runtime_base, app.entry, app.initial_stack_pointer) == (
        0x08020000, 0x08020DE8, 0x30000600,
    )
    # The sizes are the programs' own, and differ.
    assert boot.image_size != app.image_size


# -- and the ELF is that image ---------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "address"), [({"image": 0}, 0x08000000), ({"image": 1}, 0x08020000)]
)
def test_the_elf_describes_the_selected_image(two_programs, tmp_path, overrides, address):
    result = _run(two_programs, **overrides)
    placement = result.context.get("selected_placement")
    segments = result.context.get("loadable_segments")

    assert [segment.address for segment in segments] == [address]
    assert sum(segment.size for segment in segments) == placement.image_size

    target = tmp_path / "out.elf"
    target.write_bytes(result.elf)
    parsed = elfread.read(target)
    assert parsed.loads[0].virtual_address == address
    assert parsed.entry == placement.entry | 1
    assert parsed.loads[0].file_size == placement.image_size


def test_a_dump_of_several_programs_says_which_one_it_reconstructed(two_programs):
    result = _run(two_programs)
    assert any(
        "holds 2 programs" in warning and "--image" in warning
        for warning in result.context.warnings
    ), result.context.warnings


# -- the checks that refuse rather than warn -------------------------------


def test_an_entry_from_another_image_stops_the_elf(two_programs, monkeypatch):
    """Force the hybrid the old code produced, and require a refusal."""
    from raw2elf.analysis import elf_build

    result = _run(two_programs, image=0)
    context = result.context
    placement = context.get("selected_placement")
    # The application's entry against the bootloader's placement.
    context.provide("entry", 0x08020DE8)

    with pytest.raises(InconsistentPlacementError) as raised:
        elf_build.ElfReconstruction()._check_placement(context)
    assert "0x08020de8" in str(raised.value)
    assert placement.runtime_base == 0x08000000


def test_a_segment_outside_the_selected_image_stops_the_elf(two_programs):
    from raw2elf.analysis import elf_build
    from raw2elf.core.memory import LoadedSegment

    result = _run(two_programs, image=0)
    context = result.context
    context.provide(
        "loadable_segments",
        [LoadedSegment(address=0x08020000, data=b"\x00" * 16, name="flash")],
    )
    with pytest.raises(InconsistentPlacementError) as raised:
        elf_build.ElfReconstruction()._check_placement(context)
    assert "not inside the selected image" in str(raised.value)


def test_a_coherent_run_passes_the_checks(two_programs):
    from raw2elf.analysis import elf_build

    for overrides in ({}, {"image": 0}, {"image": 1}, {"vector_offset": 0x20000}):
        result = _run(two_programs, **overrides)
        # No exception: the run that produced an ELF is self-consistent.
        elf_build.ElfReconstruction()._check_placement(result.context)
        assert result.elf


# -- containers that describe their own layout are left alone --------------


def test_a_declared_layout_is_not_carved_into_one_extent(standard):
    """An Intel HEX file's segments are all part of the program."""
    from raw2elf.eval import corpus

    payload = corpus.render(standard, "ihex")
    result = reconstruct(
        ingest.parse(payload), Options(enable_svd=False, minimum_confidence=0.0)
    )
    emitted = sum(item.size for item in result.context.get("loadable_segments"))
    assert emitted == len(standard.image)
    assert result.elf
