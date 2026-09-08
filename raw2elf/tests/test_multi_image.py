"""Multi-image dumps, padding and hole detection, and image selection."""

from __future__ import annotations

import pytest

from conftest import reconstruct_bytes
from raw2elf import input as ingest
from raw2elf.analysis.carving import ImageDiscovery, PaddingDetection, find_padding
from raw2elf.core.image import FirmwareImage, FirmwareSegment
from raw2elf.core.memory import InitKind
from raw2elf.core.options import Options
from raw2elf.core.pipeline import AnalysisContext, Pipeline
from raw2elf.eval import corpus

#: Where the application sits in the synthetic flash dump.
APPLICATION_OFFSET = 0x8000
DUMP_SIZE = 0x10000


@pytest.fixture
def dump(truth):
    """A 64 KiB flash dump: bootloader, erased gap, application, erased tail."""
    return corpus.flash_dump(
        [
            (0, truth["bootloader"].image),
            (APPLICATION_OFFSET, truth["application_high"].image),
        ],
        size=DUMP_SIZE,
    )


def _discover(payload: bytes, options=None):
    from raw2elf.arch.registry import get_backend

    image = ingest.parse(payload)
    context = AnalysisContext(
        image=image, backend=get_backend("arm-cortex-m"), options=options or Options()
    )
    Pipeline([PaddingDetection(), ImageDiscovery()]).run(context)
    return context


# -- padding ---------------------------------------------------------------


def test_erased_and_zeroed_runs_are_found():
    payload = b"\x01" * 512 + b"\xff" * 1024 + b"\x02" * 512 + b"\x00" * 2048
    image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, payload),))
    runs = find_padding(image, threshold=256)
    assert [(run.image_offset, run.size, run.byte) for run in runs] == [
        (512, 1024, 0xFF),
        (2048, 2048, 0x00),
    ]


def test_a_long_run_of_some_other_byte_is_not_called_padding():
    payload = b"\xaa" * 4096
    image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, payload),))
    assert find_padding(image, threshold=256) == []


def test_padding_is_reported_for_the_dump(dump):
    context = _discover(dump)
    runs = context.get("padding")
    assert runs
    total = sum(run.size for run in runs)
    # Two images of under 1 KiB each in 64 KiB: almost all of it is erased.
    assert total > DUMP_SIZE - 4096
    assert any("padding run" in str(item) for item in context.evidence)


def test_a_large_erased_tail_is_left_out_of_the_elf(standard):
    padded = corpus.with_padding(standard.image, 0x20000)
    reconstruction = reconstruct_bytes(padded)
    segments = reconstruction.context.get("loadable_segments")
    assert sum(item.size for item in segments) == len(standard.image)
    assert any("trailing erased flash" in str(item) for item in reconstruction.context.evidence)
    # The bytes that remain are still exactly the firmware.
    assert segments[0].data == standard.image


def test_the_erased_tail_can_be_kept(standard):
    padded = corpus.with_padding(standard.image, 0x20000)
    options = Options(minimum_confidence=0.0, enable_svd=False)
    options.extra["trim_padding"] = False
    reconstruction = reconstruct_bytes(padded, options=options)
    segments = reconstruction.context.get("loadable_segments")
    assert sum(item.size for item in segments) == len(padded)


# -- image discovery -------------------------------------------------------


def test_both_images_in_a_bootloader_plus_application_dump_are_found(dump, truth):
    context = _discover(dump)
    images = context.get("candidate_images")
    assert len(images) == 2
    by_offset = {item.image_offset: item for item in images}
    assert set(by_offset) == {0, APPLICATION_OFFSET}
    assert by_offset[0].entry == truth["bootloader"].entry
    assert by_offset[APPLICATION_OFFSET].entry == truth["application_high"].entry
    assert all(item.confidence > 0.9 for item in images)


def test_candidate_image_extents_stop_at_the_erased_gap(dump, truth):
    context = _discover(dump)
    by_offset = {item.image_offset: item for item in context.get("candidate_images")}
    # Not 0x8000 bytes: the bootloader ends where the erased flash begins.
    assert by_offset[0].image_size == len(truth["bootloader"].image)
    assert by_offset[APPLICATION_OFFSET].image_size == len(truth["application_high"].image)


def test_selecting_an_image_reconstructs_that_image_alone(dump, truth):
    expected = truth["application_high"]
    reconstruction = reconstruct_bytes(dump, image=1)
    context = reconstruction.context

    assert context.get("runtime_base") == expected.base
    assert context.get("entry") == expected.entry
    segments = context.get("loadable_segments")
    assert len(segments) == 1
    assert segments[0].address == expected.base
    assert segments[0].data == expected.image
    # And its startup state is the application's, not the bootloader's.
    state = context.get("startup_state")
    copies = [item for item in state.initializations if item.kind == InitKind.COPY]
    assert copies[0].source == expected.data_load


def test_selecting_the_first_image_reconstructs_the_bootloader(dump, truth):
    expected = truth["bootloader"]
    reconstruction = reconstruct_bytes(dump, image=0)
    assert reconstruction.context.get("runtime_base") == expected.base
    assert reconstruction.context.get("entry") == expected.entry


def test_a_carved_image_does_not_inherit_its_parents_analysis(dump, truth):
    """The bug this guards against produced the bootloader for --image 1."""
    whole = reconstruct_bytes(dump)
    carved = reconstruct_bytes(dump, image=1)
    assert whole.context.get("runtime_base") == truth["bootloader"].base
    assert carved.context.get("runtime_base") == truth["application_high"].base
    assert carved.context.image is not carved.context.root_image
    assert carved.context.image.metadata["carved_from_offset"] == APPLICATION_OFFSET


def test_an_out_of_range_image_selection_is_an_error(dump):
    with pytest.raises(ValueError, match="out of range"):
        reconstruct_bytes(dump, image=7)


def test_the_whole_dump_reconstructs_as_one_image_by_default(dump, truth):
    reconstruction = reconstruct_bytes(dump)
    context = reconstruction.context
    # Without --image the dump is taken at face value: one span of flash at
    # the base the strongest evidence supports.
    assert context.get("runtime_base") == truth["bootloader"].base
    segments = context.get("loadable_segments")
    assert segments[0].address == truth["bootloader"].base
    # Both images' code is present, so references from both are recovered.
    assert len(context.get("references")) > len(
        reconstruct_bytes(truth["bootloader"].image).context.get("references")
    )


def test_two_ram_banks_are_reported_separately(truth):
    from raw2elf.core.memory import RegionKind

    reconstruction = reconstruct_bytes(truth["two_ram_banks"].image)
    banks = reconstruction.context.get("memory_map").of_kind(RegionKind.RAM)
    starts = sorted(item.start for item in banks)
    # The fixture places a buffer in the code-region SRAM window as well as
    # in main SRAM, and the two must not be merged into one range.
    assert any(0x10000000 <= start < 0x20000000 for start in starts), starts
    assert any(0x20000000 <= start < 0x40000000 for start in starts), starts


# -- larger, messier dumps -------------------------------------------------


def _large_dump(truth, staged: bool) -> bytes:
    """A 2 MiB flash dump with two images, a constant table and erased gaps.

    ``staged`` puts the application in an OTA slot at an offset that does not
    match its own link address, as a staging area holding an image destined
    for somewhere else does.
    """
    application_offset = 0x100000 if staged else 0x8000
    return corpus.flash_dump(
        [
            (0, truth["bootloader"].image),
            (application_offset, truth["application_high"].image),
            (0x40000, bytes((index * 31 + 7) & 0xFF for index in range(0x40000))),
        ],
        size=2 << 20,
    )


def test_a_two_megabyte_dump_resolves_and_stays_interactive(truth):
    import time

    dump = _large_dump(truth, staged=False)
    started = time.monotonic()
    reconstruction = reconstruct_bytes(dump, minimum_confidence=0.5)
    elapsed = time.monotonic() - started

    # Both images agree on one base, and that is the one recovered.
    assert reconstruction.context.get("runtime_base") == truth["bootloader"].base
    assert reconstruction.context.get("entry") == truth["bootloader"].entry
    assert reconstruction.context.get("base_confidence") > 0.8
    assert len(reconstruction.context.get("candidate_images")) == 2
    assert elapsed < 30.0, f"2 MiB took {elapsed:.1f}s"


def test_a_staged_image_does_not_drag_the_dumps_base_with_it(truth):
    """A second table that disagrees is evidence, not a veto.

    An OTA slot holds an image linked for where it will eventually run, not
    for where it is stored, so its vector table is inconsistent with the
    dump's own base.  The dump's base still has to come out right, and the
    disagreement has to be visible rather than silently averaged in.
    """
    dump = _large_dump(truth, staged=True)
    reconstruction = reconstruct_bytes(dump, minimum_confidence=0.5)
    context = reconstruction.context

    assert context.get("runtime_base") == truth["bootloader"].base
    assert context.get("entry") == truth["bootloader"].entry

    winner = context.get("base_candidates")[0]
    complaints = " ".join(str(item) for item in winner.contradicting)
    assert "0x100000" in complaints or "outside the image" in complaints

    # Reconstructing the staged image on its own gives its own link address.
    staged = reconstruct_bytes(dump, image=1, minimum_confidence=0.5)
    assert staged.context.get("runtime_base") == truth["application_high"].base
    assert staged.context.get("entry") == truth["application_high"].entry


def test_a_large_constant_table_is_not_mistaken_for_a_second_image(truth):
    dump = _large_dump(truth, staged=False)
    context = _discover(dump)
    offsets = {item.image_offset for item in context.get("candidate_images")}
    # The 256 KiB of pseudo-random constants at 0x40000 contains no vector
    # table, however much of it decodes as Thumb.
    assert offsets == {0, 0x8000}


def test_listing_images_gives_the_byte_range_of_each(dump, truth, capsys):
    """A range is enough to carve a program out by hand."""
    from raw2elf.report import console

    context = _discover(dump)
    listing = console.images(context.get("candidate_images"), "arm-cortex-m")
    boot = len(truth["bootloader"].image)
    application = len(truth["application_high"].image)
    assert f"0x000000-0x{boot - 1:06x}" in listing
    assert f"0x{APPLICATION_OFFSET:06x}-0x{APPLICATION_OFFSET + application - 1:06x}" in listing
