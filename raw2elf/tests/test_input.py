"""Input normalization: strict detection, exact bytes, safe refusals."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from raw2elf import input as ingest
from raw2elf.eval import corpus

PAYLOAD = bytes(range(256)) * 3 + b"\xff" * 48 + b"raw2elf test payload\n"


def test_raw_binary_is_the_fallback_and_keeps_every_byte():
    image = ingest.parse(PAYLOAD)
    assert image.source_format == "raw"
    assert image.stream == PAYLOAD
    assert image.addresses_declared is False


@pytest.mark.parametrize("form", sorted(corpus.FORMATS))
def test_every_generated_form_round_trips_exactly(form, standard):
    image = ingest.parse(corpus.render(standard, form))
    assert image.source_format == corpus.FORMATS[form]
    assert image.stream == standard.image


@pytest.mark.parametrize("form", ["ihex", "srec"])
def test_addressed_formats_preserve_their_declared_addresses(form, standard):
    image = ingest.parse(corpus.render(standard, form))
    assert image.addresses_declared
    assert image.declared_span == (standard.base, standard.base + len(standard.image))


def test_intel_hex_entry_record_becomes_an_entry_hint(standard):
    body = corpus.to_ihex(standard.chunks).decode().rstrip("\n").splitlines()
    payload = bytes.fromhex(f"{standard.entry:08x}")
    body.insert(-1, corpus._ihex_record(0, 0x05, payload))
    image = ingest.parse(("\n".join(body) + "\n").encode())
    assert image.entry_hint == standard.entry


def test_srec_termination_record_becomes_an_entry_hint(standard):
    image = ingest.parse(corpus.to_srec(standard.chunks))
    assert image.entry_hint == standard.base


def test_a_corrupt_intel_hex_checksum_is_not_accepted(standard):
    lines = corpus.to_ihex(standard.chunks).decode().splitlines()
    lines[5] = lines[5][:-2] + ("00" if not lines[5].endswith("00") else "01")
    broken = ("\n".join(lines) + "\n").encode()
    ranked = {item.parser.name: item.sniff.confidence for item in ingest.detect(broken)}
    # A single bad record does not sink the file, but the parser must notice.
    image = ingest.parse(broken)
    assert ranked["ihex"] > 0
    assert any("checksum" in note for note in image.metadata["notes"])


def test_wholly_corrupt_intel_hex_is_refused_rather_than_salvaged(standard):
    lines = [line[:-2] + "00" for line in corpus.to_ihex(standard.chunks).decode().splitlines()]
    broken = ("\n".join(lines) + "\n").encode()
    ranked = {item.parser.name: item.sniff.confidence for item in ingest.detect(broken)}
    assert ranked["ihex"] == 0.0
    # Crucially, the bare-hex parser must not strip the framing and produce
    # plausible-looking firmware from a broken record file.
    assert ranked["plainhex"] == 0.0


def test_byte_swapped_hexdump_output_is_refused_with_an_explanation(standard):
    swapped = b"\n".join(
        b"%07x " % offset
        + b" ".join(
            standard.image[offset + index : offset + index + 2][::-1].hex().encode()
            for index in range(0, 16, 2)
        )
        for offset in range(0, 256, 16)
    )
    with pytest.raises(ingest.ParseError, match="byte-swapped"):
        ingest.parse(swapped)
    # The analyst can still force it through, having been told why not to.
    assert ingest.parse(swapped, input_format="raw").size == len(swapped)


def test_an_elf_input_is_reported_rather_than_analysed(standard):
    payload = open(standard.path, "rb").read()
    with pytest.raises(ingest.ParseError, match="already an ELF"):
        ingest.parse(payload)


def test_terminal_noise_around_a_dump_is_ignored(standard):
    noisy = corpus.wrap_in_terminal_noise(corpus.to_xxd(standard.image))
    image = ingest.parse(noisy)
    assert image.source_format == "xxd"
    assert image.stream == standard.image
    assert any("surrounding" in note for note in image.metadata["notes"])


def test_a_truncated_dump_yields_the_bytes_it_actually_contains(standard):
    dump = corpus.truncate(corpus.to_xxd(standard.image), keep=0.5)
    image = ingest.parse(dump)
    assert image.source_format == "xxd"
    assert len(image.stream) < len(standard.image)
    assert standard.image.startswith(image.stream)


def test_squeezed_hexdump_repeat_markers_are_expanded(standard):
    padded = corpus.with_padding(standard.image, 0x400)
    squeezed = corpus.to_hexdump(padded, squeeze=True)
    assert b"\n*\n" in squeezed
    image = ingest.parse(squeezed)
    assert image.stream == padded


def test_a_dump_with_broken_offset_continuity_is_not_accepted(standard):
    lines = corpus.to_xxd(standard.image).decode().splitlines()
    lines[4] = "deadbe00: " + lines[4].split(": ", 1)[1]
    broken = ("\n".join(lines) + "\n").encode()
    ranked = {item.parser.name: item.sniff.confidence for item in ingest.detect(broken)}
    assert ranked["xxd"] == 0.0


def test_discontiguous_intel_hex_becomes_separate_segments():
    payload = corpus.to_ihex([(0x08000000, b"\x01" * 64), (0x08010000, b"\x02" * 64)])
    image = ingest.parse(payload)
    assert [segment.address for segment in image.segments] == [0x08000000, 0x08010000]
    assert image.size == 128


def test_a_c_array_of_bytes_is_read_as_a_hex_stream():
    image = ingest.parse(corpus.to_c_array(PAYLOAD))
    assert image.source_format == "plainhex"
    assert image.stream == PAYLOAD


def test_prose_is_not_mistaken_for_a_hex_stream():
    text = b"The quick brown fox jumped over the lazy dog, repeatedly and at length.\n" * 4
    ranked = {item.parser.name: item.sniff.confidence for item in ingest.detect(text)}
    assert ranked["plainhex"] == 0.0
    assert ingest.parse(text).source_format == "raw"


def test_an_unknown_forced_format_is_rejected():
    with pytest.raises(ingest.ParseError, match="unknown input format"):
        ingest.parse(PAYLOAD, input_format="nonsense")


@pytest.mark.skipif(shutil.which("xxd") is None, reason="xxd is not installed")
def test_real_xxd_output_parses(tmp_path, standard):
    path = tmp_path / "firmware.bin"
    path.write_bytes(standard.image)
    for arguments in (["xxd"], ["xxd", "-g1"], ["xxd", "-g4"], ["xxd", "-c", "8"], ["xxd", "-a"]):
        dump = subprocess.run(arguments + [str(path)], capture_output=True, check=True).stdout
        image = ingest.parse(dump)
        assert image.stream == standard.image, arguments


@pytest.mark.skipif(shutil.which("hexdump") is None, reason="hexdump is not installed")
def test_real_hexdump_c_output_parses(tmp_path, standard):
    path = tmp_path / "firmware.bin"
    path.write_bytes(corpus.with_padding(standard.image, 0x200))
    dump = subprocess.run(["hexdump", "-C", str(path)], capture_output=True, check=True).stdout
    image = ingest.parse(dump)
    assert image.stream == path.read_bytes()


@pytest.mark.skipif(shutil.which("hexdump") is None, reason="hexdump is not installed")
def test_real_default_hexdump_output_is_refused(tmp_path, standard):
    path = tmp_path / "firmware.bin"
    path.write_bytes(standard.image)
    dump = subprocess.run(["hexdump", str(path)], capture_output=True, check=True).stdout
    with pytest.raises(ingest.ParseError, match="byte-swapped"):
        ingest.parse(dump)
