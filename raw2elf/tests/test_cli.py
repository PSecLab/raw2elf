"""The command line: outputs, overrides, queries and safe failures."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from conftest import PACKAGE, ROOT
from raw2elf import cli
from raw2elf.eval import corpus, elfread


@pytest.fixture
def firmware(tmp_path, standard):
    path = tmp_path / "mystery.bin"
    path.write_bytes(standard.image)
    return path


def run(arguments, capsys):
    code = cli.main([str(item) for item in arguments])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_the_default_invocation_writes_an_elf_and_a_manifest(firmware, capsys, standard):
    code, out, _err = run([firmware, "--no-svd"], capsys)
    assert code == cli.EXIT_OK

    elf_path = firmware.with_suffix(".elf")
    report_path = firmware.with_name("mystery.raw2elf.json")
    assert elf_path.is_file() and report_path.is_file()
    assert str(elf_path) in out and str(report_path) in out

    elf = elfread.read(elf_path)
    assert elf.entry == standard.entry | 1
    assert elf.loads[0].virtual_address == standard.base


def test_the_report_reads_like_the_documented_summary(firmware, capsys, standard):
    _code, out, _err = run([firmware, "--no-svd"], capsys)
    assert "Input format:" in out
    assert "Architecture:        ARM Cortex-M" in out.replace("       ", "        ")
    assert f"0x{standard.base:08x}" in out
    assert f"0x{standard.entry:08x}" in out
    assert "Vector table:" in out
    assert "Initial MSP:" in out
    for label in ("Recovered:", "Memory regions:", "Startup initialization:", "Confidence:"):
        assert label in out
    assert "Architecture: HIGH" in out
    assert "Base:         HIGH" in out


def test_the_manifest_carries_the_documented_fields(firmware, capsys, standard):
    run([firmware, "--no-svd"], capsys)
    manifest = json.loads(firmware.with_name("mystery.raw2elf.json").read_text())

    assert manifest["architecture"] == "arm-cortex-m"
    assert manifest["endianness"] == "little"
    assert manifest["pointer_width"] == 32
    assert manifest["base"] == f"0x{standard.base:08x}"
    assert manifest["entry"] == f"0x{standard.entry:08x}"
    assert manifest["elf_entry"] == f"0x{standard.entry | 1:08x}"
    assert manifest["vector_table"] == f"0x{standard.base:08x}"
    assert manifest["initial_sp"] == f"0x{standard.initial_stack_pointer:08x}"
    assert manifest["confidence"]["base"] > 0.8
    assert manifest["confidence_labels"]["entry"] == "HIGH"

    # Alternatives and evidence, so a wrong answer can be traced.
    assert manifest["base_candidates"][0]["base"] == f"0x{standard.base:08x}"
    assert manifest["base_candidates"][0]["evidence"]
    assert manifest["evidence"]
    assert manifest["regions"] and manifest["mmio_accesses"]
    assert manifest["data_initialization"][0]["source"] == f"0x{standard.data_load:08x}"
    assert manifest["bss"][0]["destination"] == f"0x{standard.bss_start:08x}"
    assert {item["name"] for item in manifest["symbols"]} >= {"Reset_Handler", "__bss_start"}
    assert [item["status"] for item in manifest["passes"]].count("ok") > 5
    assert manifest["input"]["format"] == "raw"
    assert manifest["input"]["normalized_bytes"] == len(standard.image)


def test_output_paths_can_be_chosen(firmware, tmp_path, capsys):
    elf_path = tmp_path / "out" / "chosen.elf"
    elf_path.parent.mkdir()
    report_path = tmp_path / "out" / "chosen.json"
    code, out, _err = run(
        [firmware, "-o", elf_path, "--report", report_path, "--no-svd"], capsys
    )
    assert code == cli.EXIT_OK
    assert elf_path.is_file() and report_path.is_file()
    assert str(report_path) in out


def test_the_manifest_can_be_suppressed(firmware, capsys):
    run([firmware, "--no-report", "--no-svd"], capsys)
    assert not firmware.with_name("mystery.raw2elf.json").exists()
    assert firmware.with_suffix(".elf").is_file()


# -- overrides -------------------------------------------------------------


def test_every_recovery_override_takes_effect(firmware, capsys, standard):
    code, out, _err = run(
        [
            firmware,
            "--arch", "arm-cortex-m",
            "--base", "0x20000000",
            "--entry", "0x20000100",
            "--vector-offset", "0",
            "--no-svd",
        ],
        capsys,
    )
    assert code == cli.EXIT_OK
    assert "0x20000000" in out
    assert "0x20000100" in out
    elf = elfread.read(firmware.with_suffix(".elf"))
    assert elf.loads[0].virtual_address == 0x20000000
    assert elf.entry == 0x20000101


def test_an_unknown_architecture_is_reported(firmware, capsys):
    with pytest.raises(KeyError):
        run([firmware, "--arch", "sparc"], capsys)


def test_a_forced_input_format_is_honoured(tmp_path, capsys, standard):
    # A hexdump forced to be read as raw bytes: the analyst's call.
    path = tmp_path / "dump.txt"
    path.write_bytes(corpus.to_xxd(standard.image))
    code, out, _err = run([path, "--input-format", "raw", "--no-svd", "--minimum-confidence", "0"], capsys)
    assert code in (cli.EXIT_OK, cli.EXIT_AMBIGUOUS)
    if code == cli.EXIT_OK:
        assert "Raw binary" in out


# -- queries ---------------------------------------------------------------


def test_list_arch_names_the_backends(capsys):
    code, out, _err = run(["--list-arch"], capsys)
    assert code == cli.EXIT_OK
    assert "arm-cortex-m" in out
    assert "Cortex-M" in out


def test_detect_explains_what_each_parser_thought(tmp_path, capsys, standard):
    path = tmp_path / "dump.hex"
    path.write_bytes(corpus.to_ihex(standard.chunks))
    code, out, _err = run([path, "--detect"], capsys)
    assert code == cli.EXIT_OK
    assert "Selected: ihex" in out
    assert "Parser opinions:" in out
    assert "valid records" in out


def test_probe_reports_architecture_scores(firmware, capsys):
    code, out, _err = run([firmware, "--probe"], capsys)
    assert code == cli.EXIT_OK
    assert "Architecture probes:" in out
    assert "arm-cortex-m" in out
    assert "vector table" in out


def test_list_images_shows_each_candidate(tmp_path, capsys, truth):
    dump = corpus.flash_dump(
        [(0, truth["bootloader"].image), (0x8000, truth["application_high"].image)],
        size=0x10000,
    )
    path = tmp_path / "flash.bin"
    path.write_bytes(dump)
    code, out, _err = run([path, "--list-images"], capsys)
    assert code == cli.EXIT_OK
    assert "Image 0" in out and "Image 1" in out
    assert "0x000000" in out and "0x008000" in out
    assert "--image <n>" in out
    # Listing must not have written anything.
    assert not path.with_suffix(".elf").exists()


# -- failure and ambiguity -------------------------------------------------


def test_a_confidence_threshold_that_cannot_be_met_refuses_to_emit(tmp_path, capsys):
    # Random-looking bytes with a forced architecture: nothing to recover.
    path = tmp_path / "noise.bin"
    path.write_bytes(bytes((index * 7 + 11) & 0xFF for index in range(4096)))
    code, _out, err = run(
        [path, "--arch", "arm-cortex-m", "--minimum-confidence", "0.9", "--no-svd"], capsys
    )
    assert code == cli.EXIT_AMBIGUOUS
    assert "confidence" in err
    assert "--base" in err
    assert not path.with_suffix(".elf").exists()


def test_architecture_detection_refuses_rather_than_guessing(tmp_path, capsys):
    path = tmp_path / "tiny.bin"
    path.write_bytes(b"\x00\x21\x08\x60\x70\x47" * 4)
    code, _out, err = run([path, "--no-svd"], capsys)
    assert code == cli.EXIT_AMBIGUOUS
    assert "architecture" in err
    assert "--arch" in err


def test_fail_on_ambiguity_stops_a_close_call(tmp_path, capsys, monkeypatch, standard):
    from raw2elf.analysis import base_recovery

    # Force the two best candidates to score alike.
    original = base_recovery._assign_confidence

    def flatten(candidates):
        original(candidates)
        for candidate in candidates[:2]:
            candidate.confidence = 0.66
    monkeypatch.setattr(base_recovery, "_assign_confidence", flatten)

    path = tmp_path / "mystery.bin"
    path.write_bytes(standard.image)
    code, _out, err = run([path, "--fail-on-ambiguity", "--no-svd"], capsys)
    assert code == cli.EXIT_AMBIGUOUS
    assert "ambiguous" in err
    assert not path.with_suffix(".elf").exists()


def test_a_missing_file_is_a_usage_error(tmp_path, capsys):
    code, _out, err = run([tmp_path / "nope.bin"], capsys)
    assert code == cli.EXIT_USAGE
    assert "is not a file" in err


def test_an_elf_input_is_refused_with_advice(capsys, standard):
    code, _out, err = run([standard.path], capsys)
    assert code == cli.EXIT_USAGE
    assert "already an ELF" in err
    assert "objcopy" in err


# -- module invocation -----------------------------------------------------


def test_the_package_runs_as_a_module(tmp_path, standard):
    path = tmp_path / "mystery.bin"
    path.write_bytes(standard.image)
    result = subprocess.run(
        [sys.executable, "-m", "raw2elf", str(path), "--no-svd"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert "ARM Cortex-M" in result.stdout


def test_the_cli_runs_as_a_script(tmp_path, standard):
    path = tmp_path / "mystery.bin"
    path.write_bytes(standard.image)
    result = subprocess.run(
        [sys.executable, str(PACKAGE / "cli.py"), str(path), "--no-svd"],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    assert "ARM Cortex-M" in result.stdout
