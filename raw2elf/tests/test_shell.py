"""The interactive session."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from conftest import FIRMWARES
from raw2elf import shell as shell_module
from raw2elf.core.options import Options
from raw2elf.eval import corpus


def session(tmp_path=None, **overrides):
    """A shell writing to a buffer, with colour off."""
    stream = io.StringIO()
    instance = shell_module.Shell(options=Options(enable_svd=False, **overrides), stream=stream)
    instance.paint.enabled = False
    return instance, stream


def drive(instance, *commands: str) -> str:
    for command in commands:
        instance.onecmd(command)
    return instance.stream.getvalue()


@pytest.fixture
def firmware(tmp_path, standard):
    path = tmp_path / "firmware.bin"
    path.write_bytes(standard.image)
    return path


@pytest.fixture
def dump(tmp_path, truth):
    path = tmp_path / "flash.bin"
    path.write_bytes(
        corpus.flash_dump(
            [(0, truth["bootloader"].image), (0x8000, truth["application_high"].image)],
            size=0x10000,
        )
    )
    return path


# -- opening ---------------------------------------------------------------


def test_opening_reports_what_was_read(firmware, standard):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}")
    assert "Raw binary" in output
    assert instance.image is not None
    assert instance.image.size == len(standard.image)


def test_opening_something_that_is_not_there_is_an_error_not_a_crash():
    instance, _stream = session()
    output = drive(instance, "open /nonexistent/firmware.bin")
    assert "is not a file" in output
    assert instance.image is None


def test_commands_that_need_a_file_say_so_first():
    instance, _stream = session()
    for command in ("detect", "probe", "images", "run", "show base", "write"):
        assert "nothing open" in drive(instance, command)


def test_a_bad_command_does_not_end_the_session(firmware):
    instance, _stream = session()
    output = drive(instance, "wibble", f"open {firmware}")
    assert "unknown command 'wibble'" in output
    assert instance.image is not None


def test_an_unexpected_failure_is_reported_and_survived(firmware, monkeypatch):
    instance, _stream = session()
    drive(instance, f"open {firmware}")
    monkeypatch.setattr(
        shell_module, "probe_all", lambda image: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    output = drive(instance, "probe", "info")
    assert "RuntimeError: boom" in output
    assert "file" in output  # the session carried on


# -- looking before deciding ----------------------------------------------


def test_looking_at_the_programs_neither_analyses_nor_asks(dump):
    """'images' is a look. It must not trigger the choice it is informing."""
    instance, _stream = session()
    output = drive(instance, f"open {dump}", "images")
    assert "Image 0" in output and "Image 1" in output
    assert "separate programs" not in output  # nothing was asked
    assert "analysing" not in output
    assert instance.reconstruction is None


def test_detect_and_probe_report_without_committing(firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "detect", "probe")
    assert "raw" in output
    assert "arm-cortex-m" in output
    assert instance.reconstruction is None


# -- settings --------------------------------------------------------------


def test_settings_are_listed_with_what_they_do():
    instance, _stream = session()
    output = drive(instance, "set")
    assert "base" in output and "runtime load address" in output
    assert "unset" in output or "mcu" in output


def test_a_setting_takes_effect_and_shows_up_in_the_equivalent_command(firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "set base 0x20000000", "info")
    assert instance.options.base == 0x20000000
    assert "--base 0x20000000" in output


def test_a_setting_makes_a_held_analysis_stale(firmware, standard):
    instance, _stream = session()
    drive(instance, f"open {firmware}", "show base")
    assert instance.reconstruction is not None and not instance.stale
    first = instance.reconstruction

    drive(instance, "set base 0x10000000")
    assert instance.stale
    drive(instance, "show base")
    assert instance.reconstruction is not first
    assert instance.reconstruction.context.get("runtime_base") == 0x10000000


def test_a_setting_can_be_cleared(firmware, standard):
    instance, _stream = session()
    drive(instance, f"open {firmware}", "set base 0x10000000", "unset base", "show base")
    assert instance.options.base is None
    assert instance.reconstruction.context.get("runtime_base") == standard.base


def test_everything_can_be_cleared_at_once(firmware):
    instance, _stream = session()
    drive(instance, f"open {firmware}", "set base 0x1000", "set mcu STM32G", "unset all")
    assert instance.options.base is None and instance.options.mcu is None


def test_a_nonsense_setting_is_refused(firmware):
    instance, _stream = session()
    output = drive(
        instance,
        f"open {firmware}",
        "set base notanumber",
        "set minimum-confidence 7",
        "set svd-symbols wibble",
        "unset nonexistent",
    )
    assert output.count("error:") == 4
    assert "between 0 and 1" in output
    assert instance.options.base is None


@pytest.mark.parametrize(
    ("command", "field", "expected"),
    [
        ("set image 1", "image", 1),
        ("set arch arm-cortex-m", "arch", "arm-cortex-m"),
        ("set mcu STM32G474RET6", "mcu", "STM32G474RET6"),
        ("set minimum-confidence 0.8", "minimum_confidence", 0.8),
        ("set svd-symbols registers", "svd_symbols", "registers"),
        ("set split-sections on", "split_sections", True),
        ("set vector-offset 0x200", "vector_offset", 0x200),
    ],
)
def test_each_setting_reaches_the_option_it_names(command, field, expected):
    instance, _stream = session()
    drive(instance, command)
    assert getattr(instance.options, field) == expected


# -- analysing -------------------------------------------------------------


def test_running_produces_the_summary(firmware, standard):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "run")
    assert f"0x{standard.base:08x}" in output
    assert "Entry point" in output


def test_an_analysis_is_reused_until_something_changes(firmware):
    instance, _stream = session()
    drive(instance, f"open {firmware}", "show base")
    held = instance.reconstruction
    drive(instance, "show entry", "show regions")
    assert instance.reconstruction is held


def test_a_topic_name_on_its_own_works_as_a_command(firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "regions")
    assert "flash" in output


@pytest.mark.parametrize("topic", shell_module.TOPICS)
def test_every_topic_renders(topic, firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", f"show {topic}")
    assert "error:" not in output, topic
    assert output.strip()


def test_an_unknown_topic_lists_the_real_ones(firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "show wibble")
    assert "unknown topic" in output
    assert "summary" in output


def test_why_base_shows_what_was_weighed(firmware, standard):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "why base")
    assert "Candidate load addresses" in output
    assert f"0x{standard.base:08x}" in output


def test_why_searches_the_evidence_for_whatever_you_ask_about(firmware):
    instance, _stream = session()
    output = drive(instance, f"open {firmware}", "why startup")
    assert "loop at" in output or "no evidence mentions" in output

    missing = drive(instance, "why zzzz")
    assert "no evidence mentions 'zzzz'" in missing


# -- writing ---------------------------------------------------------------


def test_writing_emits_the_elf_and_the_manifest(firmware, tmp_path, standard):
    from raw2elf.eval import elfread

    instance, _stream = session()
    target = tmp_path / "out.elf"
    output = drive(instance, f"open {firmware}", f"write {target}")

    assert target.is_file()
    assert (tmp_path / "out.raw2elf.json").is_file()
    assert str(target) in output
    assert elfread.read(target).entry == standard.entry | 1


def test_writing_without_a_path_lands_beside_the_input(firmware):
    instance, _stream = session()
    drive(instance, f"open {firmware}", "write")
    assert firmware.with_suffix(".elf").is_file()


# -- leaving ---------------------------------------------------------------


@pytest.mark.parametrize("command", ["quit", "exit", "EOF"])
def test_the_session_can_be_left(command):
    instance, _stream = session()
    assert instance.onecmd(command) is True


# -- the boundary the shell must respect -----------------------------------


def test_completion_covers_commands_and_topics():
    instance, _stream = session()
    assert "images" in instance.completenames("im")
    assert "open" in instance.completenames("op")
    assert "base" in instance.complete_show("ba", "", 0, 0)
    assert "mcu" in instance.complete_set("mc", "", 0, 0)


def test_colour_is_off_when_the_output_is_not_a_terminal():
    palette = shell_module.Palette(io.StringIO())
    assert not palette.enabled
    assert palette.good("x") == "x"


def test_the_shell_is_reachable_from_the_command_line(monkeypatch, firmware):
    """`raw2elf` with nothing to do starts a session rather than erroring."""
    from raw2elf import cli

    started = {}

    def fake(argv, options):
        started["argv"] = argv
        return 0

    monkeypatch.setattr(shell_module, "run", fake)
    monkeypatch.setattr("raw2elf.shell.run", fake)
    assert cli.main([]) == 0
    assert started["argv"] is None

    assert cli.main([str(firmware), "--shell"]) == 0
    assert started["argv"] == [str(firmware)]
