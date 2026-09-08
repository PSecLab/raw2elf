"""Interactive resolution: asking only where the evidence does not decide."""

from __future__ import annotations

import io

import pytest

from conftest import reconstruct_bytes
from raw2elf import input as ingest
from raw2elf.core.hypothesis import LowConfidenceError
from raw2elf.core.interaction import Choice
from raw2elf.core.options import Options
from raw2elf.reconstruct import reconstruct
from raw2elf.report import interactive


class Scripted(interactive.TerminalSession):
    """A session that answers from a list instead of from a terminal."""

    def __init__(self, answers):
        self.transcript = io.StringIO()
        self._answers = list(answers)
        self.prompts: list[str] = []
        super().__init__(stream=self.transcript, prompt_input=self._answer)

    def _answer(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._answers:
            raise EOFError
        return self._answers.pop(0)

    @property
    def output(self) -> str:
        return self.transcript.getvalue()


NOISE = bytes(((index * 7 + 11) & 0xFF) for index in range(4096))


def _options(session, **overrides):
    return Options(enable_svd=False, interaction=session, **overrides)


# -- it must not ask when it does not need to ------------------------------


def test_a_clean_image_asks_nothing_at_all(standard):
    """The point of the tool is that it usually does not need you."""
    session = Scripted([])
    result = reconstruct(ingest.parse(standard.image), _options(session))

    assert session.prompts == []
    assert session.chosen_flags == []
    assert result.runtime_base == standard.base
    assert result.entry == standard.entry


def test_being_able_to_ask_does_not_lower_the_bar_for_deciding(standard):
    """An interaction must not turn a refusal into an automatic acceptance."""
    without = reconstruct_bytes(standard.image, minimum_confidence=0.5)
    session = Scripted([])
    with_session = reconstruct(ingest.parse(standard.image), _options(session, minimum_confidence=0.5))
    assert with_session.runtime_base == without.context.get("runtime_base")
    assert session.prompts == []


# -- and it must ask where it cannot decide --------------------------------


def test_a_refusal_becomes_a_question(standard):
    session = Scripted(["2"])
    result = reconstruct(
        ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5)
    )

    assert session.prompts, "the refusal should have been put to the analyst"
    assert "below the required 0.50" in session.output
    assert "Candidate" not in session.output or "confidence" in session.output
    # The chosen candidate is the one used, and it is recorded as a flag.
    assert result.runtime_base is not None
    assert session.chosen_flags == [f"--base 0x{result.runtime_base:08x}"]


def test_declining_to_choose_refuses_exactly_as_it_would_unattended():
    session = Scripted(["q"])
    with pytest.raises(LowConfidenceError):
        reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))
    assert "Aborted" in session.output


def test_no_answer_at_all_refuses_rather_than_looping():
    session = Scripted([])  # every read raises EOFError
    with pytest.raises(LowConfidenceError):
        reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))


def test_an_answer_the_analysis_never_proposed_is_accepted(standard):
    """The analyst may know something the image does not say."""
    session = Scripted(["e", hex(standard.base)])
    result = reconstruct(
        ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5)
    )
    assert result.runtime_base == standard.base
    assert result.elf
    assert session.chosen_flags == [f"--base 0x{standard.base:08x}"]


def test_a_bad_entry_is_rejected_and_re_asked(standard):
    session = Scripted(["e", "not-a-number", "1"])
    reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))
    assert "is not a number" in session.output
    assert len(session.prompts) >= 3


def test_an_out_of_range_selection_is_rejected_and_re_asked():
    session = Scripted(["99", "1"])
    reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))
    assert "not one of" in session.output


def test_the_candidate_list_is_capped_but_says_so():
    session = Scripted(["1"])
    reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))
    listed = [line for line in session.output.splitlines() if line.strip().startswith(("1)", "2)", "9)"))]
    assert len(listed) <= interactive.CHOICES_SHOWN
    assert "further candidate(s) scored lower" in session.output


def test_an_unrecognised_architecture_offers_the_backends():
    session = Scripted(["1"])
    tiny = b"\x00\x21\x08\x60\x70\x47" * 6
    with pytest.raises(Exception):
        # Choosing a backend gets past detection; the run then refuses later
        # for want of anything to recover, which is the honest outcome.
        reconstruct(ingest.parse(tiny), _options(session, minimum_confidence=0.5))
    assert "arm-cortex-m" in session.output


# -- image selection is a choice, not a refusal ----------------------------


def test_a_multi_image_dump_offers_its_images(truth):
    from raw2elf.eval import corpus

    dump = corpus.flash_dump(
        [(0, truth["bootloader"].image), (0x8000, truth["application_high"].image)],
        size=0x10000,
    )
    session = Scripted(["2"])  # the application
    result = reconstruct(ingest.parse(dump), _options(session))

    assert "candidate images found" in session.output
    assert result.runtime_base == truth["application_high"].base
    assert session.chosen_flags == ["--image 1"]


def test_declining_the_image_choice_analyses_the_whole_dump(truth):
    from raw2elf.eval import corpus

    dump = corpus.flash_dump(
        [(0, truth["bootloader"].image), (0x8000, truth["application_high"].image)],
        size=0x10000,
    )
    session = Scripted(["3"])  # "the whole dump as one image"
    result = reconstruct(ingest.parse(dump), _options(session))
    assert result.runtime_base == truth["bootloader"].base
    assert session.chosen_flags == []


def test_a_single_image_dump_is_not_worth_asking_about(standard):
    session = Scripted([])
    reconstruct(ingest.parse(standard.image), _options(session))
    assert "candidate images" not in session.output


# -- the session hands off to a scripted run -------------------------------


def test_choices_are_recorded_as_reproducing_flags():
    session = Scripted(["2"])
    result = reconstruct(
        ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5)
    )
    assert session.chosen_flags == [f"--base 0x{result.runtime_base:08x}"]

    # And replaying those flags non-interactively gives the same answer,
    # without asking anything.
    replay = Scripted([])
    repeated = reconstruct(
        ingest.parse(NOISE),
        _options(replay, arch="arm-cortex-m", base=result.runtime_base),
    )
    assert repeated.runtime_base == result.runtime_base
    assert replay.prompts == []


# -- refusing to prompt where nobody can answer ----------------------------


def test_a_session_needs_a_terminal(monkeypatch):
    import sys

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(interactive.NotATerminal, match="terminal"):
        interactive.require_terminal()

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    interactive.require_terminal()  # does not raise


def test_the_cli_refuses_interactive_without_a_terminal(tmp_path, capsys, monkeypatch):
    import sys

    from raw2elf import cli

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    path = tmp_path / "noise.bin"
    path.write_bytes(NOISE)
    code = cli.main([str(path), "--interactive", "--no-svd", "-o", str(tmp_path / "x.elf")])
    captured = capsys.readouterr()

    assert code == cli.EXIT_USAGE
    assert "needs a terminal" in captured.err
    assert not (tmp_path / "x.elf").exists()


def test_the_cli_prints_the_command_that_repeats_the_session(tmp_path, capsys, monkeypatch):
    import sys

    from raw2elf import cli

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    # "" skips the chip question, "2" answers the base question.
    monkeypatch.setattr(interactive, "TerminalSession", lambda: Scripted(["", "2"]))

    path = tmp_path / "noise.bin"
    path.write_bytes(NOISE)
    output = tmp_path / "out.elf"
    code = cli.main(
        [str(path), "--interactive", "--arch", "arm-cortex-m", "--no-svd", "-o", str(output)]
    )
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    assert "Repeat without prompting:" in captured.out
    assert "--base 0x" in captured.out
    assert str(output) in captured.out


# -- the abstraction itself ------------------------------------------------


def test_choices_carry_their_reasoning():
    choice = Choice(
        value=0x08000000,
        label="0x08000000",
        origin="backend seed",
        confidence=0.97,
        evidence=["+ reset vector decodes as Thumb"],
        flag="--base 0x08000000",
    )
    session = Scripted(["1"])
    picked = session.choose("runtime base address", [choice])
    assert picked is choice
    assert "backend seed" in session.output
    assert "reset vector decodes as Thumb" in session.output
    assert session.chosen_flags == ["--base 0x08000000"]


def test_choosing_from_nothing_declines():
    assert Scripted([]).choose("runtime base address", []) is None


# -- the question an analyst can actually answer ---------------------------
#
# Where a firmware is loaded is a deduction. What is printed on the package is
# an observation, and for most families it implies the answer, so that is what
# a session asks for.


def test_a_part_number_settles_the_load_address(standard):
    """Naming the chip resolves what picking an address otherwise would."""
    from raw2elf.analysis.devices import layout_for

    layout = layout_for("STM32F407VGT6")
    assert layout is not None and layout.flash[0] == standard.base

    session = Scripted(["c", "STM32F407VGT6"])
    result = reconstruct(
        ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5)
    )
    assert result.runtime_base == standard.base
    assert "STM32 family maps Flash" in session.output
    assert session.chosen_flags == ["--mcu STM32F407VGT6"]


def test_an_unknown_part_number_is_admitted_to_rather_than_guessed_at():
    session = Scripted(["c", "SOME-CUSTOM-ASIC", "1"])
    reconstruct(ingest.parse(NOISE), _options(session, arch="arm-cortex-m", minimum_confidence=0.5))
    assert "no memory layout is known for SOME-CUSTOM-ASIC" in session.output


def test_a_supplied_part_number_is_evidence_not_an_instruction(standard):
    """It must not override an image whose own evidence says otherwise."""
    # This image is genuinely linked at 0x10000000, and saying "STM32" must
    # not drag it to 0x08000000.
    result = reconstruct_bytes(
        pytest.importorskip("raw2elf.eval.corpus") and _nonstandard(), mcu="STM32F407VGT6"
    )
    assert result.context.get("runtime_base") == 0x10000000


def _nonstandard():
    from conftest import FIRMWARES
    from raw2elf.eval import corpus

    return corpus.ground_truth(FIRMWARES["nonstandard_base"]).image


def test_a_part_number_is_recorded_for_the_repeat_command(standard):
    session = Scripted(["STM32F407VGT6"])
    from raw2elf import cli
    from raw2elf.core.options import Options

    options = Options(enable_svd=False)
    cli._ask_about_the_chip(session, options)
    assert options.mcu == "STM32F407VGT6"
    assert session.chosen_flags == ["--mcu STM32F407VGT6"]
    assert "STM32 family maps Flash" in session.output


def test_skipping_the_chip_question_changes_nothing():
    from raw2elf import cli
    from raw2elf.core.options import Options

    session = Scripted([""])
    options = Options(enable_svd=False)
    cli._ask_about_the_chip(session, options)
    assert options.mcu is None
    assert session.chosen_flags == []
