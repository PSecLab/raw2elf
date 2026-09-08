"""A terminal session for the points where analysis cannot decide.

This is the presentation half of :mod:`raw2elf.core.interaction`. It prints
the candidates the analysis ranked along with the evidence for each, takes a
selection, and remembers what was chosen so the session can end by handing
back the command that reproduces it without prompting.

Prompting only happens where the tool would otherwise have refused, so a
session on a straightforward image asks nothing at all.
"""

from __future__ import annotations

import sys
from typing import Optional, TextIO

from ..core.interaction import Choice, Interaction

#: Evidence lines shown per candidate before the list gets unreadable.
EVIDENCE_SHOWN = 4
#: Candidates offered before the list stops being something you can read.
#: Synthesized base candidates run to dozens on an unrecoverable image, and
#: past the first few they are all the same near-zero score; anything not
#: shown is still reachable by entering it directly.
CHOICES_SHOWN = 8


class NotATerminal(RuntimeError):
    """Raised when a session is asked for but nobody can answer."""


class TerminalSession(Interaction):
    """Asks on a terminal, and records what was chosen."""

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        prompt_input=input,
        chip_prompt: bool = True,
    ) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self._input = prompt_input
        #: Flags reproducing this session's answers, in the order given.
        self.chosen_flags: list[str] = []
        #: Offer to take a part number where one would help.
        self.chip_prompt = chip_prompt
        #: What the analyst said was printed on the chip, if anything.
        self.chip: Optional[str] = None

    # -- Interaction ------------------------------------------------------

    def ask_text(self, question: str, hint: str = "") -> Optional[str]:
        self._say("")
        self._say(question)
        if hint:
            self._say(f"  {hint}")
        answer = self._read("> ")
        return answer or None

    def accepted(self, subject: str, label: str, confidence: Optional[float] = None) -> None:
        suffix = f"  ({confidence:.2f})" if confidence is not None else ""
        self._say(f"{subject + ':':<22}{label}{suffix}")

    def note(self, message: str) -> None:
        self._say(message)

    def choose(
        self,
        subject: str,
        choices: list[Choice],
        *,
        prompt: str = "",
        custom: Optional[str] = None,
    ) -> Optional[Choice]:
        if not choices:
            return None

        shown = choices[:CHOICES_SHOWN]
        hidden = len(choices) - len(shown)

        self._say("")
        self._say(prompt or f"Cannot choose a {subject}.")
        self._say("")
        for index, choice in enumerate(shown, start=1):
            confidence = f"  confidence {choice.confidence:.2f}" if choice.confidence is not None else ""
            origin = f"  ({choice.origin})" if choice.origin else ""
            self._say(f"  {index}) {choice.label}{confidence}{origin}")
            for line in choice.evidence[:EVIDENCE_SHOWN]:
                self._say(f"       {line}")
        if hidden:
            self._say(f"  ... {hidden} further candidate(s) scored lower and are not shown")
        self._say("  e) enter a value")
        if self.chip_prompt and subject == "runtime base address":
            # The question an analyst can actually answer. Where the firmware
            # is loaded is a deduction; what the package says is an
            # observation, and it implies the answer.
            self._say("  c) name the chip instead, if you can read it off the board")
        self._say("  q) abort")

        while True:
            answer = self._read(f"Select {subject} [1]: ")
            if answer is None or answer.lower() in ("q", "quit", "abort"):
                self._say("Aborted; nothing written.")
                return None
            if answer == "":
                answer = "1"
            if answer.lower() == "c" and self.chip_prompt and subject == "runtime base address":
                picked = self._from_chip(choices)
                if picked is not None:
                    return self._record(picked)
                continue
            if answer.lower() in ("e", "enter"):
                picked = self._read_custom(subject, choices)
                if picked is not None:
                    return self._record(picked)
                continue
            if answer.isdigit() and 1 <= int(answer) <= len(shown):
                return self._record(shown[int(answer) - 1])
            self._say(f"  not one of 1..{len(shown)}, e or q")

    # -- helpers ----------------------------------------------------------

    def _from_chip(self, choices: list[Choice]) -> Optional[Choice]:
        """Turn a part number into a load address, if the family is known."""
        from ..analysis.devices import layout_for

        answer = self.ask_text(
            "What is printed on the chip?",
            "for example STM32F407VGT6, nRF52840 or LPC1768; Enter to go back",
        )
        if not answer:
            return None
        layout = layout_for(answer)
        if layout is None or not layout.flash:
            self._say(f"  no memory layout is known for {answer}")
            return None

        self.chip = answer
        self._say(f"  {layout.describe()}")
        wanted = layout.flash[0]
        for choice in choices:
            if choice.value == wanted:
                self._say("  which is one of the candidates above")
                return choice
        return Choice(
            value=wanted,
            label=f"0x{wanted:08x}",
            origin=f"{layout.family} Flash origin",
            flag=f"--mcu {answer}",
        )

    def _read_custom(self, subject: str, choices: list[Choice]) -> Optional[Choice]:
        """Take a value the analysis never proposed."""
        raw = self._read(f"Enter {subject} (hex or decimal): ")
        if not raw:
            return None
        try:
            value = int(raw, 0)
        except ValueError:
            self._say(f"  {raw!r} is not a number")
            return None
        template = choices[0]
        if isinstance(template.value, int):
            flag = template.flag.split()[0] if template.flag else ""
            return Choice(
                value=value,
                label=f"0x{value:08x}",
                origin="entered",
                flag=f"{flag} 0x{value:08x}" if flag else "",
            )
        self._say(f"  {subject} cannot be given as a number; pick from the list")
        return None

    def _record(self, choice: Choice) -> Choice:
        self._say(f"  using {choice.label}")
        if choice.flag:
            self.chosen_flags.append(choice.flag)
        return choice

    def _read(self, prompt: str) -> Optional[str]:
        try:
            return self._input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            self._say("")
            return None

    def _say(self, message: str) -> None:
        print(message, file=self.stream)


def require_terminal(stream: Optional[TextIO] = None) -> None:
    """Refuse to start a session with nobody to answer it.

    Without this a piped or scheduled run would block on a prompt nobody can
    see, which is worse than the refusal it replaced.
    """
    if not sys.stdin.isatty():
        raise NotATerminal(
            "--interactive needs a terminal to ask questions on, and stdin is not one. "
            "Supply the answers as flags instead (--arch / --base / --entry / "
            "--vector-offset / --image)."
        )
