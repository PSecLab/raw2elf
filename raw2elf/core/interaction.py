"""Asking a person to settle something the analysis could not.

Recovery is meant to run unattended, so nothing here is reached on a normal
run: these types exist for the points where the evidence genuinely does not
pick a winner, and a human with context the image does not contain can.

The core defines only the shape of the question -- a subject, some ranked
choices, and the evidence for each. How it is presented, and whether a person
is present at all, belongs to the caller. That keeps prompting out of the
analysis and lets the same decision points serve a terminal session, a batch
run that refuses instead of asking, or a future front end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Choice:
    """One option the analysis produced, with its reasoning."""

    #: What the caller gets back if this is picked.
    value: Any
    #: How to name it, e.g. ``"0x08000000"``.
    label: str
    #: Where it came from, e.g. ``"backend seed"``.
    origin: str = ""
    confidence: Optional[float] = None
    #: Human-readable evidence lines, already prefixed ``+`` or ``-``.
    evidence: list[str] = field(default_factory=list)
    #: The flag that would reproduce this choice non-interactively.
    flag: Optional[str] = None


class Interaction:
    """How the tool asks a question. Implemented by the presentation layer."""

    def choose(
        self,
        subject: str,
        choices: list[Choice],
        *,
        prompt: str = "",
        custom: Optional[str] = None,
    ) -> Optional[Choice]:
        """Ask which of ``choices`` to use.

        ``custom`` describes a free-form answer, if one makes sense for this
        subject. Returning ``None`` means the person declined to choose, and
        the caller should refuse exactly as it would have unattended.
        """
        raise NotImplementedError

    def ask_text(self, question: str, hint: str = "") -> Optional[str]:
        """Ask something free-form, such as what is printed on the chip.

        This is the kind of question worth putting to a person: it asks what
        they can see, not what they can deduce. Returning ``None`` means no
        answer was given, which must always be a workable outcome.
        """
        return None

    def accepted(self, subject: str, label: str, confidence: Optional[float] = None) -> None:
        """Report a decision that was clear enough not to need asking."""

    def note(self, message: str) -> None:
        """Report something worth seeing during the session."""
