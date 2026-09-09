"""How strongly a decoded instruction is believed to be executable code.

    A valid instruction encoding is not the same thing as known executable
    code.

Almost any byte sequence decodes as *something*.  A page of ASCII decodes as
a run of perfectly well-formed instructions, some of which are loads and
stores, and the addresses those compute look exactly like the addresses real
loads and stores compute.  An analysis that treats every decoded instruction
alike will therefore report memory regions built out of English prose.

The defence is to record *why* each instruction is believed to be code, and
to let later analyses weigh accordingly.  The reasons form a ladder from
"execution provably reaches here" down to "these bytes decoded":

``ENTRY_POINT``
    Reachable from the entry point the backend recovered.

``DECLARED_HANDLER``
    Reachable from another entry point the backend declared -- on an
    architecture with an exception table, one of its handlers.  The hardware
    enters these directly, so they are as trustworthy as the entry point.

``DIRECT_CALL``
    Called by a direct, PC-relative call from code that is itself trusted.
    The call is part of the caller's encoding, so if the caller is code then
    the callee is too.

``VALIDATED_INDIRECT_CALL``
    Reached through an indirect call whose target value was recovered and
    checked.

``SPECULATIVE_FUNCTION``
    Looks like a function -- a recognizable prologue, say -- but nothing was
    shown to reach it.

``LINEAR_SWEEP``
    Found only by decoding forward from an arbitrary point.

``DATA_DECODE``
    Decoded from bytes there is positive reason to think are data.

Only the first four are ``trusted``: for those, something that is itself
believed to be code transfers control here.  The rest are hypotheses about
bytes, and evidence drawn from them cannot establish a fact about memory on
its own, however much of it accumulates.
"""

from __future__ import annotations

from enum import Enum


class CodeProvenance(str, Enum):
    """Why an instruction is believed to be code, most trustworthy first."""

    ENTRY_POINT = "ENTRY_POINT"
    DECLARED_HANDLER = "DECLARED_HANDLER"
    DIRECT_CALL = "DIRECT_CALL"
    VALIDATED_INDIRECT_CALL = "VALIDATED_INDIRECT_CALL"
    SPECULATIVE_FUNCTION = "SPECULATIVE_FUNCTION"
    LINEAR_SWEEP = "LINEAR_SWEEP"
    DATA_DECODE = "DATA_DECODE"

    @property
    def rank(self) -> int:
        """Position on the ladder; lower is more trustworthy."""
        return _ORDER.index(self)

    @property
    def trusted(self) -> bool:
        """Whether control provably arrives here from something else trusted."""
        return self.rank <= CodeProvenance.VALIDATED_INDIRECT_CALL.rank

    @property
    def weight(self) -> float:
        """How much one access from such an instruction is worth."""
        return _WEIGHTS[self]

    def demoted_to(self, floor: "CodeProvenance") -> "CodeProvenance":
        """This provenance, but no more trustworthy than ``floor``.

        Code called from a linear sweep's guesses is not promoted by being
        called: trust flows downhill only.
        """
        return self if self.rank >= floor.rank else floor

    @staticmethod
    def best(*values: "CodeProvenance") -> "CodeProvenance":
        """The most trustworthy of several reasons to believe the same bytes."""
        return min(values, key=lambda item: item.rank)


_ORDER = (
    CodeProvenance.ENTRY_POINT,
    CodeProvenance.DECLARED_HANDLER,
    CodeProvenance.DIRECT_CALL,
    CodeProvenance.VALIDATED_INDIRECT_CALL,
    CodeProvenance.SPECULATIVE_FUNCTION,
    CodeProvenance.LINEAR_SWEEP,
    CodeProvenance.DATA_DECODE,
)

#: What one access from an instruction of each provenance is worth as
#: evidence that the address it computes is real memory. The gap between
#: trusted and untrusted is deliberately large: it is a difference in kind,
#: not in degree.
_WEIGHTS = {
    CodeProvenance.ENTRY_POINT: 1.0,
    CodeProvenance.DECLARED_HANDLER: 1.0,
    CodeProvenance.DIRECT_CALL: 0.9,
    CodeProvenance.VALIDATED_INDIRECT_CALL: 0.7,
    CodeProvenance.SPECULATIVE_FUNCTION: 0.15,
    CodeProvenance.LINEAR_SWEEP: 0.08,
    CodeProvenance.DATA_DECODE: 0.0,
}
