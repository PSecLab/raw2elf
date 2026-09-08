"""Capstone configuration and Thumb code plausibility scoring.

raw2elf does not implement an instruction decoder.  This module owns the
Capstone configuration for Thumb/Thumb-2 on the M profile and turns decoded
instructions into the small amount of information the analyses need.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

import capstone
from capstone import arm as csarm

from ..base import CodeScore

#: Thumb instructions are two-byte aligned; a failed decode resynchronizes by
#: this much rather than by one byte.
HALFWORD = 2
#: Longest Thumb-2 encoding.
MAX_INSTRUCTION_BYTES = 4
#: An unbroken run of at least this many bytes counts as a full-strength
#: signal that code starts here; shorter runs score proportionally.
MIN_CODE_RUN = 64
#: How much of the image is handed to Capstone at a time during a sweep.
#:
#: Capstone decodes the whole buffer it is given, so restarting it on "the
#: rest of the image" after every invalid halfword costs quadratic time on a
#: multi-megabyte dump.  A bounded window keeps the sweep linear; the window
#: resumes exactly where the previous one stopped, so no instruction that
#: straddles a window edge is lost.
SWEEP_WINDOW = 4096

#: Instructions that end a linear run unconditionally.
_UNCONDITIONAL_END = frozenset((csarm.ARM_INS_B, csarm.ARM_INS_BX, csarm.ARM_INS_BXJ))

#: Encodings that are technically valid but overwhelmingly indicate that the
#: bytes are not code: ``movs r0, r0`` (0x0000) and the all-ones halfword.
_DEGENERATE_HALFWORDS = frozenset((0x0000, 0xFFFF))


def make_disassembler(big_endian: bool = False) -> "capstone.Cs":
    """A detail-enabled Thumb-2 disassembler for the M profile."""
    mode = capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS
    mode |= capstone.CS_MODE_BIG_ENDIAN if big_endian else capstone.CS_MODE_LITTLE_ENDIAN
    engine = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    engine.detail = True
    return engine


def make_a32_disassembler(big_endian: bool = False) -> "capstone.Cs":
    """An A32 disassembler, used only to rule Cortex-M *out*.

    A classic ARM image decodes acceptably as Thumb often enough to fool a
    density test, so the Cortex-M probe compares the two modes rather than
    scoring Thumb in isolation.
    """
    mode = capstone.CS_MODE_ARM
    mode |= capstone.CS_MODE_BIG_ENDIAN if big_endian else capstone.CS_MODE_LITTLE_ENDIAN
    engine = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    engine.detail = True
    return engine


@dataclass
class SweepStats:
    instructions: int = 0
    decoded_bytes: int = 0
    invalid_halfwords: int = 0
    degenerate: int = 0
    mnemonics: Optional[dict] = None
    prologues: int = 0
    branches: int = 0
    literal_loads: int = 0
    #: Bytes in the leading run of valid instructions.
    run_bytes: int = 0

    @property
    def distinct(self) -> int:
        return len(self.mnemonics or ())

    @property
    def dominance(self) -> float:
        """Share of the window taken by its single most common mnemonic."""
        if not self.mnemonics or not self.instructions:
            return 1.0
        return max(self.mnemonics.values()) / self.instructions


class Decoder:
    """A Thumb decoder with resynchronizing linear sweep and code scoring."""

    def __init__(self, big_endian: bool = False) -> None:
        self.engine = make_disassembler(big_endian)
        self.byte_order = "big" if big_endian else "little"
        self._big_endian = big_endian
        self._a32: Optional["capstone.Cs"] = None

    @property
    def a32(self) -> "capstone.Cs":
        if self._a32 is None:
            self._a32 = make_a32_disassembler(self._big_endian)
        return self._a32

    def score_a32(self, data: bytes, address: int, limit: int = 512) -> float:
        """How plausibly ``data`` is classic ARM code, for comparison only."""
        window = data[:limit]
        if len(window) < 16:
            return 0.0
        instructions = 0
        decoded = 0
        mnemonics: dict[str, int] = {}
        position = 0
        invalid = 0
        while position < len(window) - 3:
            found = None
            for instruction in self.a32.disasm(window[position:], address + position, count=1):
                found = instruction
            if found is None:
                invalid += 1
                position += 4
                continue
            instructions += 1
            decoded += found.size
            mnemonics[found.mnemonic] = mnemonics.get(found.mnemonic, 0) + 1
            position += found.size
        if not instructions:
            return 0.0
        coverage = decoded / len(window)
        distinct = len(mnemonics)
        dominance = max(mnemonics.values()) / instructions
        score = 3.0 * coverage + 2.0 * min(distinct / instructions * 2.0, 1.0)
        score -= 0.35 * invalid
        if instructions >= 8:
            if distinct <= 3:
                score -= 4.0
            if dominance > 0.5:
                score -= 6.0 * (dominance - 0.5)
        from ...core.util import logistic

        return logistic(score, midpoint=2.8, steepness=1.1)

    # -- decoding ---------------------------------------------------------

    def at(self, data: bytes, address: int) -> Optional["capstone.CsInsn"]:
        """Decode a single instruction, or ``None`` if invalid."""
        for instruction in self.engine.disasm(data, address, count=1):
            return instruction
        return None

    def sweep(self, data: bytes, address: int, limit: int = 0) -> Iterator["capstone.CsInsn"]:
        """Linearly decode ``data``, resynchronizing past invalid halfwords.

        A sweep finds literal loads and constructed addresses without needing
        a load address first, which is what makes it usable as the bootstrap
        for base recovery.
        """
        view = memoryview(data)
        position = 0
        size = len(data)
        emitted = 0
        while position < size:
            window_end = min(position + SWEEP_WINDOW, size)
            started = position
            for instruction in self.engine.disasm(
                bytes(view[position:window_end]), address + position
            ):
                yield instruction
                emitted += 1
                position = instruction.address - address + instruction.size
                if limit and emitted >= limit:
                    return
            if position == started:
                # Nothing decoded here at all: skip the invalid halfword.
                position += HALFWORD
            elif position <= window_end - MAX_INSTRUCTION_BYTES or window_end == size:
                # Capstone stopped with room to spare, so it hit something it
                # could not decode rather than the window edge.
                position += HALFWORD

    # -- scoring ----------------------------------------------------------

    def measure(
        self, data: bytes, address: int, limit: int = 4096, stop_at_invalid: bool = False
    ) -> SweepStats:
        """Collect statistics about decoding ``data`` as Thumb code.

        With ``stop_at_invalid`` the walk ends at the first halfword that does
        not decode, which is what "does a function start here?" actually asks:
        a function is a contiguous run of instructions, and whatever follows
        it -- padding, constants, the next section -- says nothing about it.
        """
        window = data[:limit]
        stats = SweepStats(mnemonics={})
        position = 0
        size = len(window)
        while position < size:
            progressed = False
            for instruction in self.engine.disasm(window[position:], address + position):
                stats.instructions += 1
                stats.decoded_bytes += instruction.size
                stats.mnemonics[instruction.mnemonic] = (
                    stats.mnemonics.get(instruction.mnemonic, 0) + 1
                )
                if instruction.size == HALFWORD:
                    halfword = int.from_bytes(
                        window[instruction.address - address : instruction.address - address + 2],
                        self.byte_order,
                    )
                    if halfword in _DEGENERATE_HALFWORDS:
                        stats.degenerate += 1
                if instruction.id in (csarm.ARM_INS_PUSH,) or (
                    instruction.id == csarm.ARM_INS_STMDB and "sp!" in instruction.op_str
                ):
                    if "lr" in instruction.op_str:
                        stats.prologues += 1
                if instruction.id in (csarm.ARM_INS_B, csarm.ARM_INS_BL, csarm.ARM_INS_BLX,
                                      csarm.ARM_INS_CBZ, csarm.ARM_INS_CBNZ):
                    stats.branches += 1
                if is_literal_load(instruction):
                    stats.literal_loads += 1
                position = instruction.address - address + instruction.size
                progressed = True
            if not progressed:
                stats.invalid_halfwords += 1
                position += HALFWORD
                if stop_at_invalid:
                    break
            elif position < size:
                stats.invalid_halfwords += 1
                position += HALFWORD
                if stop_at_invalid:
                    break
        stats.run_bytes = stats.decoded_bytes
        return stats

    def score_code(self, data: bytes, address: int, limit: int = 512) -> CodeScore:
        """Score how plausibly ``data`` at ``address`` is Thumb code.

        High decode coverage alone is not enough: constant tables and text
        decode as "valid" Thumb far too often.  Instruction variety, function
        prologues and branch density separate real code from bytes that merely
        happen to decode.
        """
        window = data[:limit]
        if len(window) < 8:
            return CodeScore(0.0, total_bytes=len(window), explanation="too few bytes to judge")
        stats = self.measure(window, address, limit=limit, stop_at_invalid=True)
        total = len(window)
        # Scored on the leading run, not the whole window: a short function
        # near the end of an image is followed by erased flash, and charging
        # it for those bytes would reject a perfectly good entry point.
        run = stats.run_bytes
        variety = stats.distinct / max(stats.instructions, 1)
        degenerate_ratio = stats.degenerate / max(stats.instructions, 1)

        score = 0.0
        score += 3.0 * min(run / MIN_CODE_RUN, 1.0)
        score += 2.0 * min(variety * 2.0, 1.0)
        score += min(stats.prologues, 3) * 0.6
        score += min(stats.branches / max(stats.instructions, 1) * 6.0, 1.5)
        score += min(stats.literal_loads, 4) * 0.25
        score -= 4.0 * degenerate_ratio

        # Byte coverage alone is a weak signal: constant tables, strings and
        # erased flash all decode "successfully" into a handful of repeated
        # encodings.  Real code uses many different instructions and no single
        # one dominates, so a window that fails both tests is rejected however
        # cleanly it decoded.
        if stats.instructions >= 10:
            if stats.distinct <= 4:
                score -= 4.0
            elif stats.distinct <= 7:
                score -= 1.5
            if stats.dominance > 0.5:
                score -= 3.0 * (stats.dominance - 0.5) * 2.0

        from ...core.util import logistic

        confidence = logistic(score, midpoint=2.8, steepness=1.1)
        explanation = (
            f"{stats.instructions} instructions over {run} unbroken bytes, "
            f"{stats.distinct} distinct mnemonics, {stats.dominance * 100:.0f}% single-mnemonic"
        )
        return CodeScore(
            confidence=confidence,
            instructions=stats.instructions,
            decoded_bytes=stats.decoded_bytes,
            total_bytes=total,
            explanation=explanation,
        )


# -- instruction predicates -----------------------------------------------


def is_literal_load(instruction: "capstone.CsInsn") -> bool:
    """True for a PC-relative literal load."""
    if instruction.id not in (
        csarm.ARM_INS_LDR,
        csarm.ARM_INS_LDRD,
        csarm.ARM_INS_LDRB,
        csarm.ARM_INS_LDRH,
        csarm.ARM_INS_VLDR,
    ):
        return False
    for operand in instruction.operands:
        if operand.type == csarm.ARM_OP_MEM and operand.mem.base == csarm.ARM_REG_PC:
            return True
    return False


def literal_address(instruction: "capstone.CsInsn") -> Optional[int]:
    """The address a PC-relative literal load reads from.

    Thumb literal loads use ``Align(PC, 4)`` where ``PC`` is the instruction
    address plus four, which is why the displacement cannot simply be added to
    the instruction address.
    """
    for operand in instruction.operands:
        if operand.type == csarm.ARM_OP_MEM and operand.mem.base == csarm.ARM_REG_PC:
            return ((instruction.address + 4) & ~3) + operand.mem.disp
    return None


def pc_relative_address(instruction: "capstone.CsInsn") -> Optional[int]:
    """The address computed by ``ADR`` or ``ADD rX, pc, #imm``."""
    if instruction.id == csarm.ARM_INS_ADR:
        for operand in instruction.operands:
            if operand.type == csarm.ARM_OP_IMM:
                return ((instruction.address + 4) & ~3) + operand.imm
        return None
    if instruction.id in (csarm.ARM_INS_ADD, csarm.ARM_INS_ADDW):
        operands = instruction.operands
        if len(operands) == 3 and operands[1].type == csarm.ARM_OP_REG:
            if operands[1].reg == csarm.ARM_REG_PC and operands[2].type == csarm.ARM_OP_IMM:
                return ((instruction.address + 4) & ~3) + operands[2].imm
    return None


def branch_target(instruction: "capstone.CsInsn") -> Optional[int]:
    """The immediate target of a direct branch or call."""
    if instruction.id not in (
        csarm.ARM_INS_B,
        csarm.ARM_INS_BL,
        csarm.ARM_INS_BLX,
        csarm.ARM_INS_CBZ,
        csarm.ARM_INS_CBNZ,
    ):
        return None
    operands = instruction.operands
    if not operands:
        return None
    last = operands[-1]
    return last.imm if last.type == csarm.ARM_OP_IMM else None


def is_conditional(instruction: "capstone.CsInsn") -> bool:
    return instruction.cc not in (csarm.ARM_CC_AL, csarm.ARM_CC_INVALID)


def is_call(instruction: "capstone.CsInsn") -> bool:
    return instruction.id in (csarm.ARM_INS_BL, csarm.ARM_INS_BLX)


def terminates_flow(instruction: "capstone.CsInsn") -> bool:
    """True when control does not fall through to the next instruction."""
    if instruction.id in _UNCONDITIONAL_END and not is_conditional(instruction):
        return True
    if instruction.id == csarm.ARM_INS_POP and "pc" in instruction.op_str:
        return True
    if instruction.id in (csarm.ARM_INS_LDM, csarm.ARM_INS_LDMIB) and "pc" in instruction.op_str:
        return True
    if instruction.id == csarm.ARM_INS_LDR:
        operands = instruction.operands
        if operands and operands[0].type == csarm.ARM_OP_REG and operands[0].reg == csarm.ARM_REG_PC:
            return True
    if instruction.id in (csarm.ARM_INS_TBB, csarm.ARM_INS_TBH):
        return True
    if instruction.id == csarm.ARM_INS_UDF:
        return True
    return False


def access_width(instruction: "capstone.CsInsn") -> Optional[int]:
    """Access width in bits for a load or store, if this is one."""
    return _WIDTHS.get(instruction.id)


_WIDTHS: dict[int, int] = {
    csarm.ARM_INS_LDRB: 8,
    csarm.ARM_INS_LDRSB: 8,
    csarm.ARM_INS_STRB: 8,
    csarm.ARM_INS_LDRBT: 8,
    csarm.ARM_INS_STRBT: 8,
    csarm.ARM_INS_LDRH: 16,
    csarm.ARM_INS_LDRSH: 16,
    csarm.ARM_INS_STRH: 16,
    csarm.ARM_INS_LDRHT: 16,
    csarm.ARM_INS_STRHT: 16,
    csarm.ARM_INS_LDR: 32,
    csarm.ARM_INS_STR: 32,
    csarm.ARM_INS_LDRT: 32,
    csarm.ARM_INS_STRT: 32,
    csarm.ARM_INS_LDREX: 32,
    csarm.ARM_INS_STREX: 32,
    csarm.ARM_INS_LDRD: 64,
    csarm.ARM_INS_STRD: 64,
}

_LOADS = frozenset(
    (
        csarm.ARM_INS_LDR,
        csarm.ARM_INS_LDRB,
        csarm.ARM_INS_LDRSB,
        csarm.ARM_INS_LDRH,
        csarm.ARM_INS_LDRSH,
        csarm.ARM_INS_LDRD,
        csarm.ARM_INS_LDREX,
        csarm.ARM_INS_LDRT,
        csarm.ARM_INS_LDRBT,
        csarm.ARM_INS_LDRHT,
    )
)
_STORES = frozenset(
    (
        csarm.ARM_INS_STR,
        csarm.ARM_INS_STRB,
        csarm.ARM_INS_STRH,
        csarm.ARM_INS_STRD,
        csarm.ARM_INS_STREX,
        csarm.ARM_INS_STRT,
        csarm.ARM_INS_STRBT,
        csarm.ARM_INS_STRHT,
    )
)


def is_load(instruction: "capstone.CsInsn") -> bool:
    return instruction.id in _LOADS


def is_store(instruction: "capstone.CsInsn") -> bool:
    return instruction.id in _STORES
