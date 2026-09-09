"""Cortex-M code discovery and value propagation.

Code is discovered from known entry points by following direct branches and
calls, which is what relative control flow is good for.  The recovered
instruction sets are then run through the generic monotone solver in
:mod:`raw2elf.core.valueflow` with Thumb-2 transfer functions supplied here,
so the analyses can ask what value a register holds at a given instruction.

The point is to answer narrow questions -- what address does this load use,
where does this indirect branch go, what pointers did startup code set up --
not to emulate the program.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from capstone import arm as csarm

from ...core.provenance import CodeProvenance
from ...core.valueflow import UNKNOWN, Const, Lattice, State, Value, solve
from .decoder import (
    Decoder,
    branch_target,
    is_call,
    is_conditional,
    is_literal_load,
    is_load,
    is_store,
    literal_address,
    pc_relative_address,
    terminates_flow,
)

#: Registers AAPCS lets a callee destroy.
CALLER_SAVED = ("r0", "r1", "r2", "r3", "r12", "lr")

_ARITHMETIC: dict[int, str] = {
    csarm.ARM_INS_ADD: "add",
    csarm.ARM_INS_ADDW: "add",
    csarm.ARM_INS_SUB: "sub",
    csarm.ARM_INS_SUBW: "sub",
    csarm.ARM_INS_RSB: "rsb",
    csarm.ARM_INS_AND: "and",
    csarm.ARM_INS_ORR: "or",
    csarm.ARM_INS_EOR: "xor",
    csarm.ARM_INS_BIC: "bic",
    csarm.ARM_INS_LSL: "shl",
    csarm.ARM_INS_LSR: "shr",
    csarm.ARM_INS_MUL: "mul",
}
_MOVES = frozenset((csarm.ARM_INS_MOV, csarm.ARM_INS_MOVW))


@dataclass
class Function:
    """A discovered run of code reachable from one entry point."""

    start: int
    instructions: dict[int, "object"] = field(default_factory=dict)
    order: list[int] = field(default_factory=list)
    calls: set[int] = field(default_factory=set)
    #: Addresses that are the target of a backward branch, i.e. loop heads.
    loop_headers: set[int] = field(default_factory=set)
    #: Why these bytes are believed to be code at all.
    provenance: CodeProvenance = CodeProvenance.LINEAR_SWEEP

    @property
    def trusted(self) -> bool:
        return self.provenance.trusted

    @property
    def size(self) -> int:
        if not self.order:
            return 0
        last = self.order[-1]
        return last + self.instructions[last].size - self.start


class CodeGraph:
    """Discovers functions from entry points and holds the results."""

    def __init__(
        self,
        decoder: Decoder,
        read: Callable[[int, int], bytes],
        max_instructions: int = 400_000,
    ) -> None:
        self.decoder = decoder
        self.read = read
        self.max_instructions = max_instructions
        self.functions: dict[int, Function] = {}
        self.visited: set[int] = set()
        self.instruction_count = 0
        self.exhausted = False

    def discover(
        self, seeds: Iterable[tuple[int, CodeProvenance] | int]
    ) -> dict[int, Function]:
        """Discover code reachable from ``seeds`` (runtime addresses).

        Seeds are taken in order of how much they are trusted, and the first
        reason to believe an address is code is the one that sticks.  Working
        outwards from the most trustworthy seeds first means a function that
        the reset path reaches is recorded as reset-reachable even if a
        linear sweep also happened to guess it, without any re-labelling.

        Trust flows downhill.  A direct call from trusted code makes its
        target trusted; a direct call found inside a linear sweep's guesses
        proves only that the sweep guessed twice.
        """
        wavefront: list[tuple[int, CodeProvenance]] = [
            ((item[0] & ~1, item[1]) if isinstance(item, tuple) else (item & ~1, CodeProvenance.LINEAR_SWEEP))
            for item in seeds
        ]
        # Most trusted first, so `visited` records the best reason, not the
        # first one to be popped off a stack.
        wavefront.sort(key=lambda item: item[1].rank)

        seen_seeds: dict[int, CodeProvenance] = {}
        pending: list[tuple[int, CodeProvenance]] = list(reversed(wavefront))
        while pending:
            start, provenance = pending.pop()
            if start in self.visited and start not in self.functions:
                continue
            if start in seen_seeds and seen_seeds[start].rank <= provenance.rank:
                continue
            seen_seeds[start] = provenance
            if self.instruction_count >= self.max_instructions:
                self.exhausted = True
                break
            function = self._walk(start, provenance)
            if function is None or not function.instructions:
                continue
            self.functions[start] = function
            inherited = provenance.demoted_to(CodeProvenance.DIRECT_CALL)
            for target in function.calls:
                if seen_seeds.get(target, CodeProvenance.DATA_DECODE).rank > inherited.rank:
                    pending.append((target, inherited))
            # Keep the queue in trust order: a newly found trusted callee
            # should be walked before the sweep's leftover guesses.
            pending.sort(key=lambda item: item[1].rank, reverse=True)
        return self.functions

    def _walk(
        self, start: int, provenance: CodeProvenance = CodeProvenance.LINEAR_SWEEP
    ) -> Optional[Function]:
        """Linearly decode one function, following its internal branches."""
        function = Function(start=start, provenance=provenance)
        worklist = [start]
        while worklist:
            address = worklist.pop()
            while True:
                if address in function.instructions or address in self.visited:
                    break
                if self.instruction_count >= self.max_instructions:
                    self.exhausted = True
                    return function
                payload = self.read(address, 4)
                if len(payload) < 2:
                    break
                instruction = self.decoder.at(payload, address)
                if instruction is None:
                    break
                function.instructions[address] = instruction
                function.order.append(address)
                self.visited.add(address)
                self.instruction_count += 1

                target = branch_target(instruction)
                if target is not None:
                    if is_call(instruction):
                        function.calls.add(target & ~1)
                    else:
                        if target <= address:
                            function.loop_headers.add(target)
                        if target not in function.instructions:
                            worklist.append(target)
                if terminates_flow(instruction):
                    break
                address += instruction.size
        function.order.sort()
        return function


@dataclass
class AccessEvent:
    """A memory access whose effective address was recovered."""

    address: int
    instruction: "object"
    is_write: bool
    width: Optional[int]
    base_value: Optional[int]
    displacement: int
    derivation: str


class ThumbSemantics:
    """Transfer functions for the generic monotone solver."""

    def __init__(
        self,
        function: Function,
        lattice: Lattice,
        read_word: Callable[[int], Optional[int]],
    ) -> None:
        self.function = function
        self.lattice = lattice
        self.read_word = read_word

    # -- solver interface -------------------------------------------------

    def transfer(self, location: int, state: State) -> tuple[State, list[int]]:
        instruction = self.function.instructions[location]
        after = state.copy()
        self.apply(instruction, after)
        successors: list[int] = []
        if not terminates_flow(instruction):
            following = location + instruction.size
            if following in self.function.instructions:
                successors.append(following)
        target = branch_target(instruction)
        if target is not None and not is_call(instruction):
            if target in self.function.instructions:
                successors.append(target)
        return after, successors

    def run(self) -> tuple[dict[int, State], dict[int, State]]:
        """Solve for the incoming and first-arrival state of each instruction."""
        initial = State()
        initial.set("sp", UNKNOWN)
        result = solve(
            seeds=[(self.function.start, initial)],
            transfer=self.transfer,
            lattice=self.lattice,
        )
        return result.states, result.first

    def predecessors(self) -> dict[int, set[int]]:
        """Reverse control-flow edges within this function."""
        edges: dict[int, set[int]] = {}
        for address in self.function.order:
            instruction = self.function.instructions[address]
            for successor in self._successors(address, instruction):
                edges.setdefault(successor, set()).add(address)
        return edges

    def _successors(self, address: int, instruction) -> list[int]:
        successors: list[int] = []
        if not terminates_flow(instruction):
            following = address + instruction.size
            if following in self.function.instructions:
                successors.append(following)
        target = branch_target(instruction)
        if target is not None and not is_call(instruction):
            if target in self.function.instructions:
                successors.append(target)
        return successors

    # -- semantics --------------------------------------------------------

    def apply(self, instruction, state: State, sink: Optional[list[AccessEvent]] = None) -> None:
        """Update ``state`` for ``instruction``, optionally recording accesses."""
        identifier = instruction.id
        operands = instruction.operands

        # An instruction inside an IT block may not execute.  Treating it as
        # unconditional would propagate values that never existed, so its
        # destinations are simply forgotten instead.
        predicated = is_conditional(instruction) and branch_target(instruction) is None

        if is_literal_load(instruction):
            self._literal_load(instruction, state, sink, predicated)
            return

        computed = pc_relative_address(instruction)
        if computed is not None and operands and operands[0].type == csarm.ARM_OP_REG:
            self._write(state, instruction, operands[0].reg, Const(computed), predicated)
            return

        if identifier in _MOVES and len(operands) >= 2:
            self._move(instruction, state, predicated)
            return

        if identifier == csarm.ARM_INS_MOVT and len(operands) >= 2:
            name = instruction.reg_name(operands[0].reg)
            current = state.get(name)
            immediate = operands[1].imm if operands[1].type == csarm.ARM_OP_IMM else None
            value = (
                self.lattice.insert_high_half(current, immediate)
                if immediate is not None
                else UNKNOWN
            )
            self._write(state, instruction, operands[0].reg, value, predicated)
            return

        if identifier in (csarm.ARM_INS_MVN,) and len(operands) >= 2:
            source = self._value(state, instruction, operands[1])
            constant = source.constant()
            value = self.lattice.constant(~constant) if constant is not None else UNKNOWN
            self._write(state, instruction, operands[0].reg, value, predicated)
            return

        if identifier in _ARITHMETIC:
            self._arithmetic(instruction, state, predicated)
            return

        if is_load(instruction) or is_store(instruction):
            self._memory(instruction, state, sink, predicated)
            return

        if identifier == csarm.ARM_INS_PUSH:
            self._adjust_stack(state, -4 * max(len(operands), 1))
            return

        if identifier == csarm.ARM_INS_POP:
            self._adjust_stack(state, 4 * max(len(operands), 1))
            for operand in operands:
                if operand.type == csarm.ARM_OP_REG:
                    state.clear(instruction.reg_name(operand.reg))
            return

        if is_call(instruction):
            for name in CALLER_SAVED:
                state.clear(name)
            return

        self._clobber_written(instruction, state)

    # -- helpers ----------------------------------------------------------

    def _value(self, state: State, instruction, operand) -> Value:
        if operand.type == csarm.ARM_OP_IMM:
            return self.lattice.constant(operand.imm)
        if operand.type == csarm.ARM_OP_REG:
            if operand.reg == csarm.ARM_REG_PC:
                return self.lattice.constant((instruction.address + 4) & ~3)
            return state.get(instruction.reg_name(operand.reg))
        return UNKNOWN

    def _write(self, state: State, instruction, register: int, value: Value, predicated: bool) -> None:
        name = instruction.reg_name(register)
        if not name:
            return
        if predicated:
            state.clear(name)
        else:
            state.set(name, value)

    def _literal_load(self, instruction, state: State, sink, predicated: bool) -> None:
        address = literal_address(instruction)
        operands = instruction.operands
        loaded = self.read_word(address) if address is not None else None
        if operands and operands[0].type == csarm.ARM_OP_REG:
            value = self.lattice.constant(loaded) if loaded is not None else UNKNOWN
            self._write(state, instruction, operands[0].reg, value, predicated)
        if sink is not None and address is not None and loaded is not None:
            sink.append(
                AccessEvent(
                    address=loaded,
                    instruction=instruction,
                    is_write=False,
                    width=32,
                    base_value=None,
                    displacement=0,
                    derivation="pc-relative literal",
                )
            )

    def _move(self, instruction, state: State, predicated: bool) -> None:
        operands = instruction.operands
        destination = operands[0]
        if destination.type != csarm.ARM_OP_REG:
            return
        self._write(
            state, instruction, destination.reg, self._value(state, instruction, operands[1]), predicated
        )

    def _arithmetic(self, instruction, state: State, predicated: bool) -> None:
        operands = instruction.operands
        if not operands or operands[0].type != csarm.ARM_OP_REG:
            self._clobber_written(instruction, state)
            return
        if len(operands) == 2:
            left = state.get(instruction.reg_name(operands[0].reg))
            right = self._value(state, instruction, operands[1])
        elif len(operands) >= 3:
            left = self._value(state, instruction, operands[1])
            right = self._value(state, instruction, operands[2])
        else:
            self._clobber_written(instruction, state)
            return

        # A shifted or rotated second source is not modelled; forget the
        # destination rather than compute a wrong constant.
        if len(operands) >= 3 and getattr(operands[-1], "shift", None) is not None:
            if operands[-1].shift.type != csarm.ARM_SFT_INVALID:
                self._write(state, instruction, operands[0].reg, UNKNOWN, predicated)
                return

        operation = _ARITHMETIC[instruction.id]
        lattice = self.lattice
        if operation == "add":
            value = lattice.add(left, right)
        elif operation == "sub":
            value = lattice.sub(left, right)
        elif operation == "rsb":
            value = lattice.sub(right, left)
        elif operation == "and":
            value = lattice.bit_and(left, right)
        elif operation == "or":
            value = lattice.bit_or(left, right)
        elif operation == "xor":
            value = lattice.bit_xor(left, right)
        elif operation == "bic":
            constant = right.constant()
            value = (
                lattice.bit_and(left, lattice.constant(~constant)) if constant is not None else UNKNOWN
            )
        elif operation == "shl":
            value = lattice.shift_left(left, right)
        elif operation == "shr":
            value = lattice.shift_right(left, right)
        elif operation == "mul":
            value = lattice.mul(left, right)
        else:  # pragma: no cover - table and dispatch stay in step
            value = UNKNOWN
        self._write(state, instruction, operands[0].reg, value, predicated)

    def _memory(self, instruction, state: State, sink, predicated: bool) -> None:
        operands = instruction.operands
        memory_operand = next(
            (operand for operand in operands if operand.type == csarm.ARM_OP_MEM), None
        )
        if memory_operand is None:
            self._clobber_written(instruction, state)
            return

        base_register = memory_operand.mem.base
        base_name = instruction.reg_name(base_register) if base_register else None
        base_value = state.get(base_name) if base_name else UNKNOWN
        if base_register == csarm.ARM_REG_PC:
            base_value = self.lattice.constant((instruction.address + 4) & ~3)

        displacement = memory_operand.mem.disp
        effective = self.lattice.add(base_value, self.lattice.constant(displacement))
        if memory_operand.mem.index:
            index_value = state.get(instruction.reg_name(memory_operand.mem.index))
            scale = memory_operand.mem.scale or 1
            effective = self.lattice.add(
                effective, self.lattice.mul(index_value, self.lattice.constant(scale))
            )

        concrete = effective.constant()
        if sink is not None and concrete is not None:
            from .decoder import access_width

            sink.append(
                AccessEvent(
                    address=concrete,
                    instruction=instruction,
                    is_write=is_store(instruction),
                    width=access_width(instruction),
                    base_value=base_value.constant(),
                    displacement=displacement,
                    derivation="recovered base + displacement",
                )
            )

        # Write-back forms update the base register.
        if getattr(instruction, "writeback", False) and base_name:
            immediate = next(
                (
                    operand.imm
                    for operand in operands
                    if operand.type == csarm.ARM_OP_IMM
                ),
                None,
            )
            step = immediate if immediate is not None else displacement
            state.set(base_name, self.lattice.add(base_value, self.lattice.constant(step)))

        if is_load(instruction):
            for operand in operands:
                if operand.type == csarm.ARM_OP_REG and operand.access & 2:
                    state.clear(instruction.reg_name(operand.reg))

    def _adjust_stack(self, state: State, delta: int) -> None:
        current = state.get("sp")
        state.set("sp", self.lattice.add(current, self.lattice.constant(delta)))

    def _clobber_written(self, instruction, state: State) -> None:
        try:
            _, written = instruction.regs_access()
        except Exception:  # pragma: no cover - detail is always enabled here
            state.registers.clear()
            return
        for register in written:
            name = instruction.reg_name(register)
            if name:
                state.clear(name)
