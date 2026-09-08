"""A small monotone value-propagation engine.

This is deliberately not symbolic execution.  It tracks a flat lattice of
values -- unknown, a single constant, a bounded set of constants, or an opaque
symbol plus a displacement -- through whatever transfer function an
architecture backend supplies.  Its only job is to answer questions such as
"what is in the register used as the base of this load?" and "where does this
indirect branch go?".

Everything here is architecture-neutral: the lattice knows about integers of a
given width, and the solver knows about locations, successors and a transfer
function.  Instruction semantics live in the backends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Hashable, Iterable, Optional

#: Beyond this many members a constant set degrades to :data:`UNKNOWN`.
MAX_SET_SIZE = 4


class Value:
    """Base class for lattice elements."""

    __slots__ = ()

    @property
    def is_known(self) -> bool:
        return False

    def constant(self) -> Optional[int]:
        """The single concrete value, when there is exactly one."""
        return None

    def constants(self) -> tuple[int, ...]:
        return ()


class Unknown(Value):
    """Top of the lattice: no information."""

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Unknown)

    def __hash__(self) -> int:
        return hash("unknown")

    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN = Unknown()


@dataclass(frozen=True)
class Const(Value):
    """Exactly one concrete value."""

    value: int

    @property
    def is_known(self) -> bool:
        return True

    def constant(self) -> Optional[int]:
        return self.value

    def constants(self) -> tuple[int, ...]:
        return (self.value,)

    def __repr__(self) -> str:
        return f"{self.value:#x}"


@dataclass(frozen=True)
class ConstSet(Value):
    """A small set of concrete values."""

    values: frozenset[int]

    @property
    def is_known(self) -> bool:
        return True

    def constants(self) -> tuple[int, ...]:
        return tuple(sorted(self.values))

    def __repr__(self) -> str:
        return "{" + ",".join(f"{value:#x}" for value in sorted(self.values)) + "}"


@dataclass(frozen=True)
class Sym(Value):
    """An opaque symbolic base plus a known displacement.

    Backends use this for quantities whose concrete value is unavailable but
    whose relationship to a starting point matters -- a pointer walked by a
    loop, or a stack slot.
    """

    symbol: str
    offset: int = 0

    def __repr__(self) -> str:
        sign = "+" if self.offset >= 0 else "-"
        return f"{self.symbol}{sign}{abs(self.offset):#x}"


def make_set(values: Iterable[int], mask: int) -> Value:
    """Build the tightest lattice element describing ``values``."""
    unique = {value & mask for value in values}
    if not unique:
        return UNKNOWN
    if len(unique) == 1:
        return Const(next(iter(unique)))
    if len(unique) <= MAX_SET_SIZE:
        return ConstSet(frozenset(unique))
    return UNKNOWN


class Lattice:
    """Width-aware lattice operations."""

    def __init__(self, width: int = 32) -> None:
        self.width = width
        self.mask = (1 << width) - 1

    # -- lattice ----------------------------------------------------------

    def join(self, left: Value, right: Value) -> Value:
        if left == right:
            return left
        if isinstance(left, Unknown) or isinstance(right, Unknown):
            return UNKNOWN
        if isinstance(left, Sym) or isinstance(right, Sym):
            if isinstance(left, Sym) and isinstance(right, Sym) and left.symbol == right.symbol:
                return left if left.offset == right.offset else Sym(left.symbol)
            return UNKNOWN
        return make_set(left.constants() + right.constants(), self.mask)

    # -- arithmetic -------------------------------------------------------

    def _lift(self, left: Value, right: Value, operation: Callable[[int, int], int]) -> Value:
        if isinstance(left, Sym) and isinstance(right, Const) and operation in (_add, _sub):
            return Sym(left.symbol, left.offset + (right.value if operation is _add else -right.value))
        if isinstance(right, Sym) and isinstance(left, Const) and operation is _add:
            return Sym(right.symbol, right.offset + left.value)
        if not left.is_known or not right.is_known:
            return UNKNOWN
        results = [
            operation(a, b)
            for a in left.constants()
            for b in right.constants()
        ]
        if len(results) > MAX_SET_SIZE:
            return UNKNOWN
        return make_set(results, self.mask)

    def add(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _add)

    def sub(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _sub)

    def mul(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _mul)

    def bit_and(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _and)

    def bit_or(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _or)

    def bit_xor(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _xor)

    def shift_left(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _shl)

    def shift_right(self, left: Value, right: Value) -> Value:
        return self._lift(left, right, _shr)

    def constant(self, value: int) -> Const:
        return Const(value & self.mask)

    def insert_high_half(self, low: Value, high_immediate: int) -> Value:
        """Combine a low half-word with a high half-word immediate.

        Two-instruction immediate construction is common enough across
        architectures to deserve a lattice primitive rather than a backend
        re-implementation.
        """
        half = self.width // 2
        low_mask = (1 << half) - 1
        if not low.is_known:
            return UNKNOWN
        return make_set(
            ((value & low_mask) | ((high_immediate & low_mask) << half) for value in low.constants()),
            self.mask,
        )


def _add(a: int, b: int) -> int:
    return a + b


def _sub(a: int, b: int) -> int:
    return a - b


def _mul(a: int, b: int) -> int:
    return a * b


def _and(a: int, b: int) -> int:
    return a & b


def _or(a: int, b: int) -> int:
    return a | b


def _xor(a: int, b: int) -> int:
    return a ^ b


def _shl(a: int, b: int) -> int:
    return a << (b & 63)


def _shr(a: int, b: int) -> int:
    return a >> (b & 63)


class State:
    """An immutable-by-convention map from register name to lattice value."""

    __slots__ = ("registers",)

    def __init__(self, registers: Optional[dict[str, Value]] = None) -> None:
        self.registers: dict[str, Value] = dict(registers or {})

    def get(self, name: str) -> Value:
        return self.registers.get(name, UNKNOWN)

    def set(self, name: str, value: Value) -> None:
        if isinstance(value, Unknown):
            self.registers.pop(name, None)
        else:
            self.registers[name] = value

    def clear(self, name: str) -> None:
        self.registers.pop(name, None)

    def copy(self) -> "State":
        return State(self.registers)

    def join(self, other: "State", lattice: Lattice) -> "State":
        merged: dict[str, Value] = {}
        for name in self.registers.keys() & other.registers.keys():
            value = lattice.join(self.registers[name], other.registers[name])
            if not isinstance(value, Unknown):
                merged[name] = value
        return State(merged)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, State) and self.registers == other.registers

    def __repr__(self) -> str:
        body = ", ".join(f"{name}={value!r}" for name, value in sorted(self.registers.items()))
        return f"State({body})"


@dataclass
class FlowResult:
    """Per-location incoming states after the fixpoint is reached."""

    states: dict[Hashable, State]
    visits: int
    exhausted: bool
    #: The state on the *first* arrival at each location, before any join.
    #:
    #: At a loop header the merged state has already absorbed the back edge,
    #: so a pointer the loop walks has widened to a set or to nothing.  The
    #: first arrival still holds the value the loop started from, which is
    #: what a section boundary actually is.
    first: dict[Hashable, State] = field(default_factory=dict)

    def state_at(self, location: Hashable) -> State:
        return self.states.get(location, State())

    def first_state_at(self, location: Hashable) -> State:
        return self.first.get(location, self.states.get(location, State()))


def solve(
    seeds: Iterable[tuple[Hashable, State]],
    transfer: Callable[[Hashable, State], tuple[State, Iterable[Hashable]]],
    lattice: Lattice,
    max_visits: int = 200_000,
    visit_limit_per_location: int = 6,
) -> FlowResult:
    """Run a monotone worklist analysis to a fixpoint.

    ``transfer`` receives a location and the state on entry to it, and returns
    the state after it plus that location's successors.  Each location is
    re-visited at most ``visit_limit_per_location`` times, which bounds work on
    loops without needing widening operators.
    """
    incoming: dict[Hashable, State] = {}
    first: dict[Hashable, State] = {}
    counts: dict[Hashable, int] = {}
    worklist: list[tuple[Hashable, State]] = []

    for location, state in seeds:
        incoming[location] = state
        first[location] = state.copy()
        worklist.append((location, state))

    visits = 0
    exhausted = False
    while worklist:
        if visits >= max_visits:
            exhausted = True
            break
        location, state = worklist.pop()
        visits += 1
        after, successors = transfer(location, state)
        for successor in successors:
            previous = incoming.get(successor)
            if previous is None:
                first[successor] = after.copy()
            merged = after.copy() if previous is None else previous.join(after, lattice)
            if previous is not None and merged == previous:
                continue
            seen = counts.get(successor, 0)
            if seen >= visit_limit_per_location:
                continue
            counts[successor] = seen + 1
            incoming[successor] = merged
            worklist.append((successor, merged))

    return FlowResult(states=incoming, visits=visits, exhausted=exhausted, first=first)
