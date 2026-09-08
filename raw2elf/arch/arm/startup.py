"""Cortex-M startup state recovery.

Cortex-M runtimes initialize memory before ``main`` with two loops that are
recognizable by *behaviour* rather than by any particular function signature:
one copies initialized data from Flash into RAM, the other clears the BSS.

Rather than collecting whichever constants happen to be live near a loop, the
recovery follows the registers the loop actually uses.  The base register of
the loop's store is the destination, the base register of its load is the
source, and the register the loop compares against is the limit.  Their values
are read from the state entering the loop, where the pointers are still
concrete.  This works across GCC, armclang and vendor CMSIS startup code --
which lay the same three pointers out in different registers, in different
orders, with the loop test before or after the body -- without matching any of
them textually.

Recovered ranges are then checked for consistency: the destination must be
writable memory, the size must be a sensible multiple of the store width, and
a copy's source must be entirely present in the image.  Table-driven
initializers (a Flash table of ``src``/``dst``/``end`` triples, as newer CMSIS
and armclang emit) are not recovered, and are reported as unrecovered rather
than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from capstone import arm as csarm

from ...core.evidence import Evidence
from ...core.memory import InitKind, MemoryInitialization, StartupState
from ...core.reference import AddressClass
from .decoder import access_width, branch_target, is_call, is_load, is_store

#: A single initializer larger than this is treated as implausible.
MAX_INIT_SIZE = 0x200000
#: Loops longer than this are unlikely to be a memory initializer.
MAX_LOOP_INSTRUCTIONS = 24
#: Smallest block copy or clear worth believing in.
MIN_CALL_INIT_SIZE = 8
#: How far from the entry point startup initialization is looked for.
#:
#: Runtimes reach their memory setup within a couple of calls of reset
#: (``reset -> prep_c -> bss_zero`` is typical).  Application code also
#: clears and copies buffers, and without this bound those calls get reported
#: as ``.data`` and ``.bss``, which is worse than reporting nothing.
STARTUP_CALL_DEPTH = 3
#: Instructions that compare a pointer against a limit.
_COMPARISONS = frozenset(
    (csarm.ARM_INS_CMP, csarm.ARM_INS_CMN, csarm.ARM_INS_SUBS, csarm.ARM_INS_SUB)
)
_SOURCE = "cortex-m/startup"


@dataclass
class LoopFacts:
    """The registers and memory operations of one candidate initializer loop."""

    header: int
    tail: int
    instructions: int = 0
    store_base: Optional[str] = None
    store_width: Optional[int] = None
    stores_zero: bool = False
    load_base: Optional[str] = None
    compared: list[str] = field(default_factory=list)


def _ram_predicate(classify: Callable[[int], AddressClass], in_image) -> Callable[[int], bool]:
    """Build the test for "this address is an initializer's RAM target".

    Vendors put SRAM in the architectural code region as well (CCM on
    STM32F4, main SRAM on LPC17xx), so that window has to count as RAM.  But
    a firmware *linked* into that same window would then have its own Flash
    addresses classified as RAM, and its data initializer would be thrown
    away.  Being inside the loaded image settles it: those bytes are the Flash
    side of the copy, whatever the architectural map says the region is for.
    """

    def is_ram(value: int) -> bool:
        if in_image(value):
            return False
        if 0x10000000 <= value < 0x20000000:
            return True
        return classify(value) == AddressClass.RAM

    return is_ram


def _base_register(instruction) -> Optional[str]:
    for operand in instruction.operands:
        if operand.type == csarm.ARM_OP_MEM and operand.mem.base:
            if operand.mem.base == csarm.ARM_REG_PC:
                return None
            return instruction.reg_name(operand.mem.base)
    return None


def _stores_zero(instruction, state) -> bool:
    """True when the value being stored is a register known to hold zero."""
    if state is None:
        return False
    for operand in instruction.operands:
        if operand.type == csarm.ARM_OP_REG and operand.access & 1:
            if state.get(instruction.reg_name(operand.reg)).constant() == 0:
                return True
    return False


def _loop_tail(function, header: int) -> Optional[int]:
    """The address of the last backward branch closing the loop at ``header``."""
    tail = None
    for address in function.order:
        if address < header:
            continue
        if branch_target(function.instructions[address]) == header:
            tail = address
    return tail


def _loop_body(function, predecessors, header: int, tail: int) -> Optional[list[int]]:
    """The instructions of the loop closed by the backward branch at ``tail``.

    Taking every address between the header and the tail does not work:
    compilers rotate loops so the body sits *after* the exit branch, and two
    initializer loops in the same function end up interleaved in address
    order, which mixes one loop's store with the other's load.

    Walking back from the closing branch through single-predecessor edges
    isolates the real body, and works for both the bottom-tested and the
    rotated shape.
    """
    body = [tail]
    current = tail
    while current != header and len(body) <= MAX_LOOP_INSTRUCTIONS:
        incoming = predecessors.get(current, set())
        if len(incoming) != 1:
            break
        current = next(iter(incoming))
        if current in body:
            break
        body.append(current)
    if len(body) > MAX_LOOP_INSTRUCTIONS:
        return None
    return sorted(body)


def _describe(function, states, predecessors, header: int, tail: int) -> Optional[LoopFacts]:
    body = _loop_body(function, predecessors, header, tail)
    if not body:
        return None
    facts = LoopFacts(header=header, tail=tail, instructions=len(body))
    for address in body:
        instruction = function.instructions[address]
        if is_store(instruction) and facts.store_base is None:
            facts.store_base = _base_register(instruction)
            facts.store_width = access_width(instruction)
            facts.stores_zero = _stores_zero(instruction, states.get(address))
        elif is_load(instruction) and facts.load_base is None:
            facts.load_base = _base_register(instruction)
        _record_comparison(instruction, facts)

    # The loop test lives at the header, which the backward walk may not have
    # reached; the registers it compares are where the limit comes from.
    ordered = function.order
    if header in function.instructions:
        start = ordered.index(header)
        for address in ordered[start : start + 4]:
            instruction = function.instructions[address]
            _record_comparison(instruction, facts)
            if branch_target(instruction) is not None:
                break
    return facts if facts.store_base else None


def _record_comparison(instruction, facts: LoopFacts) -> None:
    if instruction.id not in _COMPARISONS:
        return
    for operand in instruction.operands:
        if operand.type == csarm.ARM_OP_REG:
            name = instruction.reg_name(operand.reg)
            if name not in facts.compared:
                facts.compared.append(name)


def _entry_values(states, first_states, header: int) -> dict[str, int]:
    """Register values on entry to the loop at ``header``.

    The loop head's merged state has already absorbed the back edge, so a
    pointer the loop walks has widened to a set of values or to nothing.  The
    state on *first* arrival still holds what the loop started from, which is
    exactly the section boundary.  The merged state fills in registers the
    loop never touches, taking the lowest value each held.
    """
    values: dict[str, int] = {}
    merged = states.get(header)
    if merged is not None:
        for name, value in merged.registers.items():
            constants = value.constants()
            if constants:
                values[name] = min(constants)
    initial = first_states.get(header)
    if initial is not None:
        for name, value in initial.registers.items():
            constant = value.constant()
            if constant is not None:
                values[name] = constant
    return values


def _limit_for(
    facts: LoopFacts, values: dict[str, int], destination: int, is_ram
) -> Optional[int]:
    """The loop's upper bound: a RAM constant it compares the pointer against."""
    candidates = [
        values[name]
        for name in facts.compared
        if name in values and is_ram(values[name]) and values[name] > destination
    ]
    if candidates:
        return min(candidates)
    others = [
        value
        for name, value in values.items()
        if name != facts.store_base and is_ram(value) and value > destination
    ]
    return min(others) if others else None


def _initialization(
    facts: LoopFacts, values: dict[str, int], is_ram, in_image
) -> Optional[MemoryInitialization]:
    """Validate one loop's registers into an initialization record."""
    destination = values.get(facts.store_base or "")
    if destination is None or not is_ram(destination) or destination % 4:
        return None

    end = _limit_for(facts, values, destination, is_ram)
    if end is None:
        return None
    size = end - destination
    width = (facts.store_width or 32) // 8
    if size <= 0 or size > MAX_INIT_SIZE or size % max(width, 1):
        return None

    evidence = [
        Evidence(
            kind="startup_loop",
            source=_SOURCE,
            explanation=(
                f"loop at {facts.header:#010x} walks {facts.store_base} from {destination:#010x} "
                f"to {end:#010x} in {facts.store_width or 32}-bit stores "
                f"({facts.instructions} instructions)"
            ),
            value=facts.header,
        )
    ]

    source = values.get(facts.load_base or "") if facts.load_base else None
    if source is not None:
        # A data initializer's image must be present in Flash in full,
        # otherwise this is not what the loop is copying.
        if source % 4 or not in_image(source) or not in_image(source + size - 1):
            source = None

    if source is not None:
        confidence = 0.75
        if facts.instructions <= 12:
            confidence += 0.1
        if facts.compared:
            confidence += 0.05
        evidence.append(
            Evidence(
                kind="startup_loop",
                source=_SOURCE,
                explanation=(
                    f"its load walks {facts.load_base} from {source:#010x}, and all {size} bytes "
                    "of that range are present in the image"
                ),
                value=source,
            )
        )
        return MemoryInitialization(
            kind=InitKind.COPY,
            destination=destination,
            destination_end=end,
            size=size,
            source=source,
            confidence=min(confidence, 0.92),
            evidence=tuple(evidence),
            detected_at=facts.header,
        )

    if facts.stores_zero and facts.load_base is None:
        confidence = 0.75
        if facts.instructions <= 10:
            confidence += 0.1
        if facts.compared:
            confidence += 0.05
        evidence.append(
            Evidence(
                kind="startup_loop",
                source=_SOURCE,
                explanation="it stores a register known to hold zero, with no matching load",
                value=destination,
            )
        )
        return MemoryInitialization(
            kind=InitKind.ZERO,
            destination=destination,
            destination_end=end,
            size=size,
            confidence=min(confidence, 0.92),
            evidence=tuple(evidence),
            detected_at=facts.header,
        )

    return None


def _looks_like_block_operation(function, wants_load: bool) -> bool:
    """Whether a callee behaves like a block copy or a block fill.

    Checked by behaviour rather than by name or signature: the callee has to
    contain a loop that stores, and for a copy also loads.  Startup code that
    calls ``memcpy`` is doing the same thing as startup code that inlines the
    loop, and both should be recovered; but "some function called with a RAM
    pointer, a Flash pointer and a length" is not enough on its own.
    """
    if function is None or not function.loop_headers:
        return False
    stores = any(is_store(item) for item in function.instructions.values())
    loads = any(is_load(item) for item in function.instructions.values())
    return stores and (loads if wants_load else True)


def _call_initializations(
    graph, states, function, is_ram, in_image
) -> list[MemoryInitialization]:
    """Recover initializers performed by a call rather than an inline loop.

    AAPCS puts the destination in ``r0``, the source or fill value in ``r1``
    and the length in ``r2``.  When all three are concrete at a call whose
    callee behaves like a block copy or fill, that call is a ``.data`` or
    ``.bss`` initializer, whatever the function happens to be named.
    """
    found: list[MemoryInitialization] = []
    for address in function.order:
        instruction = function.instructions[address]
        if not is_call(instruction):
            continue
        target = branch_target(instruction)
        state = states.get(address)
        if target is None or state is None:
            continue
        destination = state.get("r0").constant()
        second = state.get("r1").constant()
        size = state.get("r2").constant()
        if destination is None or second is None or size is None:
            continue
        if not is_ram(destination) or destination % 4:
            continue
        if size < MIN_CALL_INIT_SIZE or size > MAX_INIT_SIZE:
            continue

        callee = graph.functions.get(target & ~1)
        if second == 0:
            if not _looks_like_block_operation(callee, wants_load=False):
                continue
            found.append(
                MemoryInitialization(
                    kind=InitKind.ZERO,
                    destination=destination,
                    destination_end=destination + size,
                    size=size,
                    confidence=0.7,
                    evidence=(
                        Evidence(
                            kind="startup_call",
                            source=_SOURCE,
                            explanation=(
                                f"call at {address:#010x} clears {size} bytes at "
                                f"{destination:#010x} through a block-fill routine at "
                                f"{target & ~1:#010x}"
                            ),
                            value=address,
                        ),
                    ),
                    detected_at=address,
                )
            )
            continue

        if not in_image(second) or not in_image(second + size - 1) or second % 4:
            continue
        if not _looks_like_block_operation(callee, wants_load=True):
            continue
        found.append(
            MemoryInitialization(
                kind=InitKind.COPY,
                destination=destination,
                destination_end=destination + size,
                size=size,
                source=second,
                confidence=0.7,
                evidence=(
                    Evidence(
                        kind="startup_call",
                        source=_SOURCE,
                        explanation=(
                            f"call at {address:#010x} copies {size} bytes from {second:#010x} "
                            f"to {destination:#010x} through a block-copy routine at "
                            f"{target & ~1:#010x}"
                        ),
                        value=address,
                    ),
                ),
                detected_at=address,
            )
        )
    return found


def _startup_functions(graph, entry: Optional[int], depth: int) -> set[int]:
    """Functions within ``depth`` calls of the entry point."""
    if entry is None:
        return set(graph.functions)
    start = entry & ~1
    if start not in graph.functions:
        return set(graph.functions)
    reached = {start}
    frontier = {start}
    for _level in range(depth):
        following: set[int] = set()
        for address in frontier:
            function = graph.functions.get(address)
            if function is None:
                continue
            following |= {target for target in function.calls if target in graph.functions}
        following -= reached
        if not following:
            break
        reached |= following
        frontier = following
    return reached


def recover(
    context,
    recovery,
    classify: Callable[[int], AddressClass],
    initial_stack_pointer: Optional[int] = None,
) -> StartupState:
    """Recover ``.data``/``.bss`` initialization from propagated values."""
    state = StartupState(initial_stack_pointer=initial_stack_pointer)
    if initial_stack_pointer is not None:
        state.evidence.append(
            Evidence(
                kind="initial_sp",
                source=_SOURCE,
                explanation=f"initial MSP {initial_stack_pointer:#010x} anchors a RAM bank",
                value=initial_stack_pointer,
            )
        )

    graph = recovery.graph
    if graph is None:
        return state

    def in_image(value: int) -> bool:
        return context.address_to_offset(value) is not None

    is_ram = _ram_predicate(classify, in_image)
    scope = _startup_functions(graph, context.get("entry"), STARTUP_CALL_DEPTH)

    found: dict[tuple, MemoryInitialization] = {}
    for start in sorted(scope):
        function = graph.functions[start]
        states = recovery.states.get(start, {})
        first_states = recovery.first_states.get(start, {})
        predecessors = recovery.predecessors.get(start, {})
        for header in sorted(function.loop_headers):
            tail = _loop_tail(function, header)
            if tail is None:
                continue
            facts = _describe(function, states, predecessors, header, tail)
            if facts is None:
                continue
            values = _entry_values(states, first_states, header)
            initialization = _initialization(facts, values, is_ram, in_image)
            if initialization is None:
                continue
            key = (initialization.kind, initialization.destination)
            existing = found.get(key)
            if existing is None or initialization.confidence > existing.confidence:
                found[key] = initialization

        for initialization in _call_initializations(
            graph, states, function, is_ram, in_image
        ):
            key = (initialization.kind, initialization.destination)
            existing = found.get(key)
            if existing is None or initialization.confidence > existing.confidence:
                found[key] = initialization

    state.initializations = sorted(
        found.values(), key=lambda item: (item.kind.value, item.destination)
    )
    return state
