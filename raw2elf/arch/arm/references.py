"""Cortex-M absolute reference recovery.

Two passes with different jobs:

**Bootstrap sweep.**  Before a load address is known, a resynchronizing linear
sweep collects the values that Thumb code constructs absolutely -- PC-relative
literal pool loads and ``MOVW``/``MOVT`` pairs.  Those values are invariant
under relocation, which is exactly what base recovery needs.  The sweep also
records the offsets that direct branches target; those offsets *are* relative,
so they say nothing about the base on their own, but they identify where code
starts, and intersecting them with absolute code pointers is what actually
discriminates between candidate bases.

**Access recovery.**  Once the base is known, code is discovered properly from
the recovered entry points and run through value propagation, which yields
effective addresses for loads and stores, resolved indirect branch targets and
the pointers startup code sets up.

A literal is never assumed to be a pointer.  Its provenance is recorded and
classification is left to the point where the memory map is known.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from capstone import arm as csarm

from ...core.provenance import CodeProvenance
from ...core.reference import Access, AddressClass, Reference, ReferenceKind
from .decoder import Decoder, branch_target, is_call, is_literal_load, literal_address, pc_relative_address
from .flow import CodeGraph, ThumbSemantics

#: How many instructions a ``MOVW`` may precede its ``MOVT``.
MOVT_WINDOW = 12
#: Values too small or too uniform to be worth recording as references.
_NOISE = frozenset((0x00000000, 0xFFFFFFFF, 0x0000FFFF, 0xFFFF0000))


@dataclass
class SweepResult:
    """What the pre-base linear sweep found."""

    references: list[Reference] = field(default_factory=list)
    #: Image offsets that direct branches target: base-independent code starts.
    code_locations: set[int] = field(default_factory=set)
    #: Image offsets that direct calls target: base-independent function starts.
    call_locations: set[int] = field(default_factory=set)
    instructions: int = 0
    literal_loads: int = 0
    #: Values seen in literal pools, whatever they turn out to mean.
    literal_values: set[int] = field(default_factory=set)
    truncated: bool = False


def _address_class_useful_for_base(address_class: AddressClass) -> bool:
    """Whether a value in this class could be a pointer into the image.

    Peripheral and system addresses are fixed by the architecture and never
    move with the image, so counting them as support for a candidate base
    would let a wrong base borrow credit from every MMIO literal.
    """
    return address_class in (AddressClass.CODE, AddressClass.RAM)


def sweep_image(
    image,
    decoder: Decoder,
    classify: Callable[[int], AddressClass],
    byte_order: str = "little",
    max_instructions: int = 400_000,
) -> SweepResult:
    """Collect absolute references and code locations without knowing the base."""
    result = SweepResult()
    budget = max_instructions

    for segment in image.iter_segments():
        if budget <= 0:
            result.truncated = True
            break
        pending_movw: dict[str, tuple[int, int, int]] = {}
        counter = 0
        for instruction in decoder.sweep(segment.data, segment.image_offset, limit=budget):
            counter += 1
            result.instructions += 1
            identifier = instruction.id
            operands = instruction.operands

            if is_literal_load(instruction):
                result.literal_loads += 1
                address = literal_address(instruction)
                if address is not None:
                    payload = image.read(address, 4)
                    if len(payload) == 4:
                        value = int.from_bytes(payload, byte_order)
                        if value not in _NOISE:
                            result.references.append(
                                _make(
                                    value,
                                    instruction,
                                    "pc-relative literal",
                                    classify,
                                    confidence=0.45,
                                )
                            )
                            result.literal_values.add(value)
                continue

            if identifier == csarm.ARM_INS_MOVW and len(operands) >= 2:
                if operands[0].type == csarm.ARM_OP_REG and operands[1].type == csarm.ARM_OP_IMM:
                    pending_movw[instruction.reg_name(operands[0].reg)] = (
                        operands[1].imm & 0xFFFF,
                        instruction.address,
                        counter,
                    )
                continue

            if identifier == csarm.ARM_INS_MOVT and len(operands) >= 2:
                if operands[0].type == csarm.ARM_OP_REG and operands[1].type == csarm.ARM_OP_IMM:
                    name = instruction.reg_name(operands[0].reg)
                    pending = pending_movw.pop(name, None)
                    if pending is not None and counter - pending[2] <= MOVT_WINDOW:
                        value = pending[0] | ((operands[1].imm & 0xFFFF) << 16)
                        if value not in _NOISE:
                            result.references.append(
                                _make(value, instruction, "movw+movt", classify, confidence=0.7)
                            )
                continue

            computed = pc_relative_address(instruction)
            if computed is not None:
                result.references.append(
                    Reference(
                        value=computed,
                        source_offset=instruction.address,
                        derivation="pc-relative address (ADR)",
                        kind=ReferenceKind.UNKNOWN,
                        access=Access.ADDRESS_ONLY,
                        width=32,
                        confidence=0.6,
                        source_text=f"{instruction.mnemonic} {instruction.op_str}",
                        base_relative=True,
                        useful_for_base=False,
                    )
                )
                continue

            target = branch_target(instruction)
            if target is not None and 0 <= target < image.size:
                result.code_locations.add(target & ~1)
                if is_call(instruction):
                    result.call_locations.add(target & ~1)

        budget -= counter
        if budget <= 0:
            result.truncated = True
            break

    return result


def _make(
    value: int,
    instruction,
    derivation: str,
    classify: Callable[[int], AddressClass],
    confidence: float,
) -> Reference:
    address_class = classify(value)
    return Reference(
        value=value,
        source_offset=instruction.address,
        derivation=derivation,
        kind=ReferenceKind.UNKNOWN,
        access=Access.ADDRESS_ONLY,
        width=32,
        confidence=confidence,
        source_text=f"{instruction.mnemonic} {instruction.op_str}",
        base_relative=False,
        useful_for_base=_address_class_useful_for_base(address_class),
        address_class=address_class,
    )


@dataclass
class AccessRecovery:
    """Results of post-base value propagation."""

    references: list[Reference] = field(default_factory=list)
    code_regions: list[tuple[int, int]] = field(default_factory=list)
    functions: int = 0
    instructions: int = 0
    truncated: bool = False
    graph: Optional[CodeGraph] = None
    states: dict[int, dict[int, object]] = field(default_factory=dict)
    #: Per function, the state on first arrival at each instruction.
    first_states: dict[int, dict[int, object]] = field(default_factory=dict)
    #: Per function, reverse control-flow edges.
    predecessors: dict[int, dict[int, set]] = field(default_factory=dict)
    #: Indirect-call targets recovered from trusted code, worth discovering.
    validated_targets: list[tuple[int, CodeProvenance]] = field(default_factory=list)


def recover_accesses(
    context,
    decoder: Decoder,
    classify: Callable[[int], AddressClass],
    seeds: list[tuple[int, CodeProvenance]],
    max_instructions: int = 400_000,
) -> AccessRecovery:
    """Discover code from ``seeds`` and recover its memory references."""
    from ...core.valueflow import Lattice

    lattice = Lattice(context.backend.elf_target_info().pointer_width)
    graph = CodeGraph(decoder, context.read_address, max_instructions=max_instructions)
    graph.discover(seeds)

    recovery = AccessRecovery(graph=graph, truncated=graph.exhausted)
    recovery.functions = len(graph.functions)
    recovery.instructions = graph.instruction_count

    for start, function in graph.functions.items():
        semantics = ThumbSemantics(function, lattice, context.read_word)
        states, first_states = semantics.run()
        recovery.states[start] = states
        recovery.first_states[start] = first_states
        recovery.predecessors[start] = semantics.predecessors()
        events: list = []
        for address in function.order:
            instruction = function.instructions[address]
            state = states.get(address)
            if state is None:
                continue
            working = state.copy()
            semantics.apply(instruction, working, sink=events)
            _indirect_branch(instruction, state, recovery, classify, function, graph)
        for event in events:
            recovery.references.append(
                _from_event(event, classify, function.provenance, start)
            )
        if function.order:
            last = function.order[-1]
            recovery.code_regions.append(
                (function.start, last + function.instructions[last].size - function.start)
            )
    return recovery


def _from_event(
    event,
    classify: Callable[[int], AddressClass],
    provenance: CodeProvenance = CodeProvenance.LINEAR_SWEEP,
    function_start: Optional[int] = None,
) -> Reference:
    address_class = classify(event.address)
    if event.derivation == "pc-relative literal":
        # Loading a value says nothing about what it is. Classification waits
        # for something to use it as an address.
        access = Access.ADDRESS_ONLY
        kind = ReferenceKind.CONSTANT
        confidence = 0.3
    else:
        access = Access.WRITE if event.is_write else Access.READ
        kind = _kind_for(address_class)
        confidence = 0.85
    instruction = event.instruction
    return Reference(
        value=event.address,
        source_offset=instruction.address,
        derivation=event.derivation,
        kind=kind,
        access=access,
        width=event.width,
        confidence=confidence,
        source_text=f"{instruction.mnemonic} {instruction.op_str}",
        base_relative=False,
        useful_for_base=_address_class_useful_for_base(address_class),
        base_value=event.base_value,
        offset_value=event.displacement,
        address_class=address_class,
        code_provenance=provenance,
        source_function=function_start,
    )


def _kind_for(address_class: AddressClass) -> ReferenceKind:
    if address_class == AddressClass.RAM:
        return ReferenceKind.RAM
    if address_class in (AddressClass.MMIO, AddressClass.SYSTEM):
        return ReferenceKind.MMIO
    if address_class == AddressClass.CODE:
        return ReferenceKind.FLASH_DATA
    return ReferenceKind.UNKNOWN


def _indirect_branch(
    instruction, state, recovery: AccessRecovery, classify, function=None, graph=None
) -> None:
    """Record a resolvable ``BX``/``BLX`` destination as a code reference.

    A recovered target is only as good as the code that computes it, so the
    branch inherits its function's provenance, floored at the rung for an
    indirect call that was actually resolved.
    """
    if instruction.id not in (csarm.ARM_INS_BX, csarm.ARM_INS_BLX):
        return
    operands = instruction.operands
    if not operands or operands[0].type != csarm.ARM_OP_REG:
        return
    name = instruction.reg_name(operands[0].reg)
    if name in ("lr",):
        return
    value = state.get(name)
    target = value.constant()
    if target is None or target in _NOISE:
        return
    caller = function.provenance if function is not None else CodeProvenance.LINEAR_SWEEP
    provenance = caller.demoted_to(CodeProvenance.VALIDATED_INDIRECT_CALL)
    recovery.references.append(
        Reference(
            value=target,
            source_offset=instruction.address,
            derivation="propagated indirect branch target",
            kind=ReferenceKind.CODE,
            access=Access.EXECUTE,
            width=None,
            confidence=0.8,
            source_text=f"{instruction.mnemonic} {instruction.op_str}",
            base_relative=False,
            useful_for_base=_address_class_useful_for_base(classify(target)),
            address_class=classify(target),
            code_provenance=provenance,
            source_function=None if function is None else function.start,
        )
    )
    # A validated indirect target is code, and the code it calls is code.
    if graph is not None and provenance.trusted:
        recovery.validated_targets.append((target & ~1, provenance))
