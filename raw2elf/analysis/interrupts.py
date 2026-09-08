"""Interrupt table recovery and symbol construction."""

from __future__ import annotations

from typing import Any, Optional

from ..arch.base import ArchCapability
from ..core.evidence import Evidence
from ..core.memory import InitKind, StartupState
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..elf.symbols import FUNC, NOTYPE, OBJECT, Symbol, SymbolTable


class InterruptAnnotation(AnalysisPass):
    """Recover the handler table and name its entries.

    Architecture-defined vectors get their architectural names.  Device
    interrupts start as ``IRQn_Handler`` and are renamed from SVD interrupt
    metadata when an MCU match is available.
    """

    name = "InterruptAnnotation"
    requires = frozenset({"runtime_base"})
    capabilities = frozenset({ArchCapability.INTERRUPT_TABLE_RECOVERY})
    after = frozenset({"SvdMatcher"})
    provides = frozenset({"interrupt_table", "handler_names"})

    def run(self, context: AnalysisContext) -> None:
        table = context.backend.recover_interrupt_table(context)
        context.provide("interrupt_table", table)
        if table is None:
            context.provide("handler_names", {})
            return

        annotations = context.get("svd_annotations") or {}
        interrupt_names: dict[int, str] = {
            int(number): name for number, name in (annotations.get("interrupts") or {}).items()
        }

        names: dict[int, str] = {}
        renamed = 0
        for entry in table.entries:
            name = entry.name
            if entry.irq is not None and entry.irq in interrupt_names:
                name = f"{interrupt_names[entry.irq]}_IRQHandler"
                renamed += 1
            names[entry.index] = name
        context.provide("handler_names", names)

        if renamed:
            context.note(
                Evidence(
                    kind="interrupt_names",
                    source=self.name,
                    explanation=f"named {renamed} device interrupt handler(s) from SVD metadata",
                    value=renamed,
                )
            )
        context.log(
            f"interrupts: {len(table.entries)} handler(s) recovered, {renamed} named from SVD",
            level=1,
        )


class SymbolRecovery(AnalysisPass):
    """Assemble the symbols that go into the reconstructed ELF."""

    name = "SymbolRecovery"
    requires = frozenset({"runtime_base"})
    after = frozenset(
        {"InterruptAnnotation", "StartupAnalysis", "SvdMatcher", "MemoryRegionRecovery"}
    )
    provides = frozenset({"symbols"})

    def run(self, context: AnalysisContext) -> None:
        table = SymbolTable()
        self._entry(context, table)
        self._vectors(context, table)
        self._startup(context, table)
        self._peripherals(context, table)
        table.extend(
            Symbol(
                name=request.name,
                value=(
                    request.address
                    if request.literal_value
                    else context.backend.elf_symbol_value(request.address, request.kind == "function")
                ),
                size=request.size,
                kind={"function": FUNC, "object": OBJECT}.get(request.kind, NOTYPE),
                local=request.is_local,
                origin="architecture",
            )
            for request in context.backend.elf_symbols(context)
        )
        context.provide("symbols", table)
        context.log(f"symbols: {len(table)} recovered", level=1)

    # -- sources ----------------------------------------------------------

    def _entry(self, context: AnalysisContext, table: SymbolTable) -> None:
        entry = context.get("entry")
        if entry is None:
            return
        table.add(
            Symbol(
                name="_start",
                value=context.backend.elf_symbol_value(entry, True),
                kind=FUNC,
                origin="recovered entry point",
            )
        )

    def _vectors(self, context: AnalysisContext, table: SymbolTable) -> None:
        interrupt_table = context.get("interrupt_table")
        names = context.get("handler_names") or {}
        backend = context.backend

        if interrupt_table is None:
            return

        # Unused vectors share one default handler; naming every one of them at
        # the same address buries the real symbols, so the first name wins and
        # the full table stays in the manifest.
        claimed: dict[int, str] = {}
        for entry in interrupt_table.entries:
            name = names.get(entry.index, entry.name)
            if entry.address in claimed:
                continue
            claimed[entry.address] = name
            table.add(
                Symbol(
                    name=name,
                    value=backend.elf_symbol_value(entry.address, True),
                    kind=FUNC,
                    origin="interrupt table",
                )
            )

    def _startup(self, context: AnalysisContext, table: SymbolTable) -> None:
        state: Optional[StartupState] = context.get("startup_state")
        if state is None:
            return
        if state.initial_stack_pointer is not None:
            table.add(
                Symbol(
                    name="_estack",
                    value=state.initial_stack_pointer,
                    kind=NOTYPE,
                    absolute=True,
                    origin="initial stack pointer",
                )
            )
        copies = [item for item in state.initializations if item.kind == InitKind.COPY]
        zeros = [item for item in state.initializations if item.kind == InitKind.ZERO]
        for index, item in enumerate(copies):
            suffix = "" if index == 0 else str(index + 1)
            if item.source is not None:
                table.add(
                    Symbol(
                        f"__data_load{suffix}",
                        item.source,
                        kind=NOTYPE,
                        absolute=True,
                        origin="startup analysis",
                    )
                )
            table.add(
                Symbol(
                    f"__data_start{suffix}",
                    item.destination,
                    kind=NOTYPE,
                    absolute=True,
                    origin="startup analysis",
                )
            )
            size = item.resolved_size
            if size is not None:
                table.add(
                    Symbol(
                        f"__data_end{suffix}",
                        item.destination + size,
                        kind=NOTYPE,
                        absolute=True,
                        origin="startup analysis",
                    )
                )
        for index, item in enumerate(zeros):
            suffix = "" if index == 0 else str(index + 1)
            table.add(
                Symbol(
                    f"__bss_start{suffix}",
                    item.destination,
                    kind=NOTYPE,
                    absolute=True,
                    origin="startup analysis",
                )
            )
            size = item.resolved_size
            if size is not None:
                table.add(
                    Symbol(
                        f"__bss_end{suffix}",
                        item.destination + size,
                        kind=NOTYPE,
                        absolute=True,
                        origin="startup analysis",
                    )
                )

    def _peripherals(self, context: AnalysisContext, table: SymbolTable) -> None:
        annotations: dict[str, Any] = context.get("svd_annotations") or {}
        level = context.options.svd_symbols
        if level == "none":
            return
        for peripheral in annotations.get("peripherals", []):
            table.add(
                Symbol(
                    name=f"{peripheral['name']}_BASE",
                    value=int(peripheral["base"], 16),
                    kind=OBJECT,
                    absolute=True,
                    origin="svd peripheral",
                )
            )
        if level != "registers":
            return
        for register in annotations.get("registers", []):
            table.add(
                Symbol(
                    name=register["name"],
                    value=int(register["address"], 16),
                    size=max(register["width"] // 8, 1),
                    kind=OBJECT,
                    absolute=True,
                    origin="svd register",
                )
            )
