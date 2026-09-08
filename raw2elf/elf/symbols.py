"""Symbol collection for the reconstructed ELF.

Symbols are the part of a reconstructed ELF an analyst notices first, so only
recovered facts become symbols: handler names the entry structure supplied,
section boundaries startup analysis recovered, peripheral bases a confident
MCU match provided, and whatever mapping symbols the architecture needs to be
disassembled correctly.  Nothing is invented to fill the table out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

#: Symbol types this writer emits.
FUNC = "func"
OBJECT = "object"
NOTYPE = "notype"


@dataclass(frozen=True)
class Symbol:
    """One entry destined for ``.symtab``."""

    name: str
    value: int
    size: int = 0
    kind: str = FUNC
    local: bool = False
    #: Name of the section this symbol belongs to; resolved by address when
    #: absent, and left absolute if no section contains it.
    section: Optional[str] = None
    #: Bind to ``SHN_ABS`` regardless of which section covers the address.
    #: Section boundaries and peripheral addresses are absolute values, not
    #: locations inside a section, and binding them to whichever section
    #: happens to contain them misreports them (a ``.data`` end address lands
    #: in ``.bss``, and a peripheral base lands nowhere at all).
    absolute: bool = False
    #: Where the symbol came from, for the manifest.
    origin: str = ""


class SymbolTable:
    """Accumulates symbols, keeping the first definition of each name."""

    def __init__(self) -> None:
        self._symbols: dict[str, Symbol] = {}
        self._anonymous: list[Symbol] = []

    def add(self, symbol: Symbol) -> None:
        # Mapping symbols such as ARM's ``$t`` legitimately repeat at many
        # addresses, so they are not deduplicated by name.
        if symbol.name.startswith("$"):
            self._anonymous.append(symbol)
            return
        existing = self._symbols.get(symbol.name)
        if existing is None:
            self._symbols[symbol.name] = symbol
            return
        if existing.value == symbol.value:
            return
        # A genuine collision: keep both, distinguished by address.
        self._symbols.setdefault(f"{symbol.name}_{symbol.value:08x}", symbol)

    def extend(self, symbols: Iterable[Symbol]) -> None:
        for symbol in symbols:
            self.add(symbol)

    def __iter__(self) -> Iterator[Symbol]:
        return iter(sorted(self._symbols.values(), key=lambda item: (item.value, item.name))
                    + sorted(self._anonymous, key=lambda item: item.value))

    def __len__(self) -> int:
        return len(self._symbols) + len(self._anonymous)

    def named(self) -> list[Symbol]:
        return sorted(self._symbols.values(), key=lambda item: (item.value, item.name))
