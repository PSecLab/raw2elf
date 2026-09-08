"""What a part number tells you that the image does not.

An analyst looking at a board can read the part number off the package. That
one fact -- which no amount of static analysis can recover, and which CMSIS-SVD
does not carry, because it describes peripherals rather than memory -- pins
down where the family maps Flash and SRAM, which is exactly what base recovery
is otherwise guessing at.

The knowledge lives in ``device_layouts.json`` rather than in code, so it is
data to be corrected rather than logic to be edited, and so this module holds
no addresses of its own.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

LAYOUTS = Path(__file__).with_name("device_layouts.json")
#: Fewer shared characters than this is too vague to act on.
MIN_SHARED = 4
#: Agreement required stops growing past here, so a full order code still
#: matches the shorter name an SVD file uses.
FAMILY_DEPTH = 9


@dataclass(frozen=True)
class DeviceLayout:
    """Where a family maps its memories."""

    family: str
    #: Addresses the family maps Flash at, most likely first.
    flash: tuple[int, ...] = ()
    #: Addresses the family maps SRAM at.
    ram: tuple[int, ...] = ()
    note: str = ""
    #: The part number this was matched from.
    matched: str = ""

    def describe(self) -> str:
        places = ", ".join(f"{item:#010x}" for item in self.flash)
        detail = f" ({self.note})" if self.note else ""
        return f"the {self.family} family maps Flash at {places}{detail}"


@lru_cache(maxsize=1)
def _families() -> list[dict]:
    try:
        payload = json.loads(LAYOUTS.read_text())
    except (OSError, ValueError):  # pragma: no cover - shipped with the package
        return []
    # Longest prefix first, so STM32 does not shadow a more specific entry and
    # MKL is preferred over MK.
    return sorted(payload.get("families", []), key=lambda item: -len(item["prefix"]))


def normalise(name: str) -> str:
    """Reduce a part number to something comparable.

    Package, temperature and speed suffixes vary per order code and say
    nothing about the memory map, so only the leading alphanumerics matter.
    """
    return re.sub(r"[^A-Z0-9]", "", (name or "").upper())


def layout_for(name: str) -> Optional[DeviceLayout]:
    """The memory layout implied by a part number, if the family is known."""
    normalised = normalise(name)
    if not normalised:
        return None
    for entry in _families():
        if normalised.startswith(normalise(entry["prefix"])):
            return DeviceLayout(
                family=entry["family"],
                flash=tuple(int(item, 16) for item in entry.get("flash", ())),
                ram=tuple(int(item, 16) for item in entry.get("ram", ())),
                note=entry.get("note", ""),
                matched=name,
            )
    return None


def known_families() -> list[str]:
    return sorted({entry["family"] for entry in _families()})


def search(name: str, devices, limit: Optional[int] = None) -> list:
    """Devices from an SVD index whose names plausibly match ``name``.

    Matching is loose on purpose, in both directions. What is printed on a
    package carries suffixes no SVD file names, and often only part of it is
    legible; an analyst should not have to know which part to type, nor be
    expected to read the whole thing.

    ``limit`` is for display. Leave it unset when narrowing the search: a
    family-level answer such as "STM32G" matches dozens of devices, and
    cutting the list would silently exclude whole sub-families before the
    recovered accesses ever got a say.
    """
    normalised = normalise(name)
    if not normalised:
        return []

    scored: list[tuple[int, int, object]] = []
    for device in devices:
        candidate = normalise(device.name)
        if not candidate:
            continue
        shared = _common_prefix(normalised, candidate)
        # How much agreement is required scales with how much was typed, so a
        # family answer stays inside its family -- "STM32G4" must not reach
        # STM32F0, which shares only "STM32". Beyond a few characters the
        # requirement stops growing, because order codes and SVD names
        # diverge in their tails: STM32G474RET6 should still find
        # STM32G474xx, and nRF52840 should still find an SVD named nrf52.
        required = max(MIN_SHARED, min(len(normalised), len(candidate), FAMILY_DEPTH))
        if shared < required:
            continue
        # Prefer the longest agreement, then the closest length.
        scored.append((-shared, abs(len(candidate) - len(normalised)), device))

    scored.sort(key=lambda item: (item[0], item[1], getattr(item[2], "name", "")))
    ordered = [device for _shared, _delta, device in scored]
    return ordered if limit is None else ordered[:limit]


def _common_prefix(left: str, right: str) -> int:
    """Length of the shared prefix, treating ``X`` as a wildcard.

    CMSIS-SVD names use it that way -- LPC176x, STM32G474xx, STM32F072x --
    so a real part number would otherwise fail to match the file describing
    it. Order codes occasionally carry it too, so it works from either side.
    """
    length = 0
    for a, b in zip(left, right):
        if a != b and a != "X" and b != "X":
            break
        length += 1
    return length
