"""Small formatting and arithmetic helpers used across raw2elf."""

from __future__ import annotations

from typing import Any


def hexs(value: int | None, width: int = 0) -> str | None:
    """Render an integer as a fixed-width hexadecimal string."""
    if value is None:
        return None
    return f"0x{value:0{width}x}"


def fmt_value(value: Any) -> Any:
    """Render a value for a report: wide integers become hexadecimal."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return hexs(value, 8) if abs(value) > 0xFFFF else value
    if isinstance(value, (list, tuple)):
        return [fmt_value(item) for item in value]
    if isinstance(value, dict):
        return {key: fmt_value(item) for key, item in value.items()}
    return value


def align_down(value: int, alignment: int) -> int:
    return value - (value % alignment)


def align_up(value: int, alignment: int) -> int:
    return align_down(value + alignment - 1, alignment)


def is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def logistic(total: float, midpoint: float, steepness: float = 1.0) -> float:
    """Squash an unbounded evidence score into a 0..1 confidence.

    ``midpoint`` is the score that maps to 0.5; ``steepness`` controls how
    quickly confidence saturates.  Implemented without ``math.exp`` overflow
    for very negative totals.
    """
    import math

    exponent = -steepness * (total - midpoint)
    if exponent > 60:
        return 0.0
    if exponent < -60:
        return 1.0
    return 1.0 / (1.0 + math.exp(exponent))


def human_size(size: int) -> str:
    for unit, limit in (("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if size >= limit:
            scaled = size / limit
            return f"{scaled:.1f}{unit}" if scaled < 10 else f"{scaled:.0f}{unit}"
    return f"{size}B"
