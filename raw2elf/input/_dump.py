"""Shared scanning logic for annotated terminal hexdumps.

The address prefix and the ASCII column are parsed and discarded explicitly
rather than by stripping non-hexadecimal characters from the text: the ASCII
column is full of characters that look like hex digits, and deleting
"non-hex" text from a dump is a reliable way to produce corrupted firmware.

The declared offsets are then used as a checksum of sorts -- each line's
offset must equal the previous offset plus the previous line's byte count --
which is what makes these parsers safe to try before falling back to raw
binary.  Repeat markers (``*``) are expanded using the offset arithmetic, so a
squeezed dump round-trips exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .base import AddressedChunk

#: ``offset`` followed by the rest of the line.
LINE = re.compile(r"^[ \t]*([0-9a-fA-F]{4,16})(:?)[ \t]+(.*?)[ \t]*$")
#: A line that is only an offset, as printed at the end of a hexdump.
TAIL = re.compile(r"^[ \t]*([0-9a-fA-F]{4,16})[ \t]*$")

#: Extracts firmware bytes from the portion of a line after the offset, or
#: returns ``None`` if that portion does not fit the format.
Extractor = Callable[[str], Optional[bytes]]


@dataclass
class DumpScan:
    chunks: list[AddressedChunk] = field(default_factory=list)
    data_lines: int = 0
    other_lines: int = 0
    invalid: list[str] = field(default_factory=list)
    squeezed_bytes: int = 0
    total_bytes: int = 0
    declared_end: Optional[int] = None

    @property
    def valid(self) -> bool:
        return self.data_lines >= 2 and not self.invalid


def scan(text: str, extract: Extractor, wants_colon: bool) -> DumpScan:
    """Parse an annotated hexdump into addressed chunks.

    ``wants_colon`` selects between the ``xxd`` (``offset:``) and
    ``hexdump -C`` (``offset``) prefix conventions so the two formats cannot
    silently claim each other's input.
    """
    result = DumpScan()
    chunks: list[AddressedChunk] = []
    expected: Optional[int] = None
    previous: Optional[bytes] = None
    pending_squeeze = False

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "*":
            if previous is None:
                result.invalid.append(f"line {number}: repeat marker before any data")
                continue
            pending_squeeze = True
            continue

        match = LINE.match(line)
        if match is None or bool(match.group(2)) != wants_colon:
            tail = TAIL.match(line)
            if tail is not None and expected is not None and not wants_colon:
                # hexdump prints the total length as a bare offset.
                result.declared_end = int(tail.group(1), 16)
                continue
            result.other_lines += 1
            continue

        payload = extract(match.group(3))
        if payload is None:
            result.other_lines += 1
            continue

        offset = int(match.group(1), 16)
        if expected is None:
            expected = offset
        elif offset != expected:
            gap = offset - expected
            if pending_squeeze and previous and gap > 0 and gap % len(previous) == 0:
                repeats = gap // len(previous)
                for index in range(repeats):
                    chunks.append(AddressedChunk(expected + index * len(previous), previous))
                result.squeezed_bytes += gap
                expected = offset
            else:
                result.invalid.append(
                    f"line {number}: offset {offset:#x} but {expected:#x} expected"
                )
                expected = offset
        pending_squeeze = False

        if payload:
            chunks.append(AddressedChunk(offset, payload))
            result.data_lines += 1
            previous = payload
            expected = offset + len(payload)

    if pending_squeeze and previous and result.declared_end is not None and expected is not None:
        gap = result.declared_end - expected
        if gap > 0 and gap % len(previous) == 0:
            for index in range(gap // len(previous)):
                chunks.append(AddressedChunk(expected + index * len(previous), previous))
            result.squeezed_bytes += gap
            expected = result.declared_end

    if (
        result.declared_end is not None
        and expected is not None
        and result.declared_end != expected
    ):
        result.invalid.append(
            f"trailing length {result.declared_end:#x} disagrees with {expected:#x} of data"
        )

    result.chunks = chunks
    result.total_bytes = sum(len(chunk.data) for chunk in chunks)
    return result


def hex_tokens(text: str, allowed_widths: tuple[int, ...]) -> Optional[bytes]:
    """Decode whitespace-separated hex groups of the given widths."""
    if not text:
        return b""
    payload = bytearray()
    for token in text.split():
        if len(token) not in allowed_widths or len(token) % 2:
            return None
        try:
            payload += bytes.fromhex(token)
        except ValueError:
            return None
    return bytes(payload)
