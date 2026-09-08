"""Parser for ``hexdump -C`` output.

The default ``hexdump`` format (16-bit groups, no ASCII column) is recognized
but deliberately refused: its groups are byte-swapped on little-endian hosts,
so accepting it would produce plausible-looking but wrong firmware.  The user
is told to re-dump with ``hexdump -C`` or ``xxd`` instead.
"""

from __future__ import annotations

import re
from typing import Optional

from ..core.image import FirmwareImage
from .base import InputParser, ParseError, Sniff, coalesce, decode_text
from ._dump import hex_tokens, scan

_ASCII_COLUMN = re.compile(r"\|.*\|?$")
#: ``0000000 6a2f 4320 ...`` -- default hexdump, byte-swapped 16-bit groups.
_SWAPPED_LINE = re.compile(r"^[ \t]*[0-9a-fA-F]{7,8}[ \t]+(?:[0-9a-fA-F]{4}[ \t]*){2,8}$")


def _extract(rest: str) -> Optional[bytes]:
    hex_field = _ASCII_COLUMN.sub("", rest).strip()
    return hex_tokens(hex_field, (2,))


def looks_byte_swapped(text: str) -> bool:
    """Detect default ``hexdump`` output, whose 16-bit groups are swapped."""
    lines = [line for line in text.splitlines() if line.strip() and line.strip() != "*"]
    if len(lines) < 3:
        return False
    matched = sum(1 for line in lines if _SWAPPED_LINE.match(line))
    return matched >= max(3, int(0.8 * len(lines)))


class HexdumpParser(InputParser):
    name = "hexdump"
    label = "hexdump -C"

    def _scan(self, raw: bytes):
        text = decode_text(raw)
        if text is None:
            return None, None
        return text, scan(text, _extract, wants_colon=False)

    def sniff(self, raw: bytes) -> Sniff:
        text, result = self._scan(raw)
        if result is None:
            return Sniff(0.0, "not text")
        if looks_byte_swapped(text):
            return Sniff(
                0.0,
                "this is default 'hexdump' output; its 16-bit groups are byte-swapped, so "
                "decoding it would silently produce wrong firmware. Re-dump with "
                "'hexdump -C' or 'xxd'",
                veto=True,
            )
        if result.data_lines < 2:
            return Sniff(0.0, "no hexdump -C data lines")
        if result.invalid:
            return Sniff(0.0, f"offset continuity broken: {result.invalid[0]}")
        ratio = result.data_lines / max(result.data_lines + result.other_lines, 1)
        if ratio < 0.5:
            return Sniff(0.0, "mostly non-dump lines")
        notes = []
        if result.other_lines:
            notes.append(f"{result.other_lines} surrounding line(s) ignored")
        if result.squeezed_bytes:
            notes.append(f"{result.squeezed_bytes} byte(s) expanded from repeat markers")
        return Sniff(min(0.6 + 0.35 * ratio, 0.98), f"{result.data_lines} dump lines", notes)

    def parse(self, raw: bytes) -> FirmwareImage:
        text, result = self._scan(raw)
        if result is None:
            raise ParseError("input is not text")
        if looks_byte_swapped(text):
            raise ParseError(
                "this is default 'hexdump' output; its 16-bit groups are byte-swapped. "
                "Re-dump with 'hexdump -C' or 'xxd'"
            )
        if not result.chunks:
            raise ParseError("input is not a hexdump -C dump")
        if result.invalid:
            raise ParseError("; ".join(result.invalid[:4]))
        notes = []
        if result.other_lines:
            notes.append(f"{result.other_lines} surrounding line(s) ignored")
        if result.squeezed_bytes:
            notes.append(f"{result.squeezed_bytes} byte(s) expanded from repeat markers")
        segments = coalesce(result.chunks, notes)
        segments = tuple(
            type(segment)(image_offset=segment.image_offset, data=segment.data, address=None,
                          file_offset=segment.address)
            for segment in segments
        )
        return FirmwareImage(
            source_format=self.name,
            segments=segments,
            metadata={"label": self.label, "dump_lines": result.data_lines, "notes": notes},
        )
