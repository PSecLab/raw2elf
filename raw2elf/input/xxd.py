"""Parser for ``xxd`` output.

Handles the default two-byte grouping, ``-g1``/``-g4`` groupings, non-default
column counts and ``-a`` repeat squeezing.  The ASCII column is separated from
the hex field by at least two spaces, which is how it is located and dropped.
"""

from __future__ import annotations

import re
from typing import Optional

from ..core.image import FirmwareImage
from .base import InputParser, ParseError, Sniff, coalesce, decode_text
from ._dump import hex_tokens, scan

_ASCII_SEPARATOR = re.compile(r"[ \t]{2,}")
_GROUP_WIDTHS = (2, 4, 8, 16, 32)


def _extract(rest: str) -> Optional[bytes]:
    hex_field = _ASCII_SEPARATOR.split(rest, maxsplit=1)[0]
    return hex_tokens(hex_field, _GROUP_WIDTHS)


class XxdParser(InputParser):
    name = "xxd"
    label = "xxd hexdump"

    def _scan(self, raw: bytes):
        text = decode_text(raw)
        if text is None:
            return None, None
        return text, scan(text, _extract, wants_colon=True)

    def sniff(self, raw: bytes) -> Sniff:
        text, result = self._scan(raw)
        if result is None:
            return Sniff(0.0, "not text")
        if result.data_lines < 2:
            return Sniff(0.0, "no xxd data lines")
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
        if result is None or not result.chunks:
            raise ParseError("input is not an xxd dump")
        if result.invalid:
            raise ParseError("; ".join(result.invalid[:4]))
        notes = []
        if result.other_lines:
            notes.append(f"{result.other_lines} surrounding line(s) ignored")
        if result.squeezed_bytes:
            notes.append(f"{result.squeezed_bytes} byte(s) expanded from repeat markers")
        segments = coalesce(result.chunks, notes)
        # xxd offsets are file offsets, not load addresses.
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
