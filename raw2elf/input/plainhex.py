"""Parser for bare hexadecimal byte streams.

Accepted shapes include ``xxd -p`` output, whitespace- or comma-separated
bytes, colon-separated bytes and C array initializers (``0x48, 0x65,``).

The whole line must consist of hex digits and recognized separators.  Text
containing anything else is rejected outright rather than filtered, because
deleting unexpected characters from an unknown file turns malformed input into
firmware that looks fine and is wrong.  Inputs that begin like Intel HEX or
S-Records are also rejected here so that a *corrupt* record file can never be
salvaged into a plausible byte stream by dropping its framing.
"""

from __future__ import annotations

import re
from typing import Optional

from ..core.image import FirmwareImage, FirmwareSegment
from .base import InputParser, ParseError, Sniff, decode_text

#: Everything permitted anywhere in the stream.
_ALLOWED = re.compile(r"^[0-9a-fA-F\s,;:_xX]*$")
_SEPARATORS = re.compile(r"[\s,;:_]+")
_RECORD_LIKE = re.compile(r"^\s*(?::[0-9a-fA-F]{8}|[Ss][0-9][0-9a-fA-F]{2})")

MINIMUM_BYTES = 16


def _decode(text: str) -> tuple[Optional[bytes], str]:
    if not _ALLOWED.match(text):
        offender = next((ch for ch in text if not _ALLOWED.match(ch)), "?")
        return None, f"unexpected character {offender!r}"
    for line in text.splitlines():
        if _RECORD_LIKE.match(line):
            return None, "input is framed like Intel HEX or S-Records, not a bare hex stream"

    payload = bytearray()
    for token in _SEPARATORS.split(text.strip()):
        if not token:
            continue
        prefixed = token[:2] in ("0x", "0X")
        digits = token[2:] if prefixed else token
        if not digits or not all(ch in "0123456789abcdefABCDEF" for ch in digits):
            return None, f"token {token!r} is not hexadecimal"
        if len(digits) % 2:
            if not prefixed or len(digits) != 1:
                return None, f"token {token!r} has an odd number of hex digits"
            digits = "0" + digits
        payload += bytes.fromhex(digits)

    if len(payload) < MINIMUM_BYTES:
        return None, f"only {len(payload)} byte(s) decoded"
    return bytes(payload), f"{len(payload)} bytes"


class PlainHexParser(InputParser):
    name = "plainhex"
    label = "plain hexadecimal stream"

    def sniff(self, raw: bytes) -> Sniff:
        text = decode_text(raw)
        if text is None:
            return Sniff(0.0, "not text")
        payload, detail = _decode(text)
        if payload is None:
            return Sniff(0.0, detail)
        return Sniff(0.7, detail)

    def parse(self, raw: bytes) -> FirmwareImage:
        text = decode_text(raw)
        if text is None:
            raise ParseError("input is not text")
        payload, detail = _decode(text)
        if payload is None:
            raise ParseError(detail)
        return FirmwareImage(
            source_format=self.name,
            segments=(FirmwareSegment(image_offset=0, data=payload, address=None, file_offset=0),),
            metadata={"label": self.label, "bytes": len(payload)},
        )
