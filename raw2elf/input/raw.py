"""Raw binary fallback.

Every input that no structured parser validates is a flat binary image with an
unknown load address.  ELF and a few other container magics are recognized so
the tool can say something useful instead of analysing a container as if it
were firmware.
"""

from __future__ import annotations

from ..core.image import FirmwareImage, FirmwareSegment
from .base import InputParser, ParseError, Sniff

#: Container magics worth naming when they turn up as "raw" firmware.
_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"hsqs", "squashfs"),
    (b"sqsh", "squashfs"),
    (b"UBI#", "ubi"),
    (b"\xd0\x0d\xfe\xed", "uimage"),
)


def container_magic(raw: bytes) -> str | None:
    for magic, name in _MAGICS:
        if raw.startswith(magic):
            return name
    return None


class RawBinaryParser(InputParser):
    name = "raw"
    label = "Raw binary"

    def sniff(self, raw: bytes) -> Sniff:
        if not raw:
            return Sniff(0.0, "empty input")
        # Lowest possible score: this parser is the fallback, never a winner
        # against a structured format that validated.
        return Sniff(0.01, f"{len(raw)} bytes")

    def parse(self, raw: bytes) -> FirmwareImage:
        if not raw:
            raise ParseError("input is empty")
        magic = container_magic(raw)
        return FirmwareImage(
            source_format=self.name,
            segments=(FirmwareSegment(image_offset=0, data=raw, address=None, file_offset=0),),
            metadata={"label": self.label, "bytes": len(raw), "container_magic": magic},
        )
