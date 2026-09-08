"""Input normalization: strict format detection and parsing.

Detection tries explicit parsers, each of which validates structure and (for
Intel HEX and S-Records) checksums, before anything is treated as a raw
binary.  A parser that recognizes its framing but finds it corrupt reports
zero confidence rather than repairing the input.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..core.image import FirmwareImage
from .base import InputParser, ParseError, Sniff
from .hexdump import HexdumpParser
from .ihex import IntelHexParser
from .plainhex import PlainHexParser
from .raw import RawBinaryParser, container_magic
from .srec import SRecParser
from .xxd import XxdParser

#: Detection order.  Structured, checksum-validated formats first; the raw
#: fallback last.
PARSERS: tuple[InputParser, ...] = (
    IntelHexParser(),
    SRecParser(),
    XxdParser(),
    HexdumpParser(),
    PlainHexParser(),
    RawBinaryParser(),
)

_BY_NAME = {parser.name: parser for parser in PARSERS}


@dataclass
class Detection:
    parser: InputParser
    sniff: Sniff


def format_names() -> list[str]:
    return [parser.name for parser in PARSERS]


def detect(raw: bytes) -> list[Detection]:
    """Rank every parser's opinion of ``raw``, best first."""
    results = [Detection(parser, parser.sniff(raw)) for parser in PARSERS]
    return sorted(results, key=lambda item: item.sniff.confidence, reverse=True)


def parse(raw: bytes, input_format: Optional[str] = None) -> FirmwareImage:
    """Normalize ``raw`` into a :class:`FirmwareImage`.

    ``input_format`` forces a parser and bypasses detection, which is how an
    analyst overrules a wrong guess.
    """
    if input_format:
        if input_format not in _BY_NAME:
            known = ", ".join(format_names())
            raise ParseError(f"unknown input format {input_format!r}; known formats: {known}")
        return _BY_NAME[input_format].parse(raw)

    magic = container_magic(raw)
    if magic == "elf":
        raise ParseError(
            "input is already an ELF file; raw2elf reconstructs ELFs from raw dumps. "
            "Extract the firmware bytes first (objcopy -O binary), or pass "
            "--input-format raw to analyse the container bytes anyway"
        )

    ranked = detect(raw)
    vetoed = [item for item in ranked if item.sniff.veto]
    if vetoed:
        raise ParseError(vetoed[0].sniff.detail)
    for detection in ranked:
        if detection.sniff.confidence <= 0.0:
            continue
        try:
            image = detection.parser.parse(raw)
        except ParseError:
            continue
        image.metadata.setdefault("detection", detection.sniff.detail)
        image.metadata["detection_confidence"] = detection.sniff.confidence
        image.metadata["detection_ranking"] = [
            (item.parser.name, round(item.sniff.confidence, 3))
            for item in ranked
            if item.sniff.confidence > 0
        ]
        if magic and magic != "raw":
            image.metadata.setdefault("container_magic", magic)
        return image
    raise ParseError("no input parser could read this file")


def load(path: str | Path, input_format: Optional[str] = None) -> FirmwareImage:
    """Read a file and normalize it."""
    data = Path(path).read_bytes()
    image = parse(data, input_format=input_format)
    image.metadata["source_path"] = str(path)
    image.metadata["source_bytes"] = len(data)
    return image


__all__ = [
    "PARSERS",
    "Detection",
    "InputParser",
    "ParseError",
    "detect",
    "format_names",
    "load",
    "parse",
]
