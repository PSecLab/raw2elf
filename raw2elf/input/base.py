"""Input parser interface and shared helpers.

Every parser answers two questions independently: "is this my format?"
(:meth:`InputParser.sniff`) and "give me the bytes" (:meth:`InputParser.parse`).
Sniffing returns a confidence rather than a boolean so that detection can rank
formats instead of relying on the order in which parsers happen to be tried.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..core.image import FirmwareImage, FirmwareSegment


class ParseError(ValueError):
    """Raised when a parser recognizes its format but the content is invalid."""


@dataclass
class Sniff:
    """A parser's opinion about an input."""

    confidence: float
    detail: str = ""
    notes: list[str] = field(default_factory=list)
    #: Set when the parser recognizes this framing but refuses to decode it.
    #: Detection then reports ``detail`` instead of silently falling back to a
    #: raw binary, because the fallback would be wrong in a way that is hard
    #: for an analyst to notice.
    veto: bool = False

    def __bool__(self) -> bool:
        return self.confidence > 0.0


class InputParser:
    """Base class for input format parsers."""

    #: Stable identifier accepted by ``--input-format``.
    name: str = ""
    #: Human-readable label used in reports.
    label: str = ""
    #: True for formats that carry explicit load addresses.
    addresses_declared: bool = False

    def sniff(self, raw: bytes) -> Sniff:  # pragma: no cover - abstract
        raise NotImplementedError

    def parse(self, raw: bytes) -> FirmwareImage:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class AddressedChunk:
    """A run of bytes at an explicit address, before coalescing."""

    address: int
    data: bytes


def coalesce(chunks: list[AddressedChunk], notes: list[str]) -> tuple[FirmwareSegment, ...]:
    """Merge addressed chunks into the fewest contiguous segments.

    Later chunks win where records overlap, which matches how a flash
    programmer would apply them, and the overlap is reported rather than
    silently accepted.
    """
    if not chunks:
        return ()

    written: dict[int, int] = {}
    overlaps = 0
    for chunk in chunks:
        for index, byte in enumerate(chunk.data):
            address = chunk.address + index
            if address in written and written[address] != byte:
                overlaps += 1
            written[address] = byte
    if overlaps:
        notes.append(f"{overlaps} byte(s) written more than once with differing values")

    segments: list[FirmwareSegment] = []
    image_offset = 0
    run_start: Optional[int] = None
    run: bytearray = bytearray()
    for address in sorted(written):
        if run_start is not None and address != run_start + len(run):
            segments.append(
                FirmwareSegment(image_offset=image_offset, data=bytes(run), address=run_start)
            )
            image_offset += len(run)
            run = bytearray()
            run_start = None
        if run_start is None:
            run_start = address
        run.append(written[address])
    if run_start is not None:
        segments.append(FirmwareSegment(image_offset=image_offset, data=bytes(run), address=run_start))
    return tuple(segments)


def decode_text(raw: bytes) -> Optional[str]:
    """Decode input as text, or ``None`` when it is clearly binary.

    A NUL byte or a high proportion of non-text bytes means no text parser
    should even be attempted.
    """
    if b"\x00" in raw[:65536]:
        return None
    sample = raw[:65536]
    if not sample:
        return None
    printable = sum(1 for byte in sample if 0x20 <= byte < 0x7F or byte in (9, 10, 13))
    if printable / len(sample) < 0.98:
        return None
    try:
        return raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
