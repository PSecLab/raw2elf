"""Architecture-neutral firmware image representation.

An input container is normalized into an ordered list of segments rather than
one contiguous ``bytearray``, because Intel HEX and SREC routinely describe
discontiguous memory and flattening them would either invent padding or lose
the declared addresses.

Two coordinate systems exist:

``image offset``
    Offset into the normalized byte stream (the concatenation of all segment
    payloads, in order).  For a raw binary this is identical to the file
    offset.  Analyses that have not yet recovered a load address work here.

``runtime address``
    The address the bytes occupy on the target.  Known up-front for Intel HEX
    and SREC; recovered by analysis for raw binaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Optional


@dataclass(frozen=True)
class FirmwareSegment:
    """One contiguous run of firmware bytes."""

    image_offset: int
    data: bytes
    address: Optional[int] = None
    #: Offset in the original input file, when the container preserves one.
    file_offset: Optional[int] = None

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def image_end(self) -> int:
        return self.image_offset + len(self.data)

    @property
    def address_end(self) -> Optional[int]:
        return None if self.address is None else self.address + len(self.data)

    def contains_offset(self, offset: int) -> bool:
        return self.image_offset <= offset < self.image_end

    def contains_address(self, address: int) -> bool:
        return self.address is not None and self.address <= address < self.address + len(self.data)

    def read(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes at an image offset, clamped to this segment."""
        start = offset - self.image_offset
        if start < 0:
            raise ValueError(f"offset {offset:#x} precedes segment {self.image_offset:#x}")
        return self.data[start : start + size]


@dataclass
class FirmwareImage:
    """A normalized firmware input."""

    source_format: str
    segments: tuple[FirmwareSegment, ...]
    architecture_hint: Optional[str] = None
    entry_hint: Optional[int] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.segments = tuple(self.segments)
        self._stream: Optional[bytes] = None
        # Derived results keyed to *this* image's offsets.  Kept out of
        # ``metadata`` so that a carved sub-image cannot inherit conclusions
        # that were expressed in its parent's coordinate system.
        self._derived: dict[str, Any] = {}

    def derived(self, key: str, factory: Any) -> Any:
        """Memoize a value derived from this image's bytes and offsets."""
        if key not in self._derived:
            self._derived[key] = factory()
        return self._derived[key]

    # -- geometry ---------------------------------------------------------

    @property
    def size(self) -> int:
        """Length of the normalized byte stream."""
        return sum(segment.size for segment in self.segments)

    @property
    def addresses_declared(self) -> bool:
        """True when the container declared a load address for every segment."""
        return bool(self.segments) and all(segment.address is not None for segment in self.segments)

    @property
    def declared_span(self) -> Optional[tuple[int, int]]:
        if not self.addresses_declared:
            return None
        starts = [segment.address for segment in self.segments]
        ends = [segment.address_end for segment in self.segments]
        return min(starts), max(ends)

    @property
    def stream(self) -> bytes:
        """The concatenated payload of every segment.

        Only meaningful for scanning; reads that must not cross a segment
        boundary should use :meth:`read` instead.
        """
        if self._stream is None:
            self._stream = b"".join(segment.data for segment in self.segments)
        return self._stream

    # -- access -----------------------------------------------------------

    def segment_at_offset(self, offset: int) -> Optional[FirmwareSegment]:
        for segment in self.segments:
            if segment.contains_offset(offset):
                return segment
        return None

    def segment_at_address(self, address: int) -> Optional[FirmwareSegment]:
        for segment in self.segments:
            if segment.contains_address(address):
                return segment
        return None

    def read(self, offset: int, size: int) -> bytes:
        """Read at an image offset without crossing a segment boundary."""
        segment = self.segment_at_offset(offset)
        if segment is None:
            return b""
        return segment.read(offset, size)

    def declared_address_for(self, offset: int) -> Optional[int]:
        segment = self.segment_at_offset(offset)
        if segment is None or segment.address is None:
            return None
        return segment.address + (offset - segment.image_offset)

    def iter_segments(self) -> Iterator[FirmwareSegment]:
        return iter(self.segments)

    def summary(self) -> dict[str, Any]:
        return {
            "format": self.source_format,
            "segments": len(self.segments),
            "size": self.size,
            "addresses_declared": self.addresses_declared,
        }

    def subimage(self, offset: int, size: int) -> "FirmwareImage":
        """A view of ``size`` bytes starting at an image offset.

        Offsets in the result restart at zero, so a carved candidate image can
        be analysed exactly like a standalone input.  ``file_offset`` keeps the
        provenance needed to report where the bytes came from.
        """
        parts: list[FirmwareSegment] = []
        cursor = 0
        end = offset + size
        for segment in self.segments:
            lo = max(segment.image_offset, offset)
            hi = min(segment.image_end, end)
            if lo >= hi:
                continue
            payload = segment.data[lo - segment.image_offset : hi - segment.image_offset]
            base_file = segment.file_offset if segment.file_offset is not None else segment.image_offset
            parts.append(
                FirmwareSegment(
                    image_offset=cursor,
                    data=payload,
                    address=None if segment.address is None else segment.address + (lo - segment.image_offset),
                    file_offset=base_file + (lo - segment.image_offset),
                )
            )
            cursor += hi - lo
        return FirmwareImage(
            source_format=self.source_format,
            segments=tuple(parts),
            architecture_hint=self.architecture_hint,
            entry_hint=self.entry_hint,
            metadata=dict(self.metadata, carved_from_offset=offset),
        )
