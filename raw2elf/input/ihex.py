"""Intel HEX parser.

Records are validated structurally *and* by checksum before the format is
accepted, so a text file that merely contains colons cannot be mistaken for
firmware.  Surrounding log noise is tolerated only when the lines that do look
like records overwhelmingly validate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.image import FirmwareImage
from .base import AddressedChunk, InputParser, ParseError, Sniff, coalesce, decode_text

_RECORD = re.compile(r"^\s*:([0-9A-Fa-f]{2})([0-9A-Fa-f]{4})([0-9A-Fa-f]{2})((?:[0-9A-Fa-f]{2})*)([0-9A-Fa-f]{2})\s*$")

DATA = 0x00
END_OF_FILE = 0x01
EXTENDED_SEGMENT_ADDRESS = 0x02
START_SEGMENT_ADDRESS = 0x03
EXTENDED_LINEAR_ADDRESS = 0x04
START_LINEAR_ADDRESS = 0x05

_KNOWN_TYPES = frozenset(
    (
        DATA,
        END_OF_FILE,
        EXTENDED_SEGMENT_ADDRESS,
        START_SEGMENT_ADDRESS,
        EXTENDED_LINEAR_ADDRESS,
        START_LINEAR_ADDRESS,
    )
)


@dataclass
class _Record:
    line: int
    kind: int
    address: int
    data: bytes


@dataclass
class _Scan:
    records: list[_Record]
    candidate_lines: int
    invalid: list[str]
    other_lines: int
    saw_eof: bool


def _scan(text: str) -> _Scan:
    records: list[_Record] = []
    invalid: list[str] = []
    candidates = 0
    others = 0
    saw_eof = False

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith(":"):
            others += 1
            continue
        candidates += 1
        match = _RECORD.match(line)
        if match is None:
            invalid.append(f"line {number}: malformed record")
            continue
        count = int(match.group(1), 16)
        address = int(match.group(2), 16)
        kind = int(match.group(3), 16)
        payload = bytes.fromhex(match.group(4))
        checksum = int(match.group(5), 16)
        if len(payload) != count:
            invalid.append(f"line {number}: byte count {count} but {len(payload)} data bytes")
            continue
        total = count + (address >> 8) + (address & 0xFF) + kind + sum(payload)
        if (-total) & 0xFF != checksum:
            invalid.append(f"line {number}: bad checksum")
            continue
        if kind not in _KNOWN_TYPES:
            invalid.append(f"line {number}: unknown record type {kind:#04x}")
            continue
        if kind == END_OF_FILE:
            saw_eof = True
        records.append(_Record(number, kind, address, payload))

    return _Scan(records, candidates, invalid, others, saw_eof)


class IntelHexParser(InputParser):
    name = "ihex"
    label = "Intel HEX"
    addresses_declared = True

    def sniff(self, raw: bytes) -> Sniff:
        text = decode_text(raw)
        if text is None:
            return Sniff(0.0, "not text")
        scan = _scan(text)
        valid = len(scan.records)
        if valid < 2 or not any(record.kind == DATA for record in scan.records):
            return Sniff(0.0, "no valid Intel HEX data records")
        ratio = valid / max(scan.candidate_lines, 1)
        if ratio < 0.5:
            return Sniff(0.0, f"only {valid}/{scan.candidate_lines} record lines validate")
        confidence = 0.55 + 0.35 * ratio
        if scan.saw_eof:
            confidence += 0.08
        if scan.other_lines:
            confidence -= min(0.1, 0.02 * scan.other_lines)
        notes = list(scan.invalid[:8])
        if scan.other_lines:
            notes.append(f"{scan.other_lines} non-record line(s) ignored")
        return Sniff(min(confidence, 0.99), f"{valid} valid records", notes)

    def parse(self, raw: bytes) -> FirmwareImage:
        text = decode_text(raw)
        if text is None:
            raise ParseError("input is not text")
        scan = _scan(text)
        if not scan.records:
            raise ParseError("no valid Intel HEX records")

        notes = list(scan.invalid)
        if scan.other_lines:
            notes.append(f"{scan.other_lines} non-record line(s) ignored")
        if not scan.saw_eof:
            notes.append("no end-of-file record; input may be truncated")

        chunks: list[AddressedChunk] = []
        upper = 0
        entry = None
        for record in scan.records:
            if record.kind == DATA:
                chunks.append(AddressedChunk(upper + record.address, record.data))
            elif record.kind == EXTENDED_SEGMENT_ADDRESS:
                upper = int.from_bytes(record.data, "big") << 4
            elif record.kind == EXTENDED_LINEAR_ADDRESS:
                upper = int.from_bytes(record.data, "big") << 16
            elif record.kind == START_LINEAR_ADDRESS:
                entry = int.from_bytes(record.data, "big")
            elif record.kind == START_SEGMENT_ADDRESS and len(record.data) == 4:
                segment = int.from_bytes(record.data[:2], "big")
                pointer = int.from_bytes(record.data[2:], "big")
                entry = segment * 16 + pointer

        segments = coalesce(chunks, notes)
        if not segments:
            raise ParseError("Intel HEX contained no data bytes")
        return FirmwareImage(
            source_format=self.name,
            segments=segments,
            entry_hint=entry,
            metadata={
                "label": self.label,
                "records": len(scan.records),
                "notes": notes,
                "truncated": not scan.saw_eof,
            },
        )
