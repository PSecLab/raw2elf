"""Motorola S-Record parser.

``S1``/``S2``/``S3`` data records are supported along with the header, count
and termination records; every record's checksum is verified before the format
is accepted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.image import FirmwareImage
from .base import AddressedChunk, InputParser, ParseError, Sniff, coalesce, decode_text

_RECORD = re.compile(r"^\s*[Ss]([0-9])([0-9A-Fa-f]{2})((?:[0-9A-Fa-f]{2})+)\s*$")

#: Address field width in bytes, by record digit.
_ADDRESS_WIDTH = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}
_DATA_TYPES = frozenset((1, 2, 3))
_TERMINATION_TYPES = frozenset((7, 8, 9))


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
    header: str
    declared_count: int | None
    saw_termination: bool


def _scan(text: str) -> _Scan:
    records: list[_Record] = []
    invalid: list[str] = []
    candidates = 0
    others = 0
    header = ""
    declared_count = None
    saw_termination = False

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped[:1] in ("S", "s"):
            others += 1
            continue
        candidates += 1
        match = _RECORD.match(line)
        if match is None:
            invalid.append(f"line {number}: malformed record")
            continue
        kind = int(match.group(1))
        count = int(match.group(2), 16)
        payload = bytes.fromhex(match.group(3))
        if kind == 4 or kind not in _ADDRESS_WIDTH:
            invalid.append(f"line {number}: unsupported record type S{kind}")
            continue
        if len(payload) != count:
            invalid.append(f"line {number}: byte count {count} but {len(payload)} bytes follow")
            continue
        width = _ADDRESS_WIDTH[kind]
        if count < width + 1:
            invalid.append(f"line {number}: record too short for an S{kind} address")
            continue
        checksum = payload[-1]
        body = payload[:-1]
        if (0xFF - ((count + sum(body)) & 0xFF)) & 0xFF != checksum:
            invalid.append(f"line {number}: bad checksum")
            continue
        address = int.from_bytes(body[:width], "big")
        data = body[width:]
        if kind == 0:
            header = data.decode("ascii", errors="replace").rstrip("\x00")
        elif kind in (5, 6):
            declared_count = address
        elif kind in _TERMINATION_TYPES:
            saw_termination = True
        records.append(_Record(number, kind, address, data))

    return _Scan(records, candidates, invalid, others, header, declared_count, saw_termination)


class SRecParser(InputParser):
    name = "srec"
    label = "Motorola S-Record"
    addresses_declared = True

    def sniff(self, raw: bytes) -> Sniff:
        text = decode_text(raw)
        if text is None:
            return Sniff(0.0, "not text")
        scan = _scan(text)
        data_records = [record for record in scan.records if record.kind in _DATA_TYPES]
        if len(data_records) < 2:
            return Sniff(0.0, "no valid S-Record data records")
        ratio = len(scan.records) / max(scan.candidate_lines, 1)
        if ratio < 0.5:
            return Sniff(0.0, f"only {len(scan.records)}/{scan.candidate_lines} record lines validate")
        confidence = 0.55 + 0.35 * ratio
        if scan.saw_termination:
            confidence += 0.08
        if scan.other_lines:
            confidence -= min(0.1, 0.02 * scan.other_lines)
        notes = list(scan.invalid[:8])
        return Sniff(min(confidence, 0.99), f"{len(data_records)} data records", notes)

    def parse(self, raw: bytes) -> FirmwareImage:
        text = decode_text(raw)
        if text is None:
            raise ParseError("input is not text")
        scan = _scan(text)
        data_records = [record for record in scan.records if record.kind in _DATA_TYPES]
        if not data_records:
            raise ParseError("no valid S-Record data records")

        notes = list(scan.invalid)
        if scan.other_lines:
            notes.append(f"{scan.other_lines} non-record line(s) ignored")
        if not scan.saw_termination:
            notes.append("no termination record; input may be truncated")
        if scan.declared_count is not None and scan.declared_count != len(data_records):
            notes.append(
                f"record count says {scan.declared_count} data records but {len(data_records)} were read"
            )

        entry = None
        for record in scan.records:
            if record.kind in _TERMINATION_TYPES and record.address:
                entry = record.address

        segments = coalesce([AddressedChunk(item.address, item.data) for item in data_records], notes)
        if not segments:
            raise ParseError("S-Record contained no data bytes")
        return FirmwareImage(
            source_format=self.name,
            segments=segments,
            entry_hint=entry,
            metadata={
                "label": self.label,
                "records": len(data_records),
                "header": scan.header,
                "notes": notes,
                "truncated": not scan.saw_termination,
            },
        )
