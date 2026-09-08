"""CMSIS-SVD correlation: MCU ranking and peripheral annotation.

This stage is enrichment.  It runs on recovered MMIO accesses -- effective
addresses that instructions actually computed -- and never blocks ELF
generation: a missing SVD database, an unparseable file or an ambiguous result
all degrade to "unknown MCU".

Matching happens in two stages because a full register-level index of every
vendor SVD is far too large to keep around.  A cheap index of peripheral base
addresses and interrupt numbers shortlists devices; the shortlisted SVDs are
then parsed in full so register offsets, access direction and access width can
separate the survivors.

Many parts share an effectively identical peripheral map.  When the shortlist
cannot be separated, the answer reported is the family the tied devices share,
not an arbitrary part number from the middle of it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from ..core.evidence import Evidence
from ..core.pipeline import AnalysisContext, AnalysisPass
from ..core.reference import Access
from ..core.util import hexs
from .devices import normalise, search
from .svdsource import SvdSource, default_cache_directory, open_source

#: Default window when a peripheral declares no address block.  Kept tight:
#: a generous default makes neighbouring peripherals overlap, and an access
#: then gets attributed to whichever one happens to be listed first.
DEFAULT_PERIPHERAL_WINDOW = 0x400
#: Spacing Cortex-M vendors use between peripheral register blocks.  Used to
#: recover the peripheral base an access belongs to when the compiler kept a
#: rounded base in the register and folded the rest into the displacement --
#: "ldr r3, =0x40023000; str r2, [r3, #0x800]" is an access to the peripheral
#: at 0x40023800, not to one at 0x40023000.
PERIPHERAL_STRIDE = 0x400
#: Devices always taken through register-level scoring.
SHORTLIST = 12
#: Hard cap on register-level scoring, to bound work on huge tie sets.
MAX_SHORTLIST = 64
#: Fewer distinct peripheral addresses than this cannot identify a part.
MIN_ACCESSES = 4
#: Scores within this margin are treated as indistinguishable.
TIE_MARGIN = 0.02
#: A family name shorter than this is not informative enough to report.
MIN_FAMILY_PREFIX = 4

_INDEX_VERSION = 5


@dataclass(frozen=True)
class Peripheral:
    name: str
    base: int
    window: int = DEFAULT_PERIPHERAL_WINDOW
    group: str = ""


@dataclass(frozen=True)
class Interrupt:
    name: str
    value: int


@dataclass
class Device:
    """The cheap index entry for one SVD file."""

    name: str
    vendor: str
    #: Opaque handle the source understands; a path, or a path within a repo.
    locator: str
    cpu: str = ""
    peripherals: tuple[Peripheral, ...] = ()
    interrupts: tuple[Interrupt, ...] = ()

    def peripheral_for(self, address: int) -> Optional[Peripheral]:
        best: Optional[Peripheral] = None
        for peripheral in self.peripherals:
            if peripheral.base <= address < peripheral.base + peripheral.window:
                if best is None or peripheral.base > best.base:
                    best = peripheral
        return best

    @property
    def bases(self) -> frozenset[int]:
        if self._bases is None:
            self._bases = frozenset(item.base for item in self.peripherals)
        return self._bases

    def __post_init__(self) -> None:
        self._bases: Optional[frozenset[int]] = None


@dataclass(frozen=True)
class Register:
    peripheral: str
    name: str
    address: int
    width: int
    access: str

    @property
    def readable(self) -> bool:
        return self.access in ("", "read-only", "read-write", "read-writeOnce")

    @property
    def writable(self) -> bool:
        return self.access in ("", "write-only", "read-write", "writeOnce", "read-writeOnce")


def _integer(text: str) -> Optional[int]:
    text = text.strip()
    if not text:
        return None
    try:
        if text[:2].lower() == "0x":
            return int(text, 16)
        if text[:2].lower() == "0b":
            return int(text[2:], 2)
        if text.startswith("#"):
            return int(text[1:].replace("x", "0"), 2)
        return int(text, 0)
    except ValueError:
        return None


# -- indexing --------------------------------------------------------------


#: Matches a peripheral's opening tag; the header that follows holds the
#: name and base address.
_PERIPHERAL_TAG = re.compile(r"<peripheral\b[^>]*>")
_NAME = re.compile(r"<name>([^<]+)</name>")
_BASE_ADDRESS = re.compile(r"<baseAddress>([^<]+)</baseAddress>")
_GROUP_NAME = re.compile(r"<groupName>([^<]+)</groupName>")
_BLOCK_SIZE = re.compile(r"<addressBlock>.*?<size>([^<]+)</size>", re.DOTALL)
_INTERRUPT = re.compile(
    r"<interrupt>\s*(?:<name>([^<]+)</name>\s*)?(?:<description>[^<]*</description>\s*)?"
    r"(?:<name>([^<]+)</name>\s*)?<value>\s*(\d+)\s*</value>",
    re.DOTALL,
)
_CPU_NAME = re.compile(r"<cpu>.*?<name>([^<]+)</name>", re.DOTALL)


def parse_index_entry(
    text: str, vendor: str = "", name_hint: str = "", locator: str = ""
) -> Optional[Device]:
    """Extract peripheral bases and interrupt numbers from one SVD file.

    The vendor database is several gigabytes of XML whose bulk is register and
    field documentation, and building a DOM for all of it costs minutes.  Only
    each peripheral's *header* -- the part before its ``<registers>`` -- is
    needed here, so the header is located by text search and read with small
    expressions.  The shortlisted devices are parsed properly later, where
    correctness around clusters and derived peripherals actually matters.
    """
    if "<device" not in text or "<peripheral" not in text:
        return None

    starts = [match.end() for match in _PERIPHERAL_TAG.finditer(text)]
    if not starts:
        return None

    peripherals: list[Peripheral] = []
    for index, start in enumerate(starts):
        limit = starts[index + 1] if index + 1 < len(starts) else len(text)
        registers = text.find("<registers", start)
        if 0 <= registers < limit:
            limit = registers
        header = text[start:limit]
        name = _NAME.search(header)
        base = _BASE_ADDRESS.search(header)
        if name is None or base is None:
            continue
        address = _integer(base.group(1))
        if address is None:
            continue
        window = DEFAULT_PERIPHERAL_WINDOW
        block = _BLOCK_SIZE.search(header)
        if block is not None:
            size = _integer(block.group(1))
            if size:
                window = size
        group = _GROUP_NAME.search(header)
        peripherals.append(
            Peripheral(
                name=name.group(1).strip(),
                base=address,
                window=window,
                group=group.group(1).strip() if group else "",
            )
        )
    if not peripherals:
        return None

    interrupts: dict[int, str] = {}
    for match in _INTERRUPT.finditer(text):
        label = match.group(1) or match.group(2)
        if not label:
            continue
        interrupts.setdefault(int(match.group(3)), label.strip())

    device = _NAME.search(text[: starts[0]])
    cpu = _CPU_NAME.search(text[: starts[0]])
    return Device(
        name=device.group(1).strip() if device else name_hint,
        vendor=vendor,
        locator=locator,
        cpu=cpu.group(1).strip() if cpu else "",
        peripherals=tuple(peripherals),
        interrupts=tuple(Interrupt(name, value) for value, name in sorted(interrupts.items())),
    )


_REGISTERS_OPEN = re.compile(r"<registers>")
_REGISTER = re.compile(r"<register\b[^>]*>(.*?)</register>", re.DOTALL)
_CLUSTER = re.compile(r"<cluster\b[^>]*>(.*?)</cluster>", re.DOTALL)
_ADDRESS_OFFSET = re.compile(r"<addressOffset>([^<]+)</addressOffset>")
_SIZE = re.compile(r"<size>([^<]+)</size>")
_ACCESS = re.compile(r"<access>([^<]+)</access>")
_DIM = re.compile(r"<dim>([^<]+)</dim>")
_DIM_INCREMENT = re.compile(r"<dimIncrement>([^<]+)</dimIncrement>")
_DIM_INDEX = re.compile(r"<dimIndex>([^<]+)</dimIndex>")
_DERIVED_FROM = re.compile(r'derivedFrom\s*=\s*"([^"]+)"')


@dataclass(frozen=True)
class _Span:
    """Where one peripheral's header and register list live in a file."""

    name: str
    base: Optional[int]
    derived_from: Optional[str]
    header: str
    registers: str


def _peripheral_spans(text: str) -> list[_Span]:
    """Split an SVD's text into per-peripheral header and register regions."""
    tags = list(_PERIPHERAL_TAG.finditer(text))
    spans: list[_Span] = []
    for index, tag in enumerate(tags):
        start = tag.end()
        limit = tags[index + 1].start() if index + 1 < len(tags) else len(text)
        opened = _REGISTERS_OPEN.search(text, start, limit)
        header_end = opened.start() if opened else limit
        header = text[start:header_end]
        name = _NAME.search(header)
        base = _BASE_ADDRESS.search(header)
        derived = _DERIVED_FROM.search(tag.group(0))
        spans.append(
            _Span(
                name=name.group(1).strip() if name else "",
                base=_integer(base.group(1)) if base else None,
                derived_from=derived.group(1) if derived else None,
                header=header,
                registers=text[header_end:limit] if opened else "",
            )
        )
    return spans


def parse_registers(text: str, bases: Optional[Iterable[int]] = None) -> list[Register]:
    """Parse registers from one SVD file.

    ``bases`` restricts the work to the peripherals at those exact base
    addresses.  That is normally a handful out of ninety, and since the
    register documentation is what makes these files large, scoring a
    candidate device costs a fraction of parsing it.  Derived peripherals are
    resolved against the peripheral they copy.
    """
    spans = _peripheral_spans(text)
    by_name = {span.name: span for span in spans if span.name}
    wanted = None if bases is None else set(bases)

    registers: list[Register] = []
    for span in spans:
        if span.base is None or not span.name:
            continue
        if wanted is not None and span.base not in wanted:
            continue
        source = span
        if not span.registers and span.derived_from:
            source = by_name.get(span.derived_from, span)
        if not source.registers:
            continue
        default_size = _integer(_first(_SIZE, source.header) or "") or 32
        default_access = _first(_ACCESS, source.header) or ""
        registers.extend(
            _registers_in(source.registers, span.base, span.name, default_size, default_access)
        )
    return registers


def _first(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(1).strip() if match else None


def _registers_in(
    body: str, base: int, peripheral: str, default_size: int, default_access: str
) -> Iterator[Register]:
    """Yield the registers described by one ``<registers>`` region."""
    remaining = body
    for cluster in _CLUSTER.finditer(body):
        offset = _integer(_first(_ADDRESS_OFFSET, cluster.group(1)) or "") or 0
        yield from _registers_in(
            cluster.group(1), base + offset, peripheral, default_size, default_access
        )
        remaining = remaining.replace(cluster.group(0), "")

    for match in _REGISTER.finditer(remaining):
        block = match.group(1)
        name = _first(_NAME, block)
        offset = _integer(_first(_ADDRESS_OFFSET, block) or "")
        if not name or offset is None:
            continue
        size = _integer(_first(_SIZE, block) or "") or default_size
        access = _first(_ACCESS, block) or default_access
        dimension = _integer(_first(_DIM, block) or "")
        increment = _integer(_first(_DIM_INCREMENT, block) or "") or max(size // 8, 1)
        if dimension and dimension > 1 and "%s" in name:
            indices = _first(_DIM_INDEX, block) or ""
            labels = [item.strip() for item in indices.split(",")] if indices else []
            for index in range(min(dimension, 64)):
                label = labels[index] if index < len(labels) else str(index)
                yield Register(
                    peripheral=peripheral,
                    name=name.replace("[%s]", label).replace("%s", label),
                    address=base + offset + index * increment,
                    width=size,
                    access=access,
                )
        else:
            yield Register(
                peripheral=peripheral,
                name=name.replace("[%s]", "0").replace("%s", "0"),
                address=base + offset,
                width=size,
                access=access,
            )


class SvdDatabase:
    """A lazily built, on-disk-cached index over an :class:`SvdSource`."""

    def __init__(self, source: SvdSource, cache_directory: Optional[Path] = None) -> None:
        self.source = source
        self.cache_directory = cache_directory or default_cache_directory()
        self.devices: list[Device] = []

    def load(self, log=None) -> list[Device]:
        cache = self._cache_path()
        signature = f"{_INDEX_VERSION}:{self.source.signature()}"
        if cache.exists():
            try:
                payload = json.loads(cache.read_text())
                if payload.get("signature") == signature:
                    self.devices = [_device_from_json(item) for item in payload["devices"]]
                    return self.devices
            except Exception:
                pass

        if log:
            log(f"indexing CMSIS-SVD data from {self.source.description} (first run only)")
        self.devices = [
            device
            for device in (
                parse_index_entry(text, entry.vendor, entry.name, entry.locator)
                for entry, text in self._contents()
            )
            if device is not None
        ]
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(
                json.dumps(
                    {
                        "version": _INDEX_VERSION,
                        "signature": signature,
                        "devices": [_device_to_json(device) for device in self.devices],
                    }
                )
            )
        except OSError:  # pragma: no cover - a read-only cache is not fatal
            pass
        return self.devices

    def _contents(self):
        """Every file's text, batched where the source supports it."""
        batched = getattr(self.source, "read_all", None)
        if batched is not None:
            yield from batched()
            return
        for entry in self.source.entries():
            text = self.source.read(entry.locator)
            if text is not None:
                yield entry, text

    def read(self, device: Device) -> str:
        """The full text of one device's SVD file."""
        return self.source.read(device.locator) or ""

    def _cache_path(self) -> Path:
        import hashlib

        digest = hashlib.sha256(self.source.identity.encode()).hexdigest()[:16]
        return self.cache_directory / f"svd-index-{digest}.json"


def _device_to_json(device: Device) -> dict[str, Any]:
    return {
        "name": device.name,
        "vendor": device.vendor,
        "locator": device.locator,
        "cpu": device.cpu,
        "peripherals": [
            [item.name, item.base, item.window, item.group] for item in device.peripherals
        ],
        "interrupts": [[item.name, item.value] for item in device.interrupts],
    }


def _device_from_json(payload: dict[str, Any]) -> Device:
    return Device(
        name=payload["name"],
        vendor=payload["vendor"],
        locator=payload.get("locator", payload.get("path", "")),
        cpu=payload.get("cpu", ""),
        peripherals=tuple(
            Peripheral(name=item[0], base=item[1], window=item[2], group=item[3])
            for item in payload["peripherals"]
        ),
        interrupts=tuple(Interrupt(name=item[0], value=item[1]) for item in payload["interrupts"]),
    )


# -- matching --------------------------------------------------------------


@dataclass
class Match:
    """One device's score against the recovered accesses."""

    device: Device
    peripheral_score: float = 0.0
    base_score: float = 0.0
    register_score: Optional[float] = None
    matched_addresses: int = 0
    total_addresses: int = 0
    matched_bases: int = 0
    total_bases: int = 0
    matched_peripherals: tuple[str, ...] = ()
    register_hits: int = 0
    contradictions: int = 0
    confidence: float = 0.0

    @property
    def score(self) -> float:
        """Weighted match score.

        The exact peripheral base addresses that value propagation recovered
        carry most of the weight.  Whether an address merely falls inside
        *some* peripheral window barely discriminates -- the Cortex-M
        peripheral space is dense enough that almost every device satisfies
        it -- whereas a device either declares a peripheral at exactly
        ``0x40023800`` or it does not.
        """
        if self.register_score is None:
            if not self.total_bases:
                return self.peripheral_score
            return 0.7 * self.base_score + 0.3 * self.peripheral_score
        if not self.total_bases:
            return 0.6 * self.peripheral_score + 0.4 * self.register_score
        return 0.5 * self.base_score + 0.2 * self.peripheral_score + 0.3 * self.register_score

    def as_dict(self) -> dict[str, Any]:
        return {
            "device": self.device.name,
            "vendor": self.device.vendor,
            "cpu": self.device.cpu,
            "confidence": round(self.confidence, 3),
            "peripheral_score": round(self.peripheral_score, 3),
            "base_score": round(self.base_score, 3),
            "matched_bases": self.matched_bases,
            "total_bases": self.total_bases,
            "register_score": None if self.register_score is None else round(self.register_score, 3),
            "matched_addresses": self.matched_addresses,
            "total_addresses": self.total_addresses,
            "matched_peripherals": list(self.matched_peripherals),
            "register_hits": self.register_hits,
            "contradictions": self.contradictions,
        }


def common_family(names: Iterable[str]) -> str:
    """The longest shared prefix of ``names``, trimmed to a sensible boundary.

    Deriving the family from the tie set itself avoids hard-coding a naming
    convention per vendor, and it is honest: the family reported is exactly
    the part of the name every indistinguishable candidate agrees on.
    """
    ordered = sorted(set(names))
    if not ordered:
        return ""
    if len(ordered) == 1:
        return ordered[0]
    prefix = os.path.commonprefix(ordered)
    prefix = re.sub(r"[^A-Za-z0-9]+$", "", prefix)
    return prefix


class _SingleFile(SvdSource):
    """A source wrapping one SVD file the analyst pointed at."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.identity = f"file:{path.resolve()}"
        self.description = str(path)

    def entries(self):
        from .svdsource import SvdEntry

        return [SvdEntry(locator=str(self.path), vendor=self.path.parent.name, name=self.path.stem)]

    def read(self, locator: str) -> Optional[str]:
        try:
            return Path(locator).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


def implied_bases(accesses) -> list[int]:
    """The peripheral base addresses the recovered accesses imply."""
    bases: set[int] = set()
    for reference in accesses:
        base = reference.base_value
        displacement = reference.offset_value or 0
        if base is not None and base % PERIPHERAL_STRIDE == 0 and displacement < PERIPHERAL_STRIDE:
            bases.add(base)
        else:
            bases.add(reference.value - (reference.value % PERIPHERAL_STRIDE))
    return sorted(bases)


def describe_tie(tied: list["Match"]) -> tuple[str, "Match"]:
    """Name a set of indistinguishable devices as honestly as possible.

    Register maps get cloned between vendors -- the AT32F4 parts are
    register-compatible with STM32F4, and plenty of parts within one family
    are identical in everything the firmware touched.  Naming one of them
    would be false precision, and naming only the largest group would hide
    that a different vendor fits the evidence just as well.  So every family
    represented in the tie is reported, and the device whose metadata supplies
    the peripheral names is the best-scoring one, which the caller flags as an
    arbitrary pick among equals.
    """
    groups: dict[tuple[str, str], list[Match]] = {}
    for match in tied:
        groups.setdefault((match.device.vendor, ""), []).append(match)

    labelled: list[tuple[str, int, float, Match]] = []
    for (vendor, _), members in groups.items():
        representative = max(members, key=lambda item: (item.score, item.register_hits))
        family = common_family(item.device.name for item in members)
        if len(members) == 1 or len(family) < MIN_FAMILY_PREFIX:
            family = representative.device.name
        labelled.append((family, len(members), representative.score, representative))

    labelled.sort(key=lambda item: (-item[1], -item[2], item[0]))
    representative = labelled[0][3]
    names = [item[0] for item in labelled]

    if len(names) == 1:
        return f"{names[0]} family", representative
    shown = names[:3]
    remainder = len(names) - len(shown)
    label = " / ".join(shown)
    if remainder:
        label += f" (+{remainder} more)"
    return f"{label} -- register-compatible, indistinguishable here", representative


def rank_devices(
    devices: Iterable[Device], accesses, database: Optional["SvdDatabase"] = None, log=None
) -> list[Match]:
    """Rank devices against recovered MMIO accesses, best first."""
    by_address: dict[int, list] = {}
    for reference in accesses:
        by_address.setdefault(reference.value, []).append(reference)
    addresses = sorted(by_address)
    if not addresses:
        return []

    # Peripheral base addresses recovered from instructions such as
    # "ldr r1, =0x40020000; str r0, [r1, #0x14]" are the sharpest signal
    # available: a device either declares a peripheral at that exact address
    # or it does not.
    recovered_bases = implied_bases(accesses)

    matches: list[Match] = []
    for device in devices:
        matched = 0
        peripherals: set[str] = set()
        for address in addresses:
            peripheral = device.peripheral_for(address)
            if peripheral is not None:
                matched += 1
                peripherals.add(peripheral.name)
        matched_bases = sum(1 for base in recovered_bases if base in device.bases)
        if not matched and not matched_bases:
            continue
        matches.append(
            Match(
                device=device,
                peripheral_score=matched / len(addresses),
                base_score=matched_bases / len(recovered_bases) if recovered_bases else 0.0,
                matched_addresses=matched,
                total_addresses=len(addresses),
                matched_bases=matched_bases,
                total_bases=len(recovered_bases),
                matched_peripherals=tuple(sorted(peripherals)),
            )
        )

    matches.sort(key=lambda item: (-item.score, -len(item.matched_peripherals), item.device.name))
    if not matches:
        return []

    # Cheap signals leave large groups of devices tied, so every device that
    # ties the leader goes on to register-level scoring rather than an
    # arbitrary top-N of them.  Devices that did not tie are dropped: they
    # scored strictly worse on the evidence available and were never
    # evaluated in detail, so keeping them would let an unscored device
    # outrank a scored one.
    leader = matches[0].score
    shortlist = [item for item in matches if leader - item.score <= TIE_MARGIN]
    if len(shortlist) < SHORTLIST:
        shortlist = matches[:SHORTLIST]
    truncated = max(0, len(shortlist) - MAX_SHORTLIST)
    shortlist = shortlist[:MAX_SHORTLIST]
    if log:
        log(f"svd: {len(shortlist)} candidate(s) go to register-level scoring")

    for match in shortlist:
        text = database.read(match.device) if database is not None else ""
        registers = parse_registers(text, bases=recovered_bases or None) if text else []
        by_register = {register.address: register for register in registers}
        hits = 0
        contradictions = 0
        for address, references in by_address.items():
            register = by_register.get(address)
            if register is None:
                continue
            hits += 1
            for reference in references:
                if reference.access == Access.WRITE and not register.writable:
                    contradictions += 1
                elif reference.access == Access.READ and not register.readable:
                    contradictions += 1
                elif reference.width and register.width and reference.width > register.width:
                    contradictions += 1
        match.register_hits = hits
        match.contradictions = contradictions
        # Contradictions count, but only once each: vendor SVDs mislabel
        # access direction often enough (RCC_CR is documented read-only in
        # some STM32 files despite being written by every startup routine)
        # that weighting them heavily would reject correct answers.
        match.register_score = max(0.0, (hits - contradictions) / len(addresses))

    shortlist.sort(
        key=lambda item: (-item.score, -item.register_hits, item.contradictions, item.device.name)
    )
    if truncated and log:
        log(f"svd: {truncated} further tied device(s) were not scored in detail")

    evidence_strength = min(len(addresses) / 12.0, 1.0)
    for match in shortlist:
        match.confidence = round(min(match.score, 0.99) * (0.35 + 0.65 * evidence_strength), 4)
    return shortlist


class SvdMatcher(AnalysisPass):
    """Rank candidate MCUs and gather peripheral annotations."""

    name = "SvdMatcher"
    after = frozenset({"MemoryAccessRecovery"})
    provides = frozenset({"mcu_candidates", "mcu", "svd_annotations", "svd_cpu_name"})

    def enabled(self, context: AnalysisContext) -> bool:
        return context.options.enable_svd and context.options.svd_symbols != "none"

    def run(self, context: AnalysisContext) -> None:
        accesses = context.get("peripheral_accesses") or []
        context.provide("mcu_candidates", [])
        context.provide("mcu", None)
        context.provide("svd_annotations", {})

        explicit = context.options.svd
        database = None
        if explicit and Path(explicit).is_file():
            path = Path(explicit)
            device = parse_index_entry(
                path.read_text(encoding="utf-8", errors="replace"),
                path.parent.name,
                path.stem,
                str(path),
            )
            if device is None:
                context.warn(f"could not parse {explicit} as a CMSIS-SVD file")
                return
            devices = [device]
            database = SvdDatabase(_SingleFile(path))
        else:
            source = open_source(
                explicit,
                allow_fetch=context.options.fetch_svd,
                log=lambda message: context.log(message, level=0),
            )
            if source is None:
                context.warn(
                    "no CMSIS-SVD data found, so no MCU can be identified"
                    + ("" if context.options.fetch_svd else " (it was not fetched)")
                )
                return
            database = SvdDatabase(source)
            devices = database.load(log=lambda message: context.log(message, level=0))
            context.log(f"svd: indexed {len(devices)} device(s)", level=1)

        if context.options.mcu:
            # What is printed on a package carries package, grade and speed
            # suffixes that no SVD file names, so matching is loose.
            wanted = context.options.mcu
            narrowed = search(wanted, devices) or [
                device for device in devices if normalise(wanted) == normalise(device.name)
            ]
            if narrowed:
                devices = narrowed
            else:
                # Some vendors' order codes diverge from their SVD names part
                # way through -- MK64FN1M0VLL12 against MK64F12 -- so failing
                # to place a name is not a reason to give up on identifying
                # the part from the accesses themselves.
                context.warn(
                    f"no CMSIS-SVD device is named like {wanted!r}, so the search was not "
                    "narrowed; the recovered accesses are still matched against every device"
                )
            context.log(
                f"svd: {wanted} narrowed the search to {len(devices)} device(s): "
                f"{', '.join(item.name for item in devices[:4])}"
                + ("..." if len(devices) > 4 else ""),
                level=1,
            )

        if len(accesses) == 0:
            context.warn("no MMIO accesses were recovered, so no MCU can be identified")
            return

        distinct = len({reference.value for reference in accesses})
        matches = rank_devices(
            devices, accesses, database=database, log=lambda message: context.log(message, level=2)
        )
        if not matches:
            context.note(
                Evidence(
                    kind="mcu",
                    source=self.name,
                    explanation=(
                        f"none of {len(devices)} indexed devices has a peripheral covering the "
                        f"{distinct} recovered register address(es)"
                    ),
                    value=distinct,
                    supports=False,
                )
            )
            return

        context.provide("mcu_candidates", matches[:10])

        selected = matches[0]
        if context.options.mcu:
            selected.confidence = 1.0
            label = selected.device.name
            exact = True
        else:
            tied = [item for item in matches if matches[0].score - item.score <= TIE_MARGIN]
            exact = len(tied) == 1
            if exact:
                label = selected.device.name
            else:
                label, selected = describe_tie(tied)
                context.note(
                    Evidence(
                        kind="mcu",
                        source=self.name,
                        explanation=(
                            f"{len(tied)} device(s) match the recovered accesses equally well "
                            f"across {len({item.device.vendor for item in tied})} vendor(s); "
                            f"reporting {label} rather than picking one of them"
                        ),
                        value=len(tied),
                        supports=False,
                    )
                )

        if distinct < MIN_ACCESSES:
            context.note(
                Evidence(
                    kind="mcu",
                    source=self.name,
                    explanation=(
                        f"only {distinct} distinct register address(es) recovered, too few to "
                        "identify a part with confidence"
                    ),
                    value=distinct,
                    supports=False,
                )
            )

        context.provide(
            "mcu",
            {
                "label": label,
                "exact": exact,
                "match": selected,
                "arbitrary_representative": not exact,
            },
        )
        # Published verbatim from the SVD.  Turning "CM4" into a core name is
        # architecture-specific knowledge, so the backend does that.
        context.provide("svd_cpu_name", selected.device.cpu or None)
        context.note(
            Evidence(
                kind="mcu",
                source=self.name,
                explanation=(
                    f"{label}: {selected.matched_bases} of {selected.total_bases} recovered "
                    f"peripheral base addresses are declared by this device, and "
                    f"{selected.matched_addresses} of {selected.total_addresses} register addresses "
                    f"map onto {len(selected.matched_peripherals)} peripheral(s)"
                    + (
                        f", {selected.register_hits} at exact register offsets"
                        f"{f' with {selected.contradictions} contradiction(s)' if selected.contradictions else ''}"
                        if selected.register_score is not None
                        else ""
                    )
                ),
                value=label,
                confidence=selected.confidence,
            )
        )
        context.provide("_svd_database", database)
        context.provide("svd_annotations", self._annotations(context, selected))
        context.log(f"mcu: {label} confidence {selected.confidence:.2f}", level=1)

    def _annotations(self, context: AnalysisContext, match: Match) -> dict[str, Any]:
        """Peripheral, register and interrupt names for the chosen device."""
        level = context.options.svd_symbols
        annotations: dict[str, Any] = {
            "device": match.device.name,
            "peripherals": [],
            "registers": [],
            "interrupts": {},
        }
        if level == "none":
            return annotations

        accesses = context.get("peripheral_accesses") or []
        touched = {reference.value for reference in accesses}
        # Attribute each address to the single peripheral that covers it,
        # rather than to every peripheral whose window happens to reach it.
        used: dict[str, Peripheral] = {}
        for address in sorted(touched):
            peripheral = match.device.peripheral_for(address)
            if peripheral is not None:
                used[peripheral.name] = peripheral
        annotations["peripherals"] = [
            {"name": peripheral.name, "base": hexs(peripheral.base, 8), "group": peripheral.group}
            for peripheral in sorted(used.values(), key=lambda item: item.base)
        ]
        annotations["interrupts"] = {
            interrupt.value: interrupt.name for interrupt in match.device.interrupts
        }

        if level == "registers":
            database = context.get("_svd_database")
            text = database.read(match.device) if database is not None else ""
            registers = parse_registers(
                text, bases=[peripheral.base for peripheral in used.values()]
            ) if text else []
            annotations["registers"] = [
                {
                    "name": f"{register.peripheral}_{register.name}",
                    "address": hexs(register.address, 8),
                    "width": register.width,
                    "access": register.access,
                }
                for register in registers
                if register.address in touched
            ]
        return annotations
