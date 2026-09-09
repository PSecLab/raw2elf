"""Cortex-M exception vector table discovery.

A Cortex-M image's vector table is the single strongest structural signal it
has: word 0 is the initial Main Stack Pointer, word 1 is the Reset Handler,
and the words after that are exception and device interrupt handlers.  Every
handler pointer carries the Thumb bit, the architecturally reserved slots are
zero, and unused vectors normally all point at one shared default handler.

The table is *not* assumed to be at file offset zero: a flash dump may hold a
bootloader, an application and OTA slots, each with its own table.  Plausible
aligned offsets are scanned and scored independently.

Scoring deliberately avoids anything that needs the load address, because the
load address is not known yet -- distances between handlers, the Thumb bit and
the reserved slots are all invariant under relocation.  Verification that
handlers actually point at code happens later, once a base has been chosen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ...core.evidence import Evidence
from ...core.image import FirmwareImage
from ...core.util import align_down, logistic

#: Architecturally defined vector slots, by word index.
CORE_VECTORS: dict[int, str] = {
    1: "Reset_Handler",
    2: "NMI_Handler",
    3: "HardFault_Handler",
    4: "MemManage_Handler",
    5: "BusFault_Handler",
    6: "UsageFault_Handler",
    11: "SVC_Handler",
    12: "DebugMon_Handler",
    14: "PendSV_Handler",
    15: "SysTick_Handler",
}
#: Slots the architecture reserves; real tables leave these zero.
RESERVED_SLOTS: tuple[int, ...] = (7, 8, 9, 10, 13)
#: Word index of device interrupt 0.
FIRST_DEVICE_IRQ = 16
#: Never consider a table longer than this many words.
MAX_TABLE_WORDS = 16 + 256
#: VTOR ignores the low seven bits, so a table's runtime address is always at
#: least 128-byte aligned.
VTOR_ALIGNMENT = 0x80


def alignment_of(value: int) -> int:
    """The largest power of two that divides ``value`` (0 means "any")."""
    return value & -value if value else 0


def next_power_of_two(value: int) -> int:
    result = 1
    while result < value:
        result <<= 1
    return result

_EMPTY_WORDS = frozenset((0x00000000, 0xFFFFFFFF))
#: Where internal SRAM lives. The initial stack pointer must be in here,
#: because nothing else is usable before reset code runs.
INTERNAL_SRAM = (0x20000000, 0x40000000)
#: SRAM some vendors place in the architectural code region.
VENDOR_SRAM = (0x10000000, 0x20000000)
#: Share of random words that pass a one-bit test, used to discount evidence
#: down to what exceeds chance.
CHANCE = 0.5
#: Granularities a linker plausibly uses for a firmware image's base.
BASE_ALIGNMENTS: tuple[int, ...] = (
    0x1000000, 0x100000, 0x40000, 0x20000, 0x10000, 0x8000,
    0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80,
)


@dataclass
class VectorTable:
    """A scored candidate vector table."""

    image_offset: int
    initial_sp: int
    reset_handler: int
    words: list[int] = field(default_factory=list)
    handler_slots: list[int] = field(default_factory=list)
    default_handler: Optional[int] = None
    score: float = 0.0
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def reset_address(self) -> int:
        """Reset handler with the Thumb bit removed."""
        return self.reset_handler & ~1

    @property
    def handler_addresses(self) -> list[int]:
        return [self.words[slot] & ~1 for slot in self.handler_slots]

    @property
    def span(self) -> tuple[int, int]:
        addresses = self.handler_addresses
        return (min(addresses), max(addresses)) if addresses else (0, 0)

    @property
    def word_count(self) -> int:
        return len(self.words)

    @property
    def required_alignment(self) -> int:
        """Alignment VTOR demands of this table's runtime address.

        ARMv7-M requires the vector table to be aligned to the next power of
        two at or above its size, with a floor of 128 bytes.  This is a hard
        architectural constraint, not a convention, so it prunes candidate
        load addresses outright.  The recovered word count can overestimate a
        table's real length, so the requirement is capped at the alignment
        implied by the architecturally defined vectors plus device interrupts
        actually seen carrying the Thumb bit.
        """
        observed = (max(self.handler_slots, default=15) + 1) * 4
        return max(VTOR_ALIGNMENT, next_power_of_two(observed))

    def base_range(self, remaining_bytes: int) -> Optional[tuple[int, int]]:
        """Bounds on the image base implied by this table's handlers.

        Every handler must land inside the image, which pins the base to an
        interval rather than a single value -- one table alone cannot do
        better than that, and pretending otherwise is how tools end up
        confidently wrong.
        """
        addresses = self.handler_addresses
        if not addresses:
            return None
        low = max(0, max(addresses) - remaining_bytes + 1) - self.image_offset
        high = min(addresses) - self.image_offset
        if high < low:
            return None
        return max(low, 0), high

    def base_seeds(self, remaining_bytes: int) -> list[tuple[int, float]]:
        """Candidate image bases, most plausible first.

        The table's runtime address is ``base + image_offset``, must be one
        VTOR can address, and must leave every handler inside the image.
        Among the addresses that satisfy that, the one just below the first
        handler is preferred: a vector table is immediately followed by the
        code it points to, so the table ends about where the handlers begin.

        Preferring the coarsest alignment instead puts a second image's table
        where the first image's belongs, which is how a multi-image dump ends
        up with a base that describes the wrong image.
        """
        bounds = self.base_range(remaining_bytes)
        if bounds is None:
            return []
        low, high = bounds
        first_handler = min(self.handler_addresses)
        required = self.required_alignment

        seeds: list[tuple[int, float]] = []
        seen: set[int] = set()
        for alignment in BASE_ALIGNMENTS:
            if alignment < required:
                continue
            table_address = align_down(first_handler, alignment)
            base = table_address - self.image_offset
            if base < low or base > high or base in seen:
                continue
            seen.add(base)
            seeds.append((base, first_handler - table_address))

        # Closest below the first handler first, then coarser fallbacks.
        seeds.sort(key=lambda item: item[1])
        return [
            (base, max(1.0 - 0.1 * index, 0.3))
            for index, (base, _distance) in enumerate(seeds)
        ]


def uniform_bytes(value: int) -> bool:
    """True when all four bytes of ``value`` are identical.

    Runs of one character -- ``0x2d2d2d2d`` from a row of dashes in a string
    table, ``0x20202020`` from padding -- otherwise pass every arithmetic test
    a vector table applies, and a long run of them looks exactly like a table
    full of shared default handlers.
    """
    low = value & 0xFF
    return value == low * 0x01010101


def plausible_stack_pointer(value: int, classify) -> bool:
    """Whether ``value`` could be an initial Main Stack Pointer.

    The pointer must live in a writable region and be at least word aligned;
    AAPCS wants eight-byte alignment, but linker scripts do produce merely
    four-byte-aligned stack tops, so that is scored rather than required.  The
    common case of "top of SRAM" means the value can legitimately sit one past
    the end of a bank.
    """
    from ...core.reference import AddressClass

    if value in _EMPTY_WORDS or value % 4 or uniform_bytes(value):
        return False
    # Vendors place SRAM in the architectural code region as well (CCM on
    # STM32F4, the LPC17xx main SRAM), so both windows are accepted.
    if VENDOR_SRAM[0] <= value < VENDOR_SRAM[1]:
        return True
    # Internal SRAM only. External memory needs its controller configured,
    # which has not happened when the reset vector is taken, so an initial
    # stack pointer cannot live there -- and the external window is where
    # stray constants most often land.
    return INTERNAL_SRAM[0] <= value < INTERNAL_SRAM[1]


def plausible_handler(value: int, classify) -> bool:
    """Whether ``value`` could be a handler pointer."""
    from ...core.reference import AddressClass

    if value in _EMPTY_WORDS or not value & 1:
        return False
    if value < 0x20 or uniform_bytes(value):
        return False
    return classify(value) in (AddressClass.CODE, AddressClass.RAM)


def _repeated_value(table: "VectorTable") -> Optional[int]:
    """The table's most repeated handler value, if one repeats at all."""
    counts: dict[int, int] = {}
    for slot in table.handler_slots:
        value = table.words[slot]
        counts[value] = counts.get(value, 0) + 1
    if not counts:
        return None
    value, repeats = max(counts.items(), key=lambda item: item[1])
    return value if repeats >= 3 else None


def _words(data: bytes, offset: int, count: int, byte_order: str) -> list[int]:
    return [
        int.from_bytes(data[offset + index * 4 : offset + index * 4 + 4], byte_order)
        for index in range(count)
    ]


#: Handlers in a table share a region; this is the granularity of "same".
_REGION_MASK = 0xFF000000


def _table_length(words: list[int], classify) -> int:
    """How many words of ``words`` plausibly belong to the table.

    A handler must not only look like a code pointer but live in the same
    16 MiB region as the reset vector.  Without that, the scan runs off the
    end of a real table into the code that follows it and adopts the first
    instruction word that happens to be odd, which then wrecks the handler
    clustering test.
    """
    region = (words[1] & ~1) & _REGION_MASK
    length = 2
    for index in range(2, len(words)):
        word = words[index]
        if word in _EMPTY_WORDS:
            length = index + 1
            continue
        if plausible_handler(word, classify) and ((word & ~1) & _REGION_MASK) == region:
            length = index + 1
            continue
        break
    return length


def score_table(table: VectorTable, remaining_bytes: int, classify) -> None:
    """Assign ``table`` a score and confidence from relocation-invariant facts."""
    evidence: list[Evidence] = []
    score = 0.0
    source = "cortex-m/vectors"

    aligned = table.initial_sp % 8 == 0
    evidence.append(
        Evidence(
            kind="initial_sp",
            source=source,
            explanation=(
                f"word 0 {table.initial_sp:#010x} is a plausible initial MSP"
                + (", eight-byte aligned as AAPCS wants" if aligned else ", word aligned only")
            ),
            value=table.initial_sp,
            weight=2.0 if aligned else 1.4,
        )
    )
    score += 2.0 if aligned else 1.4

    evidence.append(
        Evidence(
            kind="reset_handler",
            source=source,
            explanation=f"word 1 {table.reset_handler:#010x} is an odd (Thumb) reset vector",
            value=table.reset_handler,
            weight=2.0,
        )
    )
    score += 2.0

    handlers = table.handler_addresses
    # Carrying the Thumb bit is a one-bit test, so half of any random data
    # passes it. Only the excess over that counts: nine of nine named vectors
    # is a real table, five of nine is what noise looks like.
    named_slots = [slot for slot in CORE_VECTORS if slot != 1 and slot < table.word_count]
    named = [slot for slot in named_slots if slot in table.handler_slots]
    if named_slots:
        excess = len(named) - CHANCE * len(named_slots)
        weight = max(excess, 0.0) * 0.7
        score += weight if excess > 0 else excess * 0.5
        evidence.append(
            Evidence(
                kind="core_vectors",
                source=source,
                explanation=(
                    f"{len(named)} of {len(named_slots)} architecturally named exception vectors "
                    f"carry the Thumb bit, against {CHANCE * len(named_slots):.1f} expected by chance"
                ),
                value=len(named),
                weight=abs(weight),
                supports=excess > 0,
            )
        )

    device_slots = [
        slot
        for slot in range(FIRST_DEVICE_IRQ, table.word_count)
        if table.words[slot] not in _EMPTY_WORDS
    ]
    device_handlers = [slot for slot in device_slots if slot in table.handler_slots]
    if device_slots:
        excess = len(device_handlers) - CHANCE * len(device_slots)
        bonus = min(max(excess, 0.0) * 0.08, 2.5)
        score += bonus
        evidence.append(
            Evidence(
                kind="device_vectors",
                source=source,
                explanation=(
                    f"{len(device_handlers)} of {len(device_slots)} device interrupt vectors carry "
                    "the Thumb bit"
                ),
                value=len(device_handlers),
                weight=bonus,
            )
        )

    reserved_zero = sum(
        1 for slot in RESERVED_SLOTS if slot < table.word_count and table.words[slot] == 0
    )
    # Most startup files leave the reserved slots zero, but plenty fill them
    # with the shared default handler.  Only genuinely unrelated values there
    # argue against the candidate being a vector table.
    filler = _repeated_value(table)
    reserved_used = sum(
        1
        for slot in RESERVED_SLOTS
        if slot < table.word_count
        and table.words[slot] not in _EMPTY_WORDS
        and table.words[slot] != filler
    )
    if reserved_zero:
        score += reserved_zero * 0.4
        evidence.append(
            Evidence(
                kind="reserved_slots",
                source=source,
                explanation=f"{reserved_zero} of {len(RESERVED_SLOTS)} reserved slots are zero",
                value=reserved_zero,
                weight=reserved_zero * 0.4,
            )
        )
    if reserved_used:
        score -= reserved_used * 0.5
        evidence.append(
            Evidence(
                kind="reserved_slots",
                source=source,
                explanation=f"{reserved_used} reserved slot(s) hold non-zero values",
                value=reserved_used,
                weight=reserved_used * 0.5,
                supports=False,
            )
        )

    even_handlers = sum(
        1
        for index in range(2, table.word_count)
        if table.words[index] not in _EMPTY_WORDS
        and not table.words[index] & 1
        and index not in RESERVED_SLOTS
    )
    if even_handlers:
        penalty = min(even_handlers, 8) * 0.8
        score -= penalty
        evidence.append(
            Evidence(
                kind="thumb_bit",
                source=source,
                explanation=f"{even_handlers} vector slot(s) hold even values, which cannot be Thumb handlers",
                value=even_handlers,
                weight=penalty,
                supports=False,
            )
        )

    distinct = len(set(handlers))
    if handlers and distinct >= 3:
        spread = max(handlers) - min(handlers)
        if spread < 0x100000:
            score += 2.0
            detail = "within 1 MiB"
        elif spread < 0x1000000:
            score += 1.0
            detail = "within 16 MiB"
        else:
            score -= 1.5
            detail = f"spread over {spread / (1 << 20):.1f} MiB"
        evidence.append(
            Evidence(
                kind="handler_clustering",
                source=source,
                explanation=f"{len(handlers)} handler addresses are {detail}",
                value=spread,
                weight=2.0,
                supports=spread < 0x1000000,
            )
        )
        if spread >= remaining_bytes and remaining_bytes:
            score -= 2.0
            evidence.append(
                Evidence(
                    kind="handler_clustering",
                    source=source,
                    explanation=(
                        f"handler spread {spread:#x} exceeds the {remaining_bytes:#x} bytes "
                        "of image after this table"
                    ),
                    value=spread,
                    weight=2.0,
                    supports=False,
                )
            )

        misaligned = sum(1 for address in handlers if address % 2)
        if misaligned:
            score -= misaligned * 0.5

    if handlers and distinct < 3 and len(handlers) >= 4:
        # Even the most minimal real table has a reset handler distinct from
        # its shared default.  Several identical odd words with a plausible
        # stack pointer in front of them is repeated data, and the clustering
        # and default-handler bonuses above would otherwise reward it for
        # being uniform, so this has to outweigh them decisively.
        score -= 8.0
        evidence.append(
            Evidence(
                kind="handler_variety",
                source=source,
                explanation=(
                    f"{len(handlers)} handler slots hold only {distinct} distinct value(s), "
                    "which repeated data explains better than a vector table"
                ),
                value=distinct,
                weight=8.0,
                supports=False,
            )
        )

    if handlers and distinct >= 3:
        counts: dict[int, int] = {}
        for address in handlers:
            counts[address] = counts.get(address, 0) + 1
        repeated, repeats = max(counts.items(), key=lambda item: item[1])
        if repeats >= 3:
            table.default_handler = repeated
            score += 1.5
            evidence.append(
                Evidence(
                    kind="default_handler",
                    source=source,
                    explanation=(
                        f"{repeats} vectors share handler {repeated:#010x}, "
                        "the signature of a shared default handler"
                    ),
                    value=repeated,
                    weight=1.5,
                )
            )

    if table.image_offset % VTOR_ALIGNMENT == 0:
        score += 0.75
        evidence.append(
            Evidence(
                kind="alignment",
                source=source,
                explanation=(
                    f"table offset {table.image_offset:#x} is compatible with the "
                    f"{table.required_alignment:#x}-byte alignment VTOR requires"
                ),
                value=table.image_offset,
                weight=0.75,
            )
        )
    else:
        # VTOR ignores the low seven bits, and an image's own base is at
        # least that aligned, so a real table cannot sit at an offset like
        # this. Data that happens to look like a table lands anywhere.
        score -= 3.0
        evidence.append(
            Evidence(
                kind="alignment",
                source=source,
                explanation=(
                    f"table offset {table.image_offset:#x} is not {VTOR_ALIGNMENT:#x}-byte "
                    "aligned, so VTOR could not address a table here"
                ),
                value=table.image_offset,
                weight=3.0,
                supports=False,
            )
        )

    table.score = score
    table.confidence = logistic(score, midpoint=3.5, steepness=0.75)
    table.evidence = evidence


def find_tables(
    image: FirmwareImage,
    classify,
    byte_order: str = "little",
    alignment: int = 4,
    minimum_confidence: float = 0.35,
    limit: int = 64,
) -> list[VectorTable]:
    """Scan ``image`` for candidate vector tables, best first."""
    candidates: list[VectorTable] = []
    for segment in image.iter_segments():
        data = segment.data
        end = len(data) - 8 * 4
        offset = 0
        while offset <= end:
            reset = int.from_bytes(data[offset + 4 : offset + 8], byte_order)
            if not plausible_handler(reset, classify):
                offset += alignment
                continue
            stack = int.from_bytes(data[offset : offset + 4], byte_order)
            if not plausible_stack_pointer(stack, classify):
                offset += alignment
                continue

            # VTOR ignores the low seven bits and an image's base is at
            # least that aligned, so a table cannot sit at an offset like
            # this. Rejected outright rather than carried as a weak image:
            # a hard architectural requirement is not a matter of degree.
            if (segment.image_offset + offset) % VTOR_ALIGNMENT:
                offset += alignment
                continue

            available = min(MAX_TABLE_WORDS, (len(data) - offset) // 4)
            words = _words(data, offset, available, byte_order)
            length = _table_length(words, classify)
            if length < 8:
                offset += alignment
                continue
            words = words[:length]
            table = VectorTable(
                image_offset=segment.image_offset + offset,
                initial_sp=stack,
                reset_handler=reset,
                words=words,
                handler_slots=[
                    index
                    for index in range(1, length)
                    if plausible_handler(words[index], classify)
                ],
            )
            remaining = image.size - table.image_offset
            score_table(table, remaining, classify)
            if table.confidence >= minimum_confidence:
                candidates.append(table)
            offset += alignment
    candidates.sort(key=lambda item: item.confidence, reverse=True)
    return _deduplicate(candidates)[:limit]


def _deduplicate(tables: list[VectorTable], window: int = 0x40) -> list[VectorTable]:
    """Drop weaker candidates that overlap a stronger one.

    A real table produces a cluster of near-miss candidates at neighbouring
    offsets; only the best of each cluster is a distinct hypothesis.
    """
    kept: list[VectorTable] = []
    for table in tables:
        if any(abs(table.image_offset - other.image_offset) < window for other in kept):
            continue
        kept.append(table)
    return kept
