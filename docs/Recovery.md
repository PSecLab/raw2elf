# What gets recovered, and how

This document covers each recovery stage: what evidence it uses, what it
refuses to conclude, and where it stops. For the options that control it see
[Usage.md](Usage.md); for the machine-readable output see
[Manifest.md](Manifest.md).

## Architecture

Each architecture backend probes the image and returns a confidence with
supporting evidence; the results are ranked. `--probe` shows them:

```
$ raw2elf firmware.bin --probe
Architecture probes:
  arm-cortex-m         0.99 <-
  arm-cortex-m: + candidate Cortex-M vector table at image offset 0x0 (MSP 0x20020000, reset 0x08000319)
  arm-cortex-m: + 12 sampled window(s) decode as Thumb with mean confidence 0.79
```

Detection refuses rather than guessing below a floor confidence, so a 50-byte
instruction fragment or a block of compressed data does not become an ELF by
default.

The Cortex-M probe actively rules itself *out* as well as in. It compares Thumb
decoding against A32 decoding over windows spread across the image, and looks
for the classic ARM reset convention — eight words that branch or load `PC`,
`e59ff018` repeated. A Cortex-A or ARM7 image is therefore declined instead of
reconstructed as something it is not. Two of the images this project tests
against are exactly that case, and are correctly refused.

Architecture facts are kept separate rather than collapsed into one string,
because they vary independently: instruction set, subarchitecture, instruction
mode, endianness, pointer width, ELF machine number and ELF flags.

## Load address and entry point

Candidates come from three places, in order of authority:

1. **The analyst** — `--base`, `--entry`, `--vector-offset`.
2. **The input container** — Intel HEX and S-Records state their own addresses,
   and termination or start records give an entry hint.
3. **Inference**, when neither of the above applies.

### How inference works

1. The backend seeds candidates it can justify structurally, and states which
   alignments and address ranges the architecture permits.
2. Every recovered absolute reference value is truncated to each permitted
   alignment. This proposes the real base even when no structure named it.
3. Candidates are pre-ranked cheaply by how much reference weight resolves
   inside the image, which discards the great majority.
4. The survivors go to the backend for semantic checks.

**Relative branches are never used to choose a base.** Their source and target
move together with the image, so every candidate satisfies them equally and
they carry no information about the load address. They are used for what they
are genuinely good for — finding where code starts — and it is the absolute
references that pick a winner.

The sharpest single test follows from that split. Direct call targets are
relocation-invariant *image offsets*; absolute code pointers are *addresses*.
For the correct base the two line up, and for a wrong base every pointer is
shifted off them. Because a resynchronizing sweep also walks data and produces
some spurious call targets, the test is discounted by how many hits that noise
explains by chance: only agreement beyond the expected coincidence rate scores.

### Telling a table from data that resembles one

Constant tables produce convincing near-misses, and a scan over a few megabytes
finds plenty. Three rules do most of the work of rejecting them:

**The initial stack pointer must be in internal SRAM.** External memory needs
its controller configured, which has not happened when the reset vector is
taken, so a stack pointer cannot live there — and the external window is
exactly where stray constants land.

**Evidence is counted against chance.** Carrying the Thumb bit is a one-bit
test, so half of any random data passes it: five of nine exception vectors
looking like handlers is what noise produces, not what a table looks like.
Only the excess over the chance rate scores.

**The table's offset must be one VTOR could address.** VTOR ignores the low
seven bits and an image's base is at least that aligned, so a real table sits
at a 128-byte-aligned offset within its image. Data that happens to resemble a
table lands anywhere. This is architectural rather than statistical, so it is
applied as a hard rejection while tables are being found, before anything is
scored — an unaddressable offset never becomes a candidate at all, however
convincing its contents.

**Contradictions compound.** A structure that is at once mis-stacked,
mis-pointed and wider than the image it sits in is not a slightly worse vector
table than one with a single oddity — it is a different kind of thing. Summing
the penalties lets a pile of supporting coincidences outvote them, which is how
data that resembles a table reaches four-fifths confidence. So independent
serious contradictions are penalized super-linearly: two cost a little, three
cost a great deal.

**A stack pointer no part could have is one of those contradictions.** SRAM
banks sit at strongly aligned boundaries within the SRAM window, and no
Cortex-M part carries anything like 16 MiB of internal SRAM. A word that lands
in the window 49 MiB above the nearest bank boundary is a constant, not a stack
pointer. Alignment is deliberately *not* used for this: real initial stack
pointers are often only four- or eight-byte aligned (`0x200035cc`,
`0x200019f8`), so an alignment test would reject real firmware.

Together these take a synthetic false positive — plausible stack pointer,
Thumb reset vector, five named vectors, clustered handlers — from 0.92 to 0.11.
It is still reported, as a low-confidence vector-like structure, rather than
discarded silently.

On a real dump where floating-point tables and string data had been scoring as
high as 0.92, these leave only the genuine images standing.

### Cortex-M specifics

The backend adds four checks that need instruction semantics or the ARMv7-M
architecture:

- **VTOR addressability.** A vector table's runtime address must be aligned to
  the next power of two at or above its size, with a 128-byte floor. This is an
  architectural constraint, not a convention, so it prunes candidates outright.
- **Reset vector decoding.** The reset handler must land on bytes that decode
  as a run of Thumb instructions.
- **Handler locality.** A table heads its own image, so its handlers lie after
  it and near it. This is what separates the real base from one that happens to
  line a table's handlers up with a *different* image's code.
- **Alignment beyond the minimum.** Linkers place images at strongly aligned
  addresses, so extra alignment separates the true base from its near
  neighbours.

Every vector table found in the input is checked, not only the one chosen as
the entry point. See [Dumps with several images](#dumps-with-several-images).

### Reading the result

Each candidate keeps its own supporting and contradicting evidence, and both
appear under `-v` and in the manifest:

```
Candidate load addresses:
  1. 0x08000000    confidence 0.98    (backend seed)
       + vector table lands at 0x08000000, aligned to 0x8000000
       + reset vector 0x08000319 maps to executable bytes (94 instructions over 196 unbroken bytes)
       + all handlers lie within 0x318 bytes after their own vector table
       + 4 of 4 distinct exception vectors resolve inside the image
  2. 0x08000100    confidence 0.07    (reference value aligned to 0x100)
       - vector table would sit at 0x08000100, which VTOR cannot address:
         a 98-word table requires 0x200-byte alignment
```

Two things are reported separately, and it matters that they are: how strong
the evidence for a candidate is in absolute terms, and how clearly it beats the
alternatives. A candidate that scores well but ties with another does not get
to look certain.

## References

A small monotone value analysis tracks four kinds of value — unknown, a
constant, a bounded set of constants, or a symbol plus a displacement — through
the instructions the backend understands. It is not symbolic execution and does
not try to be. Its whole job is to answer three narrow questions: what address
does this load or store use, where does this indirect branch go, and what
pointers did startup code set up.

That produces *effective addresses* rather than a list of constants that happen
to look like peripherals. Given `ldr r1, =0x40020000` followed by
`str r0, [r1, #0x14]`:

```json
{
  "value": "0x40020014",
  "kind": "MMIO",
  "access": "WRITE",
  "width": 32,
  "base": "0x40020000",
  "offset": 20,
  "derivation": "recovered base + displacement",
  "source": "str r0, [r1, #0x14]"
}
```

References are recovered in two passes, because they answer two different
questions.

**Before the base is known**, a resynchronizing linear sweep collects the
values Thumb code constructs absolutely: PC-relative literal pool loads and
`MOVW`/`MOVT` pairs. Those values are invariant under relocation, which is
exactly what base recovery needs. The sweep also records which offsets direct
calls target.

**After the base is known**, code is discovered properly from the recovered
entry points, and value propagation yields effective addresses for loads and
stores, resolved indirect branch targets, and the pointers startup code sets
up.

### A literal is not an address until something dereferences it

A literal pool value may be an address, an integer, a bitmask, a
floating-point value, a peripheral address, a RAM pointer or a code pointer.
Every reference therefore keeps its provenance — the producing instruction, its
offset, and how the value was derived — and classification waits until
something is seen to *use* the value.

The classes are `CONSTANT`, `CODE`, `FLASH_DATA`, `RAM`, `MMIO` and `UNKNOWN`,
each with an access of `READ`, `WRITE`, `EXECUTE` or `ADDRESS_ONLY`.

`CONSTANT` is the honest default, and it is where most literals stay. A value
loaded by `ldr r3, [pc, #N]` is a value; whether it is an address is a separate
question that the load itself cannot answer. Falling inside a plausible SRAM or
peripheral window is not an answer either — a firmware image is full of
integers that do. `0x3dcccccd` is the float `0.1` and also looks exactly like
an STM32 SRAM pointer.

A value is promoted out of `CONSTANT` only when the analysis observes it being
dereferenced: the recovered effective address of a load or store, the target of
a branch, or a pointer startup code follows. Everything else keeps its literal
value, its producing instruction and its offset, and is reported as a constant
— visible, but not claimed to be memory.

Two instruction-level rules settle the obvious cases before scoring begins:

- A literal loaded into a floating-point register (`VLDR`) is a floating-point
  constant. The destination register makes that unambiguous, so those loads
  never produce address candidates at all.
- `ADDRESS_ONLY` and the three memory accesses are kept distinct throughout.
  "This value was observed" and "this address was accessed" are different
  claims, and only the second supports a memory region.

`CODE` remains the strictest class: a value is called `CODE` only if it points
at an address that actually decoded as an instruction, or if the instruction
executed it. The Thumb bit makes a code pointer look distinctive, but plenty of
ordinary constants are odd, and a literal pointing one byte into a string is
not a function. The cost of that conservatism is that a pointer into code which
discovery never reached is reported as `FLASH_DATA`; the benefit is that the
`CODE` class stays trustworthy.

The console summary reports the two populations separately, so the difference
is visible without reading the manifest:

```
  Code references:   184
  Constants:         8221   (loaded, never used as an address)
  RAM references:    13 accessed, 31 as address literals
```

## A decoded instruction is not executed code

Almost any byte sequence decodes as something. A page of compressed data
decodes into a run of well-formed Thumb instructions, several of which are
loads and stores, and the effective addresses those compute look exactly like
the addresses real loads and stores compute. An analysis that treats every
decoded instruction alike will report memory regions built out of a
compression dictionary and a string table.

    valid instruction encoding  ≠  known executable code

So every discovered instruction records *why* it is believed to be code, and
that reason travels with each reference it produces. The reasons form a ladder:

| Provenance | Why these bytes are code |
| --- | --- |
| `ENTRY_POINT` | Reachable from the recovered entry point. |
| `DECLARED_HANDLER` | Reachable from another entry the backend declared — on Cortex-M, a vector-table handler. The hardware enters these directly. |
| `DIRECT_CALL` | Called by a direct PC-relative call from code that is itself trusted. The call is part of the caller's encoding. |
| `VALIDATED_INDIRECT_CALL` | Reached through an indirect call whose target was recovered and checked. |
| `SPECULATIVE_FUNCTION` | Looks like a function; nothing was shown to reach it. |
| `LINEAR_SWEEP` | Found only by decoding forward from an arbitrary point. |
| `DATA_DECODE` | Decoded from bytes there is positive reason to think are data. |

The first four are **trusted**: something itself believed to be code transfers
control here. The rest are hypotheses about bytes.

Two rules govern how it propagates:

**Trust flows downhill only.** A direct call from reset-reachable code makes
its target trusted. A direct call found *inside* a linear sweep's guesses
proves only that the sweep guessed twice, so the callee inherits the weaker of
the caller's provenance and `DIRECT_CALL` — never better than its caller.

**The best reason wins, and it is found first.** Seeds are taken in order of
how much they are trusted, so a function the reset path reaches is recorded as
reset-reachable even when a sweep also happened to guess it. No re-labelling
pass is needed.

The console reports what this excluded, so nothing disappears silently:

```
Recovered:
  Code references:   92
  Constants:         2994   (loaded, never used as an address)
  RAM references:    10 accessed, 1123 as address literals
  MMIO accesses:     28
  Unreached code:    3105 further access(es), from bytes that decode but are never reached
```

Those 3105 accesses are real decodings of real bytes. They are not evidence
that the addresses they compute exist.

## Memory regions

Regions are clustered **only** from addresses with real provenance:

- destinations of recovered load and store instructions,
- boundaries recovered from startup code,
- the initial stack pointer.

Taking every aligned 32-bit integer in the image, sorting it, and calling the
gaps RAM or MMIO produces far more false positives than useful regions, so it
is not done.

Only references whose access actually touched memory contribute. A constant
that resembles a RAM address is not a RAM bank, however many of them a literal
pool holds.

Multiple RAM banks are expected rather than merged, including banks in the
architectural code region, where vendors place CCM and tightly-coupled SRAM.

The reported Flash regions describe the bytes that actually reach the ELF, not
the whole input, so a dump with a large erased tail reports the trimmed size.

### Established and speculative regions

A cluster's confidence reflects what the evidence *is*, not how much of it
there is. One instruction reaching one address is a fact about that
instruction; a dozen instructions reaching a dozen addresses, some of them
writing, is a memory region. The weighing is:

| Evidence | Contribution |
| --- | --- |
| A startup boundary or the reset stack pointer falls in the range | strongest |
| Addresses in the range are written **by code that is reached** | strong |
| Distinct instructions **in reached code** touch the range | accumulates, capped |
| Distinct addresses within the range | accumulates, capped |
| Several **independently reached functions** touch the range | strong |
| The range agrees with where a named part maps memory | strong |
| Accesses from bytes nothing is known to execute | capped, and the cap is low |
| The window needs an external controller the firmware never configured | counts against |

Two of those rows carry most of the weight.

**Independently reached functions corroborate; one busy block does not.**
Twenty stores in a row are one piece of code's opinion about where memory is.
Two functions reached by different paths agreeing that memory is at an address
is a corroboration, and is scored as one.

**Untrusted evidence is capped, not summed.** Accesses from instructions that
merely decoded contribute a small amount that saturates: a thousand of them
are worth no more than a handful, and cannot on their own carry a region past
the established threshold. Weak evidence repeated is still weak evidence, and
a linear sweep over a compressed asset produces a great deal of it.

Below a floor, a cluster is not reported at all. Above it but below the
established threshold, the region is reported and marked **speculative**:
visible in the console and in the manifest under `speculative_regions`, so
nothing is silently discarded, but not treated as recovered memory.

A region is **established** only when three things hold at once:

- reached code made the accesses (or a startup boundary anchors the range),
- there is enough of that evidence, and
- the target plausibly has memory there.

Any one of them missing leaves the region reported but speculative. The third
is the backend's judgement, not the core's: the neutral code asks the backend
how plausible memory is at an address and never knows the answer itself. On
Cortex-M, on-chip SRAM and the peripheral windows score full marks, while the
external RAM and external device windows — which need a memory controller
configured before they respond at all, and which is where stray constants most
often land — are held to a much higher bar.

Neither kind is inserted into the ELF. RAM and MMIO regions are analysis
output; the ELF's `PT_LOAD` segments come from the image bytes and from the
`.data`/`.bss` extents recovered from startup code, which have their own
evidence. A speculative region cannot widen an ELF segment.

Where a part number is known, its documented Flash and SRAM origins are used as
*validation*: a recovered region that agrees with the part's memory map gains
confidence, and one that does not is reported without that support rather than
suppressed. A part number is a hint about the layout, not a source of regions
in its own right.

## Startup state

Cortex-M runtimes initialize memory before `main` with two loops:

```c
src = &_sidata;
dst = &_sdata;
while (dst < &_edata)
    *dst++ = *src++;

dst = &_sbss;
while (dst < &_ebss)
    *dst++ = 0;
```

Rather than recognizing known startup functions, recovery follows the registers
each loop actually uses: the base register of its store is the destination, the
base register of its load is the source, and the register it compares against
is the limit.

Two details make that work across GCC, armclang and vendor CMSIS startup code,
which lay the same three pointers out in different registers, in different
orders, with the loop test before or after the body.

**Values are read on first arrival at the loop head.** The loop head's merged
state has already absorbed the back edge, so a pointer the loop walks has
widened to a set of values or to nothing. The state on first arrival still
holds what the loop started from, which is exactly the section boundary.

**The loop body is found by walking back from the closing branch.** Taking
every instruction between the head and the branch does not work: compilers
rotate loops so the body sits after the exit test, and two initializer loops in
one function end up interleaved in address order, which would mix one loop's
store with the other's load.

Initializers performed by a *call* to a block-copy or block-fill routine are
recovered the same way, from the argument registers, provided the callee
behaves like one — a loop containing a store, and for a copy also a load. That
is a behavioural test, not a signature match, so it does not depend on the
routine being named `memcpy`.

Every recovered range is then checked for consistency: the destination must be
writable memory outside the image, the size must be a sensible multiple of the
store width, and a copy's source must be present in the image in full.

Results become `.data` and `.bss` sections plus `__data_load`,
`__data_start`, `__data_end`, `__bss_start`, `__bss_end` and `_estack` symbols.

Recovery is scoped to three call levels from the entry point. Application code
copies and clears buffers too, and without that bound those calls get reported
as `.data` and `.bss`. Table-driven initializers — a Flash table of
source/destination/end triples walked by a generic loop, as newer CMSIS and
armclang emit — are not recovered, and are reported as unrecovered rather than
guessed at.

## MCU identification

Enrichment only. A missing SVD database, an unparseable file or an ambiguous
result all degrade to "unknown MCU" and never block ELF generation.

Matching runs on recovered MMIO accesses in two stages, because a
register-level index of every vendor SVD is far too large to keep around.

1. **A cheap index** of peripheral base addresses and interrupt numbers
   shortlists devices. Building it reads only each peripheral's header — the
   part before its `<registers>` — because the bulk of these files is register
   documentation. Indexing about 1900 files and several gigabytes of XML takes
   roughly ten seconds once, then lives in `$XDG_CACHE_HOME/raw2elf`.
2. **The shortlisted files** are then read for register offsets, access
   direction and access width, but only for the peripherals the firmware
   actually touched — normally a handful out of ninety.

The strongest signal is the exact peripheral base address, recovered from
instructions such as `ldr r1, =0x40020000; str r0, [r1, #0x14]`: a device
either declares a peripheral at that address or it does not. Where the
compiler kept a rounded base and folded the rest into the displacement, the
peripheral is recovered from the effective address instead. Whether an address
merely falls inside *some* peripheral window barely discriminates, because the
Cortex-M peripheral space is dense enough that nearly every device satisfies
it, so that signal carries little weight.

The architectural system region — NVIC, SysTick, SCB — is excluded from
matching. It is identical on every part, so it says nothing about which part
this is. Those accesses are still reported as recovered MMIO.

### Ties are real, and are reported as ties

Register maps get cloned between vendors: the AT32F4 parts are
register-compatible with STM32F4, and many parts within one family are
identical in everything a given firmware touched. When the shortlist cannot be
separated, every family in the tie is named:

```
Likely MCU:
  AT32F4 / STM32F4 -- register-compatible, indistinguishable here  (confidence 0.99)
    also matches AT32F405xx_v2 (0.99)
    also matches AT32F423xx_v2 (0.99)
```

Family names are the longest prefix the tied devices of one vendor share, so
the reported family is exactly the part of the name every candidate agrees on
rather than a naming convention hard-coded per vendor.

Vendor SVD access annotations are unreliable — some STM32 files document
`RCC_CR` as read-only despite every startup routine writing it — so
access-direction contradictions count, but only lightly.

A match adds peripheral base symbols, renames device interrupt handlers from
`IRQ37_Handler` to `USART1_IRQHandler`, and with `--svd-symbols registers` adds
register symbols such as `RCC_CFGR`.

### A candidate is not an identification

A device name is reported as identified only when the recovered accesses
identify it. Below that bar the best candidate is still published — it is the
most useful thing there is to say — but under its own key, as a candidate:

```
MCU:
  identified:      no
  supplied hint:   STM32L0
  best candidate:  STM32L0x1  (confidence 0.43)
                   STM32L0x2 (0.43)
```

and in the manifest:

```json
"mcu": {
  "supplied_family_hint": "STM32L0",
  "identified_device": null,
  "identification_confidence": 0.435,
  "best_candidate": {"device": "STM32L0x1", "vendor": "STMicro", "confidence": 0.435}
}
```

`identified_device` is the key to branch on, and it is `null` whenever the
evidence does not reach an identification. A weak match also raises a warning
naming the shortfall, so it is visible without reading the numbers:

```
Warnings:
  - the supplied part STM32L0 is only weakly supported by the firmware: 3 of 6
    recovered peripheral base addresses and 8 of 20 register addresses match it
```

### A supplied part number is a hint, not an identification

`--mcu NAME` skips ranking, and what it produces is labelled accordingly:
`STM32G474RET6 (supplied)`, not marked exact, and carrying the evidence line
*"was supplied rather than identified"*. Confidence is never reported as 1.0
for a name the tool did not derive from the firmware. The user told the tool
what the part is; the tool did not find out.

The same rule covers anything outside the bytes. **No analysis reads the input
filename.** A file called `stm32f407_app.bin` is analysed identically to the
same bytes called `dump.bin`, and there is a test that asserts it. Names are
evidence about the person who saved the file, not about the firmware.

What a supplied part number *is* good for is its memory map: its documented
Flash and SRAM origins seed base candidates and validate recovered regions,
both of which are checked against the bytes rather than believed outright.

## Dumps with several images

A flash dump is not the same thing as a firmware image. One dump may hold a
bootloader, an application, two OTA slots, a configuration block and a lot of
erased flash.

```
$ raw2elf flash.bin --list-images
Image 0
  Offset:        0x000000
  Size:          988B (988 bytes)
  Architecture:  arm-cortex-m
  Entry:         0x08000318
  Confidence:    1.00 (HIGH)
    + word 0 0x20020000 is a plausible initial MSP, eight-byte aligned as AAPCS wants
    + word 1 0x08000319 is an odd (Thumb) reset vector
    + 9 architecturally named exception vectors carry the Thumb bit
    + 82 device interrupt vectors carry the Thumb bit

Image 1
  Offset:        0x008000
  Size:          480K (491520 bytes)
  ...

Reconstruct one with: --image <n> -o <output>.elf
```

Candidate extents stop at erased flash rather than running to the next image.
A selected image is analysed in its own right and inherits no conclusion drawn
in the enclosing dump's coordinate system — offsets restart at zero, and the
file offset it came from is kept for reporting.

### Every recovered fact describes one image

Base, entry, entry structure, initial stack pointer and extent only mean
anything together, so they are not passed around separately. One type,
`ImagePlacement`, holds all of them, and every later stage — entry selection,
memory mapping, symbol emission, ELF construction — works from one selected
placement. Mixing a base recovered from one image with an entry recovered from
another produces a result in which every individual number looks reasonable and
the combination describes no image that exists; the type is what makes that
assembly happen in one place instead of implicitly in five.

It also holds all three coordinate systems at once, because confusing them is
the other half of the same failure:

| Coordinate | Meaning |
| --- | --- |
| `file_offset` | Where the bytes are in the input the analyst supplied. Survives carving. |
| `image_offset` | Where the bytes are in the image under analysis. Restarts at zero when an image is carved out of a dump. |
| `runtime_base` | Where the bytes load on the target. |

A carved image restarts its offsets at zero, so a report that echoed one back
unchanged would send the analyst to the wrong place in their own file. Every
reported file offset is converted through the placement:

```
Entry structure:    vector_table at file offset 0x020000 (0x000000 within the selected image)
Load base:          0x08020000
```

An image's `runtime_base` is where *that image* loads, not where the dump
around it loads. For a bootloader at file offset 0 and an application at
0x020000 in a dump linked at 0x08000000, the two placements are:

```json
{"file_offset": "0x000000", "runtime_base": "0x08000000", "entry_structure": "0x08000000",
 "entry": "0x080002e0", "initial_stack_pointer": "0x20000600"}
{"file_offset": "0x020000", "runtime_base": "0x08020000", "entry_structure": "0x08020000",
 "entry": "0x08020de8", "initial_stack_pointer": "0x30000600"}
```

A placement also knows when its own parts disagree — an entry outside the
image's own runtime extent means the numbers were assembled from more than one
image — and that inconsistency is reported as a warning rather than emitted.

Without `--image`, the dump is reconstructed as one span of flash. Base
recovery then **anchors on the image being converted**: the base is the one
that places *that* image's table, entry and stack pointer consistently. Other
tables in the dump may corroborate that base, at a discount, but they never
object to it. A staged OTA image is linked for where it will eventually run
rather than where it is stored, so its table legitimately disagrees with the
dump's base, and that disagreement says nothing about whether the dump's base
is right.

The failure this prevents is specific. Given a bootloader at file offset 0 and
an application at 0x20000, a base of `0x07fe0000` places the *application's*
table exactly where the bootloader's table belongs. Every constituent check
passes; the answer is wrong by one image. Anchoring, plus the first-handler
locality rule below, rules it out.

**A table is immediately followed by the code it points to.** Handlers are
scattered through an image, but the nearest one is close, because code starts
right after the vector table. A base that leaves even the nearest handler a
long way past its own table has usually put that table where some other image's
table belongs, and is penalized heavily.

### The program is not always the whole input

A dump may open with erased flash, a configuration block or a second program.
Those bytes are not part of the program being reconstructed, and treating them
as its leading bytes places it at an address it does not occupy.

The concrete failure: one image stored at file offset 0x020000 and linked to
run at 0x08000000. Reading the dump as a single span makes its load address
`0x07fe0000` — the address that would put file offset zero in the right place
if the erased flash in front of the program were part of it. Every check
passes; no Cortex-M part has flash there.

So the placement covers the extent of the image the entry structure heads, and
the ELF's `PT_LOAD` segments are clipped to it:

```
Entry structure:    vector_table at file offset 0x020000
Load base:          0x08000000  (program starts at file offset 0x020000)
Memory regions:
  flash  0x08000000-0x08001187     4.4K  flash
```

Where the program *is* the whole input — the ordinary case, and the two-image
dump above without `--image` — nothing changes.

## Padding and holes

Runs of `0xff` or `0x00` at least `--padding-threshold` bytes long are reported
as padding. A long run of any other byte is not: it is more likely a real
constant table.

Padding is used to bound candidate images, and a trailing erased run of at
least 64 KiB is left out of the ELF, which keeps a 2 MiB dump of a 512 KiB
image from producing a 2 MiB ELF. `--keep-padding` disables the trim. Nothing
else is discarded, and the manifest lists every run with its offset and size.

## The ELF

Sections stay conservative. One `.flash` per input segment is correct and
useful; inventing `.text`/`.rodata` boundaries the evidence does not support
produces an ELF that looks more authoritative than it is. `--split-sections`
asks for the split, and it happens only where code discovery actually covered a
meaningful part of the segment — otherwise the request is declined and recorded
as evidence.

`.data` and `.bss` appear only when startup analysis recovered them. `.data`
carries the Flash bytes at its RAM run address with the Flash address as its
physical load address, mirroring what the original linker did, so code
referencing initialized globals resolves in a disassembler.

The ELF is written directly rather than by generating a linker script and
shelling out to binutils. That keeps the dependency list short, and more
importantly keeps the recovered addresses under the tool's control: no linker
gets to insert padding, drop a section, or place a segment somewhere else.
Loadable sections get one `PT_LOAD` each with a four-byte `p_align`, because
these ELFs are read by disassemblers rather than mapped by an operating system
and page-aligning every segment would inflate the file for no benefit.

For ARM the output carries `.ARM.attributes` declaring the M profile and
Thumb-only ISA, plus `$t` and `$d` mapping symbols. Those are what make
`objdump` and Ghidra decode Thumb rather than guessing ARM:

```
$ arm-none-eabi-objdump -d mystery.elf
08000318 <Reset_Handler>:
 8000318:	b508      	push	{r3, lr}
 800031a:	4a0a      	ldr	r2, [pc, #40]	@ (8000344 <Reset_Handler+0x2c>)
 800031c:	4b0a      	ldr	r3, [pc, #40]	@ (8000348 <Reset_Handler+0x30>)
 ...
```

`Tag_CPU_name` is emitted only when an MCU match actually identified the core.
The profile and Thumb-only ISA are enough for a disassembler to pick the right
decoder, and inventing a core name would be a claim the tool cannot back.

Symbols are emitted for what was recovered and nothing else:

| Source | Symbols |
| --- | --- |
| Recovered entry | `_start` |
| Entry structure | `__vector_table` |
| Architectural vectors | `Reset_Handler`, `NMI_Handler`, `HardFault_Handler`, `MemManage_Handler`, `BusFault_Handler`, `UsageFault_Handler`, `SVC_Handler`, `DebugMon_Handler`, `PendSV_Handler`, `SysTick_Handler` |
| Device vectors | `IRQ0_Handler` … , renamed from SVD metadata where available |
| Startup analysis | `__data_load`, `__data_start`, `__data_end`, `__bss_start`, `__bss_end`, `_estack` |
| MCU match | `RCC_BASE`, `GPIOA_BASE`, … and with `--svd-symbols registers`, `RCC_CFGR`, `GPIOA_MODER`, … |
| Architecture | `$t`, `$d` mapping symbols |

Unused vectors share one default handler, so it is named once rather than
eighty times; the full table is in the manifest. Section boundaries and
peripheral addresses are bound to `SHN_ABS`, because they are absolute values
rather than locations inside whichever section happens to contain them.
