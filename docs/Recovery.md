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

### A literal is not assumed to be a pointer

A literal pool value may be an address, an integer, a bitmask, a
floating-point value, a peripheral address, a RAM pointer or a code pointer.
Every reference therefore keeps its provenance — the producing instruction, its
offset, and how the value was derived — and classification waits until the
memory map is known.

The classes are `CODE`, `FLASH_DATA`, `RAM`, `MMIO` and `UNKNOWN`, each with an
access of `READ`, `WRITE`, `EXECUTE` or `ADDRESS_ONLY`.

Classification is deliberately conservative. A value is called `CODE` only if
it points at an address that actually decoded as an instruction, or if the
instruction executed it. The Thumb bit makes a code pointer look distinctive,
but plenty of ordinary constants are odd, and a literal pointing one byte into
a string is not a function. The cost of that conservatism is that a pointer
into code which discovery never reached is reported as `FLASH_DATA`; the
benefit is that the `CODE` class stays trustworthy.

## Memory regions

Regions are clustered **only** from addresses with real provenance:

- destinations of recovered load and store instructions,
- boundaries recovered from startup code,
- the initial stack pointer.

Taking every aligned 32-bit integer in the image, sorting it, and calling the
gaps RAM or MMIO produces far more false positives than useful regions, so it
is not done.

A cluster is kept if it contains a recovered *store* — the instruction wrote
there, so the memory exists and is writable — or a startup boundary, or at
least three distinct read references. Multiple RAM banks are expected rather
than merged, including banks in the architectural code region, where vendors
place CCM and tightly-coupled SRAM.

The reported Flash regions describe the bytes that actually reach the ELF, not
the whole input, so a dump with a large erased tail reports the trimmed size.

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
register symbols such as `RCC_CFGR`. `--mcu NAME` skips ranking entirely.

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

Without `--image`, the dump is reconstructed as one span of flash. Base
recovery then weighs *all* the vector tables it found, which matters because
each table on its own is consistent with a base that lines its handlers up with
some other image's code. A staged OTA image is linked for where it will
eventually run rather than where it is stored, so its table disagrees with the
dump's base. The chosen entry structure carries full weight and further tables
corroborate at a discount, so one disagreeing table cannot outvote the real
one; the disagreement is recorded as evidence against the candidate rather than
silently averaged in, and the dump's real base still comes out.

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
