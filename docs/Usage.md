# Usage

## Installing

Work in a virtual environment. Capstone is a native extension, and pinning it
per project keeps a version bump for one tool from changing what another one
decodes.

```bash
git clone https://github.com/PSecLab/raw2elf.git && cd raw2elf
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

That is an editable install of the package plus its test dependencies, so
edits to the source take effect without reinstalling. For a plain install use
`.venv/bin/pip install .`, and to install from the repository without cloning
it first:

```bash
python3 -m venv .venv
.venv/bin/pip install git+https://github.com/PSecLab/raw2elf.git
```

Either way the environment gains a `raw2elf` command as well as the importable
package.

Python 3.10 or newer, and Capstone is the only runtime dependency; the `dev`
extra adds pytest for the test suite. MCU identification additionally wants a
CMSIS-SVD tree, and without one everything else still works — see
[Recovery.md](Recovery.md#mcu-identification).

## Invoking it

```bash
.venv/bin/raw2elf firmware.bin -o firmware.elf
```

Activating the environment first is equivalent, and shorter if you are running
several commands:

```bash
source .venv/bin/activate
raw2elf firmware.bin -o firmware.elf
```

The module form does the same thing and works from a clone with no install at
all:

```bash
.venv/bin/python -m raw2elf firmware.bin -o firmware.elf
```

Failing all of that, point the interpreter straight at `cli.py`, which puts its
own package directory on `sys.path`:

```bash
.venv/bin/python /path/to/raw2elf/raw2elf/cli.py firmware.bin -o firmware.elf
```

All of these are equivalent. The transcripts below use `raw2elf`, which is
literally the command once the environment is active.

## A worked example

This is a 2 MiB flash dump holding a bootloader and an application, with no
load address, no entry point, a large constant table and 1.5 MiB of erased
flash:

```
$ raw2elf mystery.bin -o mystery.elf
Input format:       Raw binary
  detected as:      2097152 bytes
Input size:         2.0M in 1 segment(s)
Architecture:       ARM Cortex-M
Entry structure:    vector_table at file offset 0x000000
Vector table:       0x08000000
Initial MSP:        0x20020000
Load base:          0x08000000
Entry point:        0x08000318  (ELF e_entry 0x08000319)

Recovered:
  Code references:   184
  Constants:         8221   (loaded, never used as an address)
  Flash references:  11
  RAM references:    13 accessed, 31 as address literals
  MMIO accesses:     54

Memory regions:
  flash  0x08000000-0x0807ffff     512K  flash
  ram    0x20000000-0x200003ff     1.0K  ram
  ram    0x2001fc00-0x2001ffff     1.0K  ram1
  mmio   0x40000000-0x40023bff     143K  mmio0
  mmio   0xe0000000-0xe00fffff     1.0M  ppb

Startup initialization:
  .data  0x080003d4 -> 0x20000000  8B
  .bss   0x20000008-0x20000128  288B

Likely MCU:
  AT32F4 / STM32F4 -- register-compatible, indistinguishable here  (confidence 0.99)

Confidence:
  Architecture: HIGH    (0.95)
  Base:         HIGH    (0.99)
  Entry:        HIGH    (1.00)

Generated:
  mystery.elf
  mystery.raw2elf.json
```

Several details in that output are deliberate, and they say most of what there is
to know about how the tool behaves.

**The Flash region is 512K, not 2M.** The erased tail is reported as padding
and left out of the ELF, so the output is not inflated by 1.5 MiB of `0xff`.
`--keep-padding` puts it back.

**Constants are counted, not converted.** 8221 values were loaded from literal
pools and never used as an address by any instruction, so they are reported as
what they are. A firmware image is full of integers, masks and floating-point
bit patterns that fall inside plausible SRAM and peripheral windows; calling
them addresses would invent a memory map out of arithmetic. They are all in the
manifest under `references.constants`, with the instruction that loaded each
one.

**RAM references are split by how strong the evidence is.** Thirteen came from
load and store instructions whose effective address was recovered — something
dereferenced them. The other thirty-one are values that reached an address
computation without a memory access being observed. Reporting one total for
both would make the weak evidence look like the strong kind, and the recovered
RAM regions are built only from the strong kind.

**The entry point is reported twice.** `0x08000318` is the address; the ELF
records `0x08000319` because Cortex-M code pointers carry the Thumb bit. Both
are in the manifest, as `entry` and `elf_entry`.

**Every region shown rests on an observed access.** A range inferred from
weaker evidence still appears, marked `speculative` with its confidence, and
stays out of the recovered memory map and out of the ELF:

```
Memory regions:
  ram    0x20000000-0x200003ff     1.0K  ram
  ram    0x24000000-0x240000ff      256  ram2      speculative (0.41)
```

**The MCU is two families, not a part number.** AT32F4 and STM32F4 are
register-compatible, so from these accesses the part genuinely cannot be
narrowed further, and saying otherwise would be false precision.

## Input formats

Detection tries explicit parsers before falling back to a raw binary, and each
one validates its own framing.

| Format | Notes |
| --- | --- |
| Raw binary | The fallback. Load address unknown until analysis. |
| Intel HEX | Records and checksums verified; extended-address and entry records honoured. |
| Motorola S-Record | `S1`/`S2`/`S3` data with checksums; termination records give an entry hint. |
| `xxd` | Default, `-g1`/`-g4`, non-default column counts, `-a` repeat squeezing. |
| `hexdump -C` | Including `*` repeat markers and the trailing length line. |
| Bare hex | `xxd -p` output, comma/colon-separated bytes, C array initializers. |

`--detect` reports what each parser thought, without analysing anything:

```
$ raw2elf firmware.hex --detect
Selected: ihex (Intel HEX)
Normalized: 988 bytes in 1 segment(s)

Parser opinions:
  ihex         0.98  32 valid records
  plainhex     0.00  input is framed like Intel HEX or S-Records, not a bare hex stream
  raw          0.01  2601 bytes
```

Three properties of ingestion are worth stating explicitly, because they are
where naive handling of these formats goes wrong.

**Nothing is repaired.** A record file whose checksums fail is reported as
broken, not salvaged. In particular the bare-hex parser refuses input that is
*framed* like Intel HEX or S-Records, so a corrupt record file can never be
rescued into plausible-looking firmware by dropping its framing and keeping
the hex digits.

**The ASCII column is parsed, not stripped.** Deleting "non-hex" characters
from a terminal dump is a reliable way to produce corrupted firmware, because
the ASCII column is full of characters that look like hex digits. Each line's
declared offset is then used as a checksum: it must equal the previous offset
plus the previous line's byte count. That is also how erased regions and `*`
repeat markers are reconstructed exactly.

**Default `hexdump` output is refused.** Its 16-bit groups are byte-swapped on
a little-endian host, so decoding it would silently produce wrong firmware:

```
$ raw2elf dump.txt
raw2elf: this is default 'hexdump' output; its 16-bit groups are byte-swapped,
so decoding it would silently produce wrong firmware. Re-dump with
'hexdump -C' or 'xxd'
```

`--input-format raw` overrides any of this when you know better.

Intel HEX and S-Records keep their declared addresses, so they need no base
recovery. Discontiguous inputs stay discontiguous: separate ELF segments, not
one segment with an enormous zero-filled hole.

An ELF handed in by mistake is recognized and refused with advice, rather than
analysed as though its headers were firmware.

## Options

Analyst input always wins over inference.

```bash
raw2elf firmware.bin \
    --arch arm-cortex-m \
    --base 0x08000000 \
    --entry 0x08001450 \
    --vector-offset 0 \
    -o firmware.elf
```

### Recovery overrides

| Option | Effect |
| --- | --- |
| `--arch NAME` | Force an architecture backend instead of probing. `auto` by default. |
| `--base ADDR` | Runtime load address of the image. |
| `--entry ADDR` | Entry point. |
| `--vector-offset OFFSET` | File offset of the entry/vector structure. |
| `--image N` | Which candidate image to reconstruct. See [Recovery.md](Recovery.md#dumps-with-several-images). |
| `--input-format NAME` | Force a parser instead of detecting one. |

### MCU identification

| Option | Effect |
| --- | --- |
| `--mcu NAME` | The part number, as printed on the package. Suffixes are ignored. Constrains the load address and skips MCU ranking. |
| `--svd PATH` | An SVD file, or a directory to search. |
| `--no-svd` | Skip MCU identification entirely. |
| `--no-svd-fetch` | Do not download the CMSIS-SVD database when no local copy is found. |
| `--svd-symbols LEVEL` | `none`, `peripherals` (default), or `registers`. |

### Confidence policy

| Option | Effect |
| --- | --- |
| `--minimum-confidence F` | Refuse to emit below this confidence. `0.5` by default. |
| `--fail-on-ambiguity` | Refuse when the runner-up is too close to the winner. |

### Output

| Option | Effect |
| --- | --- |
| `--split-sections` | Emit `.text`/`.rodata` where the evidence allows it. |
| `--keep-padding` | Keep large trailing erased-flash regions in the ELF. |
| `--max-instructions N` | Cap on instructions decoded. `400000` by default. |
| `--padding-threshold N` | Shortest run of a repeated byte reported as padding. `256` by default. |

### Queries

Each of these prints and exits without writing anything.

| Option | Effect |
| --- | --- |
| `--list-images` | List the candidate firmware images in the input. |
| `--list-arch` | List the available architecture backends. |
| `--detect` | Report input-format detection and each parser's opinion. |
| `--probe` | Report architecture probe scores and their evidence. |

### Interaction

| Option | Effect |
| --- | --- |
| `-i`, `--interactive` | Ask instead of refusing, and offer a choice of image. See [Interactive sessions](#interactive-sessions). |

### Diagnostics

`-v` prints the evidence behind the decisions, which is the first thing to
reach for when a result looks wrong:

```
Recovered base: 0x08000000
Confidence: HIGH (0.99)

Evidence:
  + word 0 0x20020000 is a plausible initial MSP, eight-byte aligned as AAPCS wants
  + 88 vectors share handler 0x080001b0, the signature of a shared default handler
  + vector table lands at 0x08000000, aligned to 0x8000000
  + reset vector 0x08000319 maps to executable bytes (94 instructions over 196
    unbroken bytes, 15 distinct mnemonics, 45% single-mnemonic)
  + all handlers lie within 0x318 bytes after their own vector table at 0x08000000
  + loop at 0x08000320 walks r3 from 0x20000000 to 0x20000008 in 32-bit stores
  + its load walks r2 from 0x080003d4, and all 8 bytes of that range are present
```

Repeating `-v` adds per-pass timing. Everything shown here, and more, is in the
[manifest](Manifest.md) regardless of verbosity.

## Interactive sessions

Running `raw2elf` with no firmware, or with `--shell`, opens a session that
holds the image and its analysis in memory:

```
$ raw2elf
raw2elf 0.1.0 -- interactive session

  open <file>     read a firmware dump        show <topic>   see the analysis
  set <k> <v>     override something          why base       what was weighed
  probe / images  look before analysing       write [file]   emit the ELF

raw2elf> open flash.bin
flash.bin  Raw binary, 2.0M in 1 segment(s)

raw2elf> images
Image 0
  Range:         0x000000-0x009b6f
  Size:          39K (39792 bytes)
  Entry:         0x080002e0
  ...

raw2elf> set mcu STM32G
  mcu = STM32G

raw2elf> set image 1
  image = 1

raw2elf> show base
analysing...
  base       0x08020000   confidence 0.99

raw2elf> why base
Candidate load addresses:
  1. 0x08020000    confidence 0.99    (backend seed)
       + vector table lands at 0x08020000, aligned to 0x20000
       ...

raw2elf> write application.elf
  application.elf  598104 bytes
  application.raw2elf.json

raw2elf> info
...
equivalent command:
  raw2elf flash.bin --image 1 --mcu STM32G
```

Working out an awkward dump is not one question, and answering it as a series
of shell invocations re-reads and re-analyses the image every time. A session
keeps both, so overriding something and looking again is immediate.

Nothing is only available here. Every setting is a flag, and `info` prints the
invocation that reproduces the session, so this is a way of arriving at a
command rather than a replacement for one.

| Command | Does |
| --- | --- |
| `open <file>` | Read a dump and report what the format detector made of it. |
| `detect` | What each input parser thought. |
| `probe` | How each architecture backend scores the image. |
| `images` | The programs in the dump. A look: it neither analyses nor asks. |
| `set` / `unset` | Override something, or go back to inferring it. `set` alone lists them. |
| `run` | Analyse now, asking if anything cannot be decided. |
| `show <topic>` | Part of the analysis. A topic name on its own works too. |
| `why [word]` | `why base` lists the candidates with their evidence; any other word searches the evidence log. |
| `write [file]` | Emit the ELF and the manifest. |
| `info` | What is open, what is set, and the equivalent command. |

Topics are `summary`, `base`, `entry`, `images`, `regions`, `startup`, `mmio`,
`references`, `symbols`, `mcu`, `sections`, `evidence`, `passes` and
`warnings`. Analysis runs on demand and is held until a setting changes it,
so `show` after `set` re-runs and the rest is instant. Command and topic names
tab-complete, and history works where readline is available.

## Answering as it goes

`-i` / `--interactive` asks rather than refusing.

It is not a configuration wizard, and it does not ask you to make judgements
about binaries. On a straightforward image it asks nothing at all.

What it does ask is what you can see:

```
$ raw2elf mystery.bin -o mystery.elf --interactive

What is printed on the chip? (Enter to skip; raw2elf will work it out)
  for example STM32F407VGT6, nRF52840 or LPC1768
> STM32F407VGT6
  the STM32 family maps Flash at 0x08000000, 0x00000000 (Flash is also
  aliased at 0 when booting from it)

[...]

Repeat without prompting:
  raw2elf mystery.bin --mcu STM32F407VGT6 -o mystery.elf
```

That one answer is the piece of evidence the image cannot contain. Where a
firmware is loaded is a deduction; what the package says is an observation,
and for most families it implies the answer. It is also the only question in
the tool that does not require knowing anything about binaries.

The part number is treated as evidence, not as an instruction. It is scored
alongside everything else, so a firmware genuinely linked somewhere unusual
still wins on its own evidence — naming an STM32 does not drag an image linked
at `0x10000000` to `0x08000000`. Suffixes are ignored, so the full order code
off the package works; `--mcu` does the same thing without a session.

Where recovery still cannot decide, naming the chip is offered first and the
addresses it weighed come after, for whoever wants them:

```
If you can read the part number off the chip, that settles it:
  c) name the chip  (for example STM32F407VGT6)

Otherwise, the addresses it weighed, best first:

  1) 0x07f00000  confidence 0.31  (backend seed)
       - handlers would lie up to 1.0 MiB past their own vector table
  2) 0x08000000  confidence 0.28
  e) enter a load address
  c) name the chip
  q) abort
```

A dump holding more than one program is the other thing worth asking about,
and it is asked the same way — by what the options *are*, not by their offsets,
with the safe answer first:

```
This dump appears to contain 2 separate programs.
If you are not sure, press Enter and the whole dump will be used.

  1) analyse the whole dump together  [0x000000-0x1fffff]  (recommended)
  2) just the program at the very start of the dump, 32K  [0x000000-0x007fff]
  3) just the program 192K into the dump, 876K  [0x030000-0x10afff]
  q) abort
```

Each option carries the byte range it covers, so a choice can also be carved
out by hand, and `--list-images` reports the same ranges.

Only credible programs are offered: a candidate needs high confidence and at
least 512 bytes, and if more than six qualify the question is dropped
altogether in favour of the whole dump, with `--list-images` mentioned. A
question with eleven answers is not a question anyone can answer.

The remaining properties are worth knowing:

**Being able to ask never lowers the bar for deciding.** The threshold and
ambiguity rules run first and unchanged; a session is consulted only once a
refusal has already been decided on.

**`q`, or end-of-input, refuses exactly as an unattended run would** — same
error, same exit code 3, nothing written.

**It will not start without a terminal.** A piped or scheduled run would block
on a prompt nobody can see, so `-i` with a non-terminal stdin is a usage error.

The session ends by printing the equivalent non-interactive command. There is
no session file to manage: the flags *are* the configuration.

## When it refuses

`raw2elf` does not emit a confidently wrong ELF. If the best candidate misses
`--minimum-confidence`, or `--fail-on-ambiguity` is set and the runner-up is
too close, it reports the candidates and exits non-zero:

```
$ raw2elf odd.bin -o odd.elf
raw2elf: best runtime base address candidate 0x07f00000 has confidence 0.31,
below the required 0.50

Candidate load addresses:
  1. 0x07f00000    confidence 0.31    (backend seed)
       + vector table lands at 0x07f00000, aligned to 0x100000
       + reset vector 0x08000319 maps to executable bytes
       - handlers would lie up to 1.0 MiB past their own vector table
  2. 0x08000000    confidence 0.28    (reference value aligned to 0x1000000)
       + all handlers lie within 0x318 bytes after their own vector table
       - none of the 4 resolvable exception handlers decode as Thumb code

raw2elf will not emit an ELF it cannot justify. Any of these settles it:

  --base 0x07f00000            take the best candidate
  --minimum-confidence 0.30    accept it as it stands
```

The candidates and their evidence are always shown, because a refusal that
only announces a verdict leaves you with nothing to act on. The suggested
flags are specific to the refusal: an ambiguity offers the tied candidates and
`--fail-on-ambiguity` rather than a threshold, since raising a threshold
cannot separate two answers that tie, and an unrecognized architecture offers
`--arch` and `--probe`, since the architecture floor is fixed and
`--minimum-confidence` would not move it.

| Exit code | Meaning |
| --- | --- |
| `0` | An ELF was written. |
| `2` | Usage error, missing file, or input that could not be read. |
| `3` | Refused: the recovered configuration did not meet the required confidence. |

Together with `--minimum-confidence` and `--fail-on-ambiguity` that makes batch
processing deterministic. A run either produces an ELF that met the bar, or
fails loudly.

## Programmatic use

The CLI is a thin layer over two calls:

```python
from raw2elf import input as ingest
from raw2elf.core.options import Options
from raw2elf.reconstruct import reconstruct
from raw2elf.report import manifest

image = ingest.load("firmware.bin")
result = reconstruct(image, Options(minimum_confidence=0.8))

open("firmware.elf", "wb").write(result.elf)
open("firmware.raw2elf.json", "w").write(manifest.dumps(result))

print(hex(result.runtime_base), hex(result.entry))
```

`reconstruct` raises `LowConfidenceError` or `AmbiguityError` from
`raw2elf.core.hypothesis` where the CLI would exit `3`, and `OptionError` from
`raw2elf.core.options` for an option that cannot be honoured. Everything the
run produced is on `result.context`; the artifact names are listed in
[Manifest.md](Manifest.md) and [Architecture.md](Architecture.md).
