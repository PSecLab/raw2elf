# Testing, evaluation, and known limitations

## Running the tests

```bash
.venv/bin/python -m pytest
```

340 tests, against the installed package. `requirements.txt` performs an
editable install, so the suite exercises the working tree rather than a stale
copy. The package ships its own `pytest.ini` so the suite is independent
of any enclosing project's pytest configuration, and `tests/conftest.py` puts
the package's parent directory on `sys.path`, so the suite runs from anywhere.

| File | Covers |
| --- | --- |
| `test_input.py` | Format detection and exact round-tripping, including real `xxd` and `hexdump` output, corrupt checksums, terminal noise, truncation, squeezed dumps, and the refusals. |
| `test_core.py` | The value lattice and solver, evidence, candidate ranking, the image coordinate systems, pipeline ordering and failure handling. |
| `test_architecture_boundary.py` | The architecture-neutral rule, a minimal backend, and registering a new one. |
| `test_cortexm.py` | The ARMv7-M address map, vector-table discovery and its rejections, code validation, reference recovery, base recovery, startup, interrupt naming. |
| `test_elf_output.py` | ELF structure, addresses, permissions, symbols, mapping symbols, the writer in isolation, and validation with `readelf` and `objdump`. |
| `test_svd.py` | SVD indexing, targeted register parsing, ranking, family naming, and graceful absence. |
| `test_multi_image.py` | Padding detection, image discovery and extents, carving, staged images, RAM banks, large dumps. |
| `test_cli.py` | Every output, override, query and failure path, plus module and script invocation. |
| `test_interactive.py` | The questions asked when evidence runs out: what is asked, when, and that answers are used rather than merely recorded. |
| `test_shell.py` | The interactive session: opening, settings and staleness, topics, `why`, writing, completion, and the boundary it must respect. |
| `test_inference_is_conservative.py` | The ways inference can outrun its evidence — image tuples staying together, constants not becoming addresses, regions resting on real accesses, a supplied part number claiming nothing. |
| `test_end_to_end.py` | The graded metric matrix over every firmware in every format. |

Tests that need external tools skip cleanly without them. The `objdump` check
looks for one that can actually disassemble ARM, because a host-only `objdump`
parses the ELF happily and then refuses to disassemble it — which would look
like a failure of the ELF rather than of the tool reading it.

## The evaluation harness

```bash
.venv/bin/python -m raw2elf.eval                        # the bundled corpus
.venv/bin/python -m raw2elf.eval firmware.elf other.elf # any Cortex-M ELFs
.venv/bin/python -m raw2elf.eval --json report.json     # machine-readable
.venv/bin/python -m raw2elf.eval --svd                  # include MCU matching
```

The harness takes ELFs whose ground truth is known, renders each into every
input format the tool accepts, reconstructs it, and grades the result against
what the original ELF says.

Both halves are deliberately independent of the tool being graded.
`eval/corpus.py` derives the input representations, and `eval/elfread.py` is a
small standalone ELF reader — written with `struct` rather than reusing the
writer — so a reconstruction is never checked by the same code that produced
it. Nothing in `eval/` is needed to run `raw2elf` itself.

### Metrics

| Metric | Question |
| --- | --- |
| `input.bytes` | Did normalization recover the exact original bytes? |
| `input.declared_base`, `input.format` | Were declared addresses and the format preserved? |
| `architecture.machine`, `architecture.confidence` | Correct architecture, confidently? |
| `base.top1`, `base.top3` | Was the linked load address recovered, and was it ranked first? |
| `entry` | Was the entry point recovered? |
| `vector_offset` | Was the entry structure's file offset recovered? |
| `initial_sp` | Was the reset-time stack pointer recovered? |
| `startup.data_load`, `.data_start`, `.data_size` | Were the `.data` source, destination and size recovered? |
| `startup.bss_start`, `.bss_end` | Were the `.bss` bounds recovered? |
| `references.code_precision` | Of the values called code pointers, how many are known functions? |
| `references.vector_recall` | Of the handlers in the reference vector table, how many came back? |
| `references.ram_precision` | Do RAM references land in writable sections? |
| `references.mmio_directed` | Does every peripheral access carry a direction and width? |
| `elf.produced`, `.parses`, `.machine`, `.entry`, `.bytes_faithful` | Is the output a valid ELF with the right target, entry and bytes? |

Two of these need explaining, because their obvious formulations are wrong.

**Recall is measured against vector-table handlers, not all functions.**
`references.function_coverage` is reported but never graded. Most functions are
only ever reached by a direct branch, so no amount of absolute-reference
recovery can name them, and a threshold there would really be a threshold on
how the firmware was compiled. Handlers in the reference vector table, by
contrast, are guaranteed to exist as absolute pointers, so they are a fair
target — and recall against them is 1.0.

**A metric with no ground truth is reported as `n/a`, never as a pass.** If a
reference ELF has no `_estack` symbol, `initial_sp` is not graded for it. This
matters more than it sounds: the alternative quietly inflates a pass rate every
time the corpus grows in a direction the tool happens not to cover.

## Reference corpus

`raw2elf/tests/fixtures/` holds five purpose-built firmwares with their
sources and a build script. The ELFs are committed so neither the tests nor the harness needs
a cross toolchain; re-run `raw2elf/tests/fixtures/build.sh` (which wants
`arm-none-eabi-gcc`) only when the sources change.

| Firmware | Exercises |
| --- | --- |
| `stm32f4_standard` | The conventional case: Flash at `0x08000000`, SRAM at `0x20000000`. |
| `nonstandard_base` | A Flash base at `0x10000000`, in the architectural code region where vendors also put SRAM. |
| `application_high` | Linked at `0x08008000`, so its vector table lands at a non-zero file offset in a dump. |
| `bootloader` | The first image of a two-image dump. |
| `two_ram_banks` | Two RAM banks that must not be merged into one range. |

All five are built from one source: a conventional vector table with named
exception handlers and 82 device interrupts, a reset handler whose `.data` copy
and `.bss` clear are ordinary C loops, real STM32F4 registers across six
peripherals, a constant table and a string in `.rodata`, and a function-pointer
table so absolute code references exist to recover.

From these the tests also build the harder layouts: bootloader-plus-application
dumps, OTA staging layouts whose vector tables disagree with the dump's base,
2 MiB dumps with large constant tables and erased regions, dumps wrapped in
terminal noise, and truncated dumps.

## Measured results

Across the five reference firmwares in all nine input representations — 45
reconstructions — every graded metric passes:

```
check                             pass  fail   n/a
architecture.confidence             45     0     0
architecture.machine                45     0     0
base.top1                           45     0     0
base.top3                           45     0     0
elf.bytes_faithful                  45     0     0
elf.entry                           45     0     0
elf.machine                         45     0     0
elf.parses                          45     0     0
elf.produced                        45     0     0
entry                               45     0     0
initial_sp                          45     0     0
input.bytes                         45     0     0
input.declared_base                 10     0    35
input.format                        45     0     0
references.code_precision           45     0     0
references.function_coverage         0     0    45
references.mmio_directed            45     0     0
references.ram_precision            45     0     0
references.vector_recall            45     0     0
startup.bss_end                     45     0     0
startup.bss_start                   45     0     0
startup.data_load                   45     0     0
startup.data_size                   45     0     0
startup.data_start                  45     0     0
vector_offset                       45     0     0

45/45 runs clean; slowest 0.18s, peak 5.8 MiB
```

`input.declared_base` is `n/a` for the seven formats that carry no addresses,
which is the correct outcome rather than a gap.

Beyond the corpus: a 2 MiB dump holding two images, a 256 KiB constant table
and 1.5 MiB of erased flash resolves to the right base with `HIGH` confidence
in about 3.5 seconds using roughly 40 MiB, and the emitted ELF is 513 KiB
rather than 2 MiB.

### On real firmware

Three real RTOS images were also graded (ChibiOS, Zephyr, ThreadX). In every
input format, base, entry, vector-table offset, code-pointer precision,
vector-handler recall, RAM precision and ELF correctness all pass.

Startup recovery is partial there, and the reasons are worth recording:

- **Zephyr's `.bss` comes back exactly**, recovered through its block-fill
  call. Its `.data` copy does not, because it does not take the shape the
  analysis looks for.
- **ThreadX and ChibiOS report nothing**, which is the intended outcome rather
  than a silent wrong answer. Earlier iterations of this analysis did produce
  values for them — application-level `memset` calls mistaken for `.bss` — and
  reporting nothing is strictly better than that.

Two further images in the same directory, built for NuttX and RT-Thread, are
not Cortex-M at all: both open with `e59ff018`, the classic A32 reset
convention. The probe declines them with confidences of 0.00 and 0.07, which is
the behaviour that matters — a tool that reconstructed them as Cortex-M would
be producing confident nonsense.

## Known limitations

Stated plainly, because knowing where a recovery tool stops is part of trusting
the rest of it.

- **Table-driven initializers are not recovered.** Newer CMSIS and armclang
  emit a Flash table of source/destination/end triples walked by a generic
  loop. Startup recovery reports nothing for those rather than guessing.
- **Startup recovery is scoped to three call levels from the entry point.**
  Application code copies and clears buffers too, and without that bound those
  calls get reported as `.data` and `.bss`.
- **One architecture backend exists.** The abstraction, the capability system
  and the registry are exercised by tests using synthetic backends, but
  RISC-V, MIPS and Xtensa are not implemented. See
  [Architecture.md](Architecture.md#adding-a-backend).
- **Big-endian and 64-bit targets are written but unexercised.** The ELF writer
  handles both and is tested directly; no backend needs them yet.
- **A reference's classification is a judgement, not a fact.** A literal is
  called `CODE` only if it points at an address that decoded as an instruction,
  which is conservative in both directions: a pointer into code that discovery
  never reached is reported as `FLASH_DATA`.
- **Vendor SVD access annotations are unreliable.** Some STM32 files document
  `RCC_CR` as read-only despite every startup routine writing it, so
  access-direction contradictions are weighted lightly.
- **Section splitting is coarse.** `--split-sections` produces at most
  `.vectors`, `.text` and `.rodata` from the extent of discovered code, not
  real compiler section boundaries.
- **Analysis is bounded, not exhaustive.** `--max-instructions` caps decoding
  at 400 000 instructions by default, and the value solver bounds revisits per
  location. On a very large image some code goes unanalysed; the manifest says
  so rather than pretending otherwise.
