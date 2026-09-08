# Internals, and adding an instruction set

The structural requirement this design exists to satisfy:

> Adding a new ISA must primarily require implementing a new architecture
> backend. Architecture-specific instruction semantics, reset conventions,
> pointer formats, startup behaviour and address-layout assumptions must not
> leak into the architecture-neutral core.

Everything below follows from that.

## Layout

```
raw2elf/
├── input/          strict format detection and normalization
│   ├── base.py         parser interface, addressed-chunk coalescing
│   ├── ihex.py         Intel HEX, checksum-validated
│   ├── srec.py         Motorola S-Records, checksum-validated
│   ├── xxd.py          xxd, all groupings and column counts
│   ├── hexdump.py      hexdump -C, and refusal of default hexdump
│   ├── _dump.py        shared dump scanning and offset continuity checks
│   ├── plainhex.py     bare hex streams and C array initializers
│   └── raw.py          the fallback, plus container-magic recognition
├── core/           architecture-neutral representations and orchestration
│   ├── image.py        firmware image, segments, the two coordinate systems
│   ├── reference.py    recovered references, kinds, accesses, provenance
│   ├── evidence.py     evidence records and confidence bands
│   ├── hypothesis.py   candidates, ranking, and refusing to guess
│   ├── memory.py       regions, loadable segments, memory initialization
│   ├── valueflow.py    the value lattice and the monotone solver
│   ├── options.py      analyst overrides
│   ├── pipeline.py     analysis passes and the shared context
│   └── util.py         formatting and alignment helpers
├── arch/
│   ├── base.py         the backend interface — contains no ISA knowledge
│   ├── registry.py     backend registration, lookup and probing
│   └── arm/            the Cortex-M backend
│       ├── cortex_m.py     the backend itself: address map, probe, base scoring
│       ├── decoder.py      Capstone configuration and code plausibility
│       ├── vectors.py      vector-table discovery and scoring
│       ├── references.py   the pre-base sweep and post-base access recovery
│       ├── flow.py         code discovery and Thumb-2 transfer functions
│       └── startup.py      .data and .bss recovery
├── analysis/       generic passes, driven by backend capabilities
│   ├── carving.py      padding detection and candidate image discovery
│   ├── entry.py        entry candidate selection
│   ├── references.py   reference recovery and classification
│   ├── base_recovery.py    candidate generation, ranking, entry resolution
│   ├── memory_recovery.py  regions, loadable segments, startup
│   ├── svd.py          CMSIS-SVD indexing, MCU ranking, annotation
│   ├── interrupts.py   handler naming and symbol collection
│   └── elf_build.py    section layout and ELF emission
├── elf/            the ELF writer and symbol table
├── report/         console output and the JSON manifest
├── eval/           the evaluation harness: corpus, metrics, an ELF reader
├── cli.py          argument parsing and output
└── reconstruct.py  backend selection and pipeline invocation
```

Dependency direction is one-way. Backends and analysis passes depend on `core`;
`core` depends on neither.

## The two coordinate systems

Almost every confusion in this problem domain comes from mixing these up, so
they are named and kept apart in `core/image.py`:

**Image offset** — an offset into the normalized byte stream. For a raw binary
this is the file offset. Analyses that have not yet recovered a load address
work here.

**Runtime address** — where the bytes sit on the target. Known up front for
Intel HEX and S-Records; recovered by analysis for raw binaries.

A `Reference` records which space its value lives in through `base_relative`.
A value produced by `ADR` is base-relative and moves with the image; a value
read out of a literal pool is absolute and does not. That single flag is what
lets base recovery know which references can discriminate between candidates
and which cannot.

Reads never cross a segment boundary. `FirmwareImage.read` clamps to the
containing segment, so a discontiguous Intel HEX file cannot be accidentally
treated as contiguous.

## Analysis passes

A pass declares what it needs and what it produces:

```python
class MemoryAccessRecovery(AnalysisPass):
    name = "MemoryAccessRecovery"
    requires = frozenset({"runtime_base"})
    capabilities = frozenset({ArchCapability.MMIO_REFERENCE_RECOVERY})
    provides = frozenset({"references", "mmio_accesses", "peripheral_accesses", "code_regions"})

    def run(self, context): ...
```

The pipeline orders passes by their artifact dependencies and runs them against
a shared `AnalysisContext`. Three rules govern what happens when something is
missing:

- **`requires`** names artifacts that must already exist. A pass whose
  requirements are unmet is *skipped and reported*, not failed.
- **`capabilities`** names architecture capabilities the selected backend must
  advertise. Same treatment.
- **`after`** is a soft ordering hint naming passes that should run first if
  present. Unlike `requires` it does not gate execution, which is how a pass
  can consume an optional artifact without being skipped when it is absent.

A failing optional pass is recorded as a warning and the run continues. An
`OptionError` — an analyst asking for something impossible, such as `--image 7`
when two images were found — always stops the run, because quietly analysing
something else would answer a different question.

The default pipeline is twelve passes: padding detection, image discovery,
entry discovery, reference recovery, base recovery, memory access recovery,
startup analysis, memory region recovery, SVD matching, interrupt annotation,
symbol recovery, and ELF reconstruction. Adding an analysis means adding it to
`analysis/default_passes()`, not editing the pipeline.

Because requirements are soft in the way described above, a backend with *no*
optional capabilities still produces a correct ELF from an analyst-supplied
base — every recovery pass stands down and the generic ones carry on. That path
is covered by a test.

## Evidence and confidence

`core/evidence.py` is deliberately dull: an `Evidence` record carries a kind, a
source, a human explanation, a value, a confidence, a weight and a `supports`
flag. Everything that reaches a conclusion emits them, and they end up in the
console output and the manifest.

Two quantities are kept separate when ranking candidates, in
`analysis/base_recovery.py`:

- **Plausibility** — how strong the evidence for a candidate is in absolute
  terms, from its total score.
- **Separation** — how clearly it beats the alternatives, from a softmax over
  the scores.

A candidate that scores well but ties with another gets a low confidence, which
is what makes `--minimum-confidence` and `--fail-on-ambiguity` meaningful. If
those two were folded into one number, a tie between two good answers would be
indistinguishable from one confident answer.

## The value lattice

`core/valueflow.py` holds four lattice elements — `Unknown`, `Const`,
`ConstSet` (bounded, degrading to `Unknown` past four members) and `Sym` (an
opaque base plus a displacement) — width-aware arithmetic over them, a register
state with a join, and a worklist solver with a per-location visit budget.

The solver records two things per location: the state after the fixpoint, and
the state on **first arrival**. That second one exists because of loops. At a
loop head the merged state has already absorbed the back edge, so a pointer the
loop walks has widened to a set or to nothing — while the first arrival still
holds the value the loop started from. That value is exactly what a section
boundary is, which is why startup recovery works at all.

The engine is architecture-neutral: it knows about integers of a given width,
locations, successors and a transfer function. Instruction semantics live
entirely in backends.

## The backend interface

`arch/base.py` is the boundary. Three methods are required:

```python
class MyBackend(ArchitectureBackend):
    name = "my-arch"
    description = "..."

    def capabilities(self):        # which optional analyses you support
        return frozenset()

    def elf_target_info(self):     # machine, endianness, pointer width, flags
        return TargetInfo(...)

    def probe(self, image):        # confidence plus evidence
        return ProbeResult(...)
```

Everything else is optional and has a working default. That is not politeness:
a vector table, a mode bit and a main stack pointer are Cortex-M concepts, not
universal ones, and a backend should not have to stub out an equivalent it does
not have. Capabilities are how a backend says what it can actually do:

| Capability | Enables |
| --- | --- |
| `ENTRY_DISCOVERY` | Entry candidate discovery and image carving. |
| `BASE_CONSTRAINTS` | Seeding and constraining base recovery. |
| `REFERENCE_RECOVERY` | Absolute reference extraction before the base is known. |
| `MMIO_REFERENCE_RECOVERY` | Effective load/store addresses after the base is known. |
| `STARTUP_ANALYSIS` | `.data` and `.bss` recovery. |
| `INTERRUPT_TABLE_RECOVERY` | Handler tables with architectural names. |
| `CODE_VALIDATION` | Scoring whether bytes decode as code. |
| `CODE_DISCOVERY` | Reporting which parts of the image are executable. |
| `MEMORY_REGION_HINTS` | Architectural regions worth recording without references. |

The optional hooks, in rough order of value:

| Hook | Purpose |
| --- | --- |
| `discover_entry_candidates` | Propose entry points from image contents. |
| `generate_base_constraints` | Seeds, alignments and permitted ranges for base recovery. |
| `evaluate_base` | Score one candidate base using instruction semantics. |
| `extract_references` | Absolute references, before the base is known. |
| `recover_memory_accesses` | Effective addresses, after the base is known. |
| `classify_reference` | Decide what a recovered value denotes. |
| `classify_address` | What the architecture's address map reserves a range for. |
| `validate_code` | Score bytes as instructions. |
| `discover_code` | Executable ranges. |
| `recover_startup_state` | Memory initialization. |
| `recover_interrupt_table` | Named handler table. |
| `normalize_code_pointer` / `encode_code_pointer` | Strip and apply mode encoding. |
| `elf_symbol_value` | What to store in a symbol. |
| `elf_extra_sections` / `elf_symbols` | Architecture metadata and mapping symbols. |
| `report_rows` / `manifest_fields` | Publish values only the backend can name. |

Those last two deserve a note, because they exist purely to keep the boundary
intact. The report needs to print "Initial MSP" and the manifest needs a
`vector_table` key, but neither the console nor the manifest builder can be
allowed to know what those mean. So the backend formats them and the reporting
code passes them through without interpretation. Where a feature needed the
rule bent, the interface was extended instead.

## The rule

> No architecture-specific instruction mnemonic, address range, reset
> convention, vector-table format, code-pointer representation or startup
> convention may be referenced directly by the architecture-neutral core.

Documentation does not hold that line. `tests/test_architecture_boundary.py`
reads every source file under `core/`, `analysis/`, `elf/`, `report/` and
`input/`, strips comments and docstrings, and fails if the remaining executable
code:

- names a Cortex-M concept (`vector_table`, `thumb`, `msp`, `vtor`, `nvic`,
  `systick`, `movw`, `ldr`, …),
- hardcodes an architectural address range (`0x20000000`, `0x40000000`,
  `0xe0000000`, …),
- imports a concrete backend,
- or, under `core/`, imports `arch` at all outside a `TYPE_CHECKING` guard.

Comments and docstrings are exempt on purpose. Explaining *why* the abstraction
exists — "a Cortex-M backend discovers these from a vector table, another from
a reset trampoline" — is what makes the interface comprehensible, and is not a
leak. Naming the concept in code that executes is.

The forbidden-token list also includes tokens for instruction sets that do not
have a backend yet (`riscv`, `rv32`, `mips`, `xtensa`, `csrrw`), so the check
stays honest as backends are added rather than becoming a Cortex-M-shaped
exception list.

Two more tests in that file cover the other half of the claim: that a backend
implementing only the three required methods works end to end, and that
registering a new backend is all it takes for architecture detection to
consider it.

## Adding a backend

1. **Write the class.** Put it in `arch/<family>/`, implement `capabilities`,
   `elf_target_info` and `probe`, and add the optional hooks you can support.
   Start with `probe` alone; the pipeline will already produce a correct ELF
   from `--base`.

2. **Register it** in `arch/registry.py`:

   ```python
   _BACKEND_MODULES = {
       "arm-cortex-m": ".arm.cortex_m:CortexMBackend",
       "my-arch":      ".myfamily.my_arch:MyBackend",
   }
   ```

   Paths are relative to the `arch` package, so the tool works under any
   top-level import name. `registry.register()` does the same at runtime for an
   out-of-tree backend.

3. **Add capabilities one at a time.** Each one switches on the passes it
   enables, and the evaluation harness will tell you what improved. A sensible
   order is `CODE_VALIDATION`, then `REFERENCE_RECOVERY` and
   `BASE_CONSTRAINTS`, then `ENTRY_DISCOVERY`, then the rest.

4. **Extend a corpus.** `eval/corpus.py` derives every input representation
   from an ELF and reads ground truth back out of it, both generically. Point
   `.venv/bin/python -m raw2elf.eval` at ELFs for your architecture and the same metrics
   apply. See [Testing.md](Testing.md).

What you should *not* need to do: touch `core/`, touch `analysis/`, or change
the pipeline. If a feature seems to require it, the interface is missing
something — extend `arch/base.py` and give the generic side a neutral name for
the concept, the way `report_rows` and `manifest_fields` were added.

## Worked example: how Cortex-M fills this in

For orientation, the mapping from the generic interface to the concrete
backend:

| Generic concept | Cortex-M realization |
| --- | --- |
| Entry candidate | An exception vector table, scored on relocation-invariant facts. |
| Code pointer encoding | The Thumb interworking bit. |
| Address class | The ARMv7-M memory map, with the vendor SRAM window in the code region handled explicitly. |
| Base constraint | VTOR alignment, handler locality, and the range the handlers imply. |
| Base assessment | Reset vectors decoding as Thumb, handlers resolving, alignment beyond the architectural minimum. |
| Reference derivation | PC-relative literal pools, `MOVW`/`MOVT` pairs, `ADR`, propagated load/store bases. |
| Startup convention | The Flash-to-RAM copy loop and the BSS clear loop, plus block-copy and block-fill calls. |
| Interrupt table | The architectural vectors by index, then device IRQs. |
| ELF metadata | `.ARM.attributes` declaring the M profile, and `$t`/`$d` mapping symbols. |

Every one of those lives under `arch/arm/`. None of it is visible from
`core/`, and the boundary test is what keeps that true.
