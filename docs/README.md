# raw2elf documentation

`raw2elf` turns an arbitrary firmware extraction into a correct,
analysis-ready ELF.

A firmware dump does not carry the information a linker recorded. There is no
load address, no entry point, no segment layout and no symbols — just bytes,
often in whatever shape the extraction tool happened to print. Before such an
image can go into Ghidra, IDA, Binary Ninja or `objdump`, somebody has to work
out where it is meant to live and where execution starts. `raw2elf` does that
from the image's own structure, and records the evidence behind every
conclusion so a wrong answer can be traced rather than merely disbelieved.

## Contents

| Document | Covers |
| --- | --- |
| [Usage.md](Usage.md) | Installing and running it, input formats, every option, exit codes. |
| [Recovery.md](Recovery.md) | What is recovered and how: architecture, base, entry, references, startup, MCU, the ELF. |
| [Manifest.md](Manifest.md) | The `*.raw2elf.json` reconstruction manifest, field by field. |
| [Architecture.md](Architecture.md) | Internals, the architecture-neutral boundary, and how to add an instruction set. |
| [Testing.md](Testing.md) | The test suite, the evaluation harness, measured results, and known limitations. |

## The short version

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/raw2elf firmware.bin -o firmware.elf
```

Python 3.10 or newer and [Capstone](https://www.capstone-engine.org/) are the
whole dependency list. Install them into a virtual environment rather than
system-wide, so a Capstone version bump for one project cannot change what
another project decodes. Capstone does the instruction decoding; everything else
is a small static-analysis framework built on top of it. There is deliberately
no angr, no symbolic execution, no LLVM IR, and no Ghidra-as-a-library.

Two files come out: the ELF, and `firmware.raw2elf.json` holding what was
recovered, the alternatives that were rejected, and the evidence for each.

## What it does

```
     Arbitrary firmware extraction
                  |
                  v
        Format normalization          strict parsers, checksums verified
                  |
                  v
        Architecture detection        per-backend probes, ranked
                  |
                  v
        Entry + base recovery         structural and absolute references
                  |
                  v
      Static memory reconstruction    value propagation, not emulation
                  |
                  v
      Optional MCU identification     recovered MMIO against CMSIS-SVD
                  |
                  v
           Reconstructed ELF          plus the reconstruction manifest
```

The first architecture backend is ARM Cortex-M. The pipeline itself contains no
Cortex-M knowledge: adding an instruction set means implementing a backend, and
that boundary is [enforced by tests](Architecture.md#the-rule) rather than by
convention.

## Design commitments

These are the things the tool will not do, and they explain most of its
behaviour:

- **It does not repair input.** A record file whose checksums fail is reported
  as broken, not salvaged.
- **It does not treat a constant as a pointer.** References come from
  instructions that constructed or used an address, and keep their provenance.
- **It does not use relative branches to choose a load address.** Their targets
  move with the image, so every candidate satisfies them equally.
- **It does not invent section boundaries.** A conservative `.flash` beats a
  fabricated `.text`/`.rodata` split.
- **It does not emit a confidently wrong ELF.** Where several answers are
  plausible it reports them, with evidence, and exits non-zero.
