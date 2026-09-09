# raw2elf

Turn an arbitrary firmware extraction into a correct, analysis-ready ELF.

A firmware dump does not carry the information a linker recorded: no load
address, no entry point, no segment layout, no symbols — just bytes, often in
whatever shape the extraction tool happened to print. `raw2elf` recovers that
structure from the image itself, and records the evidence behind every
conclusion so a wrong answer can be traced rather than merely disbelieved.

```bash
git clone https://github.com/PSecLab/raw2elf.git && cd raw2elf
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/raw2elf firmware.bin -o firmware.elf
```

Or without cloning: `pip install git+https://github.com/PSecLab/raw2elf.git`.

Python 3.10+ and [Capstone](https://www.capstone-engine.org/) are the whole
dependency list. Out come the ELF and `firmware.raw2elf.json`, a manifest
holding what was recovered, the alternatives that were rejected, and the
evidence for each.

Run it with no arguments for an interactive session that holds the image and
its analysis, so overriding something and looking again is immediate.

Reads raw binaries, Intel HEX, Motorola S-Records, `xxd`, `hexdump -C` and
bare hex streams. Recovers architecture, load address, entry point, memory
regions, `.data`/`.bss` initialization, MMIO accesses, a candidate MCU from
CMSIS-SVD, and symbols. Refuses to emit an ELF it cannot justify.

The first architecture backend is ARM Cortex-M. The pipeline contains no
Cortex-M knowledge, and that boundary is enforced by tests rather than by
convention — adding an instruction set means implementing a backend.

## Documentation

Full documentation is in [`docs/`](docs/):

| Document | Covers |
| --- | --- |
| [docs/README.md](docs/README.md) | Overview, the pipeline, and the design commitments behind it. |
| [docs/Usage.md](docs/Usage.md) | Running it, input formats, every option, exit codes, the Python API. |
| [docs/Recovery.md](docs/Recovery.md) | What is recovered and how, stage by stage. |
| [docs/Manifest.md](docs/Manifest.md) | The `*.raw2elf.json` manifest, field by field. |
| [docs/Architecture.md](docs/Architecture.md) | Internals, the architecture-neutral rule, and how to add an ISA. |
| [docs/Testing.md](docs/Testing.md) | Test suite, evaluation harness, measured results, known limitations. |

## Layout

```
pyproject.toml          packaging metadata and the raw2elf entry point
docs/                   the documentation above
raw2elf/                the package
├── input/              strict format detection and normalization
├── core/               architecture-neutral representations and orchestration
├── arch/               the backend interface, and the Cortex-M backend
├── analysis/           generic passes, driven by backend capabilities
├── elf/                the ELF writer and symbol collection
├── report/             console output and the JSON manifest
├── eval/               the evaluation harness
├── tests/              the test suite and the reference firmwares
└── cli.py              the command line
```

## Tests

```bash
.venv/bin/python -m pytest           # 340 tests
.venv/bin/python -m raw2elf.eval     # graded correctness metrics
```
