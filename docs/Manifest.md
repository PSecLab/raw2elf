# The reconstruction manifest

Alongside the ELF, `raw2elf` writes `<name>.raw2elf.json`. This is the stable
machine-readable interface to a reconstruction, for everything that does not
fit inside ELF metadata: the confidence in each conclusion, the alternatives
that were rejected, and the evidence behind both.

That last part is the point. When a reconstruction is wrong, the question is
never "is it wrong" but "which observation made it go wrong", and the manifest
is what answers it.

`--report PATH` chooses the path; `--no-report` skips the file entirely.

## Top-level answers

```json
{
  "raw2elf": { "manifest_version": 1, "tool_version": "0.1.0" },
  "architecture": "arm-cortex-m",
  "backend": "arm-cortex-m",
  "endianness": "little",
  "pointer_width": 32,
  "base": "0x08000000",
  "entry": "0x08000318",
  "elf_entry": "0x08000319",
  "vector_table": "0x08000000",
  "initial_sp": "0x20020000",
  "vector_table_entries": 98,
  "default_handler": "0x080001b0",
  "candidate_mcu": "STM32F / AT32F4 -- register-compatible, indistinguishable here",
  "confidence": {
    "architecture": 0.9855,
    "base": 0.995,
    "entry": 1.0,
    "mcu": 0.99
  },
  "confidence_labels": {
    "architecture": "HIGH",
    "base": "HIGH",
    "entry": "HIGH"
  }
}
```

`entry` is the address; `elf_entry` is what the ELF header records, which on
Cortex-M differs by the Thumb bit. Addresses are hexadecimal strings so that no
consumer has to care about integer width; sizes and counts are numbers.

`vector_table`, `initial_sp`, `vector_table_entries` and `default_handler` are
contributed by the architecture backend rather than by generic code, which is
why they use the architecture's own vocabulary. A future backend publishes its
own equivalents and these are simply absent.

`confidence` is a float in 0..1; `confidence_labels` gives the `HIGH` /
`MEDIUM` / `LOW` / `NONE` bands the console prints. `manifest_version` is
bumped only for an incompatible layout change.

## Sections

| Key | Contents |
| --- | --- |
| `raw2elf` | Manifest version and tool version. |
| `input` | Source path, detected format, the full detection ranking, byte counts, per-segment addresses, and any parser notes. |
| `target` | Architecture, subarchitecture, instruction mode, endianness, pointer width, ELF machine number and flags — kept separate rather than collapsed into one string. |
| `entry_structure` | The chosen entry structure: kind, file offset, image offset, runtime address, confidence. |
| `placement` | The selected image, which every later stage worked from — `file_offset`, `image_offset`, `image_size`, `runtime_base`, `entry_structure` (plus the `entry_structure_offset` it derives from), `entry`, `initial_stack_pointer`. This is one of the objects in `images`, not a tuple assembled beside them; read it rather than reassembling the pieces. |
| `architecture_candidates` | Every backend's probe confidence and details. |
| `base_candidates` | Ranked load addresses, each with score, confidence, origin, and its evidence. |
| `images` | Candidate firmware images found in the input, each with its own complete tuple: `runtime_base`, `entry`, `entry_structure` and `initial_stack_pointer`. |
| `entry_candidates` | Every entry structure found, with its evidence. |
| `regions` | Recovered memory map: type, bounds, size, permissions, confidence, evidence. Every region here rests on an observed memory access, a startup boundary or the reset stack pointer. |
| `speculative_regions` | Ranges the evidence suggests but does not establish, in the same shape. Reported so nothing is discarded silently; not part of the recovered memory map, and never present in the ELF. |
| `regions[].trust_path` | For an established region, the chain of reasoning showing that an instruction which touches it really executes — seed, call sites, block, instruction, access. Every established region has one. |
| `elf_sections` | The allocated sections actually emitted. |
| `padding` | Every detected padding run: offset, size, byte value. |
| `references` | Totals by kind and by access, plus the `code`, `ram`, `flash_data` and `constants` reference lists. |
| `mmio_accesses` | Every recovered peripheral access with direction, width, base and displacement. |
| `startup` | The initial stack pointer and every recovered memory initialization. |
| `data_initialization` | The `.data`-style copies, extracted from `startup` for convenience. |
| `bss` | The `.bss`-style cleared ranges, likewise. |
| `interrupts` | The full handler table: index, IRQ number, name, handler address, and whether the vector is architectural. |
| `mcu`, `mcu_candidates` | `identified_device` (null unless the firmware identified it), `identification_confidence`, `supplied_family_hint`, and `best_candidate` — plus the ranked alternatives. See [A candidate is not an identification](Recovery.md#a-candidate-is-not-an-identification). |
| `peripherals`, `peripheral_registers` | Peripheral and register annotations from a confident SVD match. |
| `symbols` | Every emitted symbol with its value, size, kind, and the analysis that produced it. |
| `evidence` | The full evidence log for the run. |
| `warnings` | Anything the run wanted to tell you but did not fail over. |
| `passes` | Which analysis passes ran, were skipped or failed, why, and how long each took. |

## Worked fragments

### Why this base and not the others

```json
"base_candidates": [
  {
    "base": "0x08000000",
    "score": 17.7,
    "confidence": 0.995,
    "origin": "backend seed",
    "evidence": [
      "+ vector table at offset 0x0 allows base 0x08000000 with its handlers inside the image",
      "+ vector table lands at 0x08000000, aligned to 0x8000000",
      "+ reset vector 0x08000319 maps to executable bytes (94 instructions over 196 unbroken bytes, 15 distinct mnemonics, 45% single-mnemonic)",
      "+ all handlers lie within 0x318 bytes after their own vector table at 0x08000000",
      "+ 4 of 4 distinct exception vectors resolve inside the image"
    ]
  },
  {
    "base": "0x08000100",
    "score": 0.7,
    "confidence": 0.035,
    "origin": "reference value aligned to 0x100",
    "evidence": [
      "+ reset vector 0x08000319 maps to executable bytes",
      "- vector table would sit at 0x08000100, which VTOR cannot address: a 98-word table requires 0x200-byte alignment"
    ]
  }
]
```

Evidence strings are prefixed `+` for support and `-` for contradiction. The
`evidence` log at the top level carries the same observations in structured
form, with a `type`, the `source` that produced them, a `value`, a
`confidence`, a `weight` and a `supports` flag.

### A recovered peripheral access

```json
{
  "value": "0x40020020",
  "kind": "MMIO",
  "access": "WRITE",
  "width": 32,
  "derivation": "recovered base + displacement",
  "source_offset": "0x000258",
  "source": "str r2, [r3, #0x20]",
  "base": "0x40020000",
  "offset": 32,
  "confidence": 0.85
}
```

`value` is the effective address, `base` and `offset` the register value and
displacement it was built from, and `source_offset` where in the image the
instruction lives. That is enough to go back to the instruction and check the
conclusion by hand.

### Constants, and what separates them from addresses

`by_kind` and `by_access` divide the same references two ways, and reading them
together is the quickest check on how much the run is claiming:

```json
"references": {
  "total": 8518,
  "by_kind":   { "CONSTANT": 8221, "CODE": 184, "MMIO": 69, "RAM": 44 },
  "by_access": { "ADDRESS_ONLY": 8267, "EXECUTE": 184, "WRITE": 45, "READ": 22 }
}
```

Every reference also carries `code_provenance`, `source_function` and
`base_credible`. The first two say why the instruction that produced it is
believed to be code and which discovered function it belongs to; the third says
whether the value the address was *built from* could address memory at all. All
three have to hold before a reference is evidence about memory — see
[A reachable instruction can still compute a nonsense address](Recovery.md#a-reachable-instruction-can-still-compute-a-nonsense-address). `by_provenance` totals the same references
that way. Only `ENTRY_POINT`, `DECLARED_HANDLER`, `DIRECT_CALL` and
`VALIDATED_INDIRECT_CALL` are trusted; see
[A decoded instruction is not executed code](Recovery.md#a-decoded-instruction-is-not-executed-code).

`CONSTANT` with `ADDRESS_ONLY` is a value some instruction loaded and nothing
dereferenced. That is most of a literal pool, and it stays a constant however
much it resembles an address. `READ`, `WRITE` and `EXECUTE` mark the references
where an address was actually used, and those are the only ones that support a
memory region. The `constants` list carries them with their producing
instruction, so nothing is lost by not calling them addresses.

### A region and what it rests on

```json
{
  "type": "ram",
  "name": "ram",
  "start": "0x20000000",
  "end": "0x200003ff",
  "size": 1024,
  "permissions": "rw-",
  "loadable": false,
  "speculative": false,
  "confidence": 0.993,
  "evidence": [
    "a startup boundary or the reset stack pointer falls in this range",
    "4 address(es) in this range are written",
    "11 instruction(s) reach 7 distinct RAM address(es)"
  ]
}
```

`speculative` is the field to branch on. A consumer building a memory map
should use `regions`; `speculative_regions` is for a human deciding whether to
look further. A region reaches `regions` only if reached code made the
accesses, there is enough such evidence, and the target plausibly has memory
at that address.

### Startup state

```json
"data_initialization": [
  {
    "kind": "copy",
    "source": "0x080003d4",
    "destination": "0x20000000",
    "destination_end": "0x20000008",
    "size": 8,
    "confidence": 0.9,
    "detected_at": "0x08000320",
    "evidence": [
      "loop at 0x08000320 walks r3 from 0x20000000 to 0x20000008 in 32-bit stores (3 instructions)",
      "its load walks r2 from 0x080003d4, and all 8 bytes of that range are present in the image"
    ]
  }
],
"bss": [
  {
    "kind": "zero",
    "destination": "0x20000008",
    "destination_end": "0x20000128",
    "size": 288,
    "confidence": 0.9,
    "detected_at": "0x0800032a"
  }
]
```

`detected_at` is the loop or call that produced the record.

### What the run actually did

```json
"passes": [
  { "name": "PaddingDetection",     "status": "ok",      "detail": "", "milliseconds": 0.05 },
  { "name": "EntryDiscovery",       "status": "ok",      "detail": "", "milliseconds": 1.2 },
  { "name": "StartupAnalysis",      "status": "skipped", "detail": "backend lacks STARTUP_ANALYSIS", "milliseconds": 0.0 }
]
```

A pass is `ok`, `skipped` with the reason — an unmet requirement, or a
capability the selected backend does not advertise — or `failed` with the
error. A failed optional pass does not stop the run, and the failure is also in
`warnings`.

## Reading it from Python

```python
import json

report = json.load(open("firmware.raw2elf.json"))

base = int(report["base"], 16)
entry = int(report["entry"], 16)

writes = [
    access for access in report["mmio_accesses"]
    if access["access"] == "WRITE"
]

if report["confidence"]["base"] < 0.9:
    for candidate in report["base_candidates"]:
        print(candidate["base"], candidate["confidence"])
        for line in candidate["evidence"]:
            print("   ", line)
```

Consumers should treat missing keys as "not recovered" rather than as an error:
`vector_table` is absent for a backend with no such concept, `mcu` is absent
when no part was identified, and `data_initialization` is absent when startup
analysis found nothing. `speculative_regions` is the other case: it is always
present, and empty means "none", which is a result rather than a gap. That is the difference between "zero" and "unknown",
and the manifest keeps it.

Long lists are capped so the manifest stays a file rather than a dump: 2000
entries for reference and access lists, 400 for the evidence log. The console
counts and the `references.by_kind` totals are not capped.
