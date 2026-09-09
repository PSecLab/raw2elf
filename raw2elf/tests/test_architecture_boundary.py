"""The architecture boundary, enforced mechanically.

The rule this suite exists to protect:

    No architecture-specific instruction mnemonic, address range, reset
    convention, vector-table format, code-pointer representation or startup
    convention may be referenced directly by the architecture-neutral core.

Documentation is not enough to hold that line, so the boundary is checked by
reading the source: the core and the generic analysis passes must not name
Cortex-M concepts, and must not import a concrete backend.  A synthetic
backend then shows that a new architecture needs nothing but a backend.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

import pytest

from raw2elf.arch import registry
from raw2elf.arch.base import ArchCapability, ArchitectureBackend, ProbeResult, TargetInfo
from raw2elf.core.image import FirmwareImage, FirmwareSegment
from raw2elf.core.options import Options
from raw2elf.core.pipeline import AnalysisContext, Pipeline

from conftest import PACKAGE, MinimalBackend

#: Directories that must stay free of per-ISA knowledge.
NEUTRAL_DIRECTORIES = ("core", "analysis", "elf", "report", "input")

#: Tokens that name something only a specific instruction set has.  A hit in
#: neutral code means either a leak or an interface that needs extending.
FORBIDDEN_TOKENS = (
    # Cortex-M structures and conventions
    "vector_table",
    "vector table",
    "isr_vector",
    "reset_handler",
    "reset handler",
    "thumb",
    "msp",
    "vtor",
    "nvic",
    "systick",
    "cortex",
    "aapcs",
    # ARM mnemonics and registers
    "movw",
    "movt",
    "ldr",
    " adr ",
    "blx",
    "cbz",
    "r0",
    "lr,",
    # Other instruction sets, so this stays honest as backends are added
    "riscv",
    "rv32",
    "mips",
    "xtensa",
    "csrrw",
)

#: Cortex-M address-map constants, which must only appear in the backend.
FORBIDDEN_ADDRESSES = (
    "0x20000000",
    "0x40000000",
    "0xe0000000",
    "0x08000000",
    "0xe000e000",
)


def code_only(source: str) -> str:
    """Blank out comments and docstrings, leaving executable code.

    The rule being enforced is about what neutral code *references*, not what
    its documentation may mention.  A docstring explaining that a backend
    might find a vector table is exactly the kind of prose that makes the
    abstraction understandable, so it is not treated as a violation.
    """
    lines = source.splitlines()
    blank: set[int] = set()

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            blank.add(token.start[0])

    tree = ast.parse(source)
    for node in ast.walk(tree):
        # A bare string expression is a docstring wherever it appears.
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                blank.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))

    return "\n".join(
        "" if number in blank else _strip_trailing_comment(line)
        for number, line in enumerate(lines, start=1)
    )


def _strip_trailing_comment(line: str) -> str:
    """Remove a trailing comment, ignoring ``#`` inside a string literal."""
    quote = None
    for index, character in enumerate(line):
        if quote:
            if character == quote and line[index - 1 : index] != "\\":
                quote = None
        elif character in "\"'":
            quote = character
        elif character == "#":
            return line[:index]
    return line


def _neutral_sources() -> list[Path]:
    files: list[Path] = []
    for directory in NEUTRAL_DIRECTORIES:
        files.extend(sorted((PACKAGE / directory).rglob("*.py")))
    files.extend(
        [
            PACKAGE / "cli.py",
            PACKAGE / "shell.py",
            PACKAGE / "reconstruct.py",
            PACKAGE / "__init__.py",
        ]
    )
    return [path for path in files if path.is_file()]


def test_there_are_neutral_sources_to_check():
    # Guard against the check silently passing because it found nothing.
    assert len(_neutral_sources()) >= 15


@pytest.mark.parametrize("path", _neutral_sources(), ids=lambda item: item.name)
def test_neutral_code_names_no_architecture_specific_concept(path):
    text = code_only(path.read_text()).lower()
    offenders = [token for token in FORBIDDEN_TOKENS if token in text]
    assert not offenders, (
        f"{path.relative_to(PACKAGE)} mentions {offenders}; architecture knowledge belongs "
        "in a backend. Extend the backend interface instead of reaching through it."
    )


@pytest.mark.parametrize("path", _neutral_sources(), ids=lambda item: item.name)
def test_neutral_code_hardcodes_no_architecture_address_range(path):
    text = code_only(path.read_text()).lower()
    offenders = [token for token in FORBIDDEN_ADDRESSES if token in text]
    assert not offenders, (
        f"{path.relative_to(PACKAGE)} hardcodes {offenders}; address maps come from "
        "ArchitectureBackend.classify_address."
    )


@pytest.mark.parametrize("path", _neutral_sources(), ids=lambda item: item.name)
def test_neutral_code_never_imports_a_concrete_backend(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imported.append("." * node.level + module)
            imported.extend(f"{'.' * node.level}{module}.{alias.name}" for alias in node.names)
    concrete = [
        name
        for name in imported
        if "arch.arm" in name or name.endswith("cortex_m") or ".arm." in name
    ]
    assert not concrete, f"{path.relative_to(PACKAGE)} imports {concrete}"


def test_the_core_never_imports_the_arch_package_at_runtime():
    """``core`` may reference the backend interface for typing only."""
    for path in sorted((PACKAGE / "core").rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        guarded: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = ast.dump(node.test)
                if "TYPE_CHECKING" in test:
                    for child in ast.walk(node):
                        guarded.add(id(child))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else ["." * node.level + (node.module or "")]
            )
            if any("arch" in name for name in names):
                assert id(node) in guarded, (
                    f"{path.relative_to(PACKAGE)} imports {names} outside a TYPE_CHECKING guard"
                )


# -- the interface actually being an interface -----------------------------


def test_a_backend_needs_only_three_methods():
    """Everything optional has a working default."""
    backend = MinimalBackend()
    image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, bytes(256)),))
    context = AnalysisContext(image=image, backend=backend, options=Options())

    assert backend.capabilities() == frozenset()
    assert backend.elf_target_info().elf_machine == 0xFE
    assert backend.probe(image).confidence == 0.5
    # None of these are concepts every architecture has, so none are required.
    assert backend.discover_entry_candidates(context) == []
    assert backend.extract_references(context) == []
    assert backend.recover_startup_state(context) is None
    assert backend.recover_interrupt_table(context) is None
    assert backend.generate_base_constraints(context).seeds == ()
    assert backend.evaluate_base(context, 0).score == 0.0
    assert backend.normalize_code_pointer(0x1235) == 0x1235
    assert backend.encode_code_pointer(0x1234) == 0x1234


def test_capability_gated_passes_are_skipped_for_a_partial_backend():
    from raw2elf.analysis import default_passes

    backend = MinimalBackend()
    image = FirmwareImage(source_format="raw", segments=(FirmwareSegment(0, bytes(4096)),))
    context = AnalysisContext(image=image, backend=backend, options=Options(base=0x1000))
    result = Pipeline(default_passes()).run(context)
    outcomes = {item.name: (item.status, item.detail) for item in result.outcomes}

    # Discovery and recovery passes that need capabilities stand down...
    for name in ("EntryDiscovery", "ImageDiscovery", "ReferenceRecovery", "StartupAnalysis"):
        assert outcomes[name][0] == "skipped", (name, outcomes[name])
        assert "lacks" in outcomes[name][1] or "missing" in outcomes[name][1]
    # ...and the architecture-neutral ones still run, producing an ELF from
    # the analyst-supplied base alone.
    assert outcomes["PaddingDetection"][0] == "ok"
    assert outcomes["ElfReconstruction"][0] == "ok"
    assert context.get("elf")


def test_a_new_backend_is_added_by_registering_it():
    class SyntheticBackend(ArchitectureBackend):
        """Stands in for the next instruction set."""

        name = "synthetic-test"
        description = "synthetic architecture used to exercise the registry"

        def capabilities(self):
            return frozenset({ArchCapability.CODE_VALIDATION})

        def elf_target_info(self):
            return TargetInfo(
                architecture="synthetic",
                endianness="big",
                pointer_width=64,
                elf_machine=0xF3,
            )

        def probe(self, image):
            confidence = 0.99 if image.stream.startswith(b"SYNTH") else 0.0
            return ProbeResult(
                backend=self.name, confidence=confidence, target=self.elf_target_info()
            )

    module = f"{__name__}:SyntheticBackend"
    globals()["SyntheticBackend"] = SyntheticBackend
    registry.register("synthetic-test", module)
    try:
        assert "synthetic-test" in registry.backend_names()
        instance = registry.get_backend("synthetic-test")
        assert instance.elf_target_info().pointer_width == 64
        assert instance.elf_target_info().byte_order == "big"

        image = FirmwareImage(
            source_format="raw", segments=(FirmwareSegment(0, b"SYNTH" + bytes(256)),)
        )
        ranked = registry.probe_all(image)
        assert ranked[0].backend == "synthetic-test"
        assert ranked[0].confidence == 0.99
        # And the Cortex-M backend correctly declines a payload that is not
        # Cortex-M, without either backend knowing about the other.
        assert any(item.backend == "arm-cortex-m" and item.confidence < 0.5 for item in ranked)
    finally:
        registry._BACKEND_MODULES.pop("synthetic-test", None)
        registry._INSTANCES.pop("synthetic-test", None)


def test_an_unknown_architecture_name_lists_the_known_ones():
    with pytest.raises(KeyError, match="arm-cortex-m"):
        registry.get_backend("nonexistent-architecture")
