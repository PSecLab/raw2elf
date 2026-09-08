"""The reconstructed ELF: structure, addresses, symbols, byte fidelity."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from conftest import reconstruct_bytes
from raw2elf.elf import writer
from raw2elf.elf.symbols import FUNC, NOTYPE, Symbol, SymbolTable
from raw2elf.eval import elfread


@pytest.fixture
def emitted(tmp_path, standard):
    """The fixture firmware reconstructed and parsed back."""
    reconstruction = reconstruct_bytes(standard.image)
    path = tmp_path / "out.elf"
    path.write_bytes(reconstruction.elf)
    return reconstruction, elfread.read(path)


def test_the_header_describes_the_recovered_target(emitted, standard):
    _reconstruction, elf = emitted
    assert elf.machine == 40  # EM_ARM
    assert elf.pointer_width == 32
    assert elf.little_endian
    assert elf.flags & 0x05000000  # EABI version 5
    # e_entry keeps the Thumb bit, as a real Cortex-M ELF does.
    assert elf.entry == standard.entry | 1


def test_firmware_bytes_appear_at_the_recovered_address(emitted, standard):
    _reconstruction, elf = emitted
    flash = next(item for item in elf.loads if item.executable)
    assert flash.virtual_address == standard.base
    assert flash.data == standard.image
    assert flash.offset % 4 == flash.virtual_address % 4  # PT_LOAD congruence


def test_recovered_sections_are_addressed_and_permissioned(emitted):
    _reconstruction, elf = emitted
    sections = {item.name: item for item in elf.sections if item.allocated}
    assert sections[".flash"].executable
    assert not sections[".flash"].flags & elfread.SHF_WRITE
    assert sections[".data"].flags & elfread.SHF_WRITE
    assert sections[".bss"].kind == elfread.SHT_NOBITS
    assert sections[".bss"].flags & elfread.SHF_WRITE


def test_initialized_data_maps_at_its_run_address_from_its_load_address(emitted, standard):
    _reconstruction, elf = emitted
    data = next(item for item in elf.loads if item.writable and item.file_size)
    assert data.virtual_address == standard.data_start
    assert data.physical_address == standard.data_load
    assert data.file_size == standard.data_size
    offset = standard.data_load - standard.base
    assert data.data == standard.image[offset : offset + standard.data_size]


def test_bss_occupies_memory_without_occupying_the_file(emitted, standard):
    _reconstruction, elf = emitted
    bss = next(item for item in elf.loads if item.writable and not item.file_size)
    assert bss.virtual_address == standard.bss_start
    assert bss.memory_size == standard.bss_end - standard.bss_start
    assert bss.file_size == 0


def test_a_discontiguous_input_becomes_several_segments_not_one_huge_one(standard):
    """A 256 KiB hole must not become 256 KiB of zero-filled ELF."""
    from raw2elf.eval import corpus

    configuration = bytes(range(256))
    payload = corpus.to_ihex(
        [(standard.base, standard.image), (standard.base + 0x40000, configuration)]
    )
    reconstruction = reconstruct_bytes(payload)
    addresses = {item["address"] for item in reconstruction.context.get("elf_sections")}
    assert f"0x{standard.base:08x}" in addresses
    assert f"0x{standard.base + 0x40000:08x}" in addresses
    assert len(reconstruction.elf) < len(standard.image) + len(configuration) + 0x2000


def test_recovered_symbols_name_what_was_recovered(emitted, standard):
    _reconstruction, elf = emitted
    symbols = {item.name: item for item in elf.symbols if item.name}

    assert symbols["Reset_Handler"].value == standard.entry | 1
    assert symbols["Reset_Handler"].is_function
    assert symbols["_start"].value == standard.entry | 1
    assert symbols["__vector_table"].value == standard.base

    for name, expected in (
        ("__data_load", standard.data_load),
        ("__data_start", standard.data_start),
        ("__data_end", standard.data_end),
        ("__bss_start", standard.bss_start),
        ("__bss_end", standard.bss_end),
        ("_estack", standard.initial_stack_pointer),
    ):
        assert symbols[name].value == expected, name
        # Section boundaries are absolute values, not offsets into whichever
        # section happens to contain them.
        assert symbols[name].is_absolute, name


def test_architectural_handler_names_are_emitted(emitted):
    _reconstruction, elf = emitted
    names = {item.name for item in elf.symbols}
    assert {"Reset_Handler", "SysTick_Handler"} <= names
    # Unused vectors share one handler; it is named once, not eighty times.
    default_handlers = [item for item in elf.symbols if item.name == "NMI_Handler"]
    assert len(default_handlers) == 1


def test_mapping_symbols_tell_a_disassembler_where_thumb_code_starts(emitted):
    _reconstruction, elf = emitted
    thumb = [item for item in elf.symbols if item.name == "$t"]
    data = [item for item in elf.symbols if item.name == "$d"]
    assert thumb, "no $t mapping symbols: objdump would guess ARM"
    assert data, "no $d over the vector table"
    assert all(item.info >> 4 == 0 for item in thumb)  # STB_LOCAL


def test_build_attributes_declare_the_m_profile(emitted):
    _reconstruction, elf = emitted
    attributes = elf.section(".ARM.attributes")
    assert attributes is not None
    assert attributes.data.startswith(b"A")
    assert b"aeabi\x00" in attributes.data


def test_symbol_table_puts_local_symbols_first(emitted):
    _reconstruction, elf = emitted
    table = next(item for item in elf.sections if item.kind == elfread.SHT_SYMTAB)
    bindings = [item.info >> 4 for item in elf.symbols]
    first_global = bindings.index(1) if 1 in bindings else len(bindings)
    # Locals must all precede globals, and sh_info must say where they end.
    assert all(binding == 0 for binding in bindings[:first_global])
    assert all(binding == 1 for binding in bindings[first_global:])
    assert table.info == first_global


def test_section_splitting_is_conservative_unless_asked_for(standard):
    plain = reconstruct_bytes(standard.image)
    assert {item["name"] for item in plain.context.get("elf_sections")} >= {".flash"}
    assert ".text" not in {item["name"] for item in plain.context.get("elf_sections")}

    split = reconstruct_bytes(standard.image, split_sections=True)
    names = {item["name"] for item in split.context.get("elf_sections")}
    # Either the evidence justified a split, or it did not and one section
    # was kept; both are acceptable, inventing boundaries is not.
    assert ".flash" in names or {".vectors", ".text"} <= names


# -- the writer in isolation ----------------------------------------------


def test_the_writer_round_trips_a_minimal_elf(tmp_path):
    image = writer.ElfImage(machine=40, entry=0x08000001, flags=0x05000000)
    image.add_section(
        writer.Section(
            name=".flash",
            section_type=writer.SHT_PROGBITS,
            flags=writer.SHF_ALLOC | writer.SHF_EXECINSTR,
            address=0x08000000,
            data=b"\xaa" * 64,
            loadable=True,
        )
    )
    image.symbols = [Symbol("entry", 0x08000001, kind=FUNC)]
    path = tmp_path / "min.elf"
    path.write_bytes(writer.ElfWriter(image).build())

    elf = elfread.read(path)
    assert elf.entry == 0x08000001
    assert len(elf.loads) == 1
    assert elf.loads[0].data == b"\xaa" * 64
    assert elf.symbol("entry").value == 0x08000001


def test_the_writer_supports_sixty_four_bit_and_big_endian_targets(tmp_path):
    """Not needed by Cortex-M, needed by whatever comes next."""
    image = writer.ElfImage(
        machine=243, entry=0x80000000, pointer_width=64, little_endian=False
    )
    image.add_section(
        writer.Section(
            name=".flash",
            section_type=writer.SHT_PROGBITS,
            flags=writer.SHF_ALLOC | writer.SHF_EXECINSTR,
            address=0x80000000,
            data=b"\x01\x02\x03\x04" * 8,
            loadable=True,
        )
    )
    path = tmp_path / "wide.elf"
    path.write_bytes(writer.ElfWriter(image).build())

    elf = elfread.read(path)
    assert elf.pointer_width == 64
    assert not elf.little_endian
    assert elf.entry == 0x80000000
    assert elf.loads[0].data == b"\x01\x02\x03\x04" * 8


def test_symbol_tables_keep_one_definition_per_name():
    table = SymbolTable()
    table.add(Symbol("handler", 0x100, kind=FUNC))
    table.add(Symbol("handler", 0x100, kind=FUNC))
    assert len(table) == 1
    # A genuine collision keeps both, distinguished by address.
    table.add(Symbol("handler", 0x200, kind=FUNC))
    assert len(table) == 2
    # Mapping symbols legitimately repeat and are never deduplicated.
    for address in (0x10, 0x20, 0x30):
        table.add(Symbol("$t", address, kind=NOTYPE, local=True))
    assert sum(1 for item in table if item.name == "$t") == 3


# -- external validation --------------------------------------------------

READELF = shutil.which("arm-none-eabi-readelf") or shutil.which("readelf")


def _arm_objdump():
    """An objdump that can actually disassemble ARM.

    A host objdump built only for the host architecture parses the ELF
    happily and then refuses to disassemble it, which would look like a
    failure of the ELF rather than of the tool being used to read it.
    """
    for candidate in ("arm-none-eabi-objdump", "objdump"):
        path = shutil.which(candidate)
        if path is None:
            continue
        info = subprocess.run([path, "--info"], capture_output=True, text=True)
        if "arm" in info.stdout.lower():
            return path
    return None


OBJDUMP = _arm_objdump()


@pytest.mark.skipif(READELF is None, reason="readelf is not installed")
def test_readelf_parses_the_output_without_complaint(tmp_path, standard):
    path = tmp_path / "out.elf"
    path.write_bytes(reconstruct_bytes(standard.image).elf)
    result = subprocess.run(
        [READELF, "-a", str(path)], capture_output=True, text=True, check=True
    )
    assert "Error" not in result.stderr and "Warning" not in result.stderr
    assert "EXEC (Executable file)" in result.stdout
    assert f"0x{standard.entry | 1:x}" in result.stdout
    assert "Tag_CPU_arch_profile: Microcontroller" in result.stdout


@pytest.mark.skipif(OBJDUMP is None, reason="objdump is not installed")
def test_objdump_disassembles_the_recovered_code_as_thumb(tmp_path, standard):
    path = tmp_path / "out.elf"
    path.write_bytes(reconstruct_bytes(standard.image).elf)
    result = subprocess.run(
        [OBJDUMP, "-d", str(path)], capture_output=True, text=True, check=True
    )
    assert result.returncode == 0
    assert "elf32-littlearm" in result.stdout
    # The reset handler must disassemble as Thumb, which only happens if the
    # mapping symbols and build attributes are right.
    assert "<Reset_Handler>" in result.stdout
    body = result.stdout.split("<Reset_Handler>:", 1)[1][:400]
    assert "push" in body or "ldr" in body
    assert ".word" not in body.splitlines()[1]
