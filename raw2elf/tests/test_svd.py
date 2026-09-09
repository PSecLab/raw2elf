"""SVD correlation: indexing, ranking, honest labelling, graceful absence."""

from __future__ import annotations

import pathlib
from pathlib import Path

import pytest

from conftest import reconstruct_bytes
from raw2elf.analysis import svd
from raw2elf.analysis.svdsource import DirectorySource
from raw2elf.core.reference import Access, AddressClass, Reference, ReferenceKind


def database(root, cache=None):
    """An index over a directory of SVD files."""
    return svd.SvdDatabase(DirectorySource(root), cache_directory=cache or root / "cache")


def text_of(path):
    return pathlib.Path(path).read_text()

DEVICE_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<device schemaVersion="1.1">
  <name>{name}</name>
  <version>1.0</version>
  <description>Synthetic device for tests</description>
  <cpu>
    <name>{cpu}</name>
    <revision>r0p0</revision>
    <endian>little</endian>
  </cpu>
  <addressUnitBits>8</addressUnitBits>
  <width>32</width>
  <size>32</size>
  <access>read-write</access>
  <peripherals>
{peripherals}
  </peripherals>
</device>
"""

PERIPHERAL_TEMPLATE = """\
    <peripheral>
      <name>{name}</name>
      <description>{name} block</description>
      <groupName>{group}</groupName>
      <baseAddress>0x{base:08X}</baseAddress>
      <addressBlock>
        <offset>0x0</offset>
        <size>0x{size:X}</size>
        <usage>registers</usage>
      </addressBlock>
{interrupt}
      <registers>
{registers}
      </registers>
    </peripheral>
"""

REGISTER_TEMPLATE = """\
        <register>
          <name>{name}</name>
          <addressOffset>0x{offset:X}</addressOffset>
          <size>32</size>
          <access>{access}</access>
        </register>
"""

INTERRUPT_TEMPLATE = """\
      <interrupt>
        <name>{name}</name>
        <value>{value}</value>
      </interrupt>
"""


def write_device(directory: Path, name: str, peripherals, cpu: str = "CM4") -> Path:
    """Write a synthetic SVD file and return its path."""
    rendered = []
    for entry in peripherals:
        registers = "".join(
            REGISTER_TEMPLATE.format(
                name=register_name, offset=offset, access=entry.get("access", "read-write")
            )
            for register_name, offset in entry["registers"]
        )
        interrupt = (
            INTERRUPT_TEMPLATE.format(name=entry["name"], value=entry["irq"])
            if "irq" in entry
            else ""
        )
        rendered.append(
            PERIPHERAL_TEMPLATE.format(
                name=entry["name"],
                group=entry.get("group", entry["name"]),
                base=entry["base"],
                size=entry.get("size", 0x400),
                interrupt=interrupt,
                registers=registers,
            )
        )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.svd"
    path.write_text(
        DEVICE_TEMPLATE.format(name=name, cpu=cpu, peripherals="".join(rendered))
    )
    return path


#: A small STM32F4-shaped device, and two neighbours that share its map.
def _standard_peripherals():
    return [
        {
            "name": "RCC",
            "base": 0x40023800,
            "irq": 5,
            "registers": [("CR", 0x00), ("CFGR", 0x08), ("AHB1ENR", 0x30), ("APB2ENR", 0x44)],
        },
        {
            "name": "GPIOA",
            "base": 0x40020000,
            "registers": [("MODER", 0x00), ("OSPEEDR", 0x08), ("AFRL", 0x20)],
        },
        {
            "name": "USART1",
            "base": 0x40011000,
            "irq": 37,
            "registers": [("SR", 0x00), ("DR", 0x04), ("BRR", 0x08), ("CR1", 0x0C)],
        },
    ]


@pytest.fixture
def svd_root(tmp_path):
    root = tmp_path / "svd"
    write_device(root / "Acme", "ACME32F407", _standard_peripherals())
    write_device(root / "Acme", "ACME32F405", _standard_peripherals())
    write_device(root / "Clone", "CLN32F4", _standard_peripherals())
    write_device(
        root / "Other",
        "OTHER100",
        [
            {
                "name": "SYSCON",
                "base": 0x40048000,
                "registers": [("MEMREMAP", 0x00), ("SYSAHBCLKCTRL", 0x80)],
            }
        ],
        cpu="CM0PLUS",
    )
    return root


def _access(address: int, base: int, offset: int, access=Access.WRITE, width=32) -> Reference:
    return Reference(
        value=address,
        source_offset=0,
        derivation="recovered base + displacement",
        kind=ReferenceKind.MMIO,
        access=access,
        width=width,
        base_value=base,
        offset_value=offset,
        address_class=AddressClass.MMIO,
    )


ACCESSES = [
    _access(0x40023800, 0x40023000, 0x800),
    _access(0x40023808, 0x40023000, 0x808),
    _access(0x40023830, 0x40023000, 0x830),
    _access(0x40020000, 0x40020000, 0x00),
    _access(0x40020020, 0x40020000, 0x20),
    _access(0x40011008, 0x40011000, 0x08),
    _access(0x4001100C, 0x40011000, 0x0C),
    _access(0x40011000, 0x40011000, 0x00, access=Access.READ),
]


# -- indexing --------------------------------------------------------------


def test_indexing_extracts_peripherals_interrupts_and_the_core(svd_root):
    devices = database(svd_root).load()
    by_name = {item.name: item for item in devices}
    assert set(by_name) == {"ACME32F407", "ACME32F405", "CLN32F4", "OTHER100"}

    device = by_name["ACME32F407"]
    assert device.vendor == "Acme"
    assert device.cpu == "CM4"
    assert device.bases == {0x40023800, 0x40020000, 0x40011000}
    assert device.peripheral_for(0x40020020).name == "GPIOA"
    assert device.peripheral_for(0x40FFFFFF) is None
    assert {item.value: item.name for item in device.interrupts} == {5: "RCC", 37: "USART1"}


def test_the_index_is_cached_and_reused(svd_root):
    cache = svd_root / "cache"
    first = database(svd_root, cache).load()
    assert list(cache.glob("svd-index-*.json"))
    second = database(svd_root, cache).load()
    assert [item.name for item in first] == [item.name for item in second]


def test_registers_are_parsed_only_for_the_peripherals_asked_about(svd_root):
    body = text_of(svd_root / "Acme" / "ACME32F407.svd")
    everything = svd.parse_registers(body)
    narrowed = svd.parse_registers(body, bases=[0x40011000])
    assert len(narrowed) == 4
    assert len(everything) > len(narrowed)
    assert {item.address for item in narrowed} == {
        0x40011000,
        0x40011004,
        0x40011008,
        0x4001100C,
    }
    assert all(item.peripheral == "USART1" for item in narrowed)


def test_register_access_flags_are_read():
    from raw2elf.analysis.svd import Register

    assert Register("P", "R", 0, 32, "read-only").readable
    assert not Register("P", "R", 0, 32, "read-only").writable
    assert Register("P", "R", 0, 32, "write-only").writable
    assert Register("P", "R", 0, 32, "").readable and Register("P", "R", 0, 32, "").writable


def test_an_unparseable_file_is_skipped_not_fatal(tmp_path):
    broken = "<device><name>OOPS</name>"  # truncated, no peripherals
    assert svd.parse_index_entry(broken, "Vendor", "broken") is None
    assert svd.parse_registers(broken) == []


# -- matching --------------------------------------------------------------


def test_the_right_device_family_outranks_an_unrelated_part(svd_root):
    index = database(svd_root)
    ranked = svd.rank_devices(index.load(), ACCESSES, database=index)
    assert ranked
    assert ranked[0].base_score == 1.0
    assert ranked[0].register_hits == len({item.value for item in ACCESSES})
    assert "OTHER100" not in [item.device.name for item in ranked]


def test_recovered_peripheral_bases_survive_a_folded_displacement():
    # "ldr r3, =0x40023000; str r2, [r3, #0x800]" is an access to the
    # peripheral at 0x40023800, not to one at 0x40023000.
    assert 0x40023800 in svd.implied_bases(ACCESSES)
    assert 0x40023000 not in svd.implied_bases(ACCESSES)
    assert 0x40020000 in svd.implied_bases(ACCESSES)


def test_indistinguishable_devices_are_reported_as_a_family(svd_root):
    index = database(svd_root)
    ranked = svd.rank_devices(index.load(), ACCESSES, database=index)
    tied = [item for item in ranked if ranked[0].score - item.score <= svd.TIE_MARGIN]
    assert len(tied) == 3
    label, representative = svd.describe_tie(tied)
    # The two Acme parts share a prefix; the clone from another vendor is
    # acknowledged rather than hidden or presented as the answer.
    assert label.startswith("ACME32F4")
    assert "register-compatible" in label
    assert "CLN32F4" in label
    assert representative.device.vendor == "Acme"


def test_a_single_clear_winner_is_named_exactly(svd_root):
    index = database(svd_root)
    only = [item for item in index.load() if item.name == "ACME32F407"]
    ranked = svd.rank_devices(only, ACCESSES, database=index)
    label, _representative = svd.describe_tie(ranked[:1])
    assert label == "ACME32F407 family"


def test_a_common_family_is_the_shared_prefix():
    assert svd.common_family(["STM32F405", "STM32F407", "STM32F415"]) == "STM32F4"
    assert svd.common_family(["STM32F407"]) == "STM32F407"
    assert svd.common_family(["STM32F4", "nRF52840"]) == ""


def test_writing_a_read_only_register_is_a_contradiction(tmp_path):
    root = tmp_path / "svd"
    write_device(
        root / "Vendor",
        "STRICT",
        [
            {
                "name": "RCC",
                "base": 0x40023800,
                "access": "read-only",
                "registers": [("CR", 0x00), ("CFGR", 0x08)],
            }
        ],
    )
    index = database(root)
    writes = [_access(0x40023800, 0x40023000, 0x800), _access(0x40023808, 0x40023000, 0x808)]
    ranked = svd.rank_devices(index.load(), writes, database=index)
    assert ranked[0].contradictions == 2
    assert ranked[0].register_score < 1.0


def test_ranking_with_no_accesses_returns_nothing(svd_root):
    assert svd.rank_devices(database(svd_root).load(), []) == []


# -- the pass --------------------------------------------------------------


def test_a_missing_svd_database_does_not_stop_reconstruction(standard, monkeypatch, tmp_path):
    monkeypatch.setenv("RAW2ELF_SVD_DIR", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(svd, "open_source", lambda *args, **kwargs: None)
    reconstruction = reconstruct_bytes(standard.image, enable_svd=True)
    assert reconstruction.elf
    assert reconstruction.context.get("mcu") is None
    assert any("no CMSIS-SVD data" in warning for warning in reconstruction.context.warnings)


def test_svd_matching_names_interrupt_handlers(standard, svd_root):
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), svd_symbols="peripherals"
    )
    names = reconstruction.context.get("handler_names") or {}
    # The fixture's vector table puts real handlers at device IRQ 28 and 37.
    assert names.get(16 + 37) == "USART1_IRQHandler"
    annotations = reconstruction.context.get("svd_annotations")
    assert {item["name"] for item in annotations["peripherals"]} >= {"RCC", "GPIOA", "USART1"}


def test_peripheral_symbols_reach_the_elf(standard, svd_root):
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), svd_symbols="peripherals"
    )
    symbols = {item.name: item.value for item in reconstruction.context.get("symbols")}
    assert symbols["RCC_BASE"] == 0x40023800
    assert symbols["USART1_BASE"] == 0x40011000
    assert "RCC_CFGR" not in symbols  # register level was not requested


def test_register_symbols_are_available_on_request(standard, svd_root):
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), svd_symbols="registers"
    )
    symbols = {item.name: item.value for item in reconstruction.context.get("symbols")}
    assert symbols["RCC_CFGR"] == 0x40023808
    assert symbols["GPIOA_AFRL"] == 0x40020020


def test_svd_symbols_can_be_turned_off_entirely(standard, svd_root):
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), svd_symbols="none"
    )
    symbols = {item.name for item in reconstruction.context.get("symbols")}
    assert not any(name.endswith("_BASE") for name in symbols)


def test_a_supplied_mcu_is_a_hint_not_an_identification(standard, svd_root):
    """Being told the part must not produce certainty about the part.

    The confidence shown has to stay whatever the recovered accesses support,
    or a name from a filename, a guess or a habit would come back as an
    identification.
    """
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), mcu="ACME32F405"
    )
    mcu = reconstruction.context.get("mcu")
    assert "ACME32F405" in mcu["label"]
    assert "supplied" in mcu["label"]
    assert mcu["exact"] is False
    assert mcu["match"].confidence < 1.0
    assert any("was supplied rather than identified" in str(item)
               for item in reconstruction.context.evidence)


def test_an_unmatched_mcu_name_widens_rather_than_giving_up(standard, svd_root):
    """A name that places nothing must not cost the identification.

    Some vendors' order codes diverge from their SVD names part way through,
    so failing to place one says nothing about whether the accesses can
    identify the part.
    """
    reconstruction = reconstruct_bytes(
        standard.image, enable_svd=True, svd=str(svd_root), mcu="NOSUCHPART"
    )
    assert any("NOSUCHPART" in warning for warning in reconstruction.context.warnings)
    assert any("still matched against every device" in w for w in reconstruction.context.warnings)
    # And identification still happened, from the accesses alone.
    assert reconstruction.context.get("mcu") is not None


@pytest.mark.parametrize(
    ("typed", "reaches", "excludes"),
    [
        ("STM32G", "STM32G030", "STM32F030"),
        ("STM32G4", "STM32G431xx", "STM32G030"),
        ("STM32G474RET6", "STM32G474xx", "STM32G431xx"),
        ("LPC1768", "LPC176x", None),
    ],
)
def test_however_much_of_the_part_number_you_can_read(typed, reaches, excludes):
    """A family answer stays in its family; a full order code narrows further."""
    from raw2elf.analysis.devices import search

    class Named:
        def __init__(self, name):
            self.name = name

    catalogue = [
        Named(name)
        for name in ("STM32F030", "STM32G030", "STM32G431xx", "STM32G474xx", "LPC176x")
    ]
    found = {device.name for device in search(typed, catalogue)}
    assert reaches in found, f"{typed} should reach {reaches}"
    if excludes:
        assert excludes not in found, f"{typed} should not reach {excludes}"


def test_a_name_too_vague_to_act_on_matches_nothing():
    from raw2elf.analysis.devices import search

    class Named:
        def __init__(self, name):
            self.name = name

    assert search("STM", [Named("STM32G474xx")]) == []
    assert search("", [Named("STM32G474xx")]) == []


# -- what a part number tells you ------------------------------------------


@pytest.mark.parametrize(
    ("part", "family", "flash"),
    [
        ("STM32F407VGT6", "STM32", 0x08000000),
        ("stm32f103c8t6", "STM32", 0x08000000),
        ("nRF52840-QIAA", "nRF52", 0x00000000),
        ("LPC1768FBD100", "LPC17xx", 0x00000000),
        ("ATSAM4S8B", "SAM4", 0x00400000),
        ("RP2040", "RP2040", 0x10000000),
        ("MKL25Z128VLK4", "Kinetis L", 0x00000000),
        ("CY8C6247BZI", "PSoC 6", 0x10000000),
    ],
)
def test_a_part_number_gives_a_memory_layout(part, family, flash):
    from raw2elf.analysis.devices import layout_for

    layout = layout_for(part)
    assert layout is not None, part
    assert layout.family == family
    assert layout.flash[0] == flash


def test_a_longer_prefix_wins_over_a_shorter_one():
    """MKL is Kinetis L, not Kinetis K, despite both starting MK."""
    from raw2elf.analysis.devices import layout_for

    assert layout_for("MKL25Z128").family == "Kinetis L"
    assert layout_for("MK64FN1M0").family == "Kinetis K"


def test_an_unknown_part_has_no_layout_rather_than_a_guessed_one():
    from raw2elf.analysis.devices import layout_for

    assert layout_for("SOME-CUSTOM-ASIC") is None
    assert layout_for("") is None
    assert layout_for(None) is None


def test_package_suffixes_do_not_prevent_a_match():
    from raw2elf.analysis.devices import normalise

    assert normalise("STM32F407VGT6") == "STM32F407VGT6"
    assert normalise("stm32-f407 vg") == "STM32F407VG"


def test_a_full_order_code_finds_the_right_svd_device(svd_root):
    from raw2elf.analysis.devices import search

    devices = database(svd_root).load()
    found = search("ACME32F407ABC-XYZ", devices)
    assert found and found[0].name == "ACME32F407"


def test_searching_for_something_unrelated_finds_nothing(svd_root):
    from raw2elf.analysis.devices import search

    assert search("ZZ9", database(svd_root).load()) == []


def test_every_layout_entry_is_well_formed():
    """The table is data, so it is checked as data."""
    import json

    from raw2elf.analysis.devices import LAYOUTS

    payload = json.loads(LAYOUTS.read_text())
    prefixes = set()
    for entry in payload["families"]:
        assert entry["prefix"] and entry["family"]
        assert entry["prefix"] not in prefixes, f"duplicate prefix {entry['prefix']}"
        prefixes.add(entry["prefix"])
        assert entry["flash"], f"{entry['prefix']} names no Flash origin"
        for group in ("flash", "ram"):
            for address in entry[group]:
                assert address.startswith("0x")
                assert int(address, 16) < (1 << 32)
