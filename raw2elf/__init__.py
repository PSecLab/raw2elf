"""raw2elf -- firmware ingestion and ELF reconstruction.

A firmware dump arrives without the load address, entry point, segment layout
or symbols that a linker would have recorded.  raw2elf normalizes common
extraction formats, recovers that structure from architectural and structural
constraints, and emits an analysis-ready ELF plus a machine-readable
reconstruction manifest.

The package is organized so that adding an instruction set means implementing
one architecture backend:

``core``
    Architecture-neutral representations and orchestration.
``input``
    Strict format detection and normalization.
``arch``
    The backend interface and per-ISA implementations.
``analysis``
    Generic analysis passes driven by backend capabilities.
``elf`` / ``report``
    Output generation.
"""

__version__ = "0.1.0"
