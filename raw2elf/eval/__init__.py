"""Evaluation harness: grade reconstructions against known-good ELFs.

Run it over any Cortex-M ELF::

    python -m raw2elf.eval firmware.elf another.elf

Each ELF is rendered into every input format the tool accepts, reconstructed,
and graded against what the original ELF says.  This is the mechanism for the
correctness metrics: input fidelity, architecture detection, base and entry
recovery, vector-table offset, startup state, reference precision and recall,
and ELF correctness.
"""

from . import corpus, elfread, metrics

__all__ = ["corpus", "elfread", "metrics"]
