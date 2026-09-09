"""Where one firmware image sits, in every coordinate system at once.

A firmware image is described by several numbers that only mean anything
together: where its bytes are in the input, where they load on the target,
where its entry structure sits, where execution begins and what the stack
pointer starts at.  Passing those around separately is how a dump holding a
bootloader and an application produces an answer in which every individual
number is defensible and the combination describes no image that exists.

Three coordinate systems meet here, and confusing them is the failure this
type exists to prevent:

``file offset``
    Where the bytes are in the input the analyst supplied.  Survives carving,
    so a report can always say where in *their* file something was found.

``image offset``
    Where the bytes are in the image currently under analysis.  Restarts at
    zero when an image is carved out of a dump.

``runtime address``
    Where the bytes are on the target.

:class:`ImagePlacement` holds all three and the facts that depend on them, and
converts between them.  Later stages take one placement rather than a base,
an entry, a structure address and an offset that may each have come from a
different image.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Optional

from .util import hexs


@dataclass(frozen=True)
class ImagePlacement:
    """One image's position and the facts recovered in that position.

    Every field describes the same image.  Constructing one from parts that
    came from different images is the mistake; the type makes that mistake
    visible rather than preventing it, because the parts are recovered
    separately and have to be assembled somewhere.
    """

    #: Offset of the image's first byte in the input the analyst supplied.
    file_offset: int
    #: Offset of the image's first byte in the image under analysis.
    image_offset: int
    #: Runtime address of the image's first byte.
    runtime_base: Optional[int] = None
    image_size: int = 0
    #: Runtime address of the structure the entry point was recovered from.
    entry_structure: Optional[int] = None
    #: Runtime address where execution begins.
    entry: Optional[int] = None
    #: Reset-time stack pointer, for architectures that have one.
    initial_stack_pointer: Optional[int] = None
    confidence: float = 0.0

    # -- geometry ---------------------------------------------------------

    @property
    def runtime_end(self) -> Optional[int]:
        if self.runtime_base is None:
            return None
        return self.runtime_base + self.image_size

    @property
    def file_end(self) -> int:
        return self.file_offset + self.image_size

    def contains_address(self, address: int) -> bool:
        end = self.runtime_end
        return end is not None and self.runtime_base <= address < end

    def contains_file_offset(self, offset: int) -> bool:
        return self.file_offset <= offset < self.file_end

    def offset_of(self, address: int) -> Optional[int]:
        """Image offset of a runtime address, or ``None`` if outside."""
        if not self.contains_address(address):
            return None
        return self.image_offset + (address - self.runtime_base)

    def address_of(self, image_offset: int) -> Optional[int]:
        """Runtime address of an image offset, or ``None`` if unplaced."""
        if self.runtime_base is None:
            return None
        return self.runtime_base + (image_offset - self.image_offset)

    def file_offset_of(self, image_offset: int) -> int:
        """File offset of an image offset."""
        return self.file_offset + (image_offset - self.image_offset)

    # -- consistency ------------------------------------------------------

    @property
    def consistent(self) -> bool:
        """Whether every placed field describes this image's own extent.

        An entry or entry structure outside the image's own runtime extent
        means the numbers were assembled from more than one image.
        """
        if self.runtime_base is None:
            return True
        for address in (self.entry_structure, self.entry):
            if address is not None and not self.contains_address(address):
                return False
        return True

    def rebased(self, runtime_base: int) -> "ImagePlacement":
        """The same image placed at a different runtime base.

        Facts expressed as runtime addresses move with it; facts recovered
        from the bytes themselves, such as the initial stack pointer, do not.
        """
        if self.runtime_base is None:
            return replace(self, runtime_base=runtime_base)
        shift = runtime_base - self.runtime_base
        return replace(
            self,
            runtime_base=runtime_base,
            entry_structure=None if self.entry_structure is None else self.entry_structure + shift,
            entry=None if self.entry is None else self.entry + shift,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_offset": hexs(self.file_offset, 6),
            "image_offset": hexs(self.image_offset, 6),
            "image_size": self.image_size,
            "runtime_base": hexs(self.runtime_base, 8),
            "entry_structure": hexs(self.entry_structure, 8),
            "entry": hexs(self.entry, 8),
            "initial_stack_pointer": hexs(self.initial_stack_pointer, 8),
            "confidence": round(self.confidence, 3),
        }
