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
    #: Image offset of the structure the entry point was recovered from.
    #: Stored as an offset rather than an address so that it cannot go stale
    #: when the image is placed somewhere else: the structure is at a fixed
    #: position *within* the image, and its address follows from the base.
    entry_structure_offset: Optional[int] = None
    #: Runtime address where execution begins, as read out of the image.
    entry: Optional[int] = None
    #: Reset-time stack pointer, for architectures that have one.
    initial_stack_pointer: Optional[int] = None
    confidence: float = 0.0

    # -- derived ----------------------------------------------------------

    @property
    def entry_structure(self) -> Optional[int]:
        """Runtime address of the structure the entry point came from."""
        if self.entry_structure_offset is None:
            return None
        return self.address_of(self.entry_structure_offset)

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
        """The same image, now believed to load at ``runtime_base``.

        This corrects a belief about where the image already lives; it does
        not relocate it.  So facts read out of the bytes -- the entry point
        recovered from an entry structure, the reset-time stack pointer --
        are unchanged, while positions expressed relative to the image, such
        as where its entry structure sits, follow the new base.
        """
        return replace(self, runtime_base=runtime_base)

    def with_entry(self, entry: Optional[int]) -> "ImagePlacement":
        """The same image with an authoritative entry point applied.

        Used when the analyst supplies ``--entry``: they know something the
        bytes do not say, and the rest of the image is unaffected.
        """
        return replace(self, entry=entry)

    def grown_to_contain(self, *addresses: Optional[int]) -> "ImagePlacement":
        """The same image, extended so its own facts fall inside it.

        An image's extent is inferred -- from where the next program starts,
        or where erased flash begins -- while its entry is read directly out
        of its own entry structure.  When the two disagree, the extent is
        what was guessed, so it gives way.  An image contains the code its
        own reset vector points at.
        """
        if self.runtime_base is None:
            return self
        end = self.runtime_base + self.image_size
        for address in addresses:
            if address is not None and self.runtime_base <= address:
                end = max(end, address + 1)
        return replace(self, image_size=end - self.runtime_base)

    def at_image_offset(self, image_offset: int) -> "ImagePlacement":
        """The same image, described in another image-offset coordinate system.

        Carving an image out of a dump restarts offsets at zero. The bytes,
        the file they came from and the address they load at are unchanged,
        so every offset shifts by the same amount and nothing else moves.
        """
        shift = image_offset - self.image_offset
        return replace(
            self,
            image_offset=image_offset,
            entry_structure_offset=(
                None
                if self.entry_structure_offset is None
                else self.entry_structure_offset + shift
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_offset": hexs(self.file_offset, 6),
            "image_offset": hexs(self.image_offset, 6),
            "image_size": self.image_size,
            "runtime_base": hexs(self.runtime_base, 8),
            "entry_structure": hexs(self.entry_structure, 8),
            "entry_structure_offset": hexs(self.entry_structure_offset, 6),
            "entry": hexs(self.entry, 8),
            "initial_stack_pointer": hexs(self.initial_stack_pointer, 8),
            "confidence": round(self.confidence, 3),
        }
