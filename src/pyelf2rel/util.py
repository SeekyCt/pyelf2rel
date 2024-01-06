"""
    Random utilities
"""

from __future__ import annotations


def align_to(offs: int, align: int) -> tuple[int, int]:
    """Aligns an offset and gets the padding required"""

    mask = align - 1

    new_offs = (offs + mask) & ~mask

    padding = new_offs - offs

    return new_offs, padding


def align_to_ttyd_tools(offs: int, align: int) -> tuple[int, int]:
    """Variant of align_to where padding of 0 changes to padding of n instead"""

    padding = align - (offs % align)

    new_offs = offs + padding

    return new_offs, padding
