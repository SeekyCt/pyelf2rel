"""
    REL file format constants and structures
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, unique
from struct import pack


@dataclass(frozen=True)
class RelSymbol:
    """Container for a symbol in a rel file"""

    module_id: int
    section_id: int
    offset: int
    name: str


@dataclass(frozen=True)
class RelSectionInfo:
    """Container for a section info table entry"""

    offset: int
    length: int
    executable: bool

    def to_binary(self) -> bytes:
        """Gets the binary representation of the struct"""

        mask = 1 if self.executable else 0
        return pack(">2I", self.offset | mask, self.length)

    @staticmethod
    def binary_size(length: int) -> int:
        """Gets the size of a section info table in bytes"""

        return length * 8


@unique
class RelType(IntEnum):
    """Types of RelReloc"""

    NONE = 0
    ADDR32 = 1
    ADDR16_LO = 4
    ADDR16_HI = 5
    ADDR16_HA = 6
    REL24 = 10
    REL14 = 11
    REL32 = 26
    RVL_NONE = 201
    RVL_SECT = 202
    RVL_STOP = 203


@dataclass(frozen=True)
class RelReloc:
    """Container for one relocation"""

    target_module: int
    offset: int
    t: RelType
    section: int
    addend: int

    MAX_DELTA = 0xFFFF

    def to_binary(self, relative_offset: int) -> bytes:
        """Gets the binary representation of the relocation"""

        return RelReloc.encode_reloc(relative_offset, self.t, self.section, self.addend)

    @staticmethod
    def encode_reloc(relative_offset: int, t: RelType, section: int, addend: int):
        """Gets the binary representation of a relocation"""

        return pack(">HBBI", relative_offset, t, section, addend)

    @staticmethod
    def encode_section(section_id: int, relocs: list[RelReloc]) -> bytes:
        """Converts a list of relocations in a section to binary"""

        dat = bytearray()
        dat.extend(RelReloc.encode_reloc(0, RelType.RVL_SECT, section_id, 0))
        offs = 0
        for rel in relocs:
            delta = rel.offset - offs

            # Use nops to get delta in range
            while delta > RelReloc.MAX_DELTA:
                dat.extend(RelReloc.encode_reloc(RelReloc.MAX_DELTA, RelType.RVL_NONE, 0, 0))
                delta -= RelReloc.MAX_DELTA

            dat.extend(rel.to_binary(delta))

            # Move to new offset
            offs = rel.offset

        return bytes(dat)


@dataclass(frozen=True)
class RelImp:
    """Container for an imp table entry"""

    module_id: int
    offset: int

    def to_binary(self) -> bytes:
        return pack(">2I", self.module_id, self.offset)


@dataclass(frozen=True)
class RelHeader:
    """Container for the rel header struct"""

    module_id: int  # u32
    next_rel: int  # u32
    prev_rel: int  # u32
    num_sections: int  # u32
    section_info_offset: int  # u32
    name_offset: int  # u32
    name_size: int  # u32
    version: int  # u32
    bss_size: int  # u32
    rel_offset: int  # u32
    imp_offset: int  # u32
    imp_size: int  # u32
    prolog_section: int  # u8
    epilog_section: int  # u8
    unresolved_section: int  # u8
    bss_section: int  # u8
    prolog: int  # u32
    epilog: int  # u32
    unresolved: int  # u32

    # v2
    align: int | None  # u32
    bss_align: int | None  # u32
    ALIGN_MIN_VER = 2

    # v3
    fix_size: int | None  # u32
    FIX_SIZE_MIN_VER = 3

    def to_binary(self) -> bytes:
        """Gets the binary representaiton of the header"""

        dat = pack(
            ">12I4B3I",
            self.module_id,
            self.next_rel,
            self.prev_rel,
            self.num_sections,
            self.section_info_offset,
            self.name_offset,
            self.name_size,
            self.version,
            self.bss_size,
            self.rel_offset,
            self.imp_offset,
            self.imp_size,
            self.prolog_section,
            self.epilog_section,
            self.unresolved_section,
            self.bss_section,
            self.prolog,
            self.epilog,
            self.unresolved,
        )

        if self.version >= RelHeader.ALIGN_MIN_VER:
            dat += pack(
                ">2I",
                self.align,
                self.bss_align,
            )

        if self.version >= RelHeader.FIX_SIZE_MIN_VER:
            dat += pack(">I", self.fix_size)

        return dat

    @staticmethod
    def binary_size(version: int) -> int:
        """Calculates the binary size of the struct"""

        size = 0x40

        if version >= RelHeader.ALIGN_MIN_VER:
            size += 8

        if version >= RelHeader.FIX_SIZE_MIN_VER:
            size += 4

        return size
