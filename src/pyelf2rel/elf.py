"""
    Faster pyelftools substitutes
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from struct import unpack
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection


@dataclass(frozen=True)
class Symbol:
    """pyelftools symbol substitute"""

    name: str
    st_value: int
    st_size: int
    st_info: int
    st_other: int
    st_shndx: int

    @cached_property
    def st_bind(self) -> int:
        return self.st_info >> 4


def read_symbols(f: BinaryIO, plf: ELFFile) -> list[Symbol]:
    """Loads symbols from the symtab section of an ELF file"""

    symtab: SymbolTableSection = plf.get_section_by_name(".symtab")
    ret = []
    for i in range(symtab.num_symbols()):
        f.seek(symtab["sh_offset"] + (i * symtab["sh_entsize"]))
        dat = f.read(symtab["sh_entsize"])

        st_name, st_value, st_size, st_info, st_other, st_shndx = unpack(">IIIBBH", dat)
        name = symtab.stringtable.get_string(st_name)
        ret.append(Symbol(name, st_value, st_size, st_info, st_other, st_shndx))

    return ret


@dataclass(frozen=True)
class Relocation:
    """pyelftools relocation substitute"""

    r_offset: int
    r_info_sym: int
    r_info_type: int
    r_addend: int


def read_relocs(f: BinaryIO, rela: RelocationSection) -> list[Relocation]:
    """Loads relocations from a rela section in an ELF file"""

    relocs = []
    for i in range(rela.num_relocations()):
        f.seek(rela._offset + (i * rela.entry_size))  # noqa: SLF001
        rela_entry = f.read(rela.entry_size)

        r_offset, r_info, r_addend = unpack(">IIi", rela_entry)
        r_info_sym = r_info >> 8
        r_info_type = r_info & 0xFF

        relocs.append(Relocation(r_offset, r_info_sym, r_info_type, r_addend))

    return relocs
