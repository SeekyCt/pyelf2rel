from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from struct import unpack
from typing import TYPE_CHECKING, BinaryIO

from elftools.elf.constants import SHN_INDICES
from elftools.elf.enums import ENUM_ST_INFO_BIND

from pyelf2rel.error import DuplicateSymbolError

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


def map_symbols(f: BinaryIO, plf: ELFFile) -> tuple[dict[str, Symbol], dict[int, Symbol]]:
    """Loads symbols from an ELF file into dicts mapped by name and id"""

    # Get symbol table
    symtab: SymbolTableSection = plf.get_section_by_name(".symtab")

    # Parse symbol table
    symbols = {}
    symbols_id = {}
    duplicates = set()
    for i in range(symtab.num_symbols()):
        # Read in symbol bytes
        f.seek(symtab["sh_offset"] + (i * symtab["sh_entsize"]))
        dat = f.read(symtab["sh_entsize"])

        # Parse bytes
        st_name, st_value, st_size, st_info, st_other, st_shndx = unpack(">IIIBBH", dat)
        name = symtab.stringtable.get_string(st_name)
        sym = Symbol(name, st_value, st_size, st_info, st_other, st_shndx)

        # Add to dicts
        if (
            sym.name != ""
            and sym.st_bind == ENUM_ST_INFO_BIND["STB_GLOBAL"]
            and sym.st_shndx != SHN_INDICES.SHN_UNDEF
        ):
            if sym.name in symbols:
                duplicates.add(sym.name)
            symbols[sym.name] = sym
        symbols_id[i] = sym

    if len(duplicates) > 0:
        raise DuplicateSymbolError(duplicates)

    return symbols, symbols_id


@dataclass(frozen=True)
class Relocation:
    """pyelftools relocation substitute"""

    r_offset: int
    r_info_sym: int
    r_info_type: int
    r_addend: int


def read_relocs(f: BinaryIO, rela: RelocationSection) -> list[Relocation]:
    """Loads relocations from a rela section in an ELF file"""

    # Iterate relocations
    relocs = []
    for i in range(rela.num_relocations()):
        # Read in reloc bytes
        f.seek(rela._offset + (i * rela.entry_size))  # noqa: SLF001
        dat = f.read(rela.entry_size)

        # Parse bytes
        r_offset, r_info, r_addend = unpack(">IIi", dat)
        r_info_sym = r_info >> 8
        r_info_type = r_info & 0xFF
        rel = Relocation(r_offset, r_info_sym, r_info_type, r_addend)

        # Add to output
        relocs.append(rel)

    return relocs
