#!/usr/bin/env python3
from argparse import ArgumentParser
from dataclasses import dataclass
from functools import cached_property
from io import FileIO
from struct import unpack
from typing import Dict, Tuple

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND
from elftools.elf.sections import SymbolTableSection


##########################
# Pyelftools Substitutes #
##########################


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


def map_symbols(f: FileIO, plf: ELFFile) -> Tuple[Dict[str, "Symbol"], Dict[int, "Symbol"]]:
    """Loads symbols from an ELF file into dicts mapped by name and id"""

    # Get symbol table
    symtab: SymbolTableSection = plf.get_section_by_name(".symtab")

    # Parse symbol table
    symbols = {}
    symbols_id = {}
    for i in range(symtab.num_symbols()):
        # Read in symbol bytes
        f.seek(symtab["sh_offset"] + (i * symtab["sh_entsize"]))
        dat = f.read(symtab["sh_entsize"])

        # Parse bytes
        st_name, st_value, st_size, st_info, st_other, st_shndx = unpack(">IIIBBH", dat)
        name = symtab.stringtable.get_string(st_name)
        sym = Symbol(name, st_value, st_size, st_info, st_other, st_shndx)

        # Add to dicts
        if sym.name != "" and sym.st_bind == ENUM_ST_INFO_BIND["STB_GLOBAL"]:
            assert sym.name not in symbols, f"Duplicate symbol {sym.name}"
            symbols[sym.name] = sym
        symbols_id[i] = sym
    
    return symbols, symbols_id


#############
# Rel Types #
#############


@dataclass
class RelSymbol:
    """Container for a symbol in a rel file"""

    module_id: int
    section_id: int
    offset: int
    name: str

    @staticmethod
    def from_elf(module_id: int, sym: Symbol):
        return RelSymbol(module_id, sym.st_shndx, sym.st_value, sym.name)

    def to_lst(self) -> str:
        if self.module_id == 0:
            return f"{self.offset:08x}:{self.name}"
        else:
            return f"{self.module_id},{self.section_id},{self.offset:08x}:{self.name}"


##############
# Conversion #
##############


def elf_to_lst(module_id: int, elf_path: str) -> str:
    """Creates an LST map of the symbols in an ELF file"""

    f = open(elf_path, 'rb')
    plf = ELFFile(f)
    symbols, _ = map_symbols(f, plf)

    rel_symbols = [
        RelSymbol.from_elf(module_id, sym)
        for sym in symbols.values()
        if sym.st_shndx != SHN_INDICES.SHN_UNDEF
    ]

    return f"// {elf_path}\n" + '\n'.join(s.to_lst() for s in rel_symbols)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("lst_path", type=str, help="Output lst path")
    parser.add_argument("inputs", type=str, nargs='+', help="Input module id and elf path pairs")
    args = parser.parse_args()

    assert len(args.inputs) % 2 == 0

    pairwise = lambda l: zip(*[iter(l)]*2) 

    txts = [
        elf_to_lst(module_id, elf_path)
        for module_id, elf_path in pairwise(args.inputs)
    ]

    with open(args.lst_path, 'w') as f:
        f.write('\n\n'.join(txts))
