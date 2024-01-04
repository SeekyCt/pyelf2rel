from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from dataclasses import dataclass
from functools import cached_property
from struct import unpack
from typing import TYPE_CHECKING

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

if TYPE_CHECKING:
    from typing import BinaryIO

    from elftools.elf.sections import SymbolTableSection

###########
# Utility #
###########


class DuplicateSymbolError(Exception):
    def __init__(self, symbol: str):
        super().__init__(f"Duplicate symbol {symbol}")


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


def map_symbols(f: BinaryIO, plf: ELFFile) -> tuple[dict[str, Symbol], dict[int, Symbol]]:
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
            if sym.name in symbols:
                raise DuplicateSymbolError(sym.name)
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


def elf_to_lst(module_id: int, file: BinaryIO) -> str:
    """Creates an LST map of the symbols in an ELF file"""

    plf = ELFFile(file)
    symbols, _ = map_symbols(file, plf)

    rel_symbols = [
        RelSymbol.from_elf(module_id, sym)
        for sym in symbols.values()
        if sym.st_shndx != SHN_INDICES.SHN_UNDEF
    ]

    return "\n".join(s.to_lst() for s in rel_symbols)


def elf2lst_main():
    parser = ArgumentParser()
    parser.add_argument("lst_path", type=str, help="Output lst path")
    arg_inputs = parser.add_argument(
        "inputs", type=str, nargs="+", help="Input module id and elf path pairs"
    )
    args = parser.parse_args()

    if len(args.inputs) % 2 != 0:
        raise ArgumentError(arg_inputs, "Inputs require a module id and path for each entry")

    def pairwise(seq: list):
        return zip(*[iter(seq)] * 2)

    txts = []
    for module_id, elf_path in pairwise(args.inputs):
        with open(elf_path, "rb") as f:
            txt = f"// {elf_path}\n" + elf_to_lst(module_id, f)
        txts.append(txt)

    with open(args.lst_path, "w") as f:
        f.write("\n\n".join(txts))


if __name__ == "__main__":
    elf2lst_main()
