from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from dataclasses import dataclass
from typing import TYPE_CHECKING

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile

from pyelf2rel.elf import Symbol, map_symbols

if TYPE_CHECKING:
    from typing import BinaryIO


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


def main():
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
    main()
