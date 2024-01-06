from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from sys import stdout
from typing import TYPE_CHECKING, Iterable

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

from pyelf2rel.elf import read_symbols
from pyelf2rel.lst import dump_lst
from pyelf2rel.rel import RelSymbol
from pyelf2rel.util import pairwise

if TYPE_CHECKING:
    from typing import BinaryIO


def load_elf(module_id: int, file: BinaryIO) -> str:
    """Creates an LST map of the symbols in an ELF file

    Returns the LST text and the list of symbols defined"""

    plf = ELFFile(file)
    symbols = read_symbols(file, plf)

    rel_symbols = [
        RelSymbol(module_id, sym.st_shndx, sym.st_value, sym.name)
        for sym in symbols
        if (
            sym.name != ""
            and sym.st_bind == ENUM_ST_INFO_BIND["STB_GLOBAL"]
            and sym.st_shndx != SHN_INDICES.SHN_UNDEF
        )
    ]

    return dump_lst(rel_symbols)


def make_lst(
    *, elfs: Iterable[tuple[int, str]] | None = None, lsts: Iterable[str] | None = None
) -> str:
    txts = []

    for module_id, elf_path in elfs or []:
        with open(elf_path, "rb") as f:
            txt = load_elf(module_id, f)
        txts.append((elf_path, txt))

    for lst_path in lsts or []:
        with open(lst_path) as f:
            txt = f.read()
        txts.append((lst_path, txt))

    return (
        "// Generated by makelst, don't edit manually\n\n"
        + "\n\n".join(f"//\n// File: {path}\n//\n\n" + txt for path, txt in txts)
        + "\n"
    )


def main():
    parser = ArgumentParser()
    arg_elf = parser.add_argument(
        "--elf", type=str, nargs="+", help="Input module id and elf path pairs", default=[]
    )
    parser.add_argument("--lst", type=str, nargs="+", help="Input lst paths", default=[])
    args = parser.parse_args()

    if len(args.elf or []) % 2 != 0:
        raise ArgumentError(arg_elf, "Inputs require a module id and path for each entry")

    elfs = [(int(module_id), path) for module_id, path in pairwise(args.elf)]
    stdout.write(make_lst(elfs=elfs, lsts=args.lst))


if __name__ == "__main__":
    main()
