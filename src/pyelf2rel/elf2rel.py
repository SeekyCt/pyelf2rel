from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from sys import argv
from typing import TYPE_CHECKING, Callable, TextIO, TypedDict

from elftools.elf.constants import SH_FLAGS, SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

from pyelf2rel.elf import Symbol, read_relocs, read_symbols
from pyelf2rel.error import (
    DuplicateSymbolError,
    MissingSymbolError,
    MissingSymbolsError,
    UnsupportedRelocationError,
)
from pyelf2rel.lst import load_lst
from pyelf2rel.rel import RelHeader, RelImp, RelReloc, RelSectionInfo, RelSymbol, RelType
from pyelf2rel.util import align_to, align_to_ttyd_tools

if TYPE_CHECKING:
    from typing import BinaryIO

    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import Section


class ElfToRelBehaviour(Enum):
    """Tool output behaviour"""

    # Modern defaults
    # Mostly based off of how official rels are laid out
    PYELF2REL = 0

    # spm-rel-loader elf2rel fork (elf2rel-13-6-2022)
    MODERN_FORK = 1

    # older spm-rel-loader elf2rel fork (elf2rel-24-6-2021)
    # LSTs can still contain modern format symbols
    OLD_FORK = 2


class RelocationModuleOrder(Enum):
    """Sorting method to use on relocation module groups"""

    # Ascending module id (unsafe for fixed link)
    NONE = 0

    # Ascending module id, self and dol moved back
    MODERN_FORK = 1

    # Ascending module id, dol second last, self last
    PYELF2REL = 2


class BehaviourDef(TypedDict):
    """Specific settings for an ElfToRelBehaviour"""

    # Whether the old external symbol syntax is supported in lsts
    old_fork_lsts: bool

    # Whether the sections to include are based on names alone
    hardcoded_section_names: bool

    # Sorting method for module groups in relocations
    relocation_order: RelocationModuleOrder

    # Valid fix size calculated
    correct_fix_size: bool

    # Send run-time relocated branches to _unresolved
    unresolved_branches: bool

    # Whether to always place the imp section is always placed before the relocations
    # If false, version 1 and 2 will place relocations first
    imp_always_first: bool

    # Whether to align the imp section to 8 bytes
    # TODO: maybe always align, and this just toggles the round up bug
    aligned_imp: bool


BEHAVIOURS: dict[ElfToRelBehaviour, BehaviourDef] = {
    ElfToRelBehaviour.PYELF2REL: {
        "old_fork_lsts": False,
        "hardcoded_section_names": False,
        "relocation_order": RelocationModuleOrder.PYELF2REL,
        "correct_fix_size": True,
        "unresolved_branches": True,
        "imp_always_first": False,
        "aligned_imp": False,
    },
    ElfToRelBehaviour.MODERN_FORK: {
        "old_fork_lsts": False,
        "hardcoded_section_names": True,
        "relocation_order": RelocationModuleOrder.MODERN_FORK,
        "correct_fix_size": True,
        "unresolved_branches": False,
        "imp_always_first": True,
        "aligned_imp": True,
    },
    ElfToRelBehaviour.OLD_FORK: {
        "old_fork_lsts": True,
        "hardcoded_section_names": True,
        "relocation_order": RelocationModuleOrder.NONE,
        "correct_fix_size": False,
        "unresolved_branches": False,
        "imp_always_first": True,
        "aligned_imp": True,
    },
}


class Context:
    """Utility struct for passing common data between the conversion functions"""

    # Module id of the rel to create
    module_id: int

    # Version of the rel to create
    version: int

    # Input ELF file handle
    file: BinaryIO

    # pyelftools ELFFile instance for the input ELF file
    plf: ELFFile

    # Symbols contained in the ELF
    symbols: list[Symbol]
    symbol_map: dict[str, Symbol]

    # External symbols provided
    lst_symbols: dict[str, RelSymbol]

    # Toggles for matching legacy behaviour
    behaviour: BehaviourDef

    def __init__(
        self,
        module_id: int,
        elf_file: BinaryIO,
        lst_file: TextIO,
        *,
        version: int = 3,
        behaviour: ElfToRelBehaviour = ElfToRelBehaviour.PYELF2REL,
        block_duplicates: bool = False,
    ):
        self.module_id = module_id
        self.version = version

        self.file = elf_file
        self.plf = ELFFile(self.file)

        self.symbols = read_symbols(self.file, self.plf)
        self.symbol_map = map_elf_symbols(self.symbols, block_duplicates=block_duplicates)

        self.behaviour = BEHAVIOURS[behaviour]

        lst_txt = lst_file.read()
        lst = load_lst(lst_txt, support_old_fork=self.behaviour["old_fork_lsts"])
        self.lst_symbols = map_rel_symbols(lst, block_duplicates=block_duplicates)

        if block_duplicates:
            overlap = self.symbol_map.keys() & self.lst_symbols.keys()
            if len(overlap) > 0:
                raise DuplicateSymbolError(overlap)


def map_elf_symbols(symbols: list[Symbol], *, block_duplicates: bool = False) -> dict[str, Symbol]:
    """Creates a dict of global symbols by name"""

    ret = {}
    duplicates = set()
    for sym in symbols:
        # Check symbol is global
        if (
            sym.name != ""
            and sym.st_bind == ENUM_ST_INFO_BIND["STB_GLOBAL"]
            and sym.st_shndx != SHN_INDICES.SHN_UNDEF
        ):
            # Save duplicates to report later
            if sym.name in ret:
                duplicates.add(sym.name)
            else:
                ret[sym.name] = sym

    if block_duplicates and len(duplicates) > 0:
        raise DuplicateSymbolError(duplicates)

    return ret


def map_rel_symbols(
    symbols: list[RelSymbol], *, block_duplicates: bool = False
) -> dict[str, RelSymbol]:
    """Creates a dict of symbols by name"""

    ret = {}
    duplicates = set()
    for sym in symbols:
        # Save duplicates to report later
        if sym.name in ret:
            duplicates.add(sym.name)
        else:
            ret[sym.name] = sym

    if block_duplicates and len(duplicates) > 0:
        raise DuplicateSymbolError(duplicates)

    return ret


def find_symbol(ctx: Context, sym_id: int) -> RelSymbol:
    """Finds a symbol by id"""

    # Get symbol
    sym = ctx.symbols[sym_id]

    # Find symbol location
    sec = sym.st_shndx
    if sec == SHN_INDICES.SHN_UNDEF:
        # Symbol in dol or other rel
        if sym.name not in ctx.lst_symbols:
            raise MissingSymbolError(sym.name)
        return ctx.lst_symbols[sym.name]
    else:
        # Symbol in this rel
        return RelSymbol(ctx.module_id, sec, sym.st_value, sym.name)


def should_include_section(ctx: Context, sec_id: int, ignore_sections: list[str]) -> bool:
    """Checks if an section should be emitted in the rel"""

    section = ctx.plf.get_section(sec_id)

    if section.name in ignore_sections:
        return False

    if ctx.behaviour["hardcoded_section_names"]:
        return any(
            section.name == val or section.name.startswith(val + ".")
            for val in [
                ".init",
                ".text",
                ".ctors",
                ".dtors",
                ".rodata",
                ".data",
                ".bss",
            ]
        )
    else:
        return (
            section["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")
            and section["sh_flags"] & SH_FLAGS.SHF_ALLOC != 0
        )


@dataclass(frozen=True)
class BinarySection:
    """Container for a processed section"""

    # Index of the section in the ELF
    sec_id: int

    # ELF header for the section
    header: Section

    # Binary contents of the section (unlinked)
    contents: bytes

    # Relocations to be applied at runtime to the section
    runtime_relocs: list[RelReloc]

    # Relocations to be applied at compile-time to the section
    static_relocs: list[RelReloc]


def parse_section(ctx: Context, sec_id: int, missing_symbols: set) -> BinarySection:
    """Extract the contents and relocations for a section"""

    # Get section
    sec = ctx.plf.get_section(sec_id)

    # Check for BSS
    if sec["sh_type"] != "SHT_PROGBITS":
        return BinarySection(sec_id, sec, b"", [], [])

    # Get relocations
    rela: RelocationSection = ctx.plf.get_section_by_name(".rela" + sec.name)

    # Return unchanged data if not relocated
    if rela is None:
        return BinarySection(sec_id, sec, sec.data(), [], [])

    # Init return data
    dat = bytearray(sec.data())
    runtime_relocs = []
    static_relocs = []

    # Build relocation lists
    for reloc in read_relocs(ctx.file, rela):
        try:
            t = RelType(reloc.r_info_type)
        except ValueError as e:
            raise UnsupportedRelocationError(str(reloc.r_info_type))
        if t == RelType.NONE:
            continue

        offs = reloc.r_offset
        try:
            target = find_symbol(ctx, reloc.r_info_sym)
        except MissingSymbolError as e:
            missing_symbols.add(e.symbol)
            continue
        target_offset = target.offset + reloc.r_addend

        # Check when to apply
        skip_runtime = False
        if t in (RelType.REL24, RelType.REL32) and target.module_id == ctx.module_id:
            skip_runtime = True

        rel_reloc = RelReloc(target.module_id, offs, t, target.section_id, target_offset)
        if skip_runtime:
            static_relocs.append(rel_reloc)
        else:
            # TODO: other relocations are supported at runtime
            if t not in (
                RelType.ADDR32,
                RelType.ADDR16_LO,
                RelType.ADDR16_HI,
                RelType.ADDR16_HA,
                RelType.REL24,
                RelType.REL14,
                RelType.REL32,
            ):
                raise UnsupportedRelocationError(t.name)

            runtime_relocs.append(rel_reloc)

    return BinarySection(sec_id, sec, dat, runtime_relocs, static_relocs)


def build_section_contents(
    ctx: Context, file_pos: int, sections: list[BinarySection]
) -> tuple[int, bytes, dict[int, int], int, int]:
    """Create the linked binary data for the sections

    Returns new file position, linked data, the file offsets of each section, rel alignment and bss alignment"""

    # Concatenate section contents, respecting alignment
    dat = bytearray()
    offsets = {}  # positions in file
    internal_offsets = {}  # positions in dat
    align = 0
    bss_align = 0
    for section in sections:
        # Force minimum alignment of 2 to avoid offset containing exec flag
        sec_align = max(section.header["sh_addralign"], 2)

        if section.header["sh_type"] == "SHT_NOBITS":
            bss_align = max(bss_align, sec_align)
        elif section.header["sh_type"] == "SHT_PROGBITS":
            align = max(align, sec_align)

            file_pos, padding = align_to(file_pos, sec_align)
            dat.extend(bytes(padding))

            offsets[section.sec_id] = file_pos
            internal_offsets[section.sec_id] = len(dat)
            file_pos += section.header["sh_size"]
            dat.extend(section.contents)

    def early_relocate(t: RelType, sec_id: int, offset: int, target_sec_id: int, target: int):
        """Apply a relocation at compile time to a section"""

        # Get instruction
        offs = internal_offsets[sec_id] + offset
        instr = int.from_bytes(dat[offs : offs + 4], "big")

        # Apply delta
        delta = (target + internal_offsets[target_sec_id]) - (offset + internal_offsets[sec_id])
        if t == RelType.REL32:
            instr = delta & 0xFFFF_FFFF
        else:  # Rel24
            instr |= delta & (0x3FF_FFFC)

        # Write new instruction
        dat[offs : offs + 4] = int.to_bytes(instr, 4, "big")

    # Apply static relocations
    for sec in sections:
        for reloc in sec.static_relocs:
            early_relocate(reloc.t, sec.sec_id, reloc.offset, reloc.section, reloc.addend)

    # Patch runtime reloc branches to _unresolved
    if ctx.behaviour["unresolved_branches"]:
        unresolved = ctx.symbol_map["_unresolved"]
        for sec in sections:
            for reloc in sec.runtime_relocs:
                if reloc.t == RelType.REL24:
                    early_relocate(
                        reloc.t, sec.sec_id, reloc.offset, unresolved.st_shndx, unresolved.st_value
                    )

    return file_pos, bytes(dat), offsets, align, bss_align


def build_section_info(sections: list[BinarySection | None], offsets: dict[int, int]) -> bytes:
    """Builds the linked section info table"""

    dat = bytearray()
    for sec in sections:
        if sec is not None:
            offset = offsets.get(sec.sec_id, 0)
            length = sec.header["sh_size"]
            executable = sec.header["sh_flags"] & SH_FLAGS.SHF_EXECINSTR
        else:
            offset = 0
            length = 0
            executable = False
        info = RelSectionInfo(offset, length, executable)
        dat.extend(info.to_binary())

    return bytes(dat)


def make_section_relocations(section: BinarySection) -> dict[int, bytes]:
    """Creates the binary data for a section's relocations

    Returns a map from module id to the data targetting that module"""

    # Get modules referenced
    modules = {r.target_module for r in section.runtime_relocs}

    # Split relocs by module
    ret = {}
    for module in modules:
        # Get relevant relocs and sort them by offset
        filtered_relocs = sorted(
            [r for r in section.runtime_relocs if r.target_module == module], key=lambda r: r.offset
        )

        ret[module] = RelReloc.encode_section(section.sec_id, filtered_relocs)

    return ret


def group_module_relocations(section_relocs: list[dict[int, bytes]]) -> dict[int, bytes]:
    """Gathers the relocations against each module from each section"""

    # Group across sections
    ret: dict[int, bytearray] = defaultdict(bytearray)
    for section in section_relocs:
        for module, relocs in section.items():
            ret[module].extend(relocs)

    # Add terminators
    for relocs in ret.values():
        relocs.extend(RelReloc.encode_reloc(0, RelType.RVL_STOP, 0, 0))

    return {module: bytes(dat) for module, dat in ret.items()}


@dataclass(frozen=True)
class RelocationInfo:
    # File offset of the relocation table
    reloc_offset: int

    # File offset of the imp table
    imp_offset: int

    # Size of the imp table (in bytes)
    imp_size: int

    # File offset of data which can be discarded after OSLink
    fix_size: int

    # Linked binary blob for the imp and relocation tables
    data: bytes


def build_relocations(
    ctx: Context, file_pos: int, module_relocs: dict[int, bytes]
) -> tuple[int, RelocationInfo]:
    """Builds the linked relocation and imp tables

    Returns new file position and the linked information"""

    # Get table size
    imp_size = RelImp.binary_size(len(module_relocs.keys()))

    # Place imp before relocations if needed
    pre_pad = 0
    if ctx.version >= RelHeader.FIX_SIZE_MIN_VER or ctx.behaviour["imp_always_first"]:
        # ttyd-tools aligns this to 8 bytes, and rounds up 0-length padding
        if ctx.behaviour["aligned_imp"]:
            file_pos, pre_pad = align_to_ttyd_tools(file_pos, 8)

        imp_offset = file_pos
        file_pos += imp_size
    else:
        imp_offset = None

    # Sort reloc groups
    base = max(module_relocs.keys())
    module_key: Callable[[int], int] | None
    if ctx.behaviour["relocation_order"] == RelocationModuleOrder.MODERN_FORK:

        def modern_fork_module_key(module):
            if module in (0, ctx.module_id):
                return base + module
            else:
                return module

        module_key = modern_fork_module_key
    elif (
        ctx.behaviour["relocation_order"] == RelocationModuleOrder.PYELF2REL
        and ctx.version >= RelHeader.FIX_SIZE_MIN_VER
    ):

        def fix_size_module_key(module):
            # Put self second last
            if module == ctx.module_id:
                return base + 1
            # Put dol last
            if module == 0:
                return base + 2
            # Put others in order of module id
            return module

        module_key = fix_size_module_key
    else:
        module_key = None
    modules = sorted(module_relocs.keys(), key=module_key)

    # Build tables
    rel_dat = bytearray()
    imp_dat = bytearray()
    reloc_offset = file_pos
    fix_size = file_pos  # Default if no relocations need to be kept
    for module_id in modules:
        imp = RelImp(module_id, file_pos)
        imp_dat.extend(imp.to_binary())

        relocs = module_relocs[module_id]
        rel_dat.extend(relocs)
        file_pos += len(relocs)

        if ctx.behaviour["correct_fix_size"] and module_id not in (0, ctx.module_id):
            fix_size = file_pos

    # Combine data
    if imp_offset is not None:
        dat = bytes(pre_pad) + imp_dat + rel_dat
    else:
        # Give space for imp if not emitted earlier
        imp_offset = file_pos
        file_pos += imp_size

        dat = bytes(pre_pad) + rel_dat + imp_dat

    return file_pos, RelocationInfo(reloc_offset, imp_offset, imp_size, fix_size, dat)


def elf_to_rel(
    module_id: int,
    elf_file: BinaryIO,
    lst_file: TextIO,
    *,
    version: int = 3,
    behaviour: ElfToRelBehaviour = ElfToRelBehaviour.PYELF2REL,
    ignore_sections: list[str] | None = None,
    block_duplicates: bool = False,
) -> bytes:
    """Converts a partially linked elf file into a rel file"""

    # Setup default parameters
    if ignore_sections is None:
        ignore_sections = []

    # Build context
    ctx = Context(
        module_id,
        elf_file,
        lst_file,
        version=version,
        behaviour=behaviour,
        block_duplicates=block_duplicates,
    )

    # Give space for header
    file_pos = RelHeader.binary_size(version)
    section_info_offset = file_pos

    # Parse sections
    missing_symbols = set()
    all_sections = [
        parse_section(ctx, sec_id, missing_symbols) if should_include_section(ctx, sec_id, ignore_sections) else None
        for sec_id in range(ctx.plf.num_sections())
    ]
    if len(missing_symbols) > 0:
        raise MissingSymbolsError(missing_symbols)
    sections = [sec for sec in all_sections if sec is not None]

    # Give space for section info
    section_info_size = RelSectionInfo.binary_size(len(all_sections))
    file_pos += section_info_size

    # Build section contents
    (
        file_pos,
        section_contents,
        section_offsets,
        align,
        bss_align,
    ) = build_section_contents(ctx, file_pos, sections)

    # Build section table
    section_info = build_section_info(all_sections, section_offsets)

    # Build relocs
    section_relocs = [make_section_relocations(sec) for sec in sections]
    module_relocs = group_module_relocations(section_relocs)

    # Build reloc contents
    file_pos, relocation_info = build_relocations(ctx, file_pos, module_relocs)

    # Find bss section
    bss_sections = [sec for sec in sections if sec.header["sh_type"] == "SHT_NOBITS"]
    bss_size = sum(s.header["sh_size"] for s in bss_sections)

    # Gather export info
    try:
        prolog = ctx.symbol_map["_prolog"]
        epilog = ctx.symbol_map["_epilog"]
        unresolved = ctx.symbol_map["_unresolved"]
    except KeyError as e:
        raise MissingSymbolError(e.args[0]) from e

    # Build header
    header = RelHeader(
        ctx.module_id,
        0,
        0,
        len(all_sections),
        section_info_offset,
        0,
        0,
        version,
        bss_size,
        relocation_info.reloc_offset,
        relocation_info.imp_offset,
        relocation_info.imp_size,
        prolog.st_shndx,
        epilog.st_shndx,
        unresolved.st_shndx,
        0,
        prolog.st_value,
        epilog.st_value,
        unresolved.st_value,
        align,
        bss_align,
        relocation_info.fix_size,
    )

    # Build full binary
    dat = bytearray()
    dat.extend(header.to_binary())
    dat.extend(section_info)
    dat.extend(section_contents)
    dat.extend(relocation_info.data)

    return bytes(dat)


def main(argv: list[str], *, ttyd_tools=False):
    parser = ArgumentParser(description="Converts an ELF file to a REL file")

    input_file_help = "Input ELF path"
    symbol_file_help = "Input LST path"
    output_file_help = "Output ELF path"

    # Recreate ttyd-tools mandatory positional API
    # boost::program_options behaves differently to argparse
    if ttyd_tools:
        parser.add_argument("positionals", nargs="*", help="input_file symbol_file [output_file]")
        arg_input_file = parser.add_argument("--input-file", "-i", help=input_file_help)
        arg_symbol_file = parser.add_argument("--symbol-file", "-s", help=symbol_file_help)
        parser.add_argument("--output-file", "-o", help=output_file_help)
    else:
        arg_input_file = parser.add_argument("input_file", help=input_file_help)
        arg_symbol_file = parser.add_argument("symbol_file", help=symbol_file_help)
        parser.add_argument("output_file", nargs="?", help=output_file_help)

    # Optional
    parser.add_argument(
        "--rel-id", type=lambda x: int(x, 0), default=0x1000, help="Module id of the output rel"
    )
    parser.add_argument(
        "--rel-version", type=int, default=3, help="Format version of the output rel"
    )
    if ttyd_tools:
        parser.add_argument(
            "--old-fork",
            action="store_true",
            help="Match the behaviour of spm-rel-loader elf2rel-24-6-2021",
        )
        parser.add_argument(
            "-x", help="Ignored, hack to support the TTYDTOOLS environment variable"
        )
    else:
        parser.add_argument(
            "--ignore-sections",
            nargs="+",
            default=[],
            help="Extra sections to strip from the output rel",
        )
        parser.add_argument(
            "--block-duplicates",
            action="store_true",
            help="Throw an error when finding duplicated symbols",
        )

    args = parser.parse_args(argv)

    positionals = list(args.positionals) if ttyd_tools else []

    if len(positionals) > 0:
        input_file = positionals.pop(0)
    else:
        if args.input_file is None:
            raise ArgumentError(arg_input_file, "input-file is required")
        input_file = args.input_file

    if len(positionals) > 0:
        symbol_file = positionals.pop(0)
    else:
        if args.symbol_file is None:
            raise ArgumentError(arg_symbol_file, "symbol-file is required")
        symbol_file = args.symbol_file

    if len(positionals) > 0:
        output_file = positionals.pop(0)
    elif args.output_file is not None:
        output_file = args.output_file
    else:
        output_file = input_file.removesuffix(".elf") + ".rel"

    if ttyd_tools:
        behaviour = ElfToRelBehaviour.OLD_FORK if args.old_fork else ElfToRelBehaviour.MODERN_FORK
    else:
        behaviour = ElfToRelBehaviour.PYELF2REL

    with open(input_file, "rb") as f, open(symbol_file) as sym:
        dat = elf_to_rel(
            args.rel_id,
            f,
            sym,
            version=args.rel_version,
            ignore_sections=None if ttyd_tools else args.ignore_sections,
            behaviour=behaviour,
            block_duplicates=False if ttyd_tools else args.block_duplicates,
        )

    with open(output_file, "wb") as f:
        f.write(dat)


def entry():
    main(argv[1:])


def entry_ttyd_tools():
    main(argv[1:], ttyd_tools=True)


if __name__ == "__main__":
    entry()
