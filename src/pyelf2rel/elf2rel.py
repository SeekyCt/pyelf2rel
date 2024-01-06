from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from elftools.elf.constants import SH_FLAGS, SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

from pyelf2rel.align import align_to, align_to_ttyd_tools
from pyelf2rel.elf import Symbol, read_relocs, read_symbols
from pyelf2rel.error import (
    DuplicateSymbolError,
    MissingSymbolError,
    UnsupportedRelocationError,
)
from pyelf2rel.lst import decode_lst
from pyelf2rel.rel import RelHeader, RelImp, RelReloc, RelSectionInfo, RelSymbol, RelType

if TYPE_CHECKING:
    from typing import BinaryIO

    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import Section


class Context:
    """Utility struct for passing common data between the conversion functions"""

    version: int
    match_ttyd_tools: bool
    module_id: int
    file: BinaryIO
    plf: ELFFile
    symbol_map: dict[str, Symbol]
    symbols: list[Symbol]
    lst_symbols: dict[str, RelSymbol]

    def __init__(
        self, version: int, module_id: int, file: BinaryIO, lst_path: str, *, match_ttyd_tools: bool
    ):
        self.version = version
        self.match_ttyd_tools = match_ttyd_tools
        self.module_id = module_id
        self.file = file
        self.plf = ELFFile(self.file)
        self.symbols = read_symbols(self.file, self.plf)
        self.symbol_map = map_symbols(self.symbols)
        with open(lst_path) as f:
            lst_txt = f.read()
        self.lst_symbols = decode_lst(lst_txt)
        overlap = self.symbol_map.keys() & self.lst_symbols.keys()
        if len(overlap) > 0:
            raise DuplicateSymbolError(overlap)


def map_symbols(symbols: list[Symbol]) -> dict[str, Symbol]:
    """Creates a dict of global symbols by name"""

    ret = {}
    duplicates = set()
    for sym in symbols:
        if (
            sym.name != ""
            and sym.st_bind == ENUM_ST_INFO_BIND["STB_GLOBAL"]
            and sym.st_shndx != SHN_INDICES.SHN_UNDEF
        ):
            if sym.name in ret:
                duplicates.add(sym.name)
            else:
                ret[sym.name] = sym

    if len(duplicates) > 0:
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


ttyd_tools_section_mask = [
    ".init",
    ".text",
    ".ctors",
    ".dtors",
    ".rodata",
    ".data",
    ".bss",
]


def should_include_section(ctx: Context, sec_id: int, ignore_sections: list[str]) -> bool:
    """Checks if an section should be emitted in the rel"""

    section = ctx.plf.get_section(sec_id)

    if section.name in ignore_sections:
        return False

    if ctx.match_ttyd_tools:
        return any(
            section.name == val or section.name.startswith(val + ".")
            for val in ttyd_tools_section_mask
        )
    else:
        return (
            section["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")
            and section["sh_flags"] & SH_FLAGS.SHF_ALLOC != 0
        )


@dataclass(frozen=True)
class BinarySection:
    """Container for a processed section"""

    sec_id: int
    header: Section
    contents: bytes
    runtime_relocs: list[RelReloc]
    static_relocs: list[RelReloc]


def parse_section(ctx: Context, sec_id: int) -> BinarySection:
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
        t = RelType(reloc.r_info_type)
        if t == RelType.NONE:
            continue

        offs = reloc.r_offset
        target = find_symbol(ctx, reloc.r_info_sym)
        target_offset = target.offset + reloc.r_addend

        # Check when to apply
        skip_runtime = False
        if (
            t in (RelType.REL24, RelType.REL32)
            and target.module_id == ctx.module_id
            and (ctx.match_ttyd_tools or sec_id == target.section_id)
        ):
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
                raise UnsupportedRelocationError(t)

            runtime_relocs.append(rel_reloc)

    return BinarySection(sec_id, sec, dat, runtime_relocs, static_relocs)


def build_section_contents(
    ctx: Context, file_pos: int, sections: list[BinarySection]
) -> tuple[int, bytes, dict[int, int]]:
    """Create the linked binary data for the sections

    Returns new file position, linked data, and the file offsets of each section"""

    dat = bytearray()
    offsets = {}  # positions in file
    internal_offsets = {}  # positions in dat
    for section in sections:
        if section.header["sh_type"] != "SHT_PROGBITS":
            continue

        file_pos, padding = align_to(file_pos, section.header["sh_addralign"])
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
    if not ctx.match_ttyd_tools:
        unresolved = ctx.symbol_map["_unresolved"]
        for sec in sections:
            for reloc in sec.runtime_relocs:
                if reloc.t == RelType.REL24:
                    early_relocate(
                        reloc.t, sec.sec_id, reloc.offset, unresolved.st_shndx, unresolved.st_value
                    )

    return file_pos, bytes(dat), offsets


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

    # Make data for modules
    ret = {}
    for module in modules:
        # Get relevant relocs and sort them by offset
        filtered_relocs = sorted(
            [r for r in section.runtime_relocs if r.target_module == module], key=lambda r: r.offset
        )

        # Convert relocs to binary
        dat = bytearray()
        dat.extend(RelReloc.encode_reloc(0, RelType.RVL_SECT, section.sec_id, 0))
        offs = 0
        for rel in filtered_relocs:
            # Calculate delta
            delta = rel.offset - offs

            # Use nops to get delta in range
            while delta > RelReloc.MAX_DELTA:
                dat.extend(RelReloc.encode_reloc(RelReloc.MAX_DELTA, RelType.RVL_NONE, 0, 0))
                delta -= RelReloc.MAX_DELTA

            # Convert to binary
            dat.extend(rel.to_binary(delta))

            # Move to offset
            offs = rel.offset

        # Add to output
        ret[module] = bytes(dat)

    return ret


def group_module_relocations(section_relocs: list[dict[int, bytes]]) -> dict[int, bytes]:
    """Split up a list of relocations into binaries for which module they're targetting"""

    # Group relocations
    ret: dict[int, bytearray] = defaultdict(bytearray)
    for section in section_relocs:
        for module, relocs in section.items():
            ret[module].extend(relocs)
    for relocs in ret.values():
        relocs.extend(RelReloc.encode_reloc(0, RelType.RVL_STOP, 0, 0))

    return {module: bytes(dat) for module, dat in ret.items()}


@dataclass(frozen=True)
class RelocationInfo:
    reloc_offset: int
    imp_offset: int
    imp_size: int
    fix_size: int
    data: bytes


def build_relocations(
    ctx: Context, file_pos: int, module_relocs: dict[int, bytes]
) -> tuple[int, RelocationInfo]:
    """Builds the linked relocation and imp tables

    Returns new file position and the linked information"""

    # Get table size
    imp_size = len(module_relocs) * 8

    # Place imp before relocations if needed
    pre_pad = 0
    if ctx.version >= RelHeader.FIX_SIZE_MIN_VER or ctx.match_ttyd_tools:
        # ttyd-tools aligns this to 8 bytes, and rounds up 0-length padding
        if ctx.match_ttyd_tools:
            file_pos, pre_pad = align_to_ttyd_tools(file_pos, 8)

        imp_offset = file_pos
        file_pos += imp_size
    else:
        imp_offset = None

    # Sort reloc groups
    base = max(module_relocs.keys())
    module_key: Callable[[int], int] | None
    if ctx.match_ttyd_tools:

        def ttyd_tools_module_key(module):
            if module in (0, ctx.module_id):
                return base + module
            else:
                return module

        module_key = ttyd_tools_module_key
    elif ctx.version >= RelHeader.FIX_SIZE_MIN_VER:

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
    fix_size = file_pos
    for module_id in modules:
        relocs = module_relocs[module_id]
        imp = RelImp(module_id, file_pos)
        imp_dat.extend(imp.to_binary())

        rel_dat.extend(relocs)
        file_pos += len(relocs)

        if module_id not in (0, ctx.module_id):
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
    file: BinaryIO,
    lst_path: str,
    version: int = 3,
    *,
    match_ttyd_tools: bool = False,
    ignore_sections: list[str] | None = None,
) -> bytes:
    """Converts a partially linked elf file into a rel file"""

    # Setup default parameters
    if ignore_sections is None:
        ignore_sections = []

    # Build context
    ctx = Context(version, module_id, file, lst_path, match_ttyd_tools=match_ttyd_tools)

    # Give space for header
    file_pos = RelHeader.binary_size(version)
    section_info_offset = file_pos

    # Parse sections
    all_sections = [
        parse_section(ctx, sec_id) if should_include_section(ctx, sec_id, ignore_sections) else None
        for sec_id in range(ctx.plf.num_sections())
    ]
    sections = [sec for sec in all_sections if sec is not None]

    # Give space for section info
    section_info_size = RelSectionInfo.binary_size(len(all_sections))
    file_pos += section_info_size

    # Build section contents
    file_pos, section_contents, section_offsets = build_section_contents(ctx, file_pos, sections)

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

    # Calculate alignment
    if version >= RelHeader.ALIGN_MIN_VER:
        align = max(
            sec.header["sh_addralign"]
            for sec in sections
            if sec.header["sh_type"] == "SHT_PROGBITS"
        )

        if len(bss_sections) > 0:
            bss_align = max(s.header["sh_addralign"] for s in bss_sections)
        else:
            bss_align = 0
    else:
        align = None
        bss_align = None

    # Gather export info
    prolog = ctx.symbol_map["_prolog"]
    epilog = ctx.symbol_map["_epilog"]
    unresolved = ctx.symbol_map["_unresolved"]

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


def main():
    parser = ArgumentParser()

    # Positional API - boost::program_options behaves differently to argparse
    parser.add_argument("positionals", type=str, nargs="*")

    # Non-positional API
    arg_input_file = parser.add_argument("--input-file", "-i", type=str)
    arg_symbol_file = parser.add_argument("--symbol-file", "-s", type=str)
    parser.add_argument("--output-file", "-o", type=str)

    # Optional
    parser.add_argument("--rel-id", type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("--rel-version", type=int, default=3)
    parser.add_argument("--match-ttyd-tools", action="store_true")
    parser.add_argument("--ignore-sections", nargs="+", default=[])

    args = parser.parse_args()

    positionals = list(args.positionals)

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

    with open(input_file, "rb") as f:
        dat = elf_to_rel(
            args.rel_id,
            f,
            symbol_file,
            args.rel_version,
            match_ttyd_tools=args.match_ttyd_tools,
            ignore_sections=args.ignore_sections,
        )

    with open(output_file, "wb") as f:
        f.write(dat)


if __name__ == "__main__":
    main()
