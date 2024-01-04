#!/usr/bin/env python3
from __future__ import annotations

from argparse import ArgumentError, ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum, unique
from functools import cached_property
from struct import pack, unpack
from typing import TYPE_CHECKING

from elftools.elf.constants import SH_FLAGS, SHN_INDICES
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_ST_INFO_BIND

if TYPE_CHECKING:
    from typing import BinaryIO

    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import Section, SymbolTableSection

###########
# Utility #
###########


class MultipleBSSError(Exception):
    def __init__(self):
        super().__init__("Multiple bss sections not supported")


class LSTFormatError(Exception):
    def __init__(self, line: int, exception: str):
        super().__init__(f"Error on line {line+1}: {exception}")


class DuplicateSymbolError(Exception):
    def __init__(self, symbol: str):
        super().__init__(f"Duplicate symbol {symbol}")


class MissingSymbolError(Exception):
    def __init__(self, symbol: str):
        super().__init__(f"Missing symbol {symbol}")


class UnsupportedRelocationError(Exception):
    def __init__(self, reloc_type: int):
        super().__init__(f"Unsupported relocation type {reloc_type}")


def align_to(offs: int, align: int) -> tuple[int, int]:
    """Aligns an offset and gets the padding required"""

    mask = align - 1

    new_offs = (offs + mask) & ~mask

    padding = new_offs - offs

    return new_offs, padding


def align_to_elf2rel(offs: int, align: int) -> tuple[int, int]:
    """Variant of align_to where padding of 0 changes to padding of n instead"""

    padding = align - (offs % align)

    new_offs = offs + padding

    return new_offs, padding


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


#############
# Rel Types #
#############


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


###############
# LST Loading #
###############


def load_lst(filename: str) -> dict[str, RelSymbol]:
    """Parses an LST symbol map"""

    # Load LST
    with open(filename) as f:
        lines = f.readlines()

    # Parse lines
    symbols = {}
    for i, full_line in enumerate(lines):
        # Ignore comments and whitespace
        line = full_line.strip()
        if line.startswith("/") or len(line) == 0:
            continue

        # Try parse
        # Dol - addr:name
        # Rel - moduleId,sectionId,offset:name
        colon_parts = [s.strip() for s in line.split(":")]
        try:
            other, name = colon_parts
        except ValueError as e:
            raise LSTFormatError(i, "Expected exactly 1 colon") from e
        comma_parts = [s.strip() for s in other.split(",")]
        if len(comma_parts) == 1:
            addr = comma_parts[0]
            try:
                symbols[name] = RelSymbol(0, 0, int(addr, 16), name)
            except ValueError as e:
                raise LSTFormatError(i, str(e)) from e
        else:
            try:
                module_id, section_id, offset = comma_parts
            except ValueError as e:
                raise LSTFormatError(i, "Expected 1 or 3 commas before colon") from e
            try:
                symbols[name] = RelSymbol(
                    int(module_id, 0), int(section_id, 0), int(offset, 16), name
                )
            except ValueError as e:
                raise LSTFormatError(i, str(e)) from e

    return symbols


##############
# Conversion #
##############


class Context:
    """Utility struct for passing common data between the conversion functions"""

    version: int
    match_elf2rel: bool
    module_id: int
    file: BinaryIO
    plf: ELFFile
    symbols: dict[str, Symbol]
    symbols_id: dict[int, Symbol]
    lst_symbols: dict[str, RelSymbol]

    def __init__(
        self, version: int, module_id: int, file: BinaryIO, lst_path: str, *, match_elf2rel: bool
    ):
        self.version = version
        self.match_elf2rel = match_elf2rel
        self.module_id = module_id
        self.file = file
        self.plf = ELFFile(self.file)
        self.symbols, self.symbols_id = map_symbols(self.file, self.plf)
        self.lst_symbols = load_lst(lst_path)


def find_symbol(ctx: Context, sym_id: int) -> RelSymbol:
    """Finds a symbol by id"""

    # Get symbol
    sym = ctx.symbols_id[sym_id]

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


elf2rel_section_mask = [
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

    if ctx.match_elf2rel:
        return any(
            section.name == val or section.name.startswith(val + ".")
            for val in elf2rel_section_mask
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
            and (ctx.match_elf2rel or sec_id == target.section_id)
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
    """Create the linked binary data for the sections"""

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
    if not ctx.match_elf2rel:
        unresolved = ctx.symbols["_unresolved"]
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
    """Creates the binary data for a section's relocations"""

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
    ret = defaultdict(bytearray)
    for section in section_relocs:
        for module, relocs in section.items():
            ret[module].extend(relocs)
    for relocs in ret.values():
        relocs.extend(RelReloc.encode_reloc(0, RelType.RVL_STOP, 0, 0))

    return dict(ret)


def build_relocations(
    ctx: Context, file_pos: int, module_relocs: dict[int, bytes]
) -> tuple[int, int, int, int, int, bytes]:
    """Builds the linked relocation and imp tables

    Returns new file position, relocations offset, imp table offset, imp table size, fix size,
    and the combined tables binary"""

    # Get table size
    imp_size = len(module_relocs) * 8

    # Place imp before relocations if needed
    pre_pad = 0
    if ctx.version >= RelHeader.FIX_SIZE_MIN_VER or ctx.match_elf2rel:
        # elf2rel aligns this to 8 bytes, and rounds up 0-length padding
        if ctx.match_elf2rel:
            file_pos, pre_pad = align_to_elf2rel(file_pos, 8)

        imp_offset = file_pos
        file_pos += imp_size
    else:
        imp_offset = None

    # Sort reloc groups
    base = max(module_relocs.keys())
    if ctx.match_elf2rel:

        def module_key(module):
            if module in (0, ctx.module_id):
                return base + module
            else:
                return module
    elif ctx.version >= RelHeader.FIX_SIZE_MIN_VER:

        def module_key(module):
            # Put self second last
            if module == ctx.module_id:
                return base + 1
            # Put dol last
            if module == 0:
                return base + 2
            # Put others in order of module id
            return module
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

    return file_pos, reloc_offset, imp_offset, imp_size, fix_size, dat


def elf_to_rel(
    module_id: int,
    file: BinaryIO,
    lst_path: str,
    version: int = 3,
    *,
    match_elf2rel: bool = False,
    ignore_sections: list[str] | None = None,
) -> bytes:
    """Converts a partially linked elf file into a rel file"""

    # Setup default parameters
    if ignore_sections is None:
        ignore_sections = []

    # Build context
    ctx = Context(version, module_id, file, lst_path, match_elf2rel=match_elf2rel)

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
    file_pos, reloc_offset, imp_offset, imp_size, fix_size, reloc_dat = build_relocations(
        ctx, file_pos, module_relocs
    )

    # Find bss section
    bss_sections = [sec for sec in sections if sec.header["sh_type"] == "SHT_NOBITS"]
    if ctx.match_elf2rel:
        bss_size = sum(s.header["sh_size"] for s in bss_sections)
    else:
        if len(bss_sections) > 1:
            raise MultipleBSSError
        bss_size = bss_sections[0].header["sh_size"] if len(bss_sections) > 0 else 0

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
    prolog = ctx.symbols["_prolog"]
    epilog = ctx.symbols["_epilog"]
    unresolved = ctx.symbols["_unresolved"]

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
        reloc_offset,
        imp_offset,
        imp_size,
        prolog.st_shndx,
        epilog.st_shndx,
        unresolved.st_shndx,
        0,
        prolog.st_value,
        epilog.st_value,
        unresolved.st_value,
        align,
        bss_align,
        fix_size,
    )

    # Build full binary
    dat = bytearray()
    dat.extend(header.to_binary())
    dat.extend(section_info)
    dat.extend(section_contents)
    dat.extend(reloc_dat)

    return bytes(dat)


def elf2rel_main():
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
    parser.add_argument("--match-elf2rel", action="store_true")
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
            match_elf2rel=args.match_elf2rel,
            ignore_sections=args.ignore_sections,
        )

    with open(output_file, "wb") as f:
        f.write(dat)


if __name__ == "__main__":
    elf2rel_main()
