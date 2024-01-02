#!/usr/bin/env python3
from argparse import ArgumentParser
from collections import defaultdict
from dataclasses import dataclass
from enum import IntEnum, unique
from functools import cached_property
from io import FileIO
from struct import pack, unpack
from typing import Dict, List, Optional, Tuple

from elftools.elf.constants import SH_FLAGS, SHN_INDICES
from elftools.elf.enums import ENUM_ST_INFO_BIND
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import Section, SymbolTableSection


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


@dataclass
class Relocation:
    """pyelftools relocation substitute"""

    r_offset: int
    r_info_sym: int
    r_info_type: int
    r_addend: int


def read_relocs(f: FileIO, rela: RelocationSection) -> List["Relocation"]:
    """Loads relocations from a rela section in an ELF file"""

    # Iterate relocations
    relocs = []
    for i in range(rela.num_relocations()):
        # Read in reloc bytes
        f.seek(rela._offset + (i * rela.entry_size))
        dat = f.read(rela.entry_size)

        # Parse bytes
        r_offset, r_info, r_addend = unpack(">IIi", dat)
        r_info_sym = r_info >> 8
        r_info_type = r_info & 0xff
        rel = Relocation(r_offset, r_info_sym, r_info_type, r_addend)

        # Add to output
        relocs.append(rel)

    return relocs


###############
# LST Loading #
###############


@dataclass
class RelSymbol:
    """Container for a symbol in a rel file"""

    module_id: int
    section_id: int
    offset: int
    name: str


def load_lst(filename: str) -> Dict[str, RelSymbol]:
    """Parses an LST symbol map"""

    # Load LST
    with open(filename) as f:
        lines = f.readlines()

    # Parse lines
    symbols = {}
    for i, line in enumerate(lines):
        # Ignore comments and whitespace
        line = line.strip()
        if line.startswith("/") or len(line) == 0:
            continue

        # Try parse
        try:
            # Dol - addr:name
            # Rel - moduleId,sectionId,offset:name
            colon_parts = [s.strip() for s in line.split(":")]
            other, name = colon_parts
            comma_parts = [s.strip() for s in other.split(',')]
            if len(comma_parts) == 1:
                addr = comma_parts[0]
                symbols[name] = RelSymbol(
                    0,
                    0,
                    int(addr, 16),
                    name
                )
            else:
                module_id, section_id, offset = comma_parts
                symbols[name] = RelSymbol(
                    int(module_id, 0),
                    int(section_id, 0),
                    int(offset, 16),
                    name
                )
        except Exception as e:
            raise Exception(f"Error on line {i+1}: {e}")

    return symbols


##############
# Conversion #
##############


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


@dataclass
class RelReloc:
    """Container for one relocation"""

    target_module: int
    offset: int
    t: RelType
    section: int
    addend: int

    def to_binary(self, relative_offset: int) -> bytes:
        """Gets the binary representation of the relocation"""

        return RelReloc.encode_reloc(relative_offset, self.t, self.section, self.addend)

    @staticmethod
    def encode_reloc(relative_offset: int, t: RelType, section: int, addend: int):
        return pack(">HBBI", relative_offset, t, section, addend)


@dataclass
class RELHeader:
    id: int # u32
    next: int # u32
    prev: int # u32
    num_sections: int # u32
    section_info_offset: int # u32
    name_offset: int # u32
    name_size: int # u32
    version: int # u32
    bss_size: int # u32
    rel_offset: int # u32
    imp_offset: int # u32
    imp_size: int # u32
    prolog_section: int # u8
    epilog_section: int # u8
    unresolved_section: int # u8
    bss_section: int # u8
    prolog: int # u32
    epilog: int # u32
    unresolved: int # u32

    # v2 
    align: Optional[int] # u32
    bss_align: Optional[int] # u32

    # v3
    fix_size: Optional[int] # u32

    def to_binary(self) -> bytes:
        dat = pack(
            ">12I4B3I",
            self.id,
            self.next,
            self.prev,
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

        if self.version >= 2:
            dat += pack(
                ">2I",
                self.align,
                self.bss_align,
            )

        if self.version >= 3:
            dat += pack(">I", self.fix_size)
        
        return dat

    @staticmethod
    def binary_size(version: int) -> int:
        size = 0x40

        if version >= 2:
            size += 8

        if version >= 3:
            size += 4

        return size


class Context:
    version: int
    match_elf2rel: bool
    module_id: int
    file: FileIO
    plf: ELFFile
    symbols: Dict[str, Symbol]
    symbols_id: Dict[int, Symbol]
    lst_symbols: Dict[str, RelSymbol]

    def __init__(self, version: int, module_id: int, elf_path: str, lst_path: str,
                 match_elf2rel: bool):
        self.version = version
        self.match_elf2rel = match_elf2rel
        self.module_id = module_id
        self.file = open(elf_path, 'rb')
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
        assert sym.name in ctx.lst_symbols, f"Symbol {sym.name} not found"
        return ctx.lst_symbols[sym.name]
    else:
        # Symbol in this rel
        return RelSymbol(ctx.module_id, sec, sym.st_value, sym.name)


@dataclass
class BinarySection:
    sec_id: int
    header: Section
    contents: bytes
    runtime_relocs: List[RelReloc]
    static_relocs: List[RelReloc]


elf2rel_section_mask = [
    ".init",
	".text",
	".ctors",
	".dtors",
	".rodata",
	".data",
	".bss",
]


def should_include_section(ctx: Context, sec_id: int, ignore_sections: List[str]) -> bool:
    section = ctx.plf.get_section(sec_id)

    if section.name in ignore_sections:
        return False

    if ctx.match_elf2rel:
        return any(
            section.name == val or section.name.startswith(val + '.')
            for val in elf2rel_section_mask
        )
    else:
        return (
            section["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")
            and section["sh_flags"] & SH_FLAGS.SHF_ALLOC != 0
        )


def parse_section(ctx: Context, sec_id: int) -> BinarySection:
    """Create the binary data and relocation list for a section"""

    # Get section
    sec = ctx.plf.get_section(sec_id)

    # Check for BSS
    if sec["sh_type"] != "SHT_PROGBITS":
        return BinarySection(sec_id, sec, b"", [], [])

    # Get relocations
    rela: RelocationSection = ctx.plf.get_section_by_name('.rela' + sec.name)

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
        if t in (RelType.REL24, RelType.REL32):
            if (
                target.module_id == ctx.module_id and
                (ctx.match_elf2rel or sec_id == target.section_id)
            ):
                skip_runtime = True

        rel_reloc = RelReloc(
            target.module_id, offs, t, target.section_id, target_offset
        )
        if skip_runtime:
            static_relocs.append(rel_reloc)
        else:
            # TODO: other relocations are supported at runtime
            assert t in (
                RelType.ADDR32, RelType.ADDR16_LO, RelType.ADDR16_HI, RelType.ADDR16_HA,
                RelType.REL24, RelType.REL14, RelType.REL32
            ), f"Unsupported relocation type {t}"

            runtime_relocs.append(rel_reloc)

    return BinarySection(sec_id, sec, dat, runtime_relocs, static_relocs)


def align_to(offs: int, align: int) -> Tuple[int, int]:
    """Aligns an offset and gets the padding required"""

    mask = align - 1

    new_offs = (offs + mask) & ~mask

    padding = new_offs - offs

    return new_offs, padding


def align_to_elf2rel(offs: int, align: int) -> Tuple[int, int]:
    padding = align - (offs % align)

    new_offs = offs + padding

    return new_offs, padding

def build_section_contents(ctx: Context, file_pos: int, sections: List[BinarySection]
                           ) -> Tuple[int, bytes, Dict[int, int]]:
    dat = bytearray()
    offsets = {}
    internal_offsets = {}
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
        # Get instruction
        offs = internal_offsets[sec_id] + offset
        instr = int.from_bytes(dat[offs:offs+4], 'big')

        # Apply delta
        delta = (target + internal_offsets[target_sec_id]) - (offset + internal_offsets[sec_id])
        if t == RelType.REL32:
            instr = delta & 0xffff_ffff
        else: # Rel24
            instr |= delta & (0x3ff_fffc)

        # Write new instruction
        dat[offs:offs+4] = int.to_bytes(instr, 4, 'big')


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
                    early_relocate(reloc.t, sec.sec_id, reloc.offset, unresolved.st_shndx, unresolved.st_value)

    return file_pos, bytes(dat), offsets


@dataclass
class RelSectionInfo:
    offset: int
    length: int
    executable: bool

    def to_binary(self) -> bytes:
        mask = 1 if self.executable else 0
        return pack(">2I", self.offset | mask, self.length)
    
    @staticmethod
    def binary_size(length: int) -> int:
        return length * 8


def build_section_info(sections: List[Optional[BinarySection]], offsets: Dict[int, int]) -> bytes:
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


def make_section_relocations(section: BinarySection) -> Dict[int, bytes]:
    """Creates the binary data for a secton's relocations"""

    # Get modules referenced
    modules = {r.target_module for r in section.runtime_relocs}
    
    # Make data for modules
    ret = {}
    for module in modules:
        # Get relevant relocs and sort them by offset
        filtered_relocs = sorted(
            [r for r in section.runtime_relocs if r.target_module == module],
            key=lambda r: r.offset
        )

        # Convert relocs to binary
        dat = bytearray()
        dat.extend(RelReloc.encode_reloc(0, RelType.RVL_SECT, section.sec_id, 0))
        offs = 0
        for rel in filtered_relocs:
            # Calculate delta
            delta = rel.offset - offs

            # Use nops to get delta in range
            while delta > 0xffff:
                dat.extend(RelReloc.encode_reloc(0xffff, RelType.RVL_NONE, 0, 0))
                delta -= 0xffff
            
            # Convert to binary
            dat.extend(rel.to_binary(delta))

            # Move to offset
            offs = rel.offset

        # Add to output
        ret[module] = bytes(dat)

    return ret


@dataclass
class ModuleRelocs:
    module_id: int
    relocs: bytes


def group_module_relocations(ctx, section_relocs: List[Dict[int, bytes]]) -> List[ModuleRelocs]:
    ret = defaultdict(bytearray)
    for section in section_relocs:
        for module, relocs in section.items():
            ret[module].extend(relocs)
    for module, relocs in ret.items():
        relocs.extend(RelReloc.encode_reloc(0, RelType.RVL_STOP, 0, 0))
    
    base = max(ret.keys())
    if ctx.match_elf2rel:
        def module_key(module):
            if module in (0, ctx.module_id):
                return base + module
            else:
                return module
    elif ctx.version >= 3:
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

    modules = sorted(ret.keys(), key=module_key)

    return [ModuleRelocs(module, ret[module]) for module in modules]


@dataclass
class RelImp:
    module_id: int
    offset: int

    def to_binary(self) -> bytes:
        return pack(">2I", self.module_id, self.offset)


def build_relocations(ctx: Context, file_pos: int, module_relocs: List[ModuleRelocs]
                      ) -> Tuple[int, int, int, int, int, bytes]:

    imp_size = len(module_relocs) * 8

    pre_pad = 0
    if ctx.version >= 3 or ctx.match_elf2rel:
        if ctx.match_elf2rel:
            file_pos, pre_pad = align_to_elf2rel(file_pos, 8)
        imp_offset = file_pos
        file_pos += imp_size
    else:
        imp_offset = None

    rel_dat = bytearray()
    imp_dat = bytearray()
    reloc_offset = file_pos
    fix_size = file_pos
    for module in module_relocs:
        imp = RelImp(module.module_id, file_pos)
        imp_dat.extend(imp.to_binary())

        rel_dat.extend(module.relocs)
        file_pos += len(module.relocs)

        if module.module_id not in (0, ctx.module_id):
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


def build_imp(rel_offsets: Dict[int, int]):
    dat = bytearray()
    for module, offset in rel_offsets.items():
        imp = RelImp(module, offset)
        dat.extend(imp.to_binary())
    
    return dat


def elf_to_rel(module_id: int, elf_path: str, lst_path: str, version: int = 3,
               match_elf2rel: bool = False, ignore_sections: Optional[List[str]] = None) -> bytes:
    ctx = Context(version, module_id, elf_path, lst_path, match_elf2rel)

    if ignore_sections is None:
        ignore_sections = []

    # Give space for header
    file_pos = RELHeader.binary_size(version)
    section_info_offset = file_pos

    # Parse sections
    all_sections = [
        parse_section(ctx, sec_id)
        if should_include_section(ctx, sec_id, ignore_sections)
        else None
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
    module_relocs = group_module_relocations(ctx, section_relocs)
    
    # Build reloc contents
    file_pos, reloc_offset, imp_offset, imp_size, fix_size, reloc_dat = \
        build_relocations(ctx, file_pos, module_relocs)

    # Find bss section
    bss_sections = [
        sec for sec in sections
        if sec.header["sh_type"] == "SHT_NOBITS"
    ]
    if ctx.match_elf2rel:
        bss_size = sum(s.header["sh_size"] for s in bss_sections)
    else:
        assert len(bss_sections) <= 1, f"Multiple bss sections not supported"
        if len(bss_sections) > 0:
            bss_size = bss_sections[0].header["sh_size"]
        else:
            bss_size = 0

    # Calculate alignment
    if version >= 2:
        align = max(
            sec.header["sh_addralign"] for sec in sections
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

    header = RELHeader(
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

    dat = bytearray()
    dat.extend(header.to_binary())
    dat.extend(section_info)
    dat.extend(section_contents)
    dat.extend(reloc_dat)
    
    return bytes(dat)

if __name__ == '__main__':
    parser = ArgumentParser()

    # Positional API - boost::program_options behaves differently to argparse
    parser.add_argument("positionals", type=str, nargs='*')

    # Non-positional API
    parser.add_argument("--input-file", "-i", type=str)
    parser.add_argument("--symbol-file", "-s", type=str)
    parser.add_argument("--output-file", "-o", type=str)

    # Optional
    parser.add_argument("--rel-id", type=lambda x: int(x, 0), default=0x1000)
    parser.add_argument("--rel-version", type=int, default=3)
    parser.add_argument("--match-elf2rel", action='store_true')
    parser.add_argument("--ignore-sections", nargs='+', default=[])

    args = parser.parse_args()

    positionals = list(args.positionals)

    if len(positionals) > 0:
        input_file = positionals.pop(0)
    else:
        assert args.input_file is not None, f"input-file is required"
        input_file = args.input_file

    if len(positionals) > 0:
        symbol_file = positionals.pop(0)
    else:
        assert args.symbol_file is not None, f"symbol-file is required"
        symbol_file = args.symbol_file

    if len(positionals) > 0:
        output_file = positionals.pop(0)
    elif args.output_file is not None:
        output_file = args.output_file
    else:
        output_file = input_file.removesuffix(".elf") + ".rel"

    with open(output_file, 'wb') as f:
        dat = elf_to_rel(args.rel_id, input_file, symbol_file, args.rel_version,
                         args.match_elf2rel, args.ignore_sections)
        f.write(dat)
