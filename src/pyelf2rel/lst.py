"""
    LST symbol map loading and encoding
"""

from __future__ import annotations

from pyelf2rel.error import LSTColonError, LSTCommaError, LSTFormatError
from pyelf2rel.rel import RelSymbol


def dump_lst_symbol(sym: RelSymbol) -> str:
    """Converts a symbol to a line of LST"""

    if sym.module_id == 0:
        return f"{sym.offset:08x}:{sym.name}"
    else:
        return f"{sym.module_id},{sym.section_id},{sym.offset:08x}:{sym.name}"


def dump_lst(symbols: list[RelSymbol]) -> str:
    """Creates an LST map of a list of symbols"""

    return "\n".join(dump_lst_symbol(s) for s in symbols)


def load_lst_symbol(line: str, line_num: int | None = None) -> RelSymbol:
    """Loads a symbol from a line of an LST"""

    # Try parse
    # Dol - addr:name
    # Rel - moduleId,sectionId,offset:name
    colon_parts = [s.strip() for s in line.split(":")]
    try:
        other, name = colon_parts
    except ValueError as e:
        raise LSTColonError(line_num) from e
    comma_parts = [s.strip() for s in other.split(",")]
    if len(comma_parts) == 1:
        # Dol
        addr = comma_parts[0]
        try:
            return RelSymbol(0, 0, int(addr, 16), name)
        except ValueError as e:
            raise LSTFormatError(str(e), line_num) from e
    else:
        # Rel
        try:
            module_id, section_id, offset = comma_parts
        except ValueError as e:
            raise LSTCommaError(line_num) from e

        try:
            return RelSymbol(int(module_id, 0), int(section_id, 0), int(offset, 16), name)
        except ValueError as e:
            raise LSTFormatError(str(e), line_num) from e


def load_lst(txt: str) -> list[RelSymbol]:
    """Parses an LST symbol map"""

    ret = []
    for i, line in enumerate(txt.splitlines()):
        # Ignore comments and whitespace
        strip = line.strip()
        if strip.startswith("/") or len(strip) == 0:
            continue

        ret.append(load_lst_symbol(strip, i + 1))

    return ret
