from __future__ import annotations

from pyelf2rel.error import LSTColonError, LSTCommaError, LSTFormatError
from pyelf2rel.rel import RelSymbol


def encode_lst_symbol(sym: RelSymbol) -> str:
    if sym.module_id == 0:
        return f"{sym.offset:08x}:{sym.name}"
    else:
        return f"{sym.module_id},{sym.section_id},{sym.offset:08x}:{sym.name}"


def encode_lst(symbols: list[RelSymbol]) -> str:
    """Creates an LST map of a list of symbols"""

    return "\n".join(encode_lst_symbol(s) for s in symbols)


def load_lst_symbol(line: str) -> tuple[str, RelSymbol]:
    # Try parse
    # Dol - addr:name
    # Rel - moduleId,sectionId,offset:name
    colon_parts = [s.strip() for s in line.split(":")]
    try:
        other, name = colon_parts
    except ValueError as e:
        raise LSTColonError from e
    comma_parts = [s.strip() for s in other.split(",")]
    if len(comma_parts) == 1:
        # Dol
        addr = comma_parts[0]
        try:
            return name, RelSymbol(0, 0, int(addr, 16), name)
        except ValueError as e:
            raise LSTFormatError(str(e)) from e
    else:
        # Rel
        try:
            module_id, section_id, offset = comma_parts
        except ValueError as e:
            raise LSTCommaError from e

        try:
            return name, RelSymbol(int(module_id, 0), int(section_id, 0), int(offset, 16), name)
        except ValueError as e:
            raise LSTFormatError(str(e)) from e


def load_lst(txt: str) -> dict[str, RelSymbol]:
    """Parses an LST symbol map"""

    # Parse lines
    symbols = {}
    for i, line in enumerate(txt.splitlines()):
        # Ignore comments and whitespace
        strip = line.strip()
        if strip.startswith("/") or len(strip) == 0:
            continue

        try:
            name, sym = load_lst_symbol(strip)
            symbols[name] = sym
        except LSTFormatError as e:
            e.add_note(f"On line {i+1}")
            raise

    return symbols
