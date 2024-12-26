"""
Project-specific errors
"""

from __future__ import annotations

from typing import Iterable


class DuplicateSymbolError(Exception):
    """Global symbol defined in multiple locations"""

    def __init__(self, symbols: Iterable[str]):
        sym_str = ", ".join(symbols)
        super().__init__(f"Duplicate symbol(s): {sym_str}")


class LSTFormatError(Exception):
    """LST file is formatted incorrectly"""

    def __init__(self, exception: str, line_num: int | None):
        line = f" on line {line_num}" if line_num else ""
        super().__init__(f"LST format error{line}: {exception}")


class LSTColonError(LSTFormatError):
    """A line of an LST has too many colons"""

    def __init__(self, line_num: int | None):
        super().__init__("Expected exactly 1 colon", line_num)


class LSTQMarkError(LSTFormatError):
    """A line of an LST has too many colons"""

    def __init__(self, line_num: int | None):
        super().__init__("Expected exactly 1 question mark", line_num)


class LSTCommaError(LSTFormatError):
    """A line of an LST has the wrong number of commas"""

    def __init__(self, line_num: int | None):
        super().__init__("Expected 1 or 3 commas before colon", line_num)


class MissingSymbolError(Exception):
    """A required symbol was not defined"""

    symbol: str

    def __init__(self, symbol: str):
        super().__init__(f"Missing symbol {symbol}")
        self.symbol = symbol


class MissingSymbolsError(Exception):
    """A required symbol was not defined"""

    symbols: set[str]

    def __init__(self, symbols: set[str]):
        super().__init__(f"Missing {len(symbols)} symbols: {', '.join(sorted(symbols))}")


class UnsupportedRelocationError(Exception):
    """An unsupported relocation type was used"""

    def __init__(self, reloc_type: str):
        super().__init__(f"Unsupported relocation type {reloc_type}")
