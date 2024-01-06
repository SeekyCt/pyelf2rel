from typing import Iterable


class DuplicateSymbolError(Exception):
    def __init__(self, symbols: Iterable[str]):
        sym_str = ", ".join(symbols)
        super().__init__(f"Duplicate symbol(s): {sym_str}")


class LSTFormatError(Exception):
    def __init__(self, exception: str):
        super().__init__(f"LST format error: {exception}")


class LSTColonError(LSTFormatError):
    def __init__(self):
        super().__init__("Expected exactly 1 colon")


class LSTCommaError(LSTFormatError):
    def __init__(self):
        super().__init__("Expected 1 or 3 commas before colon")


class MissingSymbolError(Exception):
    def __init__(self, symbol: str):
        super().__init__(f"Missing symbol {symbol}")


class UnsupportedRelocationError(Exception):
    def __init__(self, reloc_type: int):
        super().__init__(f"Unsupported relocation type {reloc_type}")
