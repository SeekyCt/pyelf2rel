from typing import Iterable


class DuplicateSymbolError(Exception):
    def __init__(self, symbols: Iterable[str]):
        sym_str = ", ".join(symbols)
        super().__init__(f"Duplicate symbol(s): {sym_str}")


class LSTFormatError(Exception):
    def __init__(self, line: int, exception: str):
        super().__init__(f"Error on line {line+1}: {exception}")


class MissingSymbolError(Exception):
    def __init__(self, symbol: str):
        super().__init__(f"Missing symbol {symbol}")


class UnsupportedRelocationError(Exception):
    def __init__(self, reloc_type: int):
        super().__init__(f"Unsupported relocation type {reloc_type}")
