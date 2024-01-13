# pyelf2rel

[![PyPI - Version](https://img.shields.io/pypi/v/pyelf2rel.svg)](https://pypi.org/project/pyelf2rel)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyelf2rel.svg)](https://pypi.org/project/pyelf2rel)

-----

**Table of Contents**

- [Installation](#installation)
- [License](#license)

## Installation

```console
pip install pyelf2rel
```

### Using in place of ttyd-tools elf2rel

The tool provides an option for matching the API and behaviour (byte-matching output) of the
ttyd-tools elf2rel tool through the `elf2rel` command.

- For building projects requiring the `ELF2REL` environment variable, set it equal to `elf2rel`
- For building projects requiring the `TTYDTOOLS` environment variable, set it equal to `elf2rel -x`

Multiple versions of the API and behaviour can be matched:
- Use `elf2rel --type modern-fork [-x]` to match the modern spm-rel-loader fork (`elf2rel-21-12-2021``)
    - This is the default
    - `elf2rel-13-6-2022` should function the same as this version other than the fact it supported
    using leading zeroes on the module id and section id without changing to octal - support for
    this quirk is not planned
- Use `elf2rel --type old-fork [-x]` to match the old spm-rel-loader fork (elf2rel-24-6-2021)
    - Notably, this brings back support for the `offset:symbol?moduleId,sectionId` syntax
    - Support for the modern LST syntax isn't disabled while using this
- Both modes are supersets of the original ttyd-tools elf2rel. When the extensions aren't used,
either mode should behave identically to the original.

## License

`pyelf2rel` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
