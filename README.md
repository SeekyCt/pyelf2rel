# pyelf2rel

[![PyPI - Version](https://img.shields.io/pypi/v/pyelf2rel.svg)](https://pypi.org/project/pyelf2rel)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyelf2rel.svg)](https://pypi.org/project/pyelf2rel)

-----

**Table of Contents**

- [About](#about)
- [Installation](#installation)
- [License](#license)

## About

pyelf2rel is a tool / library for creation of files in Nintendo's GameCube/Wii REL format.

### Alternatives

- [ttyd-tools](https://github.com/PistonMiner/ttyd-tools/tree/master/ttyd-tools) has a C++
implementation of ELF to REL conversion.
    - This doesn't support linking against other REL files, though there is 
    [a fork](https://github.com/SeekyCt/spm-rel-loader/tree/e2r-rel-link) that does.
    - This tool tends to have better performance than pyelf2rel, though in practice the difference
    seems to be negligible
    - pyelf2rel can be configured to behave the same way as this tool (see
    [below](#using-in-place-of-ttyd-tools-elf2rel))
- [ppcdis](https://github.com/SeekyCt/ppcdis) has a more specialised python implementation of the
conversion designed for matching decompilation.
    - pyelf2rel is based off of this implementation and is more friendly for general use

### Why make another elf2rel implementation?
- ttyd-tools is a bit awkward to build, requiring Visual Studio (or manual setup on Linux) and Boost
- Some legacy code requires specific fork builds of ttyd-tools elf2rel to work, all of those are
supported by pyelf2rel
- Upstream support for linking against other rels
- Redirection of unlinked branches to _unresolved
- Control over which sections to include and strip
- This is easier to customise for projects to extend the format
    - Some kind of built-in metadata extension may be coming at some point

### makelst

Also included is the makelst tool, which can generate LST symbol maps based on global symbols in ELFs
and existing LSTs, for use with this or ttyd-tools elf2rel.


## Installation

Run the following command to install the package.

```console
pip install pyelf2rel
```

You will now have access to the `pyelf2rel`, `elf2rel` and `makelst` commands.
Use each with `-h` for more information.

### Using in place of ttyd-tools elf2rel

The tool provides an option for matching the API and behaviour (byte-matching output) of the
ttyd-tools elf2rel tool through the `elf2rel` command.

- For building projects requiring the `ELF2REL` environment variable, set it equal to `elf2rel`
- For building projects requiring the `TTYDTOOLS` environment variable, set it equal to `elf2rel -x`

Multiple versions of the API and behaviour can be matched:
- Use `elf2rel [-x]` to match the modern spm-rel-loader fork (`elf2rel-21-12-2021`)
    - `elf2rel-13-6-2022` should function the same as this version other than the fact it supported
    using leading zeroes on the module id and section id without changing to octal - support for
    this quirk is not planned
- Use `elf2rel --old-fork [-x]` to match the old spm-rel-loader fork (`elf2rel-24-6-2021`)
    - Notably, this includes support for the `offset:symbol?moduleId,sectionId` syntax
    - Like in the old fork, fixed linking is unsafe for rels produced by this
    - Support for the modern LST syntax isn't disabled while using this
- Both modes are supersets of the original ttyd-tools elf2rel. When the extensions aren't used,
either mode should behave identically to the original.

## License

`pyelf2rel` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
