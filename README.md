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

The tool provides an option for matching the API and behaviour of the ttyd-tools elf2rel tool
through the `elf2rel` command.

- For building projects requiring the `ELF2REL` environment variable, set it equal to `elf2rel`
- For building projects requiring the `TTYDTOOLS` environment variable, set it equal to either
`elf2rel ` (including the trailing space), or `elf2rel -x`

## License

`pyelf2rel` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
