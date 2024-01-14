from io import StringIO

from pyelf2rel.makelst import main


def build_lst(argv: str) -> str:
    """Run makelst with given arguments"""

    out = StringIO()
    main(argv.split(), out)

    out.seek(0)
    return out.read()


def test_spm_core():
    """Test that the export LST for spm-core matches previous pyelf2rel commits"""

    name = "spm-core-2fd38f5"

    dat = build_lst(f"--elf 2 tests/resources/{name}.elf")

    with open(f"tests/resources/{name}_gen.lst") as lst:
        expected = lst.read()

    assert dat == expected
