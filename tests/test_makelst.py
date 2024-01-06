from pyelf2rel.makelst import make_lst


def test_spm_core():
    name = "spm-core-2fd38f5"

    dat = make_lst(elfs=[(2, f"tests/resources/{name}.elf")])

    with open(f"tests/resources/{name}_gen.lst") as rel:
        expected = rel.read()

    assert dat == expected
