from pyelf2rel.elf2rel import elf_to_rel


def test_spm_core():
    name = "spm-core-2fd38f5"

    with open(f"tests/resources/{name}.elf", "rb") as plf:
        dat = elf_to_rel(2, plf, f"tests/resources/{name}.lst")

    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes():
    name = "spm-practice-codes-b94a94a"

    with open(f"tests/resources/{name}.elf", "rb") as plf:
        dat = elf_to_rel(0x1000, plf, f"tests/resources/{name}.lst")

    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_core_match_elf2rel():
    name = "spm-core-2fd38f5"

    with open(f"tests/resources/{name}.elf", "rb") as plf:
        dat = elf_to_rel(2, plf, f"tests/resources/{name}.lst", match_elf2rel=True)

    with open(f"tests/resources/{name}_me2r.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_match_elf2rel():
    name = "spm-practice-codes-b94a94a"

    with open(f"tests/resources/{name}.elf", "rb") as plf:
        dat = elf_to_rel(0x1000, plf, f"tests/resources/{name}.lst", match_elf2rel=True)

    with open(f"tests/resources/{name}_me2r.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected
