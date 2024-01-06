from pyelf2rel.elf2rel import elf_to_rel


def link_rel(module_id: int, name: str, *, match_ttyd_tools=False) -> bytes:
    with open(f"tests/resources/{name}.elf", "rb") as plf, open(
        f"tests/resources/{name}.lst"
    ) as sym:
        return elf_to_rel(module_id, plf, sym, match_ttyd_tools=match_ttyd_tools)


def test_spm_core():
    name = "spm-core-2fd38f5"
    dat = link_rel(2, name)
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes():
    name = "spm-practice-codes-b94a94a"
    dat = link_rel(0x1000, name)
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_core_match_ttyd_tools():
    name = "spm-core-2fd38f5"
    dat = link_rel(2, name, match_ttyd_tools=True)
    with open(f"tests/resources/{name}_ttydt.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_match_ttyd_tools():
    name = "spm-practice-codes-b94a94a"
    dat = link_rel(0x1000, name, match_ttyd_tools=True)
    with open(f"tests/resources/{name}_ttydt.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected
