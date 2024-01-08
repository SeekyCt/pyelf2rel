from pyelf2rel.elf2rel import ElfToRelBehaviour, elf_to_rel


def link_rel(module_id: int, name: str, **kwargs) -> bytes:
    with open(f"tests/resources/{name}.elf", "rb") as plf, open(
        f"tests/resources/{name}.lst"
    ) as sym:
        return elf_to_rel(module_id, plf, sym, **kwargs)


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


def test_spm_core_modern_ttyd_tools():
    name = "spm-core-2fd38f5"
    dat = link_rel(2, name, behaviour=ElfToRelBehaviour.MODERN_FORK)
    with open(f"tests/resources/{name}_ttydt.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_match_ttyd_tools():
    name = "spm-practice-codes-b94a94a"
    dat = link_rel(0x1000, name, behaviour=ElfToRelBehaviour.MODERN_FORK)
    with open(f"tests/resources/{name}_ttydt.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_old_rel_lst():
    name = "spm-practice-codes-9f3765a"
    dat = link_rel(
        0x1000,
        name,
        behaviour=ElfToRelBehaviour.OLD_FORK,
    )
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_ttyd_tools():
    name = "spm-practice-codes-642167b"
    dat = link_rel(0x1000, name, behaviour=ElfToRelBehaviour.MODERN_FORK)
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected
