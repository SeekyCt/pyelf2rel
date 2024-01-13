import os
from tempfile import TemporaryDirectory

from pyelf2rel.elf2rel import main


def link_rel(module_id: int, in_name: str, argv: str = "", *, ttyd_tools: bool = False) -> bytes:
    """Helper to build a rel with a specifc setup"""

    with TemporaryDirectory() as d:
        out_path = os.path.join(d, f"{in_name}.elf")

        main(
            [
                f"tests/resources/{in_name}.elf",
                f"tests/resources/{in_name}.lst",
                out_path,
                "--rel-id",
                str(module_id),
                *argv.split(),
            ],
            ttyd_tools=ttyd_tools,
        )

        with open(out_path, "rb") as f:
            return f.read()


def test_spm_core():
    """Test that spm-core links the same way as in previous pyelf2rel commits"""

    name = "spm-core-2fd38f5"
    dat = link_rel(2, name)
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_core_modern_fork():
    """Tests that spm-core links the same way as in the modern spm-rel-loader elf2rel fork"""

    name = "spm-core-2fd38f5"
    dat = link_rel(2, name, ttyd_tools=True)
    with open(f"tests/resources/{name}_modern.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes():
    """Test that spm-practice-codes links the same way as in previous pyelf2rel commits"""

    name = "spm-practice-codes-3974b24"
    dat = link_rel(0x1000, name)
    with open(f"tests/resources/{name}.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_modern_fork():
    """Tests that spm-practice-codes links the same way as in the modern spm-rel-loader elf2rel
    fork"""

    name = "spm-practice-codes-3974b24"
    dat = link_rel(0x1000, name, ttyd_tools=True)
    with open(f"tests/resources/{name}_modern.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_old_fork():
    """Tests that an old spm-practice-codes commit links the same way as in the old spm-rel-loader
    elf2rel fork"""

    name = "spm-practice-codes-9f3765a"
    dat = link_rel(
        0x1000,
        name,
        "--old-fork",
        ttyd_tools=True,
    )
    with open(f"tests/resources/{name}_old.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected


def test_spm_practice_codes_ttyd_tools():
    """Tests that an old spm-practice-codes commit links the same way as in the original ttyd-tools
    elf2rel

    The LST makes no use of the fork extensions, so the modern fork mdode should behave identically
    to ttyd-tools under these conditions"""

    name = "spm-practice-codes-642167b"
    dat = link_rel(0x1000, name, ttyd_tools=True)
    with open(f"tests/resources/{name}_ttydt.rel", "rb") as rel:
        expected = rel.read()

    assert dat == expected
