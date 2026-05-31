from __future__ import annotations

import os
import struct
import subprocess

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2 import Patcherex
from patcherex2.components.binfmt_tools.elf import pack_rel_entry

R_X86_64_RELATIVE = 8

_PACK_CASES = {
    "32rel_le": (
        dict(
            mem_offset=0x12345678,
            r_info_value=8,
            is_64=False,
            is_le=True,
            is_rela=False,
        ),
        "7856341208000000",
    ),
    "32rel_be": (
        dict(
            mem_offset=0x12345678,
            r_info_value=8,
            is_64=False,
            is_le=False,
            is_rela=False,
        ),
        "1234567800000008",
    ),
    "64rela_ppc64": (
        dict(
            mem_offset=0xCAFEBABE_DEADBEEF,
            r_info_value=22,
            is_64=True,
            is_le=True,
            is_rela=True,
            addend=0x12345678,
        ),
        "efbeaddebebafeca16000000000000007856341200000000",
    ),
    "mips64_le": (
        dict(
            mem_offset=0x33558,
            r_info_value=0x1203,
            is_64=True,
            is_le=True,
            is_rela=False,
            is_mips64=True,
        ),
        "58350300000000000000000000001203",
    ),
    "mips64_be": (
        dict(
            mem_offset=0x33558,
            r_info_value=0x1203,
            is_64=True,
            is_le=False,
            is_rela=False,
            is_mips64=True,
        ),
        "00000000000335580000000000001203",
    ),
    "64rel_no_addend": (
        dict(mem_offset=0x100, r_info_value=8, is_64=True, is_le=True, is_rela=False),
        "00010000000000000800000000000000",
    ),
}


@pytest.mark.parametrize("kwargs,expected", _PACK_CASES.values(), ids=list(_PACK_CASES))
def test_pack_rel_entry(kwargs, expected):
    assert pack_rel_entry(**kwargs).hex() == expected


def _dyn_tags(elf: ELFFile) -> dict[str, int]:
    return {
        t.entry.d_tag: t.entry.d_val
        for t in elf.get_section_by_name(".dynamic").iter_tags()
    }


def _rela_file_off(elf: ELFFile, tags: dict[str, int]) -> int:
    """File offset of the DT_RELA table (vaddr -> offset via LOAD segments)."""
    for s in elf.iter_segments():
        h = s.header
        if (
            h.p_type == "PT_LOAD"
            and h.p_vaddr <= tags["DT_RELA"] < h.p_vaddr + h.p_filesz
        ):
            return tags["DT_RELA"] - h.p_vaddr + h.p_offset
    raise LookupError(f"DT_RELA {hex(tags['DT_RELA'])} not in any LOAD segment")


def _rela_table(elf: ELFFile, f, tags: dict[str, int]):
    """The Elf64_Rela table the loader uses (DT_RELA/DT_RELASZ) as (off, info, addend) triples."""
    f.seek(_rela_file_off(elf, tags))
    raw = f.read(tags["DT_RELASZ"])
    return [struct.unpack_from("<QQQ", raw, i) for i in range(0, len(raw), 24)]


def _first_relative(binary: str):
    """An existing R_X86_64_RELATIVE (off, addend) we can safely re-add."""
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        for off, info, addend in _rela_table(elf, f, _dyn_tags(elf)):
            if (info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
                return off, addend
    raise AssertionError("binary has no R_X86_64_RELATIVE entry to duplicate")


def _run(path: str):
    """Execute a binary, returning (stdout, returncode); skip if the host can't."""
    try:
        r = subprocess.run([path], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        pytest.skip(f"cannot execute test binary on this host: {e}")
    return r.stdout, r.returncode


class TestEmitDynamicRelocations:
    PIE = os.path.join(os.path.dirname(__file__), "test_binaries/amd64/printf_pie")

    def _patch(self, tmp_path, relocs) -> str:
        out = str(tmp_path / "patched")
        p = Patcherex(self.PIE, target_opts={"binary_analyzer": "angr"})
        if relocs:
            p.binfmt_tool.add_dynamic_relocations(relocs)
        p.apply_patches()
        p.save_binary(out)
        p.shutdown()
        os.chmod(out, 0o755)
        return out

    def test_rebuilt_rela_is_structurally_valid(self, tmp_path):
        off, addend = _first_relative(self.PIE)
        with open(self.PIE, "rb") as f:
            before = _dyn_tags(ELFFile(f))
        out = self._patch(tmp_path, [(off, R_X86_64_RELATIVE, addend)])
        with open(out, "rb") as f:
            elf = ELFFile(f)
            after = _dyn_tags(elf)
            entries = _rela_table(elf, f, after)
        assert after["DT_RELACOUNT"] == before["DT_RELACOUNT"] + 1
        assert entries[0] == (off, R_X86_64_RELATIVE, addend)
        assert len(entries) == before["DT_RELASZ"] // 24 + 1
        assert all(
            (e[1] & 0xFFFFFFFF) == R_X86_64_RELATIVE
            for e in entries[: after["DT_RELACOUNT"]]
        )

    def test_patched_binary_runs_identically(self, tmp_path):
        baseline = _run(self.PIE)
        off, addend = _first_relative(self.PIE)
        out = self._patch(tmp_path, [(off, R_X86_64_RELATIVE, addend)])
        assert _run(out) == baseline

    def test_broken_reloc_fails_to_run(self, tmp_path):
        baseline = _run(self.PIE)
        with open(self.PIE, "rb") as f:
            off = _rela_file_off(ELFFile(f), _dyn_tags(ELFFile(f)))
            f.seek(0)
            data = bytearray(f.read())
        # non-canonical target -> ld.so faults applying the reloc
        data[off : off + 8] = struct.pack("<Q", 0x8000000000000000)
        broken = str(tmp_path / "broken")
        with open(broken, "wb") as f:
            f.write(data)
        os.chmod(broken, 0o755)
        assert _run(broken) != baseline
