import pytest
from elftools.construct.lib.container import Container
from elftools.elf.constants import P_FLAGS

from patcherex2.components.allocation_managers.allocation_manager import MemoryFlag
from patcherex2.components.binfmt_tools.elf import (
    ELF,
    memory_flags_from_elf_segment_flags,
)


@pytest.mark.parametrize(
    ("elf_flags", "expected"),
    [
        (0, MemoryFlag(0)),
        (P_FLAGS.PF_R, MemoryFlag.R),
        (P_FLAGS.PF_W, MemoryFlag.W),
        (P_FLAGS.PF_X, MemoryFlag.X),
        (P_FLAGS.PF_R | P_FLAGS.PF_W, MemoryFlag.RW),
        (P_FLAGS.PF_R | P_FLAGS.PF_X, MemoryFlag.RX),
        (P_FLAGS.PF_R | P_FLAGS.PF_W | P_FLAGS.PF_X, MemoryFlag.RWX),
    ],
)
def test_segment_permissions_are_preserved(elf_flags, expected):
    assert memory_flags_from_elf_segment_flags(elf_flags) == expected


def test_mem_addr_to_file_offset_uses_file_backed_load_range():
    elf = ELF.__new__(ELF)
    elf._segments = [
        Container(
            p_type="PT_LOAD",
            p_offset=0x100,
            p_vaddr=0x400000,
            p_filesz=0x20,
            p_memsz=0x40,
        )
    ]

    assert elf.mem_addr_to_file_offset(0x400010) == 0x110
    with pytest.raises(ValueError, match="0x400030"):
        elf.mem_addr_to_file_offset(0x400030)


def test_new_segment_preserves_minimum_load_address_offset():
    elf = ELF.__new__(ELF)
    elf._segments = [
        Container(p_type="PT_LOAD", p_offset=0, p_vaddr=0x400000),
        Container(p_type="PT_LOAD", p_offset=0xDF8, p_vaddr=0x410DF8),
    ]

    assert elf.minimum_memory_address_for_new_segment(0x2378) == 0x402378


def test_program_headers_follow_required_load_order():
    segments = [
        Container(p_type="PT_DYNAMIC", p_vaddr=0x410E08),
        Container(p_type="PT_LOAD", p_vaddr=0x410DF8),
        Container(p_type="PT_INTERP", p_vaddr=0x400200),
        Container(p_type="PT_LOAD", p_vaddr=0x400000),
        Container(p_type="PT_PHDR", p_vaddr=0x420000),
        Container(p_type="PT_NOTE", p_vaddr=0x40021C),
    ]

    ordered = ELF._order_program_headers(segments)

    assert [segment["p_type"] for segment in ordered] == [
        "PT_PHDR",
        "PT_INTERP",
        "PT_LOAD",
        "PT_LOAD",
        "PT_DYNAMIC",
        "PT_NOTE",
    ]
    assert [
        segment["p_vaddr"] for segment in ordered if segment["p_type"] == "PT_LOAD"
    ] == [0x400000, 0x410DF8]


def test_contained_load_range_does_not_shrink_merged_extent():
    assert ELF._merge_overlapping_ranges(
        [(0, 0x10000), (0x10000, 0x30000), (0x10000, 0x20000)]
    ) == [(0, 0x10000), (0x10000, 0x30000)]
