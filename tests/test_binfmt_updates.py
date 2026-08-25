from types import SimpleNamespace

import pytest

from patcherex2.components.binfmt_tools.binary import Binary
from patcherex2.components.binfmt_tools.elf import ELF
from patcherex2.components.binfmt_tools.ihex import IHex

ORIGINAL_CONTENT = b"abcdefghijklmnopqrstuvwxyz012345"


class FakeIHex:
    def tobinarray(self, *, start, size):
        return bytearray(ORIGINAL_CONTENT[start : start + size])


def make_binfmt_tool(tool_type):
    tool = tool_type.__new__(tool_type)
    tool.file_updates = []
    tool.file_size = len(ORIGINAL_CONTENT)
    if tool_type is ELF:
        tool.original_binary_content = ORIGINAL_CONTENT
    elif tool_type is Binary:
        tool._original = ORIGINAL_CONTENT
    else:
        tool._ihex = FakeIHex()
    return tool


@pytest.fixture(params=[ELF, Binary, IHex])
def binfmt_tool(request):
    return make_binfmt_tool(request.param)


def test_base_binfmt_mapper_falls_back_to_analyzer():
    tool = Binary.__new__(Binary)
    tool.p = SimpleNamespace(
        binary_analyzer=SimpleNamespace(
            mem_addr_to_file_offset=lambda addr: addr - 0x400000
        )
    )

    assert tool.mem_addr_to_file_offset(0x400100) == 0x100


def test_ihex_file_offset_is_a_logical_address():
    tool = IHex.__new__(IHex)

    assert tool.mem_addr_to_file_offset(0x400100) == 0x400100


def test_staged_updates_overlay_partial_reads_for_all_binary_formats(binfmt_tool):
    binfmt_tool.update_binary_content(3, b"XYZ")

    assert binfmt_tool.get_binary_content(2, 5) == b"cXYZg"


def test_interval_conflicts_are_rejected_for_all_binary_formats(binfmt_tool):
    binfmt_tool.update_binary_content(3, b"XYZ")

    with pytest.raises(ValueError, match="conflicts with a previous update interval"):
        binfmt_tool.update_binary_content(2, b"cQQ")


def test_update_bridges_compatible_intervals_for_all_binary_formats(binfmt_tool):
    binfmt_tool.update_binary_content(2, ORIGINAL_CONTENT[2:4])
    binfmt_tool.update_binary_content(6, ORIGINAL_CONTENT[6:8])
    binfmt_tool.update_binary_content(3, ORIGINAL_CONTENT[3:7])

    assert binfmt_tool.get_binary_content(2, 6) == ORIGINAL_CONTENT[2:8]


@pytest.mark.parametrize(
    ("old_start", "old_end", "new_start", "new_end", "merged_start", "merged_end"),
    [
        (4, 8, 4, 8, 4, 8),
        (4, 8, 5, 7, 4, 8),
        (5, 7, 4, 8, 4, 8),
        (5, 9, 3, 7, 3, 9),
        (3, 7, 5, 9, 3, 9),
    ],
)
def test_idempotent_overlaps_preserve_combined_content(
    old_start, old_end, new_start, new_end, merged_start, merged_end
):
    tool = make_binfmt_tool(Binary)
    replacement = b"X" * (merged_end - merged_start)
    tool.update_binary_content(
        old_start,
        replacement[old_start - merged_start : old_end - merged_start],
    )
    tool.update_binary_content(
        new_start,
        replacement[new_start - merged_start : new_end - merged_start],
    )
    expected = bytearray(ORIGINAL_CONTENT)
    expected[merged_start:merged_end] = replacement

    assert tool.get_binary_content(0, tool.file_size) == bytes(expected)


def test_disjoint_updates_are_read_in_recording_independent_order():
    tool = make_binfmt_tool(Binary)
    tool.update_binary_content(12, b"cd")
    tool.update_binary_content(2, b"ab")
    expected = bytearray(ORIGINAL_CONTENT)
    expected[2:4] = b"ab"
    expected[12:14] = b"cd"

    assert tool.get_binary_content(0, tool.file_size) == bytes(expected)


@pytest.mark.parametrize(
    ("old_start", "old_content", "new_start", "new_content"),
    [
        (4, b"abcd", 5, b"XX"),
        (5, b"bc", 4, b"aXXd"),
        (5, b"bcd", 3, b"abX"),
        (3, b"abc", 5, b"XXd"),
    ],
)
def test_conflicting_overlaps_are_rejected_in_both_directions(
    old_start, old_content, new_start, new_content
):
    tool = make_binfmt_tool(Binary)
    tool.update_binary_content(old_start, old_content)

    with pytest.raises(ValueError, match="conflicts with a previous update interval"):
        tool.update_binary_content(new_start, new_content)

    assert tool.get_binary_content(old_start, len(old_content)) == old_content


def test_empty_update_is_a_noop_and_negative_offset_is_rejected():
    tool = make_binfmt_tool(Binary)

    tool.update_binary_content(4, b"")
    assert tool.get_binary_content(0, tool.file_size) == ORIGINAL_CONTENT

    with pytest.raises(ValueError, match="negative file offset"):
        tool.update_binary_content(-1, b"x")
