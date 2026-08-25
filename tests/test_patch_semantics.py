from types import SimpleNamespace

import pytest

from patcherex2.components.archinfo.x86 import X86Info
from patcherex2.components.utils.utils import Utils
from patcherex2.patches.function_patches import (
    InsertFunctionPatch,
    ModifyFunctionPatch,
)
from patcherex2.patches.instruction_patches import (
    InsertInstructionPatch,
    RemoveInstructionPatch,
)


class ResizingAllocationManager:
    def __init__(self):
        self.requests = []
        self.freed = []

    def allocate(self, size, **kwargs):
        self.requests.append((size, kwargs))
        mem_addr = len(self.requests) * 0x1000
        return SimpleNamespace(
            mem_addr=mem_addr,
            file_addr=mem_addr // 0x10,
            size=size,
            is_free=False,
        )

    def free(self, block):
        block.is_free = True
        self.freed.append(block)


def test_remove_instruction_count_uses_decoded_instruction_lengths():
    updates = []
    patcher = SimpleNamespace(
        archinfo=SimpleNamespace(nop_size=1, nop_bytes=b"\x90"),
        binary_analyzer=SimpleNamespace(
            get_instr_bytes_at=lambda addr, num_instr: b"\x01\x02\x03\x04\x05",
            mem_addr_to_file_offset=lambda addr: addr - 0x1000,
        ),
        binfmt_tool=SimpleNamespace(
            mem_addr_to_file_offset=lambda addr: addr - 0x1000,
            update_binary_content=lambda *update: updates.append(update),
        ),
    )

    patch = RemoveInstructionPatch(0x1010, num_instr=2)
    patch.apply(patcher)

    assert patch.num_bytes is None
    assert updates == [(0x10, b"\x90" * 5)]


def test_remove_instruction_bytes_replaces_exact_range_without_decoding():
    updates = []

    def reject_decode(*_args, **_kwargs):
        raise AssertionError("num_bytes must not decode instructions")

    patcher = SimpleNamespace(
        archinfo=SimpleNamespace(nop_size=1, nop_bytes=b"\x90"),
        binary_analyzer=SimpleNamespace(
            get_instr_bytes_at=reject_decode,
            mem_addr_to_file_offset=lambda addr: addr - 0x1000,
        ),
        binfmt_tool=SimpleNamespace(
            mem_addr_to_file_offset=lambda addr: addr - 0x1000,
            update_binary_content=lambda *update: updates.append(update),
        ),
    )

    RemoveInstructionPatch(0x1010, num_bytes=1).apply(patcher)

    assert updates == [(0x10, b"\x90")]


def test_remove_instruction_rejects_ambiguous_count():
    with pytest.raises(ValueError, match="either num_instr or num_bytes"):
        RemoveInstructionPatch(0x1000, num_instr=1, num_bytes=1)


def test_named_asm_patch_reassembles_until_final_address_bytes_fit():
    manager = ResizingAllocationManager()
    updates = []

    def assemble(_code, base=0, **_kwargs):
        return b"A" * (2 if base == 0 else 4)

    patcher = SimpleNamespace(
        allocation_manager=manager,
        archinfo=SimpleNamespace(alignment=1),
        assembler=SimpleNamespace(assemble=assemble),
        binfmt_tool=SimpleNamespace(
            update_binary_content=lambda *update: updates.append(update)
        ),
        symbols={},
    )
    patcher.utils = Utils(patcher, "unused")

    InsertInstructionPatch("helper", "nop").apply(patcher)

    assert [size for size, _ in manager.requests] == [2, 4]
    assert len(manager.freed) == 1
    assert patcher.symbols["helper"] == 0x2000
    assert updates == [(0x200, b"A" * 4)]


def test_named_c_patch_recompiles_until_final_address_bytes_fit():
    manager = ResizingAllocationManager()
    updates = []

    def compile_code(_code, base=0, **_kwargs):
        return b"C" * (3 if base == 0 else 7)

    patcher = SimpleNamespace(
        allocation_manager=manager,
        archinfo=SimpleNamespace(alignment=1),
        compiler=SimpleNamespace(compile=compile_code),
        binfmt_tool=SimpleNamespace(
            update_binary_content=lambda *update: updates.append(update)
        ),
        symbols={},
        sypy_info={"patcherex_added_functions": []},
    )
    patcher.utils = Utils(patcher, "unused")

    InsertFunctionPatch("helper", "void helper(void) {}").apply(patcher)

    assert [size for size, _ in manager.requests] == [3, 7]
    assert len(manager.freed) == 1
    assert patcher.symbols["helper"] == 0x2000
    assert updates == [(0x200, b"C" * 7)]


def test_addressed_c_function_patch_builds_helper_and_trampoline():
    compile_calls = []
    trampoline_calls = []
    updates = []

    def compile_code(code, base=0, **kwargs):
        compile_calls.append((code, base, kwargs))
        return b"C"

    def allocate_generated_code(initial_size, build, **_kwargs):
        assert initial_size == 1
        block = SimpleNamespace(mem_addr=0x3000, file_addr=0x300, size=1)
        return block, build(block.mem_addr)

    patcher = SimpleNamespace(
        archinfo=SimpleNamespace(
            alignment=1,
            save_context_asm="<save>",
            restore_context_asm="<restore>",
            call_asm="call {dst}",
        ),
        binary_analyzer=SimpleNamespace(
            is_thumb=lambda addr: addr == 0x1000,
        ),
        binfmt_tool=SimpleNamespace(
            update_binary_content=lambda *update: updates.append(update)
        ),
        compiler=SimpleNamespace(compile=compile_code),
        symbols={},
        sypy_info={"patcherex_added_functions": []},
        utils=SimpleNamespace(
            allocate_generated_code=allocate_generated_code,
            insert_trampoline_code=lambda *args, **kwargs: trampoline_calls.append(
                (args, kwargs)
            ),
        ),
    )
    patch = InsertFunctionPatch(
        0x1000,
        "void helper(void) {}",
        detour_pos=0x2000,
        symbols={"external": 0x4000},
        prefunc="SAVE_CONTEXT pre",
        postfunc="post RESTORE_CONTEXT",
        save_context=True,
    )

    patch.apply(patcher)

    assert [(base, kwargs["is_thumb"]) for _, base, kwargs in compile_calls] == [
        (0, True),
        (0x3000, True),
    ]
    assert patcher.symbols["__patcherex_0x1000"] == 0x3000
    assert updates == [(0x300, b"C")]
    assert len(trampoline_calls) == 1
    trampoline_args, trampoline_kwargs = trampoline_calls[0]
    source_addr, trampoline = trampoline_args
    assert source_addr == 0x1000
    assert trampoline.count("<save>") == 2
    assert trampoline.count("<restore>") == 2
    call = "call {__patcherex_0x1000}"
    assert call in trampoline
    assert trampoline.index("<save>") < trampoline.index("pre")
    assert trampoline.index("pre") < trampoline.index(call)
    assert trampoline.index(call) < trampoline.index("post")
    assert trampoline.index("post") < trampoline.index("<restore>")
    assert trampoline_kwargs == {
        "force_insert": False,
        "detour_pos": 0x2000,
        "symbols": {"external": 0x4000},
    }


def test_modify_function_recompiles_until_final_address_bytes_fit():
    manager = ResizingAllocationManager()
    updates = []

    def compile_code(_code, base=0, **_kwargs):
        return b"C" * (3 if base == 0x500 else 7)

    patcher = SimpleNamespace(
        allocation_manager=manager,
        archinfo=X86Info(),
        assembler=SimpleNamespace(assemble=lambda *_args, **_kwargs: b"J"),
        binary_analyzer=SimpleNamespace(
            get_function=lambda _target: {"addr": 0x500, "size": 2},
            is_thumb=lambda _addr: False,
            mem_addr_to_file_offset=lambda addr: addr,
        ),
        binfmt_tool=SimpleNamespace(
            is_position_independent=False,
            mem_addr_to_file_offset=lambda addr: addr,
            update_binary_content=lambda *update: updates.append(update),
        ),
        compiler=SimpleNamespace(compile=compile_code),
    )
    patcher.utils = Utils(patcher, "unused")

    ModifyFunctionPatch("target", "return 0;").apply(patcher)

    assert [size for size, _ in manager.requests] == [3, 7]
    assert len(manager.freed) == 1
    assert updates == [(0x500, b"J"), (0x200, b"C" * 7)]


def test_explicit_named_asm_detour_is_a_memory_address():
    updates = []
    patcher = SimpleNamespace(
        archinfo=SimpleNamespace(alignment=1),
        assembler=SimpleNamespace(assemble=lambda *_args, **_kwargs: b"A"),
        binary_analyzer=SimpleNamespace(
            mem_addr_to_file_offset=lambda addr: addr - 0x400000
        ),
        binfmt_tool=SimpleNamespace(
            mem_addr_to_file_offset=lambda addr: addr - 0x400000,
            update_binary_content=lambda *update: updates.append(update),
        ),
        symbols={},
    )
    patcher.utils = Utils(patcher, "unused")

    InsertInstructionPatch("helper", "nop", detour_pos=0x401234).apply(patcher)

    assert patcher.symbols["helper"] == 0x401234
    assert updates == [(0x1234, b"A")]
