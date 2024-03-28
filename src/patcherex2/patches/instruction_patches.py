"""
Contains patches that modify the binary at the instruction level.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..components.allocation_managers.allocation_manager import MemoryFlag
from .patch import Patch

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from ..patcherex import Patcherex


class ModifyInstructionPatch(Patch):
    """
    Patch that directly modifies instructions in a binary (overwrites them) starting at address given.
    If ISA is variable length, then if there are remaining bytes in the last overwritten instruction,
    it will fill them with nops, but it will fail if remaining bytes are not divisible by nop length.
    """

    def __init__(
        self, addr: int, instr: str, symbols: dict[str, int] | None = None
    ) -> None:
        """
        Constructor.

        :param addr: Memory address of instruction(s) to overwrite.
        :param instr: Assembly instruction(s) to place in binary.
        :param symbols: Symbols to include when assembling, in format {symbol name: memory address}, defaults to None
        """
        self.addr = addr
        self.instr = instr
        self.symbols = symbols if symbols else {}

    def apply(self, p) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        :type p: Patcherex
        """
        asm_bytes = p.assembler.assemble(
            self.instr,
            self.addr,
            symbols=self.symbols,
            is_thumb=p.binary_analyzer.is_thumb(self.addr),
        )
        if p.archinfo.is_variable_length_isa:
            asm_size = len(asm_bytes)
            overwritten_size = 0
            num_instrs = 1
            while overwritten_size < asm_size:
                overwritten_size = len(
                    p.binary_analyzer.get_instr_bytes_at(
                        self.addr, num_instr=num_instrs
                    )
                )
                num_instrs += 1
            remaining_size = overwritten_size - asm_size
            assert (
                remaining_size % p.archinfo.nop_size == 0
            ), f"Cannot fill in {remaining_size} bytes when modifying instruction, must be a multiple of {p.archinfo.nop_size}"
            asm_bytes += p.archinfo.nop_bytes * (remaining_size // p.archinfo.nop_size)
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, asm_bytes)


class InsertInstructionPatch(Patch):
    """
    Patch that allows instructions to be inserted into binary. These instructions are inserted at a free place in the binary.
    Then, At the address given, an instruction is inserted that jumps to this block (also in the block are the instructions this overwrites).
    At the end of the block, it jumps back to right after the initial jump. The initial jump must be able to be inserted within the basic block
    of the given address.
    """

    def __init__(
        self,
        addr_or_name: int | str,
        instr: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        is_thumb=False,
        **kwargs,
    ) -> None:
        """
        Constructor.

        :param addr_or_name: If an integer, the new instructions are placed in a free spot in the binary and the jump to them is inserted at that memory address.
                             If a string, the new instructions are placed in a free spot in the binary and added as a symbol (with this as its name).
        :param instr: Instructions to insert. You can use "SAVE_CONTEXT" and "RESTORE_CONTEXT" wherever you want to save and restore program context.
        :param force_insert: If Patcherex should ignore whether instructions can be moved when inserting, defaults to False
        :param detour_pos: If given a name, specifies the file address to place the new instructions, defaults to -1
        :param symbols: Symbols to include when assembling, in format {symbol name: memory address}, defaults to None
        :param is_thumb: Whether the instructions given are thumb, defaults to False
        :param **kwargs: Extra options. Can have a boolean "save_context" for whether context should be saved.
        """
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.instr = instr
        self.force_insert = force_insert
        self.detour_pos = detour_pos
        self.symbols = symbols if symbols else {}
        self.is_thumb = is_thumb
        self.save_context = (
            kwargs["save_context"] if "save_context" in kwargs else False
        )

    def apply(self, p) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        :type p: Patcherex
        """
        if self.addr:
            if "SAVE_CONTEXT" in self.instr:
                self.instr = self.instr.replace(
                    "SAVE_CONTEXT", f"\n{p.archinfo.save_context_asm}\n"
                )
            if "RESTORE_CONTEXT" in self.instr:
                self.instr = self.instr.replace(
                    "RESTORE_CONTEXT", f"\n{p.archinfo.restore_context_asm}\n"
                )
            if self.save_context:
                self.instr = f"{p.archinfo.save_context_asm}\n{self.instr}\n{p.archinfo.restore_context_asm}"
            p.utils.insert_trampoline_code(
                self.addr,
                self.instr,
                force_insert=self.force_insert,
                detour_pos=self.detour_pos,
                symbols=self.symbols,
            )
        elif self.name:
            assembled_size = len(
                p.assembler.assemble(
                    self.instr, symbols=self.symbols, is_thumb=self.is_thumb
                )
            )
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    assembled_size, align=p.archinfo.alignment, flag=MemoryFlag.RX
                )
                p.symbols[self.name] = block.mem_addr
                p.binfmt_tool.update_binary_content(
                    block.file_addr,
                    p.assembler.assemble(
                        self.instr,
                        block.mem_addr,
                        symbols=self.symbols,
                        is_thumb=self.is_thumb,
                    ),
                )
            else:
                p.symbols[self.name] = self.detour_pos
                p.binfmt_tool.update_binary_content(
                    self.detour_pos,
                    p.assembler.assemble(
                        self.instr,
                        self.detour_pos,
                        symbols=self.symbols,
                        is_thumb=self.is_thumb,
                    ),
                )


class RemoveInstructionPatch(Patch):
    """
    Patch that removes instructions in the binary. Currently only takes in a number of bytes and an starting address.
    The number of bytes must be divisible by the nop size of the architecture, otherwise it will fail.
    """

    def __init__(
        self,
        addr: int,
        num_instr: int | None = None,
        num_bytes: int | None = None,
    ) -> None:
        """
        Constructor.

        :param addr: Memory address to remove instructions at.
        :param num_instr: Number of instructions to remove, currently not used, defaults to None
        :param num_bytes: Number of bytes to remove, must be divisible by nop size, defaults to None
        """
        self.addr = addr
        self.num_instr = num_instr
        self.num_bytes = num_bytes
        if self.num_instr is None and self.num_bytes is None:
            self.num_instr = 1

    def apply(self, p: Patcherex) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        """
        if self.num_bytes is None:
            raise NotImplementedError()
        if self.num_bytes and self.num_bytes % p.archinfo.nop_size != 0:
            raise Exception(
                f"Cannot remove {self.num_bytes} bytes, must be a multiple of {p.archinfo.nop_size}"
            )
        num_nops = self.num_bytes // p.archinfo.nop_size
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, p.archinfo.nop_bytes * num_nops)
