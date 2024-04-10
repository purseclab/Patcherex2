"""
Contains patches that modify the binary at the instruction level.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from collections.abc import Iterable

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
        :param instr: Assembly instruction(s) to place in binary. If you want to use any symbols from the program or from previous patches, you must surround them with curly braces.
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

def convert_to_subregisters(cc: list[str], subregisters: dict[str, dict[int, list[str]]], regs: frozenset[str]) -> list[tuple[int, str]]:
    # parent_regs maps all children registers to their largest parent register and their bit size
    # For example in x64, we will have
    # parent_regs = {'rax': (64, 'rax'), 'eax': (32, 'rax'), 'ax': (16, 'rax'), 'ah': (8, 'rax'), 'al': (8, 'rax'), ...}
    parent_regs: dict[str, tuple[int, str]] = dict()
    for (parent, subregister_info) in subregisters.items():
        for (child_bits, children) in subregister_info.items():
            for (i, child) in enumerate(children):
                if i > 0 and child in regs:
                    # Only allow the 0th subregister to actually be used.
                    raise ValueError("Unable to create the calling convention when the {} register is present. The {} subregister is the only {} bit subregister that can be used.".format(child, children[0], child_bits))
                parent_regs[child] = (child_bits, parent)

    # The rewrites that should be applied to the cc to compute the transformed cc output
    rewrites: dict[str, tuple[int, str]] = dict()
    for r in regs:
        if r not in parent_regs:
            raise ValueError("Unknown register {}".format(r))
        (r_bits, parent) = parent_regs[r]
        if parent != r:
            if parent in rewrites:
                raise ValueError("The following two input registers overlapped while computing the calling convention: " + r + " and " + rewrites[parent][1])
            rewrites[parent] = (r_bits, r)

    def convert_cc_reg(cc_reg):
        return rewrites.get(cc_reg, parent_regs[cc_reg])
    return list(map(convert_cc_reg, cc))

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
        language: str="ASM",
        c_forward_header: str="",
        c_scratch_regs: Iterable[str]=None,
        c_sub_regs: Iterable[str]=None,
        c_in_float_types: dict[str, str]=None,
        c_out_float_types: dict[str, str]=None,
        **kwargs,
    ) -> None:
        """
        Constructor.

        :param addr_or_name: If an integer, the new instructions are placed in a free spot in the binary and the jump to them is inserted at that memory address.
                             If a string, the new instructions are placed in a free spot in the binary and added as a symbol (with this as its name).
        :param instr: Instructions to insert. You can use "SAVE_CONTEXT" and "RESTORE_CONTEXT" wherever you want to save and restore program context. If you want to use any symbols from the program or from previous patches, you must surround them with curly braces.
        :param force_insert: If Patcherex should ignore whether instructions can be moved when inserting, defaults to False
        :param detour_pos: If given a name, specifies the file address to place the new instructions, defaults to -1
        :param symbols: Symbols to include when assembling, in format {symbol name: memory address}, defaults to None
        :param is_thumb: Whether the instructions given are thumb, defaults to False
        :param language: The language of the patch, can be either "ASM" or "C"
        :param c_forward_header: If the language is "C", then this field contains the code that should be inserted before the instr code. This string will typically contain the #includes necessary to bring in function prototypes and any required type declarations.
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
        self.language = language
        self.c_forward_header = c_forward_header
        self.c_scratch_regs = frozenset() if c_scratch_regs is None else frozenset(c_scratch_regs)
        self.c_sub_regs = frozenset() if c_sub_regs is None else frozenset(c_sub_regs)
        self.c_in_float_types = dict() if c_in_float_types is None else c_in_float_types
        self.c_out_float_types = dict() if c_out_float_types is None else c_out_float_types
        self.save_context = (
            kwargs["save_context"] if "save_context" in kwargs else False
        )
        self.compile_opts = kwargs["compile_opts"] if "compile_opts" in kwargs else {}

    def apply(self, p):
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        :type p: Patcherex
        """
        if self.language == "ASM":
            self._apply_asm(p)
        elif self.language == "C":
            self._apply_c(p)

    def _apply_c(self, p) -> None:
        if self.addr is None:
            raise ValueError("An address must be provided for a C instruction patch")

        calling_convention = p.target.get_cc(preserve_none=p.compiler.preserve_none)
        subregister_table = p.archinfo.subregisters

        # Figure out if there are any extra registers that we need to expose to the user
        # that aren't part of the calling convention. For x64 preserve_none, this will be
        # registers r10 and rbx.
        extra_saved = set(p.archinfo.regs)
        extra_saved = extra_saved - set(calling_convention)
        extra_saved.discard(p.archinfo.sp_reg)
        extra_saved.discard(p.archinfo.bp_reg)
        extra_saved_in = list(extra_saved)
        # We don't want to necessarily output registers that have been marked as scratch
        # However we always want to make them available as input
        extra_saved_out = list(extra_saved - self.c_scratch_regs)
        extra_saved_in_converted = convert_to_subregisters(extra_saved_in, subregister_table, self.c_sub_regs)
        extra_saved_out_converted = convert_to_subregisters(extra_saved_out, subregister_table, self.c_sub_regs)

        attribute = "__attribute__((preserve_none))" if p.compiler.preserve_none else ""

        args = convert_to_subregisters(calling_convention, subregister_table, self.c_sub_regs)
        args_str = ', '.join(['uint{}_t {}'.format(bits, name) for (bits, name) in args])

        callback_forward_decl = 'extern void {} _CALLBACK({});'.format(attribute, args_str)

        # Stupid macro tricks to make coding the patch a little bit nicer. This allows the user
        # to write 'return;' instead of having to understand how to call the callback
        # reg_name if reg_name in self.c_out_regs else '_dummy'
        return_macro_lines = [
            '#define return do {',
        ]

        for (bits, reg) in extra_saved_out_converted:
            return_macro_lines.append('    asm ("" : : "r"({}) :);'.format(reg))

        return_macro_lines += [
            '    return _CALLBACK({});'.format(', '.join(['_dummy' if reg_name in self.c_scratch_regs else reg_name for (bits, reg_name) in args])),
            '} while(0)'
        ]

        return_macro = '\\\n'.join(return_macro_lines)

        lines = [
            '#include <stdint.h>',
            '',
            callback_forward_decl,
            '',
            self.c_forward_header,
            '',
            return_macro,
            '',
            'void {} _MICROPATCH({}) {{'.format(attribute, args_str),
            '    uint{}_t _dummy;'.format(p.archinfo.bits)
        ]
        for (bits, reg) in extra_saved_in_converted:
            # Force the variables to live in a specific register using the register C extension
            lines.append('    register uint{0}_t {1} asm("{1}");'.format(bits, reg))
        for (bits, reg) in extra_saved_in_converted:
            # Trick the C compiler into thinking that the variables we just defined are actually live
            lines.append('    asm ("" : "=r"({}) : : );'.format(reg))
        lines += [
            self.instr,
            # Make sure we actually do the callback in case the user forgets to put in a return
            '    return;',
            '}',
            '#undef return'
        ]
        code = '\n'.join(lines)
        logger.info("InsertInstructionPatch generated C code:\n" + code)
        p.utils.insert_trampoline_code(
            self.addr,
            code,
            force_insert=self.force_insert,
            detour_pos=self.detour_pos,
            symbols=self.symbols,
            language="C"
        )

    def _apply_asm(self, p) -> None:
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
