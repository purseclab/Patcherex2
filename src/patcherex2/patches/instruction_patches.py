"""
Contains patches that modify the binary at the instruction level.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
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
            assert remaining_size % p.archinfo.nop_size == 0, (
                f"Cannot fill in {remaining_size} bytes when modifying instruction, must be a multiple of {p.archinfo.nop_size}"
            )
            asm_bytes += p.archinfo.nop_bytes * (remaining_size // p.archinfo.nop_size)
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, asm_bytes)


def convert_to_subregisters(
    cc: list[str],
    subregisters: dict[str, dict[int, list[str]]],
    regs_sort: list[str | tuple[str, int] | tuple[str, str]],
    type_converter: Callable[[int], str],
) -> list[tuple[str, str]]:
    regs = [r if isinstance(r, str) else r[0] for r in regs_sort]

    # reg_sizes maps registers to their size
    reg_sizes: dict[str, int] = dict()
    # parent_regs maps all children registers to their largest parent register
    parent_regs: dict[str, str] = dict()
    for parent, subregister_info in subregisters.items():
        for child_bits, children in subregister_info.items():
            for i, child in enumerate(children):
                if i > 0 and child in regs:
                    # Only allow the 0th subregister to actually be used.
                    raise ValueError(
                        f"Unable to create the calling convention when the {child} register is present. The {children[0]} subregister is the only {child_bits} bit subregister that can be used."
                    )
                reg_sizes[child] = child_bits
                parent_regs[child] = parent

    # The rewrites that should be applied to the cc to compute the transformed cc output
    rewrites: dict[str, tuple[str, str]] = dict()
    for r in regs_sort:
        if isinstance(r, str):
            reg_name = r
        else:
            reg_name = r[0]
        if reg_name in parent_regs:
            if isinstance(r, str):
                reg_bits = reg_sizes[reg_name]
                reg_type = type_converter(reg_bits)
            elif isinstance(r[1], int):
                (_, reg_bits) = r
                reg_type = type_converter(reg_bits)
            else:
                (_, reg_type) = r
            parent = parent_regs[reg_name]
            if parent in rewrites:
                raise ValueError(
                    "The following two input registers overlapped while computing the calling convention: "
                    + r
                    + " and "
                    + rewrites[parent][1]
                )
            rewrites[parent] = (reg_name, reg_type)

    def convert_cc_reg(cc_reg):
        if cc_reg in rewrites:
            return rewrites[cc_reg]
        else:
            parent_reg = parent_regs[cc_reg]
            parent_bits = reg_sizes[parent_reg]
            parent_type = type_converter(parent_bits)
            return (parent_reg, parent_type)

    return list(map(convert_cc_reg, cc))


class InsertInstructionPatch(Patch):
    class CConfig:
        def __init__(
            self,
            c_forward_header: str = "",
            scratch_regs: Iterable[str] = None,
            regs_sort: Iterable[str | tuple[str, int] | tuple[str, str]] | None = None,
            asm_header: str = "",
            asm_footer: str = "",
        ):
            """
            Used to configure an InsertInstructionPatch when language == "C"

            :param c_forward_header: C code that will be inserted before the micropatch code. This is useful when you want\
            to use C types, C headers, and C function forward declarations.
            :param scratch_regs: It is generally a good idea to mark some registers as scratch to give the compiler\
            breathing room for allocating registers to use for intermediate variables in your micropatch.\
            All of the registers that we mark as scratch can be freely clobbered by the compiler\
            Note that you can still read from scratch registers stored in the variables. What the scratch\
            register denotation will indicate however is that the register can be re-used after the variable\
            is no longer live.
            :param regs_sort: Some architectures have subregisters\
            which allow access to a portion of a register, such as the lower 32 bits of a 64 bit register. If you want\
            to use a subregister instead of the full register you can request this by passing in a list of subregisters\
            here. Note that if you specify a subregister here, the full parent register is not available in the C\
            patch. Some registers allow values of smaller types to be stored in larger registers. For example, you can\
            store float values in xmm0 on x64, but there is no 32 bit subregister. To indicate that a register\
            should be treated as a specific size, you may specify register size in bits in the second element of the\
            tuple. Alternatively, you may specify the type as a string. An example of a valid list for x64 is\
            ['eax', ('xmm0', 32), ('xmm1', 'double')].
            :param asm_header: The asm_header is inserted in the main body of the patch before the C code. This header is\
            primarily useful for gaining access to the stack pointer, which is a register that is typically unavailable in\
            our C patch code.
            :param asm_footer: The asm_footer is the same as the asm_header, except that it runs after the C code executes.\
            This is typically less useful than asm_header, but is still available here if you need to do any cleanup in\
            assembly.
            """
            self.c_forward_header = c_forward_header
            self.scratch_regs = scratch_regs
            self.regs_sort = regs_sort
            self.asm_header = asm_header
            self.asm_footer = asm_footer

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
        language: str = "ASM",
        c_config: CConfig | None = None,
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
        :param c_config: Configuration options for when language == "C"
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
        self.language = language.upper()
        self.c_config = self.CConfig() if c_config is None else c_config
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

        c_forward_header = self.c_config.c_forward_header
        c_scratch_regs = (
            frozenset()
            if self.c_config.scratch_regs is None
            else frozenset(self.c_config.scratch_regs)
        )
        c_regs_sort = (
            [] if self.c_config.regs_sort is None else list(self.c_config.regs_sort)
        )

        # TODO: make it os agnostic?
        calling_convention = (
            p.archinfo.cc["LinuxPreserveNone"]
            if p.compiler.preserve_none
            else p.archinfo.cc["Linux"]
        )
        subregister_table = p.archinfo.subregisters
        subregister_float_table = p.archinfo.subregisters_float

        # Figure out if there are any extra registers that we need to expose to the user
        # that aren't part of the calling convention. For x64 preserve_none, this will be
        # registers r10 and rbx.
        extra_saved = set(p.archinfo.regs)
        # Note that we cannot control callee saved registers. If we attempt to define
        # some registers via 'register uint64_t rbx asm("rbx");', the compiler will insert
        # push and pop instructions to save these registers.
        extra_saved = (
            extra_saved
            - set(calling_convention)
            - set(p.archinfo.callee_saved["Linux"])
        )
        extra_saved_in = list(extra_saved)
        # We don't want to necessarily output registers that have been marked as scratch
        # However we always want to make them available as input
        extra_saved_out = list(extra_saved - c_scratch_regs)

        def uint_converter(size: int):
            return f"uint{size}_t"

        extra_saved_in_converted = convert_to_subregisters(
            extra_saved_in, subregister_table, c_regs_sort, uint_converter
        )
        extra_saved_out_converted = convert_to_subregisters(
            extra_saved_out, subregister_table, c_regs_sort, uint_converter
        )

        calling_convention_float: list[str] = p.archinfo.cc_float["Linux"]
        extra_saved_float = set(p.archinfo.regs_float)
        extra_saved_float = (
            extra_saved_float
            - set(calling_convention_float)
            - set(p.archinfo.callee_saved_float["Linux"])
        )
        extra_saved_float_in = list(extra_saved_float)
        extra_saved_float_out = list(extra_saved_float - c_scratch_regs)

        def float_converter(size: int):
            if size in p.archinfo.float_types:
                return p.archinfo.float_types[size]
            else:
                raise ValueError(
                    f"Unable to determine type of float with size of {size} bits"
                )

        extra_saved_float_in_converted = convert_to_subregisters(
            extra_saved_float_in, subregister_float_table, c_regs_sort, float_converter
        )
        extra_saved_float_out_converted = convert_to_subregisters(
            extra_saved_float_out, subregister_float_table, c_regs_sort, float_converter
        )

        attribute = "__attribute__((preserve_none))" if p.compiler.preserve_none else ""

        int_args = convert_to_subregisters(
            calling_convention, subregister_table, c_regs_sort, uint_converter
        )
        int_args_str = [f"{itype} {name}" for (name, itype) in int_args]
        float_args: list[tuple[str, str]] = convert_to_subregisters(
            calling_convention_float,
            subregister_float_table,
            c_regs_sort,
            float_converter,
        )
        float_args_str = [f"{ftype} {name}" for (name, ftype) in float_args]
        args_str = ", ".join(int_args_str + float_args_str)

        callback_forward_decl = f"extern void {attribute} _CALLBACK({args_str});"

        # Stupid macro tricks to make coding the patch a little bit nicer. This allows the user
        # to write 'return;' instead of having to understand how to call the callback
        # reg_name if reg_name in self.c_out_regs else '_dummy'
        return_macro_lines = [
            "#define return do {",
        ]

        for reg, _ in extra_saved_out_converted:
            # Make sure the variables are live just before the return statement
            return_macro_lines.append(f'    asm ("" : : "r"({reg}) :);')
        for reg, _ in extra_saved_float_out_converted:
            # Make sure the variables are live just before the return statement
            return_macro_lines.append(f'    asm ("" : : "r"({reg}) :);')

        callback_args = [
            "_dummy" if reg_name in c_scratch_regs else reg_name
            for (reg_name, bits) in int_args
        ]
        callback_args += [
            "_dummyFloat" if reg_name in c_scratch_regs else reg_name
            for (reg_name, ftype) in float_args
        ]
        return_macro_lines += [
            "    __attribute__((musttail)) return _CALLBACK({});".format(
                ", ".join(callback_args)
            ),
            "} while(0)",
        ]

        return_macro = "\\\n".join(return_macro_lines)

        lines = [
            "#include <stdint.h>",
            "",
            callback_forward_decl,
            "",
            c_forward_header,
            "",
            return_macro,
            "",
            f"void {attribute} _MICROPATCH({args_str}) {{",
            f"    uint{p.archinfo.bits}_t _dummy;",
            "    float _dummyFloat;",
        ]
        for reg, reg_type in extra_saved_in_converted:
            # Force the variables to live in a specific register using the register C extension
            lines.append(f'    register {reg_type} {reg} asm("{reg}");')
        for reg, ftype in extra_saved_float_in_converted:
            lines.append(f'    register {ftype} {reg} asm("{reg}");')
        for reg, _ in extra_saved_in_converted:
            # Trick the C compiler into thinking that the variables we just defined are actually live
            lines.append(f'    asm ("" : "=r"({reg}) : : );')
        for reg, _ in extra_saved_float_in_converted:
            lines.append(f'    asm ("" : "=r"({reg}) : : );')
        lines += [
            self.instr,
            # Make sure we actually do the callback in case the user forgets to put in a return
            "    return;",
            "}",
            "#undef return",
        ]
        code = "\n".join(lines)
        logger.info("InsertInstructionPatch generated C code:\n" + code)
        p.utils.insert_trampoline_code(
            self.addr,
            code,
            force_insert=self.force_insert,
            detour_pos=self.detour_pos,
            symbols=self.symbols,
            language="C",
            asm_header=self.c_config.asm_header,
            asm_footer=self.c_config.asm_footer,
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
