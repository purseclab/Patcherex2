"""
Contains patches that modify the binary at the function level.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..components.allocation_managers.allocation_manager import MemoryFlag
from .patch import Patch

if TYPE_CHECKING:
    from ..patcherex import Patcherex

logger = logging.getLogger(__name__)


class ModifyFunctionPatch(Patch):
    """
    Patch that replaces an existing function in the binary with your own. If there is enough room in the existing
    function, your code is compiled and placed there. If not, your code is placed in a free spot in the binary, and
    the function will jump there instead.
    """

    def __init__(
        self,
        addr_or_name: int | str,
        code: str,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        **kwargs,
    ) -> None:
        """
        Constructor.

        :param addr_or_name: The name or file address of the function.
        :param code: C code to replace the function.
        :param detour_pos: If original function is not big enough, file address to place the given code, defaults to -1
        :param symbols: Symbols to include when compiling, in format {symbol name: memory address}, defaults to None
        """
        self.code = code
        self.detour_pos = detour_pos
        self.addr_or_name = addr_or_name
        self.symbols = symbols if symbols else {}
        self.compile_opts = kwargs["compile_opts"] if "compile_opts" in kwargs else {}

    def apply(self, p: Patcherex) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        """
        func = p.binary_analyzer.get_function(self.addr_or_name)
        compiled_size = len(
            p.compiler.compile(
                self.code,
                symbols=self.symbols,
                is_thumb=p.binary_analyzer.is_thumb(func["addr"]),
                **self.compile_opts,
            )
        )
        if compiled_size <= func["size"]:
            mem_addr = func["addr"]
            file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
        else:
            # TODO: mark the function as free (exclude jump instr)
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    compiled_size + 0x20, align=0x4, flag=MemoryFlag.RX
                )
                mem_addr = block.mem_addr
                file_addr = block.file_addr
            else:
                mem_addr = self.detour_pos
                file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            jmp_instr = p.archinfo.jmp_asm.format(dst=hex(mem_addr))
            jmp_bytes = p.assembler.assemble(
                jmp_instr,
                func["addr"],
                is_thumb=p.binary_analyzer.is_thumb(func["addr"]),
            )
            p.binfmt_tool.update_binary_content(
                p.binary_analyzer.mem_addr_to_file_offset(func["addr"]),
                jmp_bytes,
            )
        p.binfmt_tool.update_binary_content(
            file_addr,
            p.compiler.compile(
                self.code,
                mem_addr,
                symbols=self.symbols,
                is_thumb=p.binary_analyzer.is_thumb(func["addr"]),
                **self.compile_opts,
            ),
        )


class InsertFunctionPatch(Patch):
    """
    Inserts a function into the binary.
    """

    def __init__(
        self,
        addr_or_name: int | str,
        code: str,
        force_insert=False,
        detour_pos=-1,
        symbols: dict[str, int] | None = None,
        is_thumb=False,
        **kwargs,
    ) -> None:
        """
        Constructor.

        :param addr_or_name: If an integer, an intermediate function is created in a free spot in the binary,
                             and at that address, a jump to the function is made with necessary context saves.
                             If a string, the function is created in a free spot in the binary with that name.
        :param code: C code for the new function. "SAVE_CONTEXT" and "RESTORE_CONTEXT" can be used to save and restore context.
        :param force_insert: If Patcherex should ignore whether instructions can be moved when inserting, defaults to False
        :param detour_pos: If address is used, this is the address to place trampoline code for jumping to function.
                           If name is used, this is where the new function will be placed, defaults to -1
        :param symbols: Symbols to include when compiling/assembling, in format {symbol name: memory address}, defaults to None
        :param is_thumb: Whether the instructions given are thumb, defaults to False
        :param kwargs: Extra options. Can include "prefunc" and "postfunc", instructions to go before or after your function if you give an address.
                         Can also have "save_context" for whether context should be saved and "compile_opts" for extra compile options.
        """
        self.addr = None
        self.name = None
        if isinstance(addr_or_name, int):
            self.addr = addr_or_name
        elif isinstance(addr_or_name, str):
            self.name = addr_or_name
        self.code = code
        self.detour_pos = detour_pos
        self.symbols = symbols if symbols else {}
        self.is_thumb = is_thumb
        self.force_insert = force_insert
        self.prefunc = kwargs["prefunc"] if "prefunc" in kwargs else None
        self.postfunc = kwargs["postfunc"] if "postfunc" in kwargs else None
        self.compile_opts = kwargs["compile_opts"] if "compile_opts" in kwargs else {}
        self.save_context = (
            kwargs["save_context"] if "save_context" in kwargs else False
        )

    def apply(self, p: Patcherex) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        """
        if self.addr:
            if self.prefunc:
                if "SAVE_CONTEXT" in self.prefunc:
                    self.prefunc = self.prefunc.replace(
                        "SAVE_CONTEXT", f"\n{p.archinfo.save_context_asm}\n"
                    )
                if "RESTORE_CONTEXT" in self.prefunc:
                    self.prefunc = self.prefunc.replace(
                        "RESTORE_CONTEXT", f"\n{p.archinfo.restore_context_asm}\n"
                    )
            if self.postfunc:
                if "SAVE_CONTEXT" in self.postfunc:
                    self.postfunc = self.postfunc.replace(
                        "SAVE_CONTEXT", f"\n{p.archinfo.save_context_asm}\n"
                    )
                if "RESTORE_CONTEXT" in self.postfunc:
                    self.postfunc = self.postfunc.replace(
                        "RESTORE_CONTEXT", f"\n{p.archinfo.restore_context_asm}\n"
                    )
            ifp = InsertFunctionPatch(
                f"__patcherex_{hex(self.addr)}",
                self.code,
                is_thumb=p.binary_analyzer.is_thumb(self.addr),
                symbols=self.symbols,
            )
            ifp.apply(p)
            instrs = ""
            instrs += p.archinfo.save_context_asm if self.save_context else ""
            instrs += self.prefunc if self.prefunc else ""
            instrs += "\n"
            # NOTE: ↓ this is hardcoded to bl, not blx, but it should be fine for this use case
            instrs += p.archinfo.call_asm.format(
                dst=f"{{__patcherex_{hex(self.addr)}}}"
            )
            instrs += "\n"
            instrs += self.postfunc if self.postfunc else ""
            instrs += p.archinfo.restore_context_asm if self.save_context else ""
            p.utils.insert_trampoline_code(
                self.addr,
                instrs,
                force_insert=self.force_insert,
                detour_pos=self.detour_pos,
                symbols=self.symbols,
            )
        elif self.name:
            compiled_size = len(
                p.compiler.compile(
                    self.code,
                    symbols=self.symbols,
                    is_thumb=self.is_thumb,
                    **self.compile_opts,
                )
            )
            if self.detour_pos == -1:
                block = p.allocation_manager.allocate(
                    compiled_size + 0x20, align=p.archinfo.alignment, flag=MemoryFlag.RX
                )  # TODO: adjust that 0x20 part
                mem_addr = block.mem_addr
                file_addr = block.file_addr
            else:
                mem_addr = self.detour_pos
                file_addr = p.binary_analyzer.mem_addr_to_file_offset(mem_addr)
            p.sypy_info["patcherex_added_functions"].append(hex(mem_addr))
            p.symbols[self.name] = mem_addr
            p.binfmt_tool.update_binary_content(
                file_addr,
                p.compiler.compile(
                    self.code,
                    mem_addr,
                    symbols=self.symbols,
                    is_thumb=self.is_thumb,
                    **self.compile_opts,
                ),
            )


class RemoveFunctionPatch(Patch):
    """
    Patch that removes a function from the binary. Not implemented.
    """

    def __init__(self, parent=None) -> None:
        """
        Constructor.
        """
        raise NotImplementedError()
