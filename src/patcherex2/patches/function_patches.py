"""
Contains patches that modify the binary at the function level.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import partial
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
        :param detour_pos: If needed, memory address where the replacement is placed, defaults to -1
        :param symbols: Symbols to include when compiling, in format {symbol name: memory address}, defaults to None
        """
        self.code = code
        self.detour_pos = detour_pos
        self.addr_or_name = addr_or_name
        self.symbols = symbols if symbols else {}
        self.compile_opts = kwargs.get("compile_opts", {})

    def apply(self, p: Patcherex) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        """
        func = p.binary_analyzer.get_function(self.addr_or_name)
        func_addr = func["addr"]
        is_thumb = p.binary_analyzer.is_thumb(func_addr)

        compile_at = partial(
            p.compiler.compile,
            self.code,
            symbols=self.symbols,
            is_thumb=is_thumb,
            **self.compile_opts,
        )

        compiled = compile_at(func_addr)
        if len(compiled) <= func["size"]:
            file_addr = p.binfmt_tool.mem_addr_to_file_offset(func_addr)
            p.binfmt_tool.update_binary_content(file_addr, compiled)
            return

        mem_addr, file_addr, compiled = self._create_detour_target(
            p,
            func_addr,
            compiled,
            compile_at,
        )
        self._install_detour(
            p,
            source_addr=func_addr,
            target_addr=mem_addr,
            is_thumb=is_thumb,
        )
        p.binfmt_tool.update_binary_content(file_addr, compiled)

    def _create_detour_target(
        self,
        p: Patcherex,
        source_addr: int,
        initial_compiled: bytes,
        compile_at: Callable[[int], bytes],
    ) -> tuple[int, int, bytes]:
        if self.detour_pos != -1:
            mem_addr = self.detour_pos
            compiled = compile_at(mem_addr)
            file_addr = p.binfmt_tool.mem_addr_to_file_offset(mem_addr)
            return mem_addr, file_addr, compiled

        block, compiled = p.utils.allocate_generated_code(
            len(initial_compiled),
            compile_at,
            align=p.archinfo.alignment,
            flag=MemoryFlag.RX,
            allocation_options=lambda _requested_size: p.utils.jump_allocation_options(
                source_addr
            ),
        )
        return block.mem_addr, block.file_addr, compiled

    def _install_detour(
        self,
        p: Patcherex,
        source_addr: int,
        target_addr: int,
        is_thumb: bool,
    ) -> None:
        p.utils.validate_jump_reachability(source_addr, target_addr)
        jmp_bytes = p.assembler.assemble(
            p.archinfo.jmp_asm.format(dst=hex(target_addr)),
            source_addr,
            is_thumb=is_thumb,
        )
        p.binfmt_tool.update_binary_content(
            p.binfmt_tool.mem_addr_to_file_offset(source_addr),
            jmp_bytes,
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
        :param detour_pos: Memory address for the trampoline or named function, defaults to -1
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
        self.prefunc = kwargs.get("prefunc", None)
        self.postfunc = kwargs.get("postfunc", None)
        self.compile_opts = kwargs.get("compile_opts", {})
        self.save_context = kwargs.get("save_context", False)

    def apply(self, p: Patcherex) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        """
        if self.addr is not None:
            self._apply_at_address(p, self.addr)
            return
        if self.name:
            self._apply_named(p, self.name)

    def _apply_at_address(self, p: Patcherex, addr: int) -> None:
        prefunc = self._expand_context_macros(p, self.prefunc)
        postfunc = self._expand_context_macros(p, self.postfunc)
        function_name = f"__patcherex_{hex(addr)}"

        InsertFunctionPatch(
            function_name,
            self.code,
            is_thumb=p.binary_analyzer.is_thumb(addr),
            symbols=self.symbols,
        ).apply(p)

        instrs = ""
        instrs += p.archinfo.save_context_asm if self.save_context else ""
        instrs += prefunc
        instrs += "\n"
        # NOTE: This is hardcoded to bl, not blx, but it is valid for this use case.
        instrs += p.archinfo.call_asm.format(dst=f"{{{function_name}}}")
        instrs += "\n"
        instrs += postfunc
        instrs += p.archinfo.restore_context_asm if self.save_context else ""
        p.utils.insert_trampoline_code(
            addr,
            instrs,
            force_insert=self.force_insert,
            detour_pos=self.detour_pos,
            symbols=self.symbols,
        )

    @staticmethod
    def _expand_context_macros(
        p: Patcherex,
        instrs: str | None,
    ) -> str:
        if not instrs:
            return ""
        return instrs.replace(
            "SAVE_CONTEXT",
            f"\n{p.archinfo.save_context_asm}\n",
        ).replace(
            "RESTORE_CONTEXT",
            f"\n{p.archinfo.restore_context_asm}\n",
        )

    def _apply_named(self, p: Patcherex, name: str) -> None:
        compile_at = partial(
            p.compiler.compile,
            self.code,
            symbols=self.symbols,
            is_thumb=self.is_thumb,
            **self.compile_opts,
        )

        compiled = compile_at(0)
        if self.detour_pos == -1:
            block, compiled = p.utils.allocate_generated_code(
                len(compiled),
                compile_at,
                align=p.archinfo.alignment,
                flag=MemoryFlag.RX,
            )
            mem_addr = block.mem_addr
            file_addr = block.file_addr
        else:
            mem_addr = self.detour_pos
            compiled = compile_at(mem_addr)
            file_addr = p.binfmt_tool.mem_addr_to_file_offset(mem_addr)

        p.sypy_info["patcherex_added_functions"].append(hex(mem_addr))
        p.symbols[name] = mem_addr
        p.binfmt_tool.update_binary_content(file_addr, compiled)


class RemoveFunctionPatch(Patch):
    """
    Patch that removes a function from the binary. Not implemented.
    """

    def __init__(self, parent=None) -> None:
        """
        Constructor.
        """
        raise NotImplementedError()
