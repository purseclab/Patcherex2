import logging
from typing import Dict, Optional, Union

from ..components.allocation_managers.allocation_manager import MemoryFlag
from .patch import Patch

logger = logging.getLogger(__name__)


class ModifyFunctionPatch(Patch):
    def __init__(
        self,
        addr_or_name: Union[int, str],
        code: str,
        detour_pos=-1,
        symbols: Optional[Dict[str, int]] = None,
        **kwargs,
    ) -> None:
        self.code = code
        self.detour_pos = detour_pos
        self.addr_or_name = addr_or_name
        self.symbols = symbols if symbols else {}
        self.compile_opts = kwargs["compile_opts"] if "compile_opts" in kwargs else {}

    def apply(self, p) -> None:
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
    def __init__(
        self,
        addr_or_name: Union[int, str],
        code: str,
        force_insert=False,
        detour_pos=-1,
        symbols: Optional[Dict[str, int]] = None,
        is_thumb=False,
        **kwargs,
    ) -> None:
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

    def apply(self, p) -> None:
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
    def __init__(self, parent=None) -> None:
        raise NotImplementedError()
