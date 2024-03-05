import logging
from typing import Dict, Optional, Union

from ..components.allocation_managers.allocation_manager import MemoryFlag
from .patch import Patch

logger = logging.getLogger(__name__)


class ModifyInstructionPatch(Patch):
    def __init__(
        self, addr: int, instr: str, symbols: Optional[Dict[str, int]] = None
    ) -> None:
        self.addr = addr
        self.instr = instr
        self.symbols = symbols if symbols else {}

    def apply(self, p) -> None:
        # TODO: check size, insert jump if necessary
        asm_bytes = p.assembler.assemble(
            self.instr,
            self.addr,
            symbols=self.symbols,
            is_thumb=p.binary_analyzer.is_thumb(self.addr),
        )
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, asm_bytes)


class InsertInstructionPatch(Patch):
    def __init__(
        self,
        addr_or_name: Union[int, str],
        instr: str,
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
        self.instr = instr
        self.force_insert = force_insert
        self.detour_pos = detour_pos
        self.symbols = symbols if symbols else {}
        self.is_thumb = is_thumb
        self.save_context = (
            kwargs["save_context"] if "save_context" in kwargs else False
        )

    def apply(self, p) -> None:
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
    def __init__(
        self,
        addr: int,
        num_instr: Optional[int] = None,
        num_bytes: Optional[int] = None,
    ) -> None:
        self.addr = addr
        self.num_instr = num_instr
        self.num_bytes = num_bytes
        if self.num_instr is None and self.num_bytes is None:
            self.num_instr = 1

    def apply(self, p):
        if self.num_bytes is None:
            raise NotImplementedError()
        if self.num_bytes and self.num_bytes % p.archinfo.nop_size != 0:
            raise Exception(
                f"Cannot remove {self.num_bytes} bytes, must be a multiple of {p.archinfo.nop_size}"
            )
        num_nops = self.num_bytes // p.archinfo.nop_size
        offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
        p.binfmt_tool.update_binary_content(offset, p.archinfo.nop_bytes * num_nops)
