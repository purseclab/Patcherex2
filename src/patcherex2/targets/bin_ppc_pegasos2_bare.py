"""
0000000000000000-000000001fffffff (prio 0, ram): pegasos2.ram
00000000fff00000-00000000fff7ffff (prio 0, rom): pegasos2.rom
execution starts at 0xfff00100 (0x100 from ROM base).
first 0x100 bytes are the interrupt vector table
"""

from __future__ import annotations

import logging

from ..components.allocation_managers.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from ..components.archinfo.ppc import PpcInfo
from ..components.assemblers.keystone import Keystone, keystone
from ..components.assemblers.nyxstone import Nyxstone as NyxstoneAssembler
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.binary import Binary
from ..components.compilers.clang import Clang
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.disassemblers.nyxstone import Nyxstone as NyxstoneDisassembler
from ..components.utils.utils import Utils
from .target import Target

logger = logging.getLogger(__name__)

_DEFAULT_LOAD_BASE = 0xFFF00000
_DEFAULT_ENTRY = 0xFFF00100
_DEFAULT_MAX_SIZE = 0x80000


class BarePpcBinary(Binary):
    def __init__(
        self,
        p,
        binary_path: str,
        load_base: int = _DEFAULT_LOAD_BASE,
        max_size: int = _DEFAULT_MAX_SIZE,
    ) -> None:
        super().__init__(p, binary_path)
        self.load_base = load_base
        self.max_size = max_size
        if self.file_size > max_size:
            raise ValueError(
                f"Input binary ({self.file_size} bytes) is larger than "
                f"the configured ROM region ({hex(max_size)})"
            )
        self._init_memory_analysis()

    def _init_memory_analysis(self) -> None:
        self.p.allocation_manager.add_block(
            MappedBlock(
                file_addr=0,
                mem_addr=self.load_base,
                size=self.file_size,
                is_free=False,
                flag=MemoryFlag.RX,
            )
        )
        self.p.allocation_manager.add_block(FileBlock(self.file_size, -1))
        self.p.allocation_manager.add_block(
            MemoryBlock(self.load_base + self.file_size, -1)
        )

    def page_alignment(self) -> int:
        return 4

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        end = offset + len(new_content)
        if end > self.max_size:
            raise ValueError(
                f"Patched binary would grow to {hex(end)} bytes, exceeding "
                f"the configured ROM size of {hex(self.max_size)}"
            )
        super().update_binary_content(offset, new_content)

    def append_to_binary_content(self, new_content: bytes) -> None:
        end = self.file_size + len(new_content)
        if end > self.max_size:
            raise ValueError(
                f"Appending {len(new_content)} bytes would grow the binary "
                f"to {hex(end)}, exceeding the configured ROM size of "
                f"{hex(self.max_size)}"
            )
        super().append_to_binary_content(new_content)


class BinPpcPegasos2Bare(Target):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return Keystone(
                self.p,
                keystone.KS_ARCH_PPC,
                keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_PPC32,
            )
        if assembler == "nyxstone":
            return NyxstoneAssembler(
                self.p,
                "powerpc-unknown-linux-gnu",
                "7450",
                "+altivec",
            )
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "nyxstone"
        if disassembler == "nyxstone":
            return NyxstoneDisassembler(
                "powerpc-unknown-linux-gnu",
                "7450",
                "+altivec",
            )
        if disassembler == "capstone":
            cs = Capstone(
                capstone.CS_ARCH_PPC,
                capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_32,
            )
            cs.cs.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME
            return cs
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return Clang(
                self.p,
                compiler_flags=[
                    "-target",
                    "powerpc-unknown-elf",
                    "-mcpu=7450",
                    "-mbig-endian",
                    "-ffreestanding",
                    "-nostdlib",
                    "-fno-pic",
                    "-fno-builtin",
                ],
            )
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool, **kwargs):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return BarePpcBinary(self.p, self.binary_path, **kwargs)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer, **kwargs):
        base_addr = kwargs.pop("base_addr", _DEFAULT_LOAD_BASE)
        entry_point = kwargs.pop("entry_point", _DEFAULT_ENTRY)
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(
                self.binary_path,
                angr_kwargs={
                    "main_opts": {
                        "backend": "blob",
                        "arch": "PowerPC:BE:32:default",
                        "base_addr": base_addr,
                        "entry_point": entry_point,
                    },
                    "auto_load_libs": False,
                },
                angr_cfg_kwargs={
                    "normalize": True,
                    "data_references": True,
                },
            )
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()

    def get_archinfo(self, archinfo):
        archinfo = archinfo or "default"
        if archinfo == "default":
            return PpcInfo()
        raise NotImplementedError()
