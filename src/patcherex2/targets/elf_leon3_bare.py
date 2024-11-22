import logging

from ..components.allocation_managers.allocation_manager import (
    AllocationManager,
    MappedBlock,
    MemoryFlag,
)
from ..components.archinfo.sparc import SparcInfo
from ..components.assemblers.bcc import Bcc as BccAssembler
from ..components.assemblers.keystone_sparc import KeystoneSparc, keystone
from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ghidra import Ghidra
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.bcc import Bcc as BccCompiler
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.utils.utils import Utils
from .target import Target

logger = logging.getLogger(__name__)


class CustomElf(ELF):
    def _init_memory_analysis(self):
        # remove all non-RWX segments
        self._segments = [s for s in self._segments if s["p_flags"] & 0b111 == 0b111]
        block = MappedBlock(
            self._segments[0]["p_offset"],
            self._segments[0]["p_vaddr"],
            self._segments[0]["p_memsz"],
            is_free=False,
            flag=MemoryFlag.RWX,
        )
        self.p.allocation_manager.add_block(block)


class ElfLeon3Bare(Target):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return KeystoneSparc(
                self.p,
                keystone.KS_ARCH_SPARC,
                keystone.KS_MODE_SPARC32 + keystone.KS_MODE_BIG_ENDIAN,
            )
        elif assembler == "bcc":
            return BccAssembler(self.p)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "bcc"
        if compiler == "bcc":
            return BccCompiler(self.p)
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return Capstone(capstone.CS_ARCH_SPARC, capstone.CS_MODE_BIG_ENDIAN)
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "custom"
        if binfmt_tool == "custom":
            return CustomElf(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer, **kwargs):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path, **kwargs)
        if binary_analyzer == "ghidra":
            return Ghidra(self.binary_path, **kwargs)
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()

    def get_archinfo(self, archinfo):
        archinfo = archinfo or "default"
        if archinfo == "default":
            return SparcInfo()
        raise NotImplementedError()
