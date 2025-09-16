import logging

from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.archinfo.riscv32 import Riscv32Info
from ..components.assemblers.keystone import Keystone, keystone
from ..components.assemblers.nyxstone import Nyxstone as NyxstoneAssembler
from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ida import Ida
from ..components.binfmt_tools.ihex import IHex
from ..components.compilers.clang import Clang
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.disassemblers.nyxstone import Nyxstone as NyxstoneDisassembler
from ..components.utils.utils import Utils
from .target import Target

logger = logging.getLogger(__name__)


class IHexRiscv32Bare(Target):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "nyxstone"
        if assembler == "nyxstone":
            return NyxstoneAssembler(
                self.p, "riscv32", "", "+c"
            )  # +c for compressed instructions
        if assembler == "keystone":
            return Keystone(self.p, keystone.KS_ARCH_RISCV, keystone.KS_MODE_RISCV32)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "default"
        if compiler == "default":
            return Clang(self.p, compiler_flags=["-target", "riscv32-unknown-elf"])
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "nyxstone"
        if disassembler == "nyxstone":
            return NyxstoneDisassembler(
                "riscv32", "", "+c"
            )  # +c for compressed instructions
        if disassembler == "capstone":
            return Capstone(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV32 | capstone.CS_MODE_RISCVC,
            )
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return IHex(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "ida"
        if binary_analyzer == "angr":
            return Angr(
                self.binary_path,
                angr_kwargs={
                    "arch": "riscv32",  # 32b unsupported?
                    "auto_load_libs": False,
                },
                angr_cfg_kwargs={
                    "normalize": True,
                    "data_references": True,
                },
            )
        if binary_analyzer == "ida":
            return Ida(self.binary_path, processor="riscv")
        raise NotImplementedError()

    def get_utils(self, utils):
        utils = utils or "default"
        if utils == "default":
            return Utils(self.p, self.binary_path)
        raise NotImplementedError()

    def get_archinfo(self, archinfo):
        archinfo = archinfo or "default"
        if archinfo == "default":
            return Riscv32Info()
        raise NotImplementedError()
