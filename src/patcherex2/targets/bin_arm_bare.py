import logging

from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.archinfo.arm import ArmInfo
from ..components.assemblers.keystone_arm import KeystoneArm
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.binary import Binary
from ..components.compilers.clang_arm import ClangArm
from ..components.disassemblers.capstone_arm import CapstoneArm
from ..components.utils.utils import Utils
from .target import Target

logger = logging.getLogger(__name__)


class BinArmBare(Target):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return KeystoneArm(self.p)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return ClangArm(self.p, compiler_flags=["-target", "arm-linux-gnueabihf"])
        elif compiler == "clang19":
            return ClangArm(
                self.p,
                compiler_flags=["-target", "arm-linux-gnueabihf"],
                clang_version=19,
            )
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return CapstoneArm(self.p)
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return Binary(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(
                self.binary_path,
                angr_kwargs={
                    "arch": "ARMEL",
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
            return ArmInfo()
        raise NotImplementedError()
