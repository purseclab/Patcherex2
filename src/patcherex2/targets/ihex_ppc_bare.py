import logging

import archinfo

from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.archinfo.ppc_vle import PpcVleInfo
from ..components.assemblers.ppc_vle import PpcVle as PpcVleAssembler
from ..components.binary_analyzers.angr import Angr
from ..components.binfmt_tools.ihex import IHex
from ..components.compilers.ppc_vle import PpcVle as PpcVleCompiler
from ..components.disassemblers.ppc_vle import PpcVle as PpcVleDisassembler
from ..components.utils.utils import Utils
from .target import Target

logger = logging.getLogger(__name__)


class IHexPPCBare(Target):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "default"
        if assembler == "default":
            return PpcVleAssembler(self.p)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "default"
        if compiler == "default":
            return PpcVleCompiler(self.p)
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "default"
        if disassembler == "default":
            return PpcVleDisassembler(self.p)
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return IHex(self.p, self.binary_path)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(
                self.binary_path,
                angr_kwargs={
                    "arch": archinfo.ArchPcode("PowerPC:BE:32:MPC8270"),
                    "auto_load_libs": False,
                    "load_debug_info": True,
                },
                angr_cfg_kwargs={
                    "normalize": True,
                    "data_references": True,
                    "force_smart_scan": False,
                    "force_complete_scan": False,
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
            return PpcVleInfo()
        raise NotImplementedError()
