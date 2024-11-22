from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.archinfo.mips import MipsInfo
from ..components.assemblers.keystone import Keystone, keystone
from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ghidra import Ghidra
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.clang import Clang
from ..components.disassemblers.capstone import Capstone, capstone
from ..components.utils.utils import Utils
from .target import Target


class ElfMipsLinux(Target):
    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF\x01") and magic.startswith(
                b"\x00\x08", 0x12
            ):  # EM_MIPS
                return True
        return False

    def get_assembler(self, assembler):
        assembler = assembler or "keystone"
        if assembler == "keystone":
            return Keystone(
                self.p,
                keystone.KS_ARCH_MIPS,
                keystone.KS_MODE_BIG_ENDIAN + keystone.KS_MODE_MIPS32,
            )
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return AllocationManager(self.p)
        raise NotImplementedError()

    def get_compiler(self, compiler):
        compiler = compiler or "clang"
        if compiler == "clang":
            return Clang(self.p, compiler_flags=["--target=mips-linux-gnu"])
        raise NotImplementedError()

    def get_disassembler(self, disassembler):
        disassembler = disassembler or "capstone"
        if disassembler == "capstone":
            return Capstone(
                capstone.CS_ARCH_MIPS,
                capstone.CS_MODE_BIG_ENDIAN + capstone.CS_MODE_MIPS32,
            )
        raise NotImplementedError()

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "pyelftools"
        if binfmt_tool == "pyelftools":
            return ELF(self.p, self.binary_path)
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
            return MipsInfo()
        raise NotImplementedError()
