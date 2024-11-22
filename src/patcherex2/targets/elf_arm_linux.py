from ..components.allocation_managers.allocation_manager import AllocationManager
from ..components.archinfo.arm import ArmInfo
from ..components.assemblers.keystone_arm import KeystoneArm
from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ghidra import Ghidra
from ..components.binfmt_tools.elf import ELF
from ..components.compilers.clang_arm import ClangArm
from ..components.disassemblers.capstone_arm import CapstoneArm
from ..components.utils.utils import Utils
from .target import Target


class ElfArmLinux(Target):
    @staticmethod
    def detect_target(binary_path):
        with open(binary_path, "rb") as f:
            magic = f.read(0x14)
            if magic.startswith(b"\x7fELF") and magic.startswith(
                b"\x28\x00", 0x12
            ):  # EM_ARM
                return True
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
            return ArmInfo()
        raise NotImplementedError()
