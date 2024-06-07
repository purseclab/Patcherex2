from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ghidra import Ghidra
from ..components.compilers.llvm_recomp_arm import LLVMRecompArm
from .elf_arm_linux import ElfArmLinux


class ElfArmLinuxRecomp(ElfArmLinux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_compiler(self, compiler):
        compiler = compiler or "llvm_recomp"
        if compiler == "llvm_recomp":
            return LLVMRecompArm(self.p)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer, **kwargs):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path, **kwargs)
        if binary_analyzer == "ghidra":
            return Ghidra(self.binary_path, **kwargs)
        raise NotImplementedError()
