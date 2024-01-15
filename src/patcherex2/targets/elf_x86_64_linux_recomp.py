from ..components.binary_analyzers.angr import Angr
from ..components.compilers.llvm_recomp import LLVMRecomp
from .elf_x86_64_linux import ElfX8664Linux


class ElfX8664LinuxRecomp(ElfX8664Linux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_compiler(self, compiler):
        compiler = compiler or "llvm_recomp"
        if compiler == "llvm_recomp":
            return LLVMRecomp(self.p)
        raise NotImplementedError()

    def get_binary_analyzer(self, binary_analyzer, **kwargs):
        binary_analyzer = binary_analyzer or "angr"
        if binary_analyzer == "angr":
            return Angr(self.binary_path, **kwargs)
        raise NotImplementedError()
