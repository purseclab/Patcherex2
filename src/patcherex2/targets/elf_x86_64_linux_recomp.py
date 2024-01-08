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
