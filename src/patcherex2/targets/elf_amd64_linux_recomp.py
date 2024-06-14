from ..components.binary_analyzers.angr import Angr
from ..components.binary_analyzers.ghidra import Ghidra
from ..components.compilers.llvm_recomp import LLVMRecomp
from .elf_amd64_linux import ElfAmd64Linux


class ElfAmd64LinuxRecomp(ElfAmd64Linux):
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
        if binary_analyzer == "ghidra":
            return Ghidra(self.binary_path, **kwargs)
        raise NotImplementedError()
