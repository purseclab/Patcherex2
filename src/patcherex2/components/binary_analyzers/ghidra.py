import pyhidra

from .binary_analyzer import BinaryAnalyzer


class Ghidra(BinaryAnalyzer):
    def __init__(self, binary_path: str, **kwargs):
        self.ctx = pyhidra.open_program(binary_path)
        self.flatapi = self.ctx.__enter__()
        self.currentProgram = self.flatapi.getCurrentProgram()

        import ghidra
        self.ghidra = ghidra

        self.bbm = self.ghidra.program.model.block.BasicBlockModel(
            self.currentProgram)

    def __del__(self):
        self.ctx.__exit__(None, None, None)

    def normalize_addr(self, addr):
        return addr - self.currentProgram.getImageBase().getOffset()

    def denormalize_addr(self, addr):
        return addr + self.currentProgram.getImageBase().getOffset()

    def mem_addr_to_file_offset(self, addr: int) -> int:
        addr = self.denormalize_addr(addr)
        return self.currentProgram.getMemory().getAddressSourceInfo(self.flatapi.toAddr(addr)).getFileOffset()

    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        addr = self.denormalize_addr(addr)

        block = self.bbm.getFirstCodeBlockContaining(self.flatapi.toAddr(
            addr), self.ghidra.util.task.TaskMonitor.DUMMY)
        if block is None:
            raise Exception(
                f"Cannot find block containing address {hex(addr)}")
        instrs = []
        i = self.currentProgram.getListing().getInstructions(block, True)
        while i.hasNext():
            instrs.append(self.normalize_addr(
                i.next().getAddress().getOffset()))
        return {
            "start": self.normalize_addr(block.getMinAddress().getOffset()),
            "end": self.normalize_addr(block.getMinAddress().getOffset())+block.getNumAddresses(),
            "size": block.getNumAddresses(),
            "instruction_addrs": instrs
        }

    def get_instr_bytes_at(self, addr: int, num_instr=1):
        addr = self.denormalize_addr(addr)
        instr = self.currentProgram.getListing(
        ).getInstructionContaining(self.flatapi.toAddr(addr))
        if instr is None:
            return None
        b = instr.getBytes()
        for i in range(1, num_instr):
            instr = instr.getNext()
            b += instr.getBytes()
        return b

    def get_unused_funcs(self) -> list[dict[str, int]]:
        fi = self.currentProgram.getListing().getFunctions(True)
        unused_funcs = []
        while fi.hasNext():
            f = fi.next()
            if not f.getSymbol().hasReferences():
                b = f.getBody()
                unused_funcs.append(
                    {"addr": self.normalize_addr(b.getMinAddress().getOffset()), "size": b.getNumAddresses()})
        return unused_funcs

    def get_all_symbols(self) -> dict[str, int]:
        symbols = {}
        # si = self.currentProgram.getSymbolTable().getAllSymbols(True)
        # while si.hasNext():
        #     s = si.next()
        #     if not s.isPrimary():
        #         continue
        #     symbols[s.getName()] = self.normalize_addr(
        #         s.getAddress().getOffset())
        fi = self.currentProgram.getListing().getFunctions(True)
        while fi.hasNext():
            f = fi.next()
            if f.getName() in symbols.keys():
                continue
            symbols[f.getName()] = self.normalize_addr(f.getEntryPoint().getOffset())
        return symbols

    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        if isinstance(name_or_addr, int):
            name_or_addr = self.denormalize_addr(name_or_addr)
            func = self.currentProgram.getListing(
            ).getFunctionContaining(self.flatapi.toAddr(name_or_addr))
            if func is None:
                return None
        elif isinstance(name_or_addr, str):
            funcs = self.currentProgram.getListing().getGlobalFunctions(name_or_addr)
            if len(funcs) == 0:
                return None
            func = funcs[0]
        else:
            raise Exception("Invalid type for argument")

        b = func.getBody()
        return {"addr": self.normalize_addr(b.getMinAddress().getOffset()), "size": b.getNumAddresses()}

    def is_thumb(self, addr: int) -> bool:
        addr = self.denormalize_addr(addr)
        r = self.currentProgram.getRegister("TMode")
        if r is None:
            return False
        v = self.currentProgram.getProgramContext().getRegisterValue(r,
                                                                     self.flatapi.toAddr(addr))
        return v.unsignedValueIgnoreMask == 1
