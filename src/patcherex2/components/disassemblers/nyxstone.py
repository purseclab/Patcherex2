from __future__ import annotations

import nyxstone

from .disassembler import Disassembler


class Nyxstone(Disassembler):
    def __init__(self, target_triple: str, cpu: str = "", features: str = ""):
        self.target_triple = target_triple
        self.cpu = cpu
        self.features = features
        self.ns = nyxstone.Nyxstone(target_triple, cpu, features)

    def disassemble(self, input: bytes, base=0, **kwargs) -> list[dict[str, int | str]]:
        ns_insns = self.ns.disassemble_to_instructions(bytearray(input), base)
        result = []
        for insn in ns_insns:
            if self.target_triple == "riscv32" and insn.assembly.split(" ")[0] in [
                "j",
                "jal",
                "call",
                "tail",
            ]:
                # convert the target address back to absolute address
                parts = insn.assembly.split(" ")
                if len(parts) == 2:
                    try:
                        addr = int(parts[1], 0)
                        if addr < 0x80000000:
                            addr += insn.address
                        insn.assembly = f"{parts[0]} {hex(addr)}"
                    except ValueError:
                        pass
            result.append(
                {
                    "address": insn.address,
                    "size": len(insn.bytes),
                    "mnemonic": insn.assembly.split(" ")[0],
                    "op_str": insn.assembly.split(" ", 1)[1]
                    if " " in insn.assembly
                    else "",
                }
            )
        return result
