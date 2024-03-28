from __future__ import annotations

import capstone

from .disassembler import Disassembler


class Capstone(Disassembler):
    def __init__(self, arch: int, mode: int) -> None:
        self.cs = capstone.Cs(arch, mode)

    def disassemble(self, input: bytes, base=0, **kwargs) -> list[dict[str, int | str]]:
        cs_insns = self.cs.disasm(input, base)
        result = []
        for insn in cs_insns:
            result.append(
                {
                    "address": insn.address,
                    "size": insn.size,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                }
            )
        return result
