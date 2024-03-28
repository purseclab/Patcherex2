from __future__ import annotations


class Disassembler:
    def __init__(self, p) -> None:
        self.p = p

    def disassemble(self, input: bytes, base=0, **kwargs) -> None:
        raise NotImplementedError()

    def to_asm_string(self, insn: dict[str, int | str]) -> str:
        return "{} {}".format(insn["mnemonic"], insn["op_str"])
