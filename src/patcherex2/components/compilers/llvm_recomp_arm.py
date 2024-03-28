from __future__ import annotations

import logging

from .llvm_recomp import LLVMRecomp

logger = logging.getLogger(__name__)


class LLVMRecompArm(LLVMRecomp):
    def compile(
        self,
        code: str,
        base=0,
        symbols: dict[str, int] | None = None,
        extra_compiler_flags: list[str] | None = None,
        is_thumb=False,
        **kwargs,
    ) -> bytes:
        if symbols is None:
            symbols = {}
        if extra_compiler_flags is None:
            extra_compiler_flags = []
        if is_thumb:
            extra_compiler_flags += ["-mthumb"]
        else:
            extra_compiler_flags += ["-mno-thumb"]
        compiled = super().compile(
            code,
            base=base,
            symbols=symbols,
            extra_compiler_flags=extra_compiler_flags,
            **kwargs,
        )

        # FIXME: damn this is too hacky
        _symbols = {}
        _symbols.update(self.p.symbols)
        _symbols.update(self.p.binary_analyzer.get_all_symbols())
        _symbols.update(symbols)
        symbols = _symbols
        disasm = self.p.disassembler.disassemble(compiled, base=base, is_thumb=is_thumb)
        reassembled = b""
        for instr in disasm:
            if (
                is_thumb
                and instr["mnemonic"] == "bl"
                and int(instr["op_str"][1:], 0) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("bl", "blx") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                is_thumb
                and instr["mnemonic"] == "blx"
                and (int(instr["op_str"][1:], 0) + 1) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("blx", "bl") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                not is_thumb
                and instr["mnemonic"] == "bl"
                and (int(instr["op_str"][1:], 0) + 1) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("bl", "blx") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            elif (
                not is_thumb
                and instr["mnemonic"] == "blx"
                and int(instr["op_str"][1:], 0) in symbols.values()
            ):
                disasm_str = (
                    self.p.disassembler.to_asm_string(instr).replace("blx", "bl") + "\n"
                )
                reassembled += self.p.assembler.assemble(
                    disasm_str, base=instr["address"], is_thumb=is_thumb
                )
            else:
                reassembled += compiled[
                    instr["address"] - base : instr["address"] - base + instr["size"]
                ]
        compiled = reassembled + compiled[len(reassembled) :]
        if len(compiled) % 2 != 0:
            compiled += b"\x00"
        return compiled
