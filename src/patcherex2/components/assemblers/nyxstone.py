import logging

import nyxstone

from .assembler import Assembler

logger = logging.getLogger(__name__)


class Nyxstone(Assembler):
    def __init__(
        self, p, target_triple: str, cpu: str = "", features: str = ""
    ) -> None:
        super().__init__(p)
        self.target_triple = target_triple
        self.cpu = cpu
        self.features = features
        self.ns = nyxstone.Nyxstone(target_triple, cpu, features)

    def _assemble(self, code: str, base=0, **kwargs) -> bytes:
        symbols = {}
        if self.target_triple == "riscv32":
            for line in code.splitlines():
                line = line.strip()
                if (
                    line.startswith("j ")
                    or line.startswith("jal ")
                    or line.startswith("call ")
                    or line.startswith("tail ")
                ):
                    parts = line.split(" ")
                    if len(parts) == 2 and not parts[1].startswith("__patcherex_"):
                        addr = int(parts[1], 0)
                        code = code.replace(line, f"{parts[0]} __patcherex_{hex(addr)}")
                        symbols[f"__patcherex_{hex(addr)}"] = addr
        try:
            binary = self.ns.assemble(code, base, symbols)
            logger.debug(f"Assembled bytes: {bytes(binary).hex()}")
            return bytes(binary)
        except Exception as e:
            raise Exception(
                f'Failed to assemble: """\n{code}\n"""\nat base: {hex(base)}'
            ) from e
