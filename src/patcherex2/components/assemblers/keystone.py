import logging

import keystone

from .assembler import Assembler

logger = logging.getLogger(__name__)


class Keystone(Assembler):
    def __init__(self, p, arch: int, mode: int) -> None:
        super().__init__(p)
        self.arch = arch
        self.mode = mode
        self.ks = keystone.Ks(arch, mode)

    def _assemble(self, code: str, base=0, **kwargs) -> bytes:
        binary, _ = self.ks.asm(code, base)
        logger.debug(f"Assembled bytes: {bytes(binary)}")
        return bytes(binary)
