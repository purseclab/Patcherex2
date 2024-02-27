import logging
import os

from ..assets.assets import Assets
from .compiler import Compiler

logger = logging.getLogger(__name__)


class PpcVle(Compiler):
    def __init__(self, p) -> None:
        super().__init__(p)
        self.assets_path = Assets("ppc_vle").path
        self._compiler = os.path.join(self.assets_path, "powerpc-eabivle-gcc")
        self._linker = os.path.join(self.assets_path, "powerpc-eabivle-ld")
        self._compiler_flags = ["-mno-vle"]
