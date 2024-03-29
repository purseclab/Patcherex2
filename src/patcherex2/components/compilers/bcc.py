import logging
import os

from ..assets.assets import Assets
from .compiler import Compiler

logger = logging.getLogger(__name__)


class Bcc(Compiler):
    def __init__(self, p) -> None:
        super().__init__(p)
        self.assets_path = Assets("bcc").path
        self._compiler = os.path.join(self.assets_path, "sparc-gaisler-elf-gcc")
        self._linker = os.path.join(self.assets_path, "sparc-gaisler-elf-ld")
        self._compiler_flags = ["-qbsp=gr712rc", "-mcpu=leon3", "-mfix-gr712rc"]
