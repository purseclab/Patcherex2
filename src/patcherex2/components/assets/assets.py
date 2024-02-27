import logging
import os
import tarfile
import tempfile
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class Assets:
    ASSETS_DIR = Path(__file__).parent
    ASSETS = {
        "bcc": {
            "url": "https://assets.patcherex.pursec.han.ac/bcc-2.2.4-gcc-linux64.tar.xz",
            "path": ASSETS_DIR / "bcc" / "bcc-2.2.4-gcc" / "bin",
        },
        "ppc_vle": {
            "url": "https://assets.patcherex.pursec.han.ac/powerpc-eabivle.tgz",
            "path": ASSETS_DIR / "ppc_vle" / "bin",
        },
        "llvm_recomp": {
            "url": "https://assets.patcherex.pursec.han.ac/llvm_recomp.tgz",
            "path": ASSETS_DIR / "llvm_recomp",
        },
    }

    def __init__(self, name: str) -> None:
        self.name = name
        self.url = self.ASSETS[name]["url"]
        self.path = self.ASSETS[name]["path"]
        if not os.path.exists(self.ASSETS_DIR / self.name):
            logger.info(f"{self.name} not found, downloading...")
            self.download()

    def download(self) -> None:
        r = requests.get(self.url)
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "asset.tgz"), "wb") as f:
                f.write(r.content)
            with tarfile.open(os.path.join(td, "asset.tgz")) as tar:
                # FIXME: better use filter here but it requires > py3.12. all tarball are manually verified to be safe so it's fine for now
                tar.extractall(path=self.ASSETS_DIR / self.name)
