import hashlib
import logging
import os
import tarfile
import tempfile
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class AssetIntegrityError(RuntimeError):
    """Raised when a downloaded asset's sha256 does not match the pinned value."""


class Assets:
    ASSETS_DIR = Path(__file__).parent
    # Each asset is pinned to a sha256 computed against the canonical
    # tarball. We refuse to extract anything that doesn't match -- these
    # archives ship binaries (compilers, assemblers, shared objects) that
    # patcherex2 then invokes, so a tampered tarball would have full RCE
    # on the host.
    ASSETS = {
        "bcc": {
            "url": "https://assets.patcherex.pursec.han.ac/bcc-2.2.4-gcc-linux64.tar.xz",
            "path": ASSETS_DIR / "bcc" / "bcc-2.2.4-gcc" / "bin",
            "sha256": "1cc391f317e59aaa8fec965d0ebeea7bb24be2ef32b2ec5e066118c156ed2d7f",
        },
        "ppc_vle": {
            "url": "https://assets.patcherex.pursec.han.ac/powerpc-eabivle.tgz",
            "path": ASSETS_DIR / "ppc_vle" / "bin",
            "sha256": "8fbf19ec4033736095a9146d6c7b32eebae6f33a1494510fdc16c16ec5e8753d",
        },
        "llvm_recomp": {
            "url": "https://assets.patcherex.pursec.han.ac/llvm_recomp.tgz",
            "path": ASSETS_DIR / "llvm_recomp",
            "sha256": "dbf01eb233026b60685a96a0449f0c4fe77d99827124204eddd46632ca81ddf8",
        },
    }

    def __init__(self, name: str) -> None:
        self.name = name
        self.url = self.ASSETS[name]["url"]
        self.path = self.ASSETS[name]["path"]
        self.sha256 = self.ASSETS[name]["sha256"]
        if not os.path.exists(self.ASSETS_DIR / self.name):
            logger.info(f"{self.name} not found, downloading...")
            self.download()

    def download(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            archive_path = os.path.join(td, "asset.tgz")
            digest = hashlib.sha256()
            # Stream to disk and hash in one pass: these tarballs are
            # hundreds of MB, no need to buffer them in memory.
            with requests.get(self.url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(archive_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        if not chunk:
                            continue
                        digest.update(chunk)
                        f.write(chunk)
            actual = digest.hexdigest()
            if actual != self.sha256:
                raise AssetIntegrityError(
                    f"sha256 mismatch for {self.name}: "
                    f"expected {self.sha256}, got {actual}"
                )
            with tarfile.open(archive_path) as tar:
                # FIXME: better use filter here but it requires > py3.12. all tarball are manually verified to be safe so it's fine for now
                tar.extractall(path=self.ASSETS_DIR / self.name)
