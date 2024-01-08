import json
import logging
import os
import subprocess
import tempfile

import cle

from ..assets.assets import Assets
from .clang import Clang

logger = logging.getLogger(__name__)


class LLVMRecomp(Clang):
    def __init__(self, p, clang_version=15, compiler_flags=None):
        super().__init__(p, clang_version, compiler_flags)
        self._clang_version = clang_version
        self._assets_path = Assets("llvm_recomp").path

    def compile(
        self,
        code,
        base=0,
        symbols=None,
        extra_compiler_flags=None,
        is_thumb=False,
        **kwargs,
    ):
        if symbols is None:
            symbols = {}
        if extra_compiler_flags is None:
            extra_compiler_flags = []
        with tempfile.TemporaryDirectory() as td:
            # source file
            with open(os.path.join(td, "code.c"), "w") as f:
                f.write(code)

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            _symbols.update(self.p.binary_analyzer.get_all_symbols())
            _symbols.update(symbols)
            linker_script = (
                "SECTIONS { .text : SUBALIGN(0) { . = " + hex(base) + "; *(.text) "
            )
            for name, addr in _symbols.items():
                linker_script += name + " = " + hex(addr) + ";"
            linker_script += "} }"
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

            librecomp_path = os.path.join(self._assets_path, "libRecompiler.so")

            # c -> ll
            try:
                args = (
                    [self._compiler]
                    + self._compiler_flags
                    + extra_compiler_flags
                    + [
                        "-Wno-incompatible-library-redeclaration",
                        "-S",
                        "-w",
                        "-emit-llvm",
                        "-g",
                        "-o",
                        os.path.join(td, "code.ll"),
                        os.path.join(td, "code.c"),
                        "-I" "/usr/lib/clang/15/include",
                    ]
                )
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

            # ll --force-dso-local --> ll
            if "dso_local_fix" in kwargs and kwargs["dso_local_fix"]:
                try:
                    args = [
                        f"opt-{self._clang_version}",
                        f"-load-pass-plugin={librecomp_path}",
                        "-passes=force-dso-local",
                        "-S",
                        os.path.join(td, "code.ll"),
                        "-o",
                        os.path.join(td, "code.ll"),
                    ]
                    subprocess.run(args, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise e

            # ll -> o
            if "stacklayout" in kwargs and kwargs["stacklayout"]:
                with open(os.path.join(td, "stacklayout.json"), "w") as f:
                    json.dump(kwargs["stacklayout"], f)
                try:
                    args = [
                        f"llc-{self._clang_version}",
                        "-stop-before=prologepilog",
                        os.path.join(td, "code.ll"),
                        "-o",
                        os.path.join(td, "code.mir"),
                        "-relocation-model=pic",
                    ]
                    subprocess.run(args, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise e
                try:
                    args = [
                        f"llc-{self._clang_version}",
                        "-load",
                        librecomp_path,
                        "-run-pass=updated-prologepilog",
                        f"-stkloc={os.path.join(td, 'stacklayout.json')}",
                        "-o",
                        os.path.join(td, "code.2.mir"),
                        os.path.join(td, "code.mir"),
                        "-relocation-model=pic",
                    ]
                    subprocess.run(args, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise e
                try:
                    args = [
                        f"llc-{self._clang_version}",
                        "-start-after=prologepilog",
                        "-o",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "code.2.mir"),
                        "-relocation-model=pic",
                        "--filetype=obj",
                    ]
                    subprocess.run(args, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise e
            else:
                try:
                    args = [
                        f"llc-{self._clang_version}",
                        "-o",
                        os.path.join(td, "obj.o"),
                        os.path.join(td, "code.ll"),
                        "-relocation-model=pic",
                        "--filetype=obj",
                    ]
                    subprocess.run(args, check=True, capture_output=True)
                except subprocess.CalledProcessError as e:
                    logger.error(e.stderr.decode("utf-8"))
                    raise e

            # link object file
            try:
                args = [self._linker] + [
                    "-relocatable",
                    os.path.join(td, "obj.o"),
                    "-T",
                    os.path.join(td, "linker.ld"),
                    "-o",
                    os.path.join(td, "obj_linked.o"),
                ]
                subprocess.run(args, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

            # extract compiled code
            ld = cle.Loader(
                os.path.join(td, "obj_linked.o"), main_opts={"base_addr": 0x0}
            )
            compiled = ld.memory.load(
                ld.all_objects[0].entry + base, ld.memory.max_addr
            )
        return compiled
