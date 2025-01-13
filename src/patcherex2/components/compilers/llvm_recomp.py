from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile

import cle
from elftools.elf.elffile import ELFFile

from ..assets.assets import Assets
from .clang import Clang

logger = logging.getLogger(__name__)


class LLVMRecomp(Clang):
    def __init__(
        self, p, clang_version=15, compiler_flags: list[str] | None = None
    ) -> None:
        super().__init__(p, clang_version, compiler_flags)
        self._clang_version = clang_version
        self._assets_path = Assets("llvm_recomp").path

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
        with tempfile.TemporaryDirectory() as td:
            # source file
            with open(os.path.join(td, "code.c"), "w") as f:
                f.write(code)

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
                        "-I/usr/lib/clang/15/include",
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

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            _symbols.update(self.p.binary_analyzer.get_all_symbols())
            _symbols.update(symbols)

            with open(os.path.join(td, "obj.o"), "rb") as f:
                elf = ELFFile(f)
                linker_script_rodata_sections = " ".join(
                    [
                        f". = ALIGN({section['sh_addralign']}); *({section.name})"
                        for section in elf.iter_sections()
                        if section.name.startswith(".rodata")
                    ]
                )

                # automatically add symbols like off_deadbeef, dword_deadbeef, etc.
                for sym in elf.get_section_by_name(".symtab").iter_symbols():
                    if (
                        sym.entry.st_shndx == "SHN_UNDEF"
                        and sym.name
                        and "_" in sym.name
                    ):
                        try:
                            _, addr = sym.name.split("_", 1)
                            addr = int(addr, 16)
                            if sym.name not in _symbols:
                                _symbols[sym.name] = addr
                        except ValueError:
                            pass
            linker_script_symbols = "".join(
                f"{name} = {hex(addr)};" for name, addr in _symbols.items()
            )

            linker_script = f"SECTIONS {{ .patcherex2 : SUBALIGN(0) {{ . = {hex(base)}; *(.text) {linker_script_rodata_sections} {linker_script_symbols} }} }}"
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

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

            patcherex2_section = next(
                (s for s in ld.main_object.sections if s.name == ".patcherex2"), None
            )
            compiled_start = ld.all_objects[0].entry + base

            compiled = ld.memory.load(
                compiled_start,
                patcherex2_section.memsize - compiled_start,
            )
        return compiled
