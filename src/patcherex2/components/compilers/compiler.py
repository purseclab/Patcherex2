import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Optional

import cle

logger = logging.getLogger(__name__)


class Compiler:
    def __init__(self, p) -> None:
        self.p = p

    def compile(
        self,
        code: str,
        base=0,
        symbols: Optional[Dict[str, int]] = None,
        extra_compiler_flags: Optional[List[str]] = None,
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

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            _symbols.update(self.p.binary_analyzer.get_all_symbols())
            _symbols.update(symbols)
            linker_script = (
                "SECTIONS { .text : SUBALIGN(0) { . = "
                + hex(base)
                # TODO: shouldn't put .rodata in .text, but otherwise switch case jump table won't work
                # Note that even we don't include .rodata here, cle might still include it if there is
                # no gap between .text and .rodata
                + "; *(.text) *(.rodata) *(.rodata.*)"
            )
            for name, addr in _symbols.items():
                linker_script += name + " = " + hex(addr) + ";"
            linker_script += "} }"
            with open(os.path.join(td, "linker.ld"), "w") as f:
                f.write(linker_script)

            # compile to object file
            try:
                args = (
                    [self._compiler]
                    + self._compiler_flags
                    + extra_compiler_flags
                    + [
                        "-c",
                        os.path.join(td, "code.c"),
                        "-o",
                        os.path.join(td, "obj.o"),
                    ]
                )
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
            # TODO: cle will stop at the beginning of the first unallocated region
            # found, or when `ld.memory.max_addr` bytes have been read.
            # So if there is no gap between .text and the next section, cle will
            # include the next section in the compiled code as well.

            # text_section = next(
            #     (s for s in ld.main_object.sections if s.name == ".text"), None
            # )
            compiled = ld.memory.load(
                ld.all_objects[0].entry + base,
                ld.memory.max_addr,
                # (text_section.vaddr + text_section.memsize),
            )
        return compiled
