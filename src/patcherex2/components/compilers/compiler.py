from __future__ import annotations

import logging
import os
import subprocess
import tempfile

import cle
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


class ObjectArchMismatchError(Exception):
    """
    Raised when compiled patch code is not for the architecture of the binary
    being patched. Writing such an object into the target would produce a patch
    that silently faults at runtime, so we refuse it at compile time.
    """


class Compiler:
    def __init__(self, p) -> None:
        self.p = p
        # preserve_none is a special attribute flag to allow us to control more registers as input to a C function
        # This feature is used for a C instruction patch
        self.preserve_none = False

    def check_object_arch(self, elf: ELFFile) -> None:
        """
        Verify that a compiled object file matches the target's architecture.

        The compiler is driven by flags (``-target``, ``-m32``, ...) that are easy
        to get wrong or omit, and neither pyelftools nor cle objects to loading an
        object for the wrong machine, so without this check a patch compiled for
        the build host rather than the target is applied silently.

        :param elf: The compiled object file, opened for reading.
        :raises ObjectArchMismatchError: If the object is not for the target's
            machine, class or data encoding.
        """
        expected = getattr(self.p.target, "expected_object_arch", None)
        if not expected:
            return
        actual = {
            "e_machine": elf.header["e_machine"],
            "ei_class": elf.header["e_ident"]["EI_CLASS"],
            "ei_data": elf.header["e_ident"]["EI_DATA"],
        }
        mismatched = {
            key: (value, actual[key])
            for key, value in expected.items()
            if actual[key] != value
        }
        if mismatched:
            details = ", ".join(
                f"{key}: expected {want}, got {got}"
                for key, (want, got) in mismatched.items()
            )
            raise ObjectArchMismatchError(
                f"Compiled patch code does not match the target architecture "
                f"({details}). This usually means the compiler is missing or has "
                f"the wrong target triple, and the patch would not run on the "
                f"binary being patched. Compiler flags: "
                f"{getattr(self, '_compiler_flags', [])}"
            )

    def compile(
        self,
        code: str,
        base=0,
        symbols: dict[str, int] | None = None,
        extra_compiler_flags: list[str] | None = None,
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
                raise

            # linker script
            _symbols = {}
            _symbols.update(self.p.symbols)
            _symbols.update(self.p.binary_analyzer.get_all_symbols())
            _symbols.update(symbols)

            # TODO: shouldn't put .rodata in .text, but otherwise switch case jump table won't work
            # Note that even we don't include .rodata here, cle might still include it if there is
            # no gap between .text and .rodata
            with open(os.path.join(td, "obj.o"), "rb") as f:
                elf = ELFFile(f)
                self.check_object_arch(elf)
                linker_script_rodata_sections = " ".join(
                    [
                        f". = ALIGN({section['sh_addralign']}); *({section.name})"
                        for section in elf.iter_sections()
                        if section.name.startswith(".rodata")
                    ]
                )
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
                raise

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
