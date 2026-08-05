#!/usr/bin/env python

# ruff: noqa
import os

import pytest
from elftools.elf.elffile import ELFFile

from patcherex2.components.compilers.compiler import (
    Compiler,
    ObjectArchMismatchError,
)
from patcherex2.targets import (
    ElfAArch64Linux,
    ElfAmd64Linux,
    ElfArmLinux,
    ElfMips64elLinux,
    ElfMips64Linux,
    ElfMipselLinux,
    ElfMipsLinux,
    ElfPpc64leLinux,
    ElfPpc64Linux,
    ElfPpcLinux,
    ElfS390xLinux,
    ElfX86Linux,
    Target,
)

bin_location = str(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_binaries")
)

# Targets that compile patch code, and a binary of that architecture to drive
# them with. Each entry must produce an object matching its own target.
TARGETS = [
    (ElfAmd64Linux, "amd64/printf_nopie"),
    (ElfX86Linux, "x86/printf_nopie"),
    (ElfAArch64Linux, "aarch64/printf_nopie"),
    (ElfArmLinux, "armhf/printf_nopie"),
    (ElfMipsLinux, "mips/printf_nopie"),
    (ElfMipselLinux, "mipsel/printf_nopie"),
    (ElfMips64Linux, "mips64/printf_nopie"),
    (ElfMips64elLinux, "mips64el/printf_nopie"),
    (ElfPpcLinux, "ppc/printf_nopie"),
    (ElfPpc64Linux, "ppc64/printf_nopie"),
    (ElfPpc64leLinux, "ppc64le/printf_nopie"),
    (ElfS390xLinux, "s390x/printf_nopie"),
]

C_CODE = "int f(int x) { return x + 1; }"


class StubTarget:
    """Minimal stand-in for a Target, exposing only the arch expectation."""

    def __init__(self, expected_object_arch):
        self.expected_object_arch = expected_object_arch


class StubPatcherex:
    def __init__(self, expected_object_arch):
        self.target = StubTarget(expected_object_arch)


def check(expected_object_arch, obj_path):
    compiler = Compiler(StubPatcherex(expected_object_arch))
    with open(obj_path, "rb") as f:
        compiler.check_object_arch(ELFFile(f))


class TestObjectArchCheck:
    """
    Unit tests for the mismatch check itself, driven by prebuilt test binaries
    standing in for compiled objects (the check only reads the ELF header, so
    an executable works the same as a relocatable object).
    """

    def test_matching_arch_passes(self):
        check(
            ElfAmd64Linux.expected_object_arch,
            os.path.join(bin_location, "amd64/printf_nopie"),
        )

    def test_wrong_machine_raises(self):
        # An aarch64 object against an amd64 target: exactly the failure in #39.
        with pytest.raises(ObjectArchMismatchError, match="e_machine"):
            check(
                ElfAmd64Linux.expected_object_arch,
                os.path.join(bin_location, "aarch64/printf_nopie"),
            )

    def test_wrong_class_raises(self):
        # Same machine and endianness, wrong width: what bare `-m32`/`-m64`
        # gets wrong. mips64 vs mips are both EM_MIPS big-endian, so only
        # ei_class distinguishes them.
        with pytest.raises(ObjectArchMismatchError, match="ei_class"):
            check(
                ElfMips64Linux.expected_object_arch,
                os.path.join(bin_location, "mips/printf_nopie"),
            )

    def test_wrong_endianness_raises(self):
        # Same machine and width, opposite byte order.
        with pytest.raises(ObjectArchMismatchError, match="ei_data"):
            check(
                ElfPpc64Linux.expected_object_arch,
                os.path.join(bin_location, "ppc64le/printf_nopie"),
            )

    def test_no_expectation_skips_check(self):
        # A target that declares nothing keeps the old permissive behaviour.
        check(None, os.path.join(bin_location, "aarch64/printf_nopie"))

    @pytest.mark.parametrize("target_cls", [t for t, _ in TARGETS])
    def test_target_declares_expectation(self, target_cls):
        assert target_cls.expected_object_arch, (
            f"{target_cls.__name__} declares no expected_object_arch, so a "
            f"wrong-architecture patch would be applied silently"
        )

    def test_every_registered_target_declares_expectation(self):
        # Catches targets added later: without an expectation they fall back to
        # the permissive default and lose the mismatch check entirely.
        missing = sorted(
            t.__name__ for t in Target.target_classes if not t.expected_object_arch
        )
        assert not missing, (
            f"targets without expected_object_arch: {', '.join(missing)}"
        )

    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_expectation_matches_own_binary(self, target_cls, binary):
        # The declared expectation must describe the architecture the target
        # detects, otherwise the check would reject correct patches.
        check(target_cls.expected_object_arch, os.path.join(bin_location, binary))


class NoSymbolsAnalyzer:
    """Stands in for a binary analyzer; compile() only needs its symbols."""

    def get_all_symbols(self):
        return {}


class CompileOnlyPatcherex:
    """
    Enough of a Patcherex for Compiler.compile(): the target (for the arch
    expectation) and empty symbol sources. Avoids constructing a real binary
    analyzer, which is not what these tests are about.
    """

    def __init__(self, target_cls, binary_path):
        self.binary_path = binary_path
        self.target = target_cls(self, binary_path)
        self.symbols = {}
        self.binary_analyzer = NoSymbolsAnalyzer()
        # ClangArm post-processes its output through these.
        self.assembler = self.target.get_assembler(None)
        self.disassembler = self.target.get_disassembler(None)


class TestCompiledObjectArch:
    """
    End-to-end: each target's configured compiler must emit an object for that
    target's architecture. This is what actually fails on a non-x86 host when a
    target omits its triple -- and, with the check in place, what now raises
    instead of silently producing a patch in the wrong instruction set.
    """

    @pytest.mark.parametrize("target_cls,binary", TARGETS)
    def test_compiles_for_target_arch(self, target_cls, binary):
        p = CompileOnlyPatcherex(target_cls, os.path.join(bin_location, binary))
        compiler = p.target.get_compiler(None)
        # compile() runs check_object_arch internally, so a wrong-architecture
        # object raises here rather than being returned as bytes.
        assert compiler.compile(C_CODE)
