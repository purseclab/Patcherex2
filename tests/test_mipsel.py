#!/usr/bin/env python

# ruff: noqa
import logging
import os
import shutil
import subprocess
import tempfile

import pytest

from patcherex2 import *

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests:
    @pytest.fixture(autouse=True, scope="class", params=["angr", "ghidra"])
    def setup(self, request):
        request.cls.bin_location = str(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "./test_binaries/mipsel",
            )
        )
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x81B, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x8EF, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x40081B, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x8EF, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x400710, "addiu $a1, $at, 0x818"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0x7E0, "addiu $a1, $at, 0x8EC"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            li $v0, 0xfa4
            li $a0, 0x1
            la $a1, 0x40081b
            li $a2, 0x3
            syscall
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x400720, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            li $v0, 0xfa4
            li $a0, 0x1
            li $a1, 0x0
            move $a1, $s4
            li $a3, 0xfff
            not $a3, $a3
            and $a1, $a1, $a3
            addiu $a1, $a1, 0x8EF
            li $a2, 0x3
            syscall
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x7F0, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            li $v0, 0xfa1
            li $a0, 0x32
            syscall
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x400720, "j {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            li $v0, 0xfa1
            li $a0, 0x32
            syscall
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x7F0, "j {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x40081C, num_bytes=4),
            ],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x8F0, num_bytes=4),
            ],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x40081B, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x8EF, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch_nopie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            li $v0, 0xfa4
            li $a0, 0x1
            li $a1, {added_data}
            li $a2, %s
            syscall
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x400720, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    @pytest.mark.skip(reason="difficult to do with pie")
    def test_insert_data_patch_pie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            li $v0, 0xfa4
            li $a0, 0x1
            li $a1, {added_data}
            li $a2, %s
            syscall
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x7F0, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x40081C, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x8F0, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x860, code)],
            expected_output=b"70707070",
            expected_returnCode=0,
        )

    @pytest.mark.skip(reason="waiting for cle relocation support")
    def test_replace_function_patch_with_function_reference(self):
        code = """
        extern int add(int, int);
        extern int subtract(int, int);
        int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = subtract(c, a)) if(b <= 0) return c; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x970, code)],
            expected_output=b"-21-21",
            expected_returnCode=0,
        )

    @pytest.mark.skip(reason="waiting for cle relocation support")
    def test_replace_function_patch_with_function_reference_and_rodata(self):
        code = """
        extern int printf(const char *format, ...);
        int multiply(int a, int b){ printf("%sWorld %s %s %s %d\\n", "Hello ", "Hello ", "Hello ", "Hello ", a * b);printf("%sWorld\\n", "Hello "); return a * b; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x970, code)],
            expected_output=b"Hello World Hello  Hello  Hello  21\nHello World\n2121",
            expected_returnCode=0,
        )

    @pytest.mark.skip(reason="waiting for cle relocation support")
    def test_insert_function_patch(self):
        insert_code = """
        int min(int a, int b) { return (a < b) ? a : b; }
        """
        replace_code = """
        extern int min(int, int);
        int max(int a, int b) { return min(a, b); }
        """
        self.run_one(
            "replace_function_patch",
            [
                InsertFunctionPatch("min", insert_code),
                ModifyFunctionPatch(0xAD4, replace_code),
            ],
            expected_output=b"2121212121",
            expected_returnCode=0,
        )

    def run_one(
        self,
        filename,
        patches,
        set_oep=None,
        inputvalue=None,
        expected_output=None,
        expected_returnCode=None,
    ):
        filepath = os.path.join(self.bin_location, filename)
        pipe = subprocess.PIPE

        with tempfile.TemporaryDirectory() as td:
            tmp_file = os.path.join(td, "patched")
            p = Patcherex(
                filepath, target_opts={"binary_analyzer": self.binary_analyzer}
            )
            for patch in patches:
                p.patches.append(patch)
            p.apply_patches()
            p.save_binary(tmp_file)
            p.shutdown()
            # os.system(f"readelf -hlS {tmp_file}")

            p = subprocess.Popen(
                ["qemu-mipsel", "-L", "/usr/mipsel-linux-gnu", tmp_file],
                stdin=pipe,
                stdout=pipe,
                stderr=pipe,
            )
            res = p.communicate(inputvalue)
            if expected_output:
                if res[0] != expected_output:
                    pytest.fail(
                        f"AssertionError: {res[0]} != {expected_output}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(res[0], expected_output)
            if expected_returnCode:
                if p.returncode != expected_returnCode:
                    pytest.fail(
                        f"AssertionError: {p.returncode} != {expected_returnCode}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(p.returncode, expected_returnCode)

    def dump_file(self, file):
        shutil.copy(file, "/tmp/patcherex_failed_binary")
        return "/tmp/patcherex_failed_binary"
