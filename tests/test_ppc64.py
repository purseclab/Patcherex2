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
                "./test_binaries/ppc64",
            )
        )
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x88F, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0xB74, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x1000088F, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0xB74, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x1000076C, "subi 4, 4, 0x7674"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0xA4C, "subi 4, 4, 0x738C"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            li 0, 0x4
            li 3, 1
            lis 4, 0x1000088f@h
            addi 4, 4, 0x1000088f@l
            li 5, 0x3
            sc
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x10000774, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            li 0, 0x4
            li 3, 1
            addi 4, 4, 0x1
            li 5, 0x3
            sc
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0xA54, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            li 3, 0x32
            li 0, 0x1
            sc
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x10000774, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            li 3, 0x32
            li 0, 0x1
            sc
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0xA54, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x10000890, num_bytes=4),
            ],
            expected_output=b"H\x60",
            expected_returnCode=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0xB78, num_bytes=4),
            ],
            expected_output=b"H\x60",
            expected_returnCode=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x1000088F, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0xB77, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch_nopie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            li 0, 0x4
            li 3, 0x1
            lis 4, {added_data}@h
            addi 4, 4, {added_data}@l
            li 5, %s
            sc
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x10000774, instrs)
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
            li 0, 0x4
            li 3, 0x1
            lis 4, {added_data}@h
            addi 4, 4, {added_data}@l
            li 5, %s
            sc
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0xA54, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x10000890, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0xB78, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0xB44, code)],
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
            [ModifyFunctionPatch(0xBEC, code)],
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
            [ModifyFunctionPatch(0xBEC, code)],
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
                ModifyFunctionPatch(0xD2C, replace_code),
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
                ["qemu-ppc64", "-L", "/usr/powerpc64-linux-gnu", tmp_file],
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
