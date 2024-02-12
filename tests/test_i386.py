#!/usr/bin/env python

# ruff: noqa
import logging
import os
import shutil
import subprocess
import tempfile
import unittest
import pytest

from patcherex2 import *

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bin_location = str(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "./test_binaries/i386",
            )
        )

    def test_raw_file_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x2008, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x804A008, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x8049192, "lea edx, [0x804a00b]"),
                ModifyInstructionPatch(0x8049198, "push edx"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch(self):
        instrs = """
            mov eax, 0x4
            mov ebx, 0x1
            lea ecx, [0x804a008]
            mov edx, 0x3
            int 0x80
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x80491A7, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2(self):
        instrs = """
            mov eax, 0x32
            leave
            ret
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x80491A7, "jmp {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x804A009, num_bytes=1),
            ],
            expected_output=b"H\x90",
            expected_returnCode=0,
        )

    def test_modify_data_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x804A008, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov eax, 0x4
            mov ebx, 0x1
            lea ecx, [{added_data}]
            mov edx, %s
            int 0x80
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x80491A7, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x804A009, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x119D, code)],
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
            [ModifyFunctionPatch(0x11C9, code)],
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
            [ModifyFunctionPatch(0x11c9, code)],
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
                ModifyFunctionPatch(0x1261, replace_code),
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
            p = Patcherex(filepath)
            for patch in patches:
                p.patches.append(patch)
            p.apply_patches()
            p.binfmt_tool.save_binary(tmp_file)
            # os.system(f"readelf -hlS {tmp_file}")

            p = subprocess.Popen(
                [tmp_file],
                stdin=pipe,
                stdout=pipe,
                stderr=pipe,
            )
            res = p.communicate(inputvalue)
            if expected_output:
                if res[0] != expected_output:
                    self.fail(
                        f"AssertionError: {res[0]} != {expected_output}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(res[0], expected_output)
            if expected_returnCode:
                if p.returncode != expected_returnCode:
                    self.fail(
                        f"AssertionError: {p.returncode} != {expected_returnCode}, binary dumped: {self.dump_file(tmp_file)}"
                    )
                # self.assertEqual(p.returncode, expected_returnCode)

    def dump_file(self, file):
        shutil.copy(file, "/tmp/patcherex_failed_binary")
        return "/tmp/patcherex_failed_binary"


if __name__ == "__main__":
    unittest.main()
