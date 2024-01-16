#!/usr/bin/env python

# ruff: noqa
import logging
import os
import shutil
import subprocess
import tempfile
import unittest

from patcherex2 import *

logging.getLogger("patcherex2").setLevel("DEBUG")


class Tests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bin_location = str(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "./test_binaries/mips64",
            )
        )

    def test_raw_file_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0xBD3, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x120000BD3, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x120000AB0, "daddiu $a1, $at, 0xbd0"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch(self):
        instrs = """
            li $v0, 0x1389
            li $a0, 0x1
            ld $at, -0x7fc0($gp)
            daddiu $a1, $at, 0xbd3
            li $a2, 0x3
            syscall
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x120000AC0, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2(self):
        instrs = """
            li $v0, 0x13c2
            li $a0, 0x32
            syscall
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x120000AC0, "j {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x120000BD4, num_bytes=4),
            ],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_modify_data_patch(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x120000BD3, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        p = Patcherex(os.path.join(self.bin_location, "printf_nopie"))
        p.patches.append(p1)
        p.apply_patches()
        added_data_address = p.symbols["added_data"] - 0x120000000
        upper = added_data_address >> 16
        lower = added_data_address & 0b1111111111111111
        instrs = """
            li $v0, 0x1389
            li $a0, 0x1
            ld $at, -0x7fc0($gp)
            lui $a1, %s
            ori $a1, $a1, %s
            daddu $a1, $at, $a1
            li $a2, %s
            syscall
        """ % (hex(upper), hex(lower), hex(tlen))
        p2 = InsertInstructionPatch(0x120000AC0, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x120000BD4, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0xC00, code)],
            expected_output=b"70707070",
            expected_returnCode=0,
        )

    def test_replace_function_patch_with_function_reference(self):
        code = """
        extern int add(int, int);
        extern int subtract(int, int);
        int multiply(int a, int b){ for(int c = 0;; b = subtract(b, 1), c = subtract(c, a)) if(b <= 0) return c; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0xD00, code)],
            expected_output=b"-21-21",
            expected_returnCode=0,
        )

    def test_replace_function_patch_with_function_reference_and_rodata(self):
        code = """
        extern int printf(const char *format, ...);
        int multiply(int a, int b){ printf("%sWorld %s %s %s %d\\n", "Hello ", "Hello ", "Hello ", "Hello ", a * b);printf("%sWorld\\n", "Hello "); return a * b; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0xD00, code)],
            expected_output=b"Hello World Hello  Hello  Hello  21\nHello World\n2121",
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

            if expected_returnCode == 0x32:
                with open(tmp_file, "rb") as f:
                    result = f.read()
                with open("/home/bilbin/patched_test", "wb") as f:
                    f.write(result)
            p = subprocess.Popen(
                ["qemu-mips64", "-L", "/usr/mips64-linux-gnuabi64", tmp_file],
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