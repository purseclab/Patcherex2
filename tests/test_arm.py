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
                "./test_binaries/armhf",
            )
        )

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x44C, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x5DF, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x1044C, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x5DF, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x103E2, "ldr r1, [pc, #0x14]"),
                ModifyInstructionPatch(0x103E4, "add r1, pc"),
                ModifyInstructionPatch(0x103E6, "mov r0, r1"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0x520, "mov r1, 0xb0"),
                ModifyInstructionPatch(0x524, "add r1, pc, r1"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, =0x1044C
            mov r2, 3
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x103EC, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            mov r1, lr
            ldr r2, =0xfffff000
            and r1, r1, r2
            ldr r2, =0x5df
            add r1, r1, r2
            mov r2, 3
            svc 0
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x52C, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            mov r7, 0x1
            mov r0, 0x32
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs, is_thumb=True),
                ModifyInstructionPatch(0x103EC, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    @pytest.mark.skip(reason="difficult to do with pie")
    def test_insert_instruction_patch_2_pie(self):
        return_instrs = """
            mov r7, 0x1
            mov r0, 0x32
            svc 0
        """
        jump_instrs = """
            mov r0, pc
            ldr r1, =0xfff00000
            and r0, r0, r1
            ldr r1, ={return_0x32}
            add r0, r0, r1
            blx r0
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", return_instrs, is_thumb=True),
                InsertInstructionPatch(0x52C, jump_instrs),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x1044B, num_bytes=4),
            ],
            expected_output=b"\xf0\x20\xe3",
            expected_returnCode=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x5DE, num_bytes=4),
            ],
            expected_output=b"\xf0\x20\xe3",
            expected_returnCode=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x1044C, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x5DF, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch_nopie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            ldr r1, ={added_data}
            mov r2, %s
            svc 0
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x103EC, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_insert_data_patch_pie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov r7, 0x4
            mov r0, 0x1
            mov r1, pc
            ldr r2, =0xfff00000
            and r1, r1, r2
            ldr r2, ={added_data}
            add r1, r1, r2
            mov r2, %s
            svc 0
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x52C, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x1044D, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x5E0, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x52C, code)],
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
            [ModifyFunctionPatch(0x588, code)],
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
            [ModifyFunctionPatch(0x588, code)],
            expected_output=b"Hello World Hello  Hello  Hello  21\nHello World\n2121",
            expected_returnCode=0,
        )

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
                ModifyFunctionPatch(0x50C, replace_code),
            ],
            expected_output=b"2121212121",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c(self):
        # Original computation was (n + 2) * 2 where n = 4
        # New computation inserts a factorial step at the beginning
        # The new computation is (n! + 2) * 2 where n=4
        instrs = """
        uint32_t n = r0;
        for (uint32_t i = 1; i < n; i++) {
            r0 *= i;
        }
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "r1",
                "r2",
                "r3",
                "d0",
                "d1",
                "d2",
                "d3",
                "d4",
                "d5",
                "d6",
                "d7",
            ]
        )

        self.run_one(
            "iip_c",
            [InsertInstructionPatch(0x1062C, instrs, language="C", c_config=config)],
            expected_output=b"52",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_asm_header(self):
        asm_header = "mov r12, r11"

        # Original computation computed the area as pi * radius
        # Here our micropatch loops over the areas array and multiplies by another radius to fix the bug
        instrs = """
        int num_radii = *((int *) (r12 - 0x10));
        float *areas = *((float **) (r12 - 0x20));
        float *radii = *((float **) (r12 - 0x0c));
        for (int i = 0; i < num_radii; i++) {
            areas[i] *= radii[i];
        }
        """

        config = InsertInstructionPatch.CConfig(
            asm_header=asm_header,
            scratch_regs=[
                "r0",
                "r1",
                "r2",
                "r3",
                "d0",
                "d1",
                "d2",
                "d3",
                "d4",
                "d5",
                "d6",
                "d7",
            ],
        )

        expected_output = b"".join(
            [
                b"The area of the circle with radius 1.500000 is 7.065000\n",
                b"The area of the circle with radius 2.000000 is 12.560000\n",
                b"The area of the circle with radius 4.300000 is 58.058605\n",
            ]
        )

        self.run_one(
            "iip_c_asm_header",
            [InsertInstructionPatch(0x1077C, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_float(self):
        # Original computation calculated the square magnitude of a 3D vector as x^2 + y^2
        # Here we insert an additional step to fix the calculation to be x^2 + y^2 + z^2
        instrs = """
        s6 = *(float*)r12;
        s0 += s6 * s6;
        """

        config = InsertInstructionPatch.CConfig(
            asm_header="mov r12, r13",
            scratch_regs=[
                "r0",
                "r1",
                "r2",
                "r3",
                "d4",
                "d5",
                "d6",
                "d7",
            ],
            regs_sort=["s0", "s2", "s4", "s6"],
        )

        expected_output = b"".join(
            [
                b"The square magnitude of the vector (0.000000, 0.000000, 0.000000) is 0.000000\n",
                b"The square magnitude of the vector (1.000000, 2.000000, 3.000000) is 14.000000\n",
                b"The square magnitude of the vector (-20.000000, 33.200001, 5.200000) is 1529.280029\n",
                b"The square magnitude of the vector (3.000000, 4.000000, 0.000000) is 25.000000\n",
            ]
        )

        self.run_one(
            "iip_c_float",
            [InsertInstructionPatch(0x1067C, instrs, language="C", c_config=config)],
            expected_output=expected_output,
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
        target_opts=None,
    ):
        filepath = os.path.join(self.bin_location, filename)
        pipe = subprocess.PIPE

        with tempfile.TemporaryDirectory() as td:
            tmp_file = os.path.join(td, "patched")
            p = Patcherex(filepath, target_opts=target_opts)
            for patch in patches:
                p.patches.append(patch)
            p.apply_patches()
            p.save_binary(tmp_file)
            # os.system(f"readelf -hlS {tmp_file}")

            p = subprocess.Popen(
                ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", tmp_file],
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
