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
                "./test_binaries/aarch64",
            )
        )
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x640, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x7AB, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x400640, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x7AB, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyInstructionPatch(0x400570, "add x1,x0,#0x648")],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyInstructionPatch(0x778, "add x1,x1,#0x7a8")],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            mov x8, 0x40
            mov x0, 0x1
            ldr x1, =0x400640
            mov x2, 0x3
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x400580, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            mov x8, 0x40
            mov x0, 0x1
            adrp x1, 0x0
            add x1, x1, #0x7ab
            mov x2, 0x3
            svc 0
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x780, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            mov x8, 0x5d
            mov x0, 0x32
            svc 0
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x400580, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            mov x8, 0x5d
            mov x0, 0x32
            svc 0
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x780, "b {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x400641, num_bytes=4),
            ],
            expected_output=b"H\x1f\x20\x03\xd5",
            expected_returnCode=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x7AC, num_bytes=4),
            ],
            expected_output=b"H\x1f\x20\x03\xd5",
            expected_returnCode=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x400640, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x7AB, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch_nopie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov x8, 0x40
            mov x0, 0x1
            ldr x1, ={added_data}
            mov x2, %s
            svc 0
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x400580, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_insert_data_patch_pie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov x8, 0x40
            mov x0, 0x1
            adrp x1, 0x0
            ldr x3, ={added_data}
            add x1, x1, x3
            mov x2, %s
            svc 0
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x780, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x400641, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x7AC, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x74C, code)],
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
            [ModifyFunctionPatch(0x7D4, code)],
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
            [ModifyFunctionPatch(0x7D4, code)],
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
                ModifyFunctionPatch(0x724, replace_code),
            ],
            expected_output=b"2121212121",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c(self):
        # Original computation was (n + 2) * 2 where n = 4
        # New computation inserts a factorial step at the beginning
        # The new computation is (n! + 2) * 2 where n=4
        instrs = """
        uint32_t n = x0;
        for (uint32_t i = 1; i < n; i++) {
            x0 *= i;
        }
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "x1",
                "x2",
                "x3",
                "x4",
                "x5",
                "x6",
                "x7",
                "x8",
                "x9",
                "x10",
                "x11",
                "x12",
                "x13",
                "x14",
                "x15",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
                "v6",
                "v7",
            ]
        )

        self.run_one(
            "iip_c",
            [InsertInstructionPatch(0x760, instrs, language="C", c_config=config)],
            expected_output=b"52",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_subreg(self):
        # TODO: Currently this test fails due to the following missing cle relocation:
        # WARNING  | 2024-05-08 13:58:10,162 | cle.backends.elf.relocation | Unknown reloc 299 on AARCH64

        # Original computation was (n + 2) * 2 where n = 4
        # New computation inserts a factorial step at the beginning
        # The new computation is (n! + 2) * 2 where n=4
        instrs = """
        uint32_t n = w0;
        for (uint32_t i = 1; i < n; i++) {
            w0 *= i;
        }
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "x1",
                "x2",
                "x3",
                "x4",
                "x5",
                "x6",
                "x7",
                "x8",
                "x9",
                "x10",
                "x11",
                "x12",
                "x13",
                "x14",
                "x15",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
                "v6",
                "v7",
            ],
            regs_sort=["w0"],
        )

        self.run_one(
            "iip_c",
            [InsertInstructionPatch(0x760, instrs, language="C", c_config=config)],
            expected_output=b"52",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_asm_header(self):
        asm_header = "mov x12, x29"

        # Original computation computed the area as pi * radius
        # Here our micropatch loops over the areas array and multiplies by another radius to fix the bug
        instrs = """
        int num_radii = *((int *) (x12 - 0x2c));
        float *areas = *((float **) (x12 - 0x10));
        float *radii = *((float **) (x12 - 0x28));
        for (int i = 0; i < num_radii; i++) {
            areas[i] *= radii[i];
        }
        """

        config = InsertInstructionPatch.CConfig(
            asm_header=asm_header,
            scratch_regs=[
                "x1",
                "x3",
                "x4",
                "x5",
                "x6",
                "x7",
                "x8",
                "x9",
                "x10",
                "x11",
                "x13",
                "x14",
                "x15",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
                "v6",
                "v7",
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
            [InsertInstructionPatch(0xA20, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
            target_opts={"compiler": "clang19"},
        )

    def test_insert_instruction_patch_c_asm_header2(self):
        asm_header = "mov x12, x29"

        # Original computation computed the area as pi * radius
        # Here our micropatch loops over the areas array and multiplies by another radius to fix the bug
        instrs = """
        int num_radii = 3;
        float *areas = *((float **) (x12 - 0x10));
        float *radii = *((float **) (x12 - 0x28));
        for (int i = 0; i < num_radii; i++) {
            areas[i] *= radii[i];
        }
        """

        config = InsertInstructionPatch.CConfig(
            asm_header=asm_header,
            scratch_regs=[
                "x1",
                "x3",
                "x4",
                "x5",
                "x6",
                "x7",
                "x8",
                "x9",
                "x10",
                "x11",
                "x13",
                "x14",
                "x15",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
                "v6",
                "v7",
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
            [InsertInstructionPatch(0xA20, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
            target_opts={"compiler": "clang19"},
        )

    def test_insert_instruction_patch_c_float(self):
        # Original computation calculated the square magnitude of a 3D vector as x^2 + y^2
        # Here we insert an additional step to fix the calculation to be x^2 + y^2 + z^2
        instrs = """
        s0 += s2 * s2;
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "x1",
                "x2",
                "x3",
                "x4",
                "x5",
                "x6",
                "x7",
                "x8",
                "x9",
                "x10",
                "x11",
                "x12",
                "x13",
                "x14",
                "x15",
                "v3",
                "v4",
                "v5",
                "v6",
                "v7",
            ],
            regs_sort=["s0", "s1", "s2"],
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
            [InsertInstructionPatch(0x774, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
            target_opts={"compiler": "clang19"},
        )

    def run_one(
        self,
        filename,
        patches,
        set_oep=None,
        inputvalue=None,
        expected_output=None,
        expected_returnCode=None,
        target_opts={},
    ):
        filepath = os.path.join(self.bin_location, filename)
        pipe = subprocess.PIPE

        with tempfile.TemporaryDirectory() as td:
            tmp_file = os.path.join(td, "patched")
            p = Patcherex(
                filepath,
                target_opts=target_opts | {"binary_analyzer": self.binary_analyzer},
            )
            for patch in patches:
                p.patches.append(patch)
            p.apply_patches()
            p.save_binary(tmp_file)
            p.shutdown()
            # os.system(f"readelf -hlS {tmp_file}")

            p = subprocess.Popen(
                ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", tmp_file],
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
