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
                "./test_binaries/amd64",
            )
        )
        request.cls.binary_analyzer = request.param

    def test_raw_file_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x2004, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_file_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x2007, b"No", addr_type="raw")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyRawBytesPatch(0x402004, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_raw_mem_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyRawBytesPatch(0x2007, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                ModifyInstructionPatch(0x40113E, "lea rax, [0x402007]"),
                ModifyInstructionPatch(0x401145, "mov rsi, rax"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                ModifyInstructionPatch(0x1156, "lea rsi, [rip + 0xea7]"),
            ],
            expected_output=b"%s",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch2_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyInstructionPatch(0x401152, "lea rax, [rip + 0xeb8]")],
            expected_output="",
            expected_returnCode=0,
        )

    def test_modify_instruction_patch2_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyInstructionPatch(0x115D, "mov eax, 0x0")],
            expected_output="",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_nopie(self):
        instrs = """
            mov rax, 0x1
            mov rdi, 0x1
            lea rsi, [0x402004]
            mov rdx, 0x3
            syscall
        """
        self.run_one(
            "printf_nopie",
            [InsertInstructionPatch(0x40115C, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_pie(self):
        instrs = """
            mov rax, 0x1
            mov rdi, 0x1
            lea rsi, [0x2007]
            mov rdx, 0x3
            syscall
        """
        self.run_one(
            "printf_pie",
            [InsertInstructionPatch(0x1164, instrs)],
            expected_output=b"Hi\x00Hi",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_2_nopie(self):
        instrs = """
            mov rax, 0x32
            leave
            ret
        """
        self.run_one(
            "printf_nopie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x40115C, "jmp {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_insert_instruction_patch_2_pie(self):
        instrs = """
            mov rax, 0x32
            leave
            ret
        """
        self.run_one(
            "printf_pie",
            [
                InsertInstructionPatch("return_0x32", instrs),
                ModifyInstructionPatch(0x1164, "jmp {return_0x32}"),
            ],
            expected_returnCode=0x32,
        )

    def test_remove_instruction_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [
                RemoveInstructionPatch(0x402005, num_bytes=1),
            ],
            expected_output=b"H\x90",
            expected_returnCode=0,
        )

    def test_remove_instruction_patch_pie(self):
        self.run_one(
            "printf_pie",
            [
                RemoveInstructionPatch(0x2008, num_bytes=1),
            ],
            expected_output=b"H\x90",
            expected_returnCode=0,
        )

    def test_modify_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [ModifyDataPatch(0x402004, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_modify_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [ModifyDataPatch(0x2004, b"No")],
            expected_output=b"No",
            expected_returnCode=0,
        )

    def test_insert_data_patch_nopie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov rax, 1
            mov rdi, 1
            lea rsi, [{added_data}]
            mov rdx, %s
            syscall
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x40115C, instrs)
        self.run_one(
            "printf_nopie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_insert_data_patch_pie(self, tlen=5):
        p1 = InsertDataPatch("added_data", b"A" * tlen)
        instrs = """
            mov rax, 1
            mov rdi, 1
            lea rsi, [{added_data}]
            mov rdx, %s
            syscall
        """ % hex(tlen)
        p2 = InsertInstructionPatch(0x1164, instrs)
        self.run_one(
            "printf_pie",
            [p1, p2],
            expected_output=b"A" * tlen + b"Hi",
            expected_returnCode=0,
        )

    def test_remove_data_patch_nopie(self):
        self.run_one(
            "printf_nopie",
            [RemoveDataPatch(0x402005, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_remove_data_patch_pie(self):
        self.run_one(
            "printf_pie",
            [RemoveDataPatch(0x2008, 1)],
            expected_output=b"H",
            expected_returnCode=0,
        )

    def test_replace_function_patch(self):
        code = """
        int add(int a, int b){ for(;; b--, a+=2) if(b <= 0) return a; }
        """
        self.run_one(
            "replace_function_patch",
            [ModifyFunctionPatch(0x1149, code)],
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
            [ModifyFunctionPatch(0x1177, code)],
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
            [ModifyFunctionPatch(0x1177, code)],
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
                ModifyFunctionPatch(0x1219, replace_code),
            ],
            expected_output=b"2121212121",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_with_force_insert(self):
        instrs = """
            mov rdi, rax
            add rdi, 3
            call {puts}
        """
        self.run_one(
            "issue8",
            [InsertInstructionPatch(0x117A, instrs, force_insert=True)],
            expected_output=b"ched failed\n",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c(self):
        # Original computation was (n + 2) * 2 where n = 4
        # New computation inserts a factorial step at the beginning
        # The new computation is (n! + 2) * 2 where n=4
        instrs = """
        uint32_t n = rax;
        for (uint32_t i = 1; i < n; i++) {
            rax *= i;
        }
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "r8",
                "r9",
                "r10",
                "r11",
                "r13",
                "r14",
                "r15",
                "xmm0",
                "xmm1",
                "xmm2",
                "xmm3",
                "xmm4",
                "xmm5",
                "xmm6",
                "xmm7",
                "xmm9",
                "xmm10",
                "xmm11",
                "xmm12",
                "xmm13",
                "xmm14",
                "xmm15",
            ]
        )

        self.run_one(
            "iip_c",
            [InsertInstructionPatch(0x1157, instrs, language="C", c_config=config)],
            expected_output=b"52",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_subreg(self):
        # Original computation was (n + 2) * 2 where n = 4
        # New computation inserts a factorial step at the beginning
        # The new computation is (n! + 2) * 2 where n=4
        instrs = """
        uint32_t n = eax;
        for (uint32_t i = 1; i < n; i++) {
            eax *= i;
        }
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "r8",
                "r9",
                "r10",
                "r11",
                "r13",
                "r14",
                "r15",
                "xmm0",
                "xmm1",
                "xmm2",
                "xmm3",
                "xmm4",
                "xmm5",
                "xmm6",
                "xmm7",
                "xmm9",
                "xmm10",
                "xmm11",
                "xmm12",
                "xmm13",
                "xmm14",
                "xmm15",
            ],
            regs_sort=["eax"],
        )

        self.run_one(
            "iip_c",
            [InsertInstructionPatch(0x1157, instrs, language="C", c_config=config)],
            expected_output=b"52",
            expected_returnCode=0,
        )

    def test_insert_instruction_patch_c_asm_header(self):
        asm_header = "mov r12, rbp"

        # Original computation computed the area as pi * radius
        # Here our micropatch loops over the areas array and multiplies by another radius to fix the bug
        instrs = """
        int num_radii = *((int *) (r12 - 0x3c));
        float *areas = *((float **) (r12 - 0x20));
        float *radii = *((float **) (r12 - 0x38));
        for (int i = 0; i < num_radii; i++) {
            areas[i] *= radii[i];
        }
        """

        config = InsertInstructionPatch.CConfig(
            asm_header=asm_header,
            scratch_regs=[
                "r8",
                "r9",
                "r10",
                "r11",
                "r13",
                "r14",
                "r15",
                "xmm0",
                "xmm1",
                "xmm2",
                "xmm3",
                "xmm4",
                "xmm5",
                "xmm6",
                "xmm7",
                "xmm9",
                "xmm10",
                "xmm11",
                "xmm12",
                "xmm13",
                "xmm14",
                "xmm15",
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
            [InsertInstructionPatch(0x130D, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
            target_opts={"compiler": "clang19"},
        )

    def test_insert_instruction_patch_c_asm_header2(self):
        asm_header = "mov r12, rbp"

        # Original computation computed the area as pi * radius
        # Here our micropatch loops over the areas array and multiplies by another radius to fix the bug
        instrs = """
        int num_radii = 3;
        float *areas = *((float **) (r12 - 0x20));
        float *radii = *((float **) (r12 - 0x38));
        for (int i = 0; i < num_radii; i++) {
            areas[i] *= radii[i];
        }
        """

        config = InsertInstructionPatch.CConfig(
            asm_header=asm_header,
            scratch_regs=[
                "r8",
                "r9",
                "r10",
                "r11",
                "r13",
                "r14",
                "r15",
                "xmm0",
                "xmm1",
                "xmm2",
                "xmm3",
                "xmm4",
                "xmm5",
                "xmm6",
                "xmm7",
                "xmm9",
                "xmm10",
                "xmm11",
                "xmm12",
                "xmm13",
                "xmm14",
                "xmm15",
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
            [InsertInstructionPatch(0x130D, instrs, language="C", c_config=config)],
            expected_output=expected_output,
            expected_returnCode=0,
            target_opts={"compiler": "clang19"},
        )

    def test_insert_instruction_patch_c_float(self):
        # Original computation calculated the square magnitude of a 3D vector as x^2 + y^2
        # Here we insert an additional step to fix the calculation to be x^2 + y^2 + z^2
        instrs = """
        xmm0 += xmm2 * xmm2;
        """

        config = InsertInstructionPatch.CConfig(
            scratch_regs=[
                "r8",
                "r9",
                "r10",
                "r11",
                "r13",
                "r14",
                "r15",
                "xmm3",
                "xmm4",
                "xmm5",
                "xmm6",
                "xmm7",
                "xmm9",
                "xmm10",
                "xmm11",
                "xmm12",
                "xmm13",
                "xmm14",
                "xmm15",
            ],
            regs_sort=[("xmm0", "float"), ("xmm2", "float")],
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
            [InsertInstructionPatch(0x1175, instrs, language="C", c_config=config)],
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
                [tmp_file],
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
