from patcherex2 import *

p = Patcherex("add", target_opts={"compiler": "clang19"})

c_str = """
rdi += rdi;
rdi += 5;
"""

asm_str = """
    add edi, edi
    add edi, 5
"""

p.patches.append(InsertInstructionPatch(0x114d, c_str, language="C", c_in_regs=["rdi"], c_out_regs=["rdi"]))
p.apply_patches()

p.binfmt_tool.save_binary()
