from patcherex2 import *

p = Patcherex("add")


asm_str = """
    add edi, edi
    add edi, 5
"""

p.patches.append(InsertInstructionPatch(0x114d,asm_str))
p.apply_patches()

p.save_binary()
