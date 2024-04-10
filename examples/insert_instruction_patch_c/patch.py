from patcherex2 import *
import logging

logger = logging.getLogger("patcherex2.patches.instruction_patches")
logger.setLevel(logging.INFO)

p = Patcherex("add", target_opts={"compiler": "clang19"})

c_str = """
rdi += rdi;
rdi += 5;
"""

p.patches.append(InsertInstructionPatch(0x114d, c_str, language="C"))
p.apply_patches()

p.binfmt_tool.save_binary()
