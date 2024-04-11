from patcherex2 import *
import logging

logger = logging.getLogger("patcherex2.patches.instruction_patches")
logger.setLevel(logging.INFO)

p = Patcherex("add", target_opts={"compiler": "clang19"})

c_forward_header = """
// This string will be inserted outside the micropatch function. It will be inserted before your code.
// This is how you can define types and function forward declarations used by your C micropatch
"""

# We can access assembly registers directly by using their name, while still using high level C constructs
# as well as intermediate variables. Note that you can use a return statement anywhere in your C micropatch
# to jump back to the next instruction after the micropatch insertion point.
c_str = """
rdi += rdi;
rdi += 5;
"""

# It is generally a good idea to mark some registers as scratch to give the compiler
# breathing room for allocating registers to use for intermediate variables in your micropatch
# All of the registers that we mark as scratch can be freely clobbered by the compiler
# Note that you can still read from scratch registers stored in the variables. What the scratch
# register denotation will indicate however is that the register can be re-used after the variable
# is no longer live.
c_scratch_regs = ['r8', 'r9', 'r11', 'r10', 'r12', 'r13', 'r14', 'r15']

# By default floating point registers will have the 'float' type. We can use c_float_types to override
# certain registers so they hold different types. In this example we denote that xmm8 is of type double
c_float_types = {'xmm8': 'double'}

p.patches.append(InsertInstructionPatch(0x114d, c_str, language="C", c_forward_header=c_forward_header,
                                        c_scratch_regs=c_scratch_regs, c_float_types=c_float_types))
p.apply_patches()

p.binfmt_tool.save_binary()
