from patcherex2 import *
import logging

logger = logging.getLogger("patcherex2.patches.instruction_patches")
logger.setLevel(logging.INFO)

p = Patcherex("add", target_opts={"compiler": "clang19"})

c_forward_header = """
// This string will be inserted outside the micropatch function. It will be inserted before your code.
// This is how you can define types and function forward declarations used by your C micropatch
#include <stdio.h>
"""

# The asm_header is inserted in the main body of the patch before the C code. This header is primarily
# useful for gaining access to the stack pointer, which is a register that is unavailable in our C
# code. In this example we have moved rsp to the r12 register, which is a register that is accessible.
# This means that inside the C code we can access variables on the stack by using the r10 variable.
# There is also an asm_footer
asm_header = "mov r12, rsp"

# We can access assembly registers directly by using their name, while still using high level C constructs
# as well as intermediate variables. Note that you can use a return statement anywhere in your C micropatch
# to jump back to the next instruction after the micropatch insertion point.
c_str = """
rdi += rdi;
rdi += 5;
// Print out rsp as it was before the patch was started
printf("%p\\n", (void *) r12);
"""

# It is generally a good idea to mark some registers as scratch to give the compiler
# breathing room for allocating registers to use for intermediate variables in your micropatch
# All of the registers that we mark as scratch can be freely clobbered by the compiler
# Note that you can still read from scratch registers stored in the variables. What the scratch
# register denotation will indicate however is that the register can be re-used after the variable
# is no longer live.
c_scratch_regs = [
    'r8', 'r9', 'r10', 'r11', 'r13', 'r14', 'r15'
    'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15'
]

# By default floating point registers will have the 'float' type. We can use c_regs_sort to override
# certain registers so they hold different types. In this example we denote that xmm8 is of type double
c_regs_sort = [('xmm8', 'double')]

config = InsertInstructionPatch.CConfig(
    c_forward_header = c_forward_header,
    scratch_regs=c_scratch_regs,
    regs_sort=c_regs_sort,
    asm_header=asm_header
)

p.patches.append(InsertInstructionPatch(0x114d, c_str, language="C", c_config=config))
p.apply_patches()

p.binfmt_tool.save_binary()
