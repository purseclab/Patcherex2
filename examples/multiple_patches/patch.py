from patcherex2 import *

p = Patcherex("getline")

p.patches.append(InsertInstructionPatch(0x120b,"mov esi, 0xa\n"))
p.patches.append(InsertDataPatch("my_str",b"Ran out of space\0"))

p.patches.append(InsertInstructionPatch(0x1199,"mov [rbp-0xc],esi"))

asm_string = """
    cmp edx, [rbp-0xc]
    jl less
    SAVE_CONTEXT
    lea rdi, [{my_str}]
    call {puts}
    RESTORE_CONTEXT
    mov rsi, [rbp-0x18]
    mov byte ptr [rsi+rax], 0
    mov eax, edx
    leave
    ret
less:
"""

p.patches.append(InsertInstructionPatch(0x11c1,asm_string))

p.apply_patches()

p.save_binary()