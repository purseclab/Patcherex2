class Amd64Info:
    nop_bytes = b"\x90"
    nop_size = 1
    jmp_asm = "jmp {dst}"
    jmp_size = 6
    call_asm = "call {dst}"
