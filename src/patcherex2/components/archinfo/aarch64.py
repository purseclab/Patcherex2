class Aarch64Info:
    nop_bytes = b"\x1f\x20\x03\xd5"
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    call_asm = "bl {dst}"
