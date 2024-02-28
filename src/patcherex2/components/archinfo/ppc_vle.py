class PpcVleInfo:
    nop_bytes = b"\x01\x00\x00\x00"
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    call_asm = "bl {dst}"
    save_context_asm = ""  # TODO
    restore_context_asm = ""  # TODO
