class MipsInfo:
    nop_bytes = b"\x00\x00\x00\x00"
    nop_size = 4
    jmp_asm = "j {dst}"
    # NOTE: keystone will always add nop for branch delay slot, so include it in size
    jmp_size = 8
    call_asm = "jal {dst}"
