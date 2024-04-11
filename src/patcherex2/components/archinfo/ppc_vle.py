class PpcVleInfo:
    nop_bytes = b"\x01\x00\x00\x00"
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    alignment = 4
    bits = 32
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "bl {dst}"
    pc_reg_names = []
    save_context_asm = ""  # TODO
    restore_context_asm = ""  # TODO
