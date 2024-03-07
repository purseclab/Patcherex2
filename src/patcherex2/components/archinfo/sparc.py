class SparcInfo:
    nop_bytes = b"\x01\x00\x00\x00"
    nop_size = 4
    jmp_asm = "b {dst}\nnop"  # nop due to delay slot
    jmp_size = 8
    alignment = 4
    is_variable_length_isa = False
    instr_size = 4
    call_asm = "call {dst}"
    pc_reg_names = ["pc"]
    save_context_asm = ""  # TODO
    restore_context_asm = ""  # TODO
