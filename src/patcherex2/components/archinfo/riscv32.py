class Riscv32Info:
    nop_bytes = b"\x13\x00\x00\x00"
    nop_size = 4
    jmp_asm = "tail {dst}"  # pseudo-instruction
    jmp_size = 8
    alignment = 2
    bits = 32
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "call {dst}"  # pseudo-instruction
    pc_reg_names = ["pc", "ra"]
    save_context_asm = ""  # TODO
    restore_context_asm = ""  # TODO
