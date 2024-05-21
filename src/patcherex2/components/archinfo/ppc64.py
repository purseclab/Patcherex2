class Ppc64Info:
    nop_bytes = b"\x60\x00\x00\x00"
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    alignment = 4
    bits = 64
    is_variable_length_isa = False
    instr_size = 4
    call_asm = "bl {dst}"
    pc_reg_names = []
    save_context_asm = """
    stwu r1, -0x80(r1)
    stmw r3, 0x8(r1)
    """
    restore_context_asm = """
    lmw r3, 0x8(r1)
    addi r1, r1, 0x80
    """
