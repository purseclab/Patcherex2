class S390xInfo:
    nop_bytes = b"\x07\x00"
    nop_size = 2
    jmp_asm = "jg {dst}"
    jmp_size = 6
    alignment = 2
    bits = 64
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "brasl %r14, {dst}"
    pc_reg_names = []
    save_context_asm = """
    stmg %r6,%r15,48(%r15)
    aghi %r15,-160
    """
    restore_context_asm = """
    lmg %r6,%r15,208(%r15)
    """
