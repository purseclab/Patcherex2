class X86Info:
    nop_bytes = b"\x90"
    nop_size = 1
    jmp_asm = "jmp {dst}"
    jmp_size = 5
    alignment = 4
    bits = 32
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "call {dst}"
    pc_reg_names = ["eip"]
    save_context_asm = """
    pusha
    """
    restore_context_asm = """
    popa
    """
