class Mips64Info:
    nop_bytes = b"\x00\x00\x00\x00"
    nop_size = 4
    jmp_asm = "j {dst}"
    # NOTE: keystone will aldays add nop for branch delay slot, so include it in size
    jmp_size = 8
    alignment = 4
    bits = 64
    is_variable_length_isa = False
    instr_size = 4
    call_asm = "jal {dst}"
    pc_reg_names = ["pc"]
    save_context_asm = """
    sub $sp, $sp, -248
    sd $ra, 240($sp)
    sd $s0, 232($sp)
    sd $s1, 224($sp)
    sd $s2, 216($sp)
    sd $s3, 208($sp)
    sd $s4, 200($sp)
    sd $s5, 192($sp)
    sd $s6, 184($sp)
    sd $s7, 176($sp)
    sd $s8, 168($sp)
    sd $s9, 160($sp)
    sd $s10, 152($sp)
    sd $s11, 144($sp)
    sd $s12, 136($sp)
    sd $s13, 128($sp)
    sd $s14, 120($sp)
    sd $s15, 112($sp)
    sd $s16, 104($sp)
    sd $s17, 96($sp)
    sd $s18, 88($sp)
    sd $s19, 80($sp)
    sd $s20, 72($sp)
    sd $s21, 64($sp)
    sd $s22, 56($sp)
    sd $s23, 48($sp)
    sd $s24, 40($sp)
    sd $s25, 32($sp)
    sd $s26, 24($sp)
    sd $s27, 16($sp)
    sd $s28, 8($sp)
    sd $s29, 0($sp)
    """
    restore_context_asm = """
    ld $s29, 0($sp)
    ld $s28, 8($sp)
    ld $s27, 16($sp)
    ld $s26, 24($sp)
    ld $s25, 32($sp)
    ld $s24, 40($sp)
    ld $s23, 48($sp)
    ld $s22, 56($sp)
    ld $s21, 64($sp)
    ld $s20, 72($sp)
    ld $s19, 80($sp)
    ld $s18, 88($sp)
    ld $s17, 96($sp)
    ld $s16, 104($sp)
    ld $s15, 112($sp)
    ld $s14, 120($sp)
    ld $s13, 128($sp)
    ld $s12, 136($sp)
    ld $s11, 144($sp)
    ld $s10, 152($sp)
    ld $s9, 160($sp)
    ld $s8, 168($sp)
    ld $s7, 176($sp)
    ld $s6, 184($sp)
    ld $s5, 192($sp)
    ld $s4, 200($sp)
    ld $s3, 208($sp)
    ld $s2, 216($sp)
    ld $s1, 224($sp)
    ld $s0, 232($sp)
    ld $ra, 240($sp)
    add $sp, $sp, 248
    """
