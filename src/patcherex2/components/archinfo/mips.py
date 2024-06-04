class MipsInfo:
    nop_bytes = b"\x00\x00\x00\x00"
    nop_size = 4
    jmp_asm = "j {dst}"
    # NOTE: keystone will always add nop for branch delay slot, so include it in size
    jmp_size = 8
    alignment = 4
    bits = 32
    is_variable_length_isa = False
    instr_size = 4
    call_asm = "jal {dst}"
    pc_reg_names = ["pc"]
    save_context_asm = """
    sub $sp, $sp, -124
    sw $ra, 120($sp)
    sw $s0, 116($sp)
    sw $s1, 112($sp)
    sw $s2, 108($sp)
    sw $s3, 104($sp)
    sw $s4, 100($sp)
    sw $s5, 96($sp)
    sw $s6, 92($sp)
    sw $s7, 88($sp)
    sw $s8, 84($sp)
    sw $s9, 80($sp)
    sw $s10, 76($sp)
    sw $s11, 72($sp)
    sw $s12, 68($sp)
    sw $s13, 64($sp)
    sw $s14, 60($sp)
    sw $s15, 56($sp)
    sw $s16, 52($sp)
    sw $s17, 48($sp)
    sw $s18, 44($sp)
    sw $s19, 40($sp)
    sw $s20, 36($sp)
    sw $s21, 32($sp)
    sw $s22, 28($sp)
    sw $s23, 24($sp)
    sw $s24, 20($sp)
    sw $s25, 16($sp)
    sw $s26, 12($sp)
    sw $s27, 8($sp)
    sw $s28, 4($sp)
    sw $s29, 0($sp)
    """
    restore_context_asm = """
    lw $s29, 0($sp)
    lw $s28, 4($sp)
    lw $s27, 8($sp)
    lw $s26, 12($sp)
    lw $s25, 16($sp)
    lw $s24, 20($sp)
    lw $s23, 24($sp)
    lw $s22, 28($sp)
    lw $s21, 32($sp)
    lw $s20, 36($sp)
    lw $s19, 40($sp)
    lw $s18, 44($sp)
    lw $s17, 48($sp)
    lw $s16, 52($sp)
    lw $s15, 56($sp)
    lw $s14, 60($sp)
    lw $s13, 64($sp)
    lw $s12, 68($sp)
    lw $s11, 72($sp)
    lw $s10, 76($sp)
    lw $s9, 80($sp)
    lw $s8, 84($sp)
    lw $s7, 88($sp)
    lw $s6, 92($sp)
    lw $s5, 96($sp)
    lw $s4, 100($sp)
    lw $s3, 104($sp)
    lw $s2, 108($sp)
    lw $s1, 112($sp)
    lw $s0, 116($sp)
    lw $ra, 120($sp)
    add $sp, $sp, 124
    """
