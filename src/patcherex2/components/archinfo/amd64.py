class Amd64Info:
    nop_bytes = b"\x90"
    nop_size = 1
    jmp_asm = "jmp {dst}"
    jmp_size = 6
    alignment = 4
    is_variable_length_isa = True
    instr_size = -1  # variable length
    call_asm = "call {dst}"
    pc_reg_names = ["rip"]
    save_context_asm = """
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push rsp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    """
    restore_context_asm = """
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsp
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    """
