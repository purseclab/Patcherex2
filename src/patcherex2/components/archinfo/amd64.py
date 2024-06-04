class Amd64Info:
    nop_bytes = b"\x90"
    nop_size = 1
    jmp_asm = "jmp {dst}"
    jmp_size = 6
    alignment = 4
    bits = 64
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

    cc = {
        "Linux": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        "LinuxPreserveNone": [
            "r12",
            "r13",
            "r14",
            "r15",
            "rdi",
            "rsi",
            "rdx",
            "rcx",
            "r8",
            "r9",
            "r11",
            "rax",
        ],
        "Windows": ["rcx", "rdx", "r8", "r9"],
    }
    callee_saved = {"Linux": ["r12", "r13", "r14", "r15", "rbx", "rsp", "rbp"]}
    cc_float = {
        "Linux": ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"]
    }
    callee_saved_float = {"Linux": []}

    float_types = {32: "float", 64: "double", 128: "__float128"}

    @property
    def regs(self):
        return list(self.subregisters.keys())

    @property
    def regs_float(self):
        return list(self.subregisters_float.keys())

    subregisters = {
        "rax": {
            64: ["rax"],
            32: ["eax"],
            16: ["ax"],
            # Note that the order of the children registers is important. Only the 0th
            # element of this list (al) is used when determining the calling convention.
            # That is, we can only use the following argument 'uint8_t al' in the
            # calling convention at the rax position. 'uint8_t ah' is NOT allowed.
            8: ["al", "ah"],
        },
        "rbx": {64: ["rbx"], 32: ["ebx"], 16: ["bx"], 8: ["bl", "bh"]},
        "rcx": {64: ["rcx"], 32: ["ecx"], 16: ["cx"], 8: ["cl", "ch"]},
        "rdx": {64: ["rdx"], 32: ["edx"], 16: ["dx"], 8: ["dl", "dh"]},
        "rsi": {64: ["rsi"], 32: ["esi"], 16: ["si"], 8: ["sil"]},
        "rdi": {64: ["rdi"], 32: ["edi"], 16: ["di"], 8: ["dil"]},
        "rbp": {64: ["rbp"], 32: ["ebp"], 16: ["bp"], 8: ["bpl"]},
        "rsp": {64: ["rsp"], 32: ["esp"], 16: ["sp"], 8: ["spl"]},
        "r8": {64: ["r8"], 32: ["r8d"], 16: ["r8w"], 8: ["r8b"]},
        "r9": {64: ["r9"], 32: ["r9d"], 16: ["r9w"], 8: ["r9b"]},
        "r10": {64: ["r10"], 32: ["r10d"], 16: ["r10w"], 8: ["r10b"]},
        "r11": {64: ["r11"], 32: ["r11d"], 16: ["r11w"], 8: ["r11b"]},
        "r12": {64: ["r12"], 32: ["r12d"], 16: ["r12w"], 8: ["r12b"]},
        "r13": {64: ["r13"], 32: ["r13d"], 16: ["r13w"], 8: ["r13b"]},
        "r14": {64: ["r14"], 32: ["r14d"], 16: ["r14w"], 8: ["r14b"]},
        "r15": {64: ["r15"], 32: ["r15d"], 16: ["r15w"], 8: ["r15b"]},
    }

    subregisters_float = {f"xmm{i}": {128: [f"xmm{i}"]} for i in range(0, 15 + 1)}
