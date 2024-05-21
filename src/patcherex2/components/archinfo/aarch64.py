class Aarch64Info:
    nop_bytes = b"\x1f\x20\x03\xd5"
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    alignment = 4
    bits = 64
    is_variable_length_isa = False
    instr_size = 4
    call_asm = "bl {dst}"
    pc_reg_names = ["pc", "ip"]
    save_context_asm = """
        sub sp, sp, #0x1f0
        stp x0, x1, [sp, #0x0]
        stp x2, x3, [sp, #0x10]
        stp x4, x5, [sp, #0x20]
        stp x6, x7, [sp, #0x30]
        stp x8, x9, [sp, #0x40]
        stp x10, x11, [sp, #0x50]
        stp x12, x13, [sp, #0x60]
        stp x14, x15, [sp, #0x70]
        stp x16, x17, [sp, #0x80]
        stp x18, x19, [sp, #0x90]
        stp x20, x21, [sp, #0xa0]
        stp x22, x23, [sp, #0xb0]
        stp x24, x25, [sp, #0xc0]
        stp x26, x27, [sp, #0xd0]
        stp x28, x29, [sp, #0xe0]
        str x30, [sp, #0xf0]
    """
    restore_context_asm = """
        ldp x0, x1, [sp, #0x0]
        ldp x2, x3, [sp, #0x10]
        ldp x4, x5, [sp, #0x20]
        ldp x6, x7, [sp, #0x30]
        ldp x8, x9, [sp, #0x40]
        ldp x10, x11, [sp, #0x50]
        ldp x12, x13, [sp, #0x60]
        ldp x14, x15, [sp, #0x70]
        ldp x16, x17, [sp, #0x80]
        ldp x18, x19, [sp, #0x90]
        ldp x20, x21, [sp, #0xa0]
        ldp x22, x23, [sp, #0xb0]
        ldp x24, x25, [sp, #0xc0]
        ldp x26, x27, [sp, #0xd0]
        ldp x28, x29, [sp, #0xe0]
        ldr x30, [sp, #0xf0]
        add sp, sp, #0x1f0
    """

    cc = {
        'default': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
        'defaultPreserveNone': None # TODO once aarch64 support lands in LLVM for preserve_none
    }
    callee_saved = {
        'default': ['x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30']
    }
    cc_float = {
        'default': ['v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7']
    }
    callee_saved_float = {
        'default': ['v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15']
    }

    float_types = {
        32: 'float',
        64: 'double',
        128: 'long double'
    }

    @property
    def regs(self):
        return list(self.subregisters.keys())

    @property
    def regs_float(self):
        return list(self.subregisters_float.keys())

    subregisters = {
        'x{}'.format(i):
            {
                64: ['x{}'.format(i)],
                32: ['w{}'.format(i)]
            }
        for i in range(0, 30 + 1)
    }

    subregisters_float = {
        'v{}'.format(i): {
            128: ['v{}'.format(i)],
            64: ['d{}'.format(i)],
            32: ['s{}'.format(i)],
            16: ['h{}'.format(i)],
            8: ['b{}'.format(i)]
        }
        for i in range(0, 30 + 1)
    }