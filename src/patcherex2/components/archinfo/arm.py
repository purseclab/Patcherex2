class ArmInfo:
    nop_bytes = b"\x00\xf0\x20\xe3"  # TODO: thumb
    nop_size = 4
    jmp_asm = "b {dst}"
    jmp_size = 4
    alignment = 4
    bits = 32
    is_variable_length_isa = False
    instr_size = 4  # TODO: thumb 2
    call_asm = "bl {dst}"
    pc_reg_names = ["pc", "r15"]
    save_context_asm = """
        push {r0-r11}
    """
    restore_context_asm = """
        pop {r0-r11}
    """

    cc = {
        "Linux": ["r0", "r1", "r2", "r3"],
        # TODO: update LinuxPreserveNone once aarch64 support lands
        # in LLVM for preserve_none, currently defaults to Linux
        "LinuxPreserveNone": ["r0", "r1", "r2", "r3"],
    }
    callee_saved = {
        "Linux": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r13", "r14", "r15"]
    }
    cc_float = {"Linux": ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"]}
    callee_saved_float = {
        "Linux": ["d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"]
    }

    float_types = {32: "float", 64: "double"}

    @property
    def regs(self):
        return list(self.subregisters.keys())

    @property
    def regs_float(self):
        return list(self.subregisters_float.keys())

    subregisters = {f"r{i}": {32: [f"r{i}"]} for i in range(0, 16)}

    subregisters_float = {}
    for i in range(0, 16):
        subregisters_float[f"d{i}"] = {64: [f"d{i}"], 32: [f"s{2 * i}"]}
    for i in range(16, 32):
        subregisters_float[f"d{i}"] = {64: [f"d{i}"]}
