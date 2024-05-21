class Target:
    target_classes = []

    def __init__(self, p, binary_path):
        self.binary_path = binary_path
        self.p = p

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.target_classes.append(cls)

    @classmethod
    def detect_target(cls, p, binary_path):
        for target_class in cls.target_classes:
            if target_class.detect_target(binary_path):
                return target_class(p, binary_path)
        raise ValueError("Unknown target")

    def get_component(self, component_type, component_name, component_opts=None):
        if component_opts is None:
            component_opts = {}
        return getattr(self, f"get_{component_type}")(component_name, **component_opts)

    def get_cc(self, archinfo=None, preserve_none=False):
        raise NotImplementedError("The calling convention for this target is unknown")

    def get_cc_float(self, archinfo=None):
        raise NotImplementedError("The floating point calling convention for this target is unknown")

    def get_archinfo(self, archinfo):
        raise NotImplementedError("get_archinfo not implemented")

    def get_callee_saved(self, archinfo=None):
        raise NotImplementedError("get_callee_saved not implemented")

    def get_callee_saved_float(self, archinfo=None):
        raise NotImplementedError("get_callee_saved_float not implemented")