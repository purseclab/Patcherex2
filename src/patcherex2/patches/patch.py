class Patch:
    patch_classes = []

    def __init__(self, parent=None) -> None:
        self.parent = parent

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.patch_classes.append(cls)

    def apply(self, p):
        raise NotImplementedError()
