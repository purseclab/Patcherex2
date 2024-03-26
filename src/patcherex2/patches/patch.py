class Patch:
    """
    Base class for patches. Not instantiated direactly.
    """

    def __init__(self, parent=None) -> None:
        self.parent = parent

    def apply(self, p):
        raise NotImplementedError()
