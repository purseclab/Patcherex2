import logging

logger = logging.getLogger(__name__)


class BinFmtTool:
    def __init__(self, p, binary_path: str) -> None:
        self.p = p
        self.binary_path = binary_path

    def _init_memory_analysis(self) -> None:
        raise NotImplementedError()

    def save_binary(self, filename=None) -> None:
        raise NotImplementedError()

    def update_binary_content(self, offset: str, new_content: bytes) -> None:
        raise NotImplementedError()

    def append_to_binary_content(self, new_content: bytes) -> None:
        raise NotImplementedError()
