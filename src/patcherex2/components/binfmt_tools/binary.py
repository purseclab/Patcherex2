from __future__ import annotations

import logging

from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


class Binary(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        with open(binary_path, "rb") as f:
            self._original = f.read()
        self.file_size = len(self._original)
        self.file_updates = []

    def _init_memory_analysis(self) -> None:
        pass

    def finalize(self) -> None:
        pass

    def save_binary(self, filename: str | None = None) -> None:
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            f.write(self._original)
            for update in self.file_updates:
                f.seek(update["offset"])
                f.write(update["content"])

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        logger.debug(
            f"Updating offset {hex(offset)} with content ({len(new_content)} bytes) {new_content.hex()}"
        )
        for update in self.file_updates:
            if offset >= update["offset"] and offset < update["offset"] + len(
                update["content"]
            ):
                raise ValueError(
                    f"Cannot update offset {hex(offset)} with content {new_content}, it overlaps with a previous update"
                )
        self.file_updates.append({"offset": offset, "content": new_content})
        if offset + len(new_content) > self.file_size:
            self.file_size = offset + len(new_content)

    def get_binary_content(self, offset: int, size: int) -> bytes:
        # FIXME: content partially in the file and partially in the updates (check other binfmt tools as well)
        for update in self.file_updates:
            if offset >= update["offset"] and offset + size <= update["offset"] + len(
                update["content"]
            ):
                return update["content"][
                    offset - update["offset"] : offset - update["offset"] + size
                ]
        return self._original[offset : offset + size]

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.file_updates.append({"offset": self.file_size, "content": new_content})
        self.file_size += len(new_content)
