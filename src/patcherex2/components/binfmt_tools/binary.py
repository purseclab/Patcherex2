from __future__ import annotations

import io
import logging

from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


class Binary(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        self._file = open(binary_path, "rb")
        self.file_size = self._file.seek(0, io.SEEK_END)
        self._file.seek(0)
        self.file_updates = []

    def __del__(self) -> None:
        self._file.close()

    def _init_memory_analysis(self) -> None:
        pass

    def finalize(self) -> None:
        pass

    def save_binary(self, filename: str | None = None) -> None:
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            self._file.seek(0)
            f.write(self._file.read())
            # apply the updates
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
        # check if it's in the file updates
        for update in self.file_updates:
            if offset >= update["offset"] and offset + size <= update["offset"] + len(
                update["content"]
            ):
                return update["content"][
                    offset - update["offset"] : offset - update["offset"] + size
                ]
        # otherwise read from the file
        self._file.seek(offset)
        return self._file.read(size)

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.file_updates.append({"offset": self.file_size, "content": new_content})
        self.file_size += len(new_content)
