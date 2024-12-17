from __future__ import annotations

import io
import logging

import intelhex

from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


class IHex(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        self._file = open(binary_path, "rb")
        self._ihex = intelhex.IntelHex(binary_path)
        self.file_size = self._ihex.maxaddr() + 1
        self.file_updates = []

    def __del__(self) -> None:
        self._file.close()

    def _init_memory_analysis(self) -> None:
        pass

    def finalize(self) -> None:
        pass

    def save_binary(self, filename: str | None = None) -> None:
        for update in self.file_updates:
            self._ihex.puts(update["offset"], update["content"])
        if filename is None:
            filename = f"{self.binary_path}.patched"
        sio = io.StringIO()
        self._ihex.write_hex_file(sio, byte_count=0x20)
        final_content = sio.getvalue()
        sio.close()
        entry_point = ""
        final = ""
        for line in final_content.splitlines():
            if line.startswith(":04000005"):
                entry_point = line
            elif line == ":00000001FF":
                final += entry_point + "\n"
                final += line + "\n"
            else:
                final += line + "\n"

        with open(filename, "w") as f:
            f.write(final)

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
        # check if it's in the file updates
        for update in self.file_updates:
            if offset >= update["offset"] and offset + size <= update["offset"] + len(
                update["content"]
            ):
                return update["content"][
                    offset - update["offset"] : offset - update["offset"] + size
                ]
        # otherwise read from the file
        return self._ihex.tobinarray(start=offset, size=size)

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.file_updates.append({"offset": self.file_size, "content": new_content})
        self.file_size += len(new_content)
