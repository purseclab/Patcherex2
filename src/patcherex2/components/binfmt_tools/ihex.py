from __future__ import annotations

import io
import logging

import intelhex

from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


class IHex(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        self._ihex = intelhex.IntelHex(binary_path)
        self.file_size = self._ihex.maxaddr() + 1
        self.file_updates = []

    def _init_memory_analysis(self) -> None:
        pass

    def finalize(self) -> None:
        pass

    def mem_addr_to_file_offset(self, addr: int) -> int:
        # IHex updates use logical addresses, not text-file byte offsets.
        return addr

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
        self._record_file_update(offset, new_content)

    def get_binary_content(self, offset: int, size: int) -> bytes:
        read_size = self._read_size(offset, size)
        if read_size == 0:
            return b""
        original_content = bytes(self._ihex.tobinarray(start=offset, size=read_size))
        return self._overlay_file_updates(offset, original_content)

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.update_binary_content(self.file_size, new_content)
