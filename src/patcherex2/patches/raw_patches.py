"""
Contains patches that modify the binary at the byte level.
"""

import logging

from .patch import Patch

logger = logging.getLogger(__name__)


class ModifyRawBytesPatch(Patch):
    """
    Patch that modifies bytes of the binary.
    """

    def __init__(self, addr: int, new_bytes: bytes, addr_type="mem") -> None:
        """
        Constructor.

        :param addr: Starting address of bytes you want to change.
        :param new_bytes: New bytes to replace original ones.
        :param addr_type: The type of address given, "mem" (memory address) or "raw" (file address), defaults to "mem"
        """
        self.addr = addr
        self.new_bytes = new_bytes
        self.addr_type = addr_type

    def apply(self, p) -> None:
        """
        Applies the patch to the binary, intended to be called by a Patcherex instance.

        :param p: Patcherex instance.
        :raises NotImplementedError: Raised if an address type other than "raw" or "mem" is specified.
        """
        if self.addr_type == "raw":
            offset = self.addr
        elif self.addr_type == "mem":
            offset = p.binary_analyzer.mem_addr_to_file_offset(self.addr)
            if not offset:
                logger.warning(
                    "failed to convert mem addr to file offset, will just default to raw addr"
                )
                offset = self.addr
        else:
            raise NotImplementedError()
        p.binfmt_tool.update_binary_content(offset, self.new_bytes)
