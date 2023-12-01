# from .backends import Backend

# class Patcherex:
#     def __init__(self, binary_path) -> None:
#         self.binary_path = binary_path
#         self._backend_class = Backend._resolver(binary_path)
#         self._backend = self._backend_class(binary_path)

#     def apply_patches(self, patch_manager):
#         self._backend.apply_patches(patch_manager.patches)

#     def save_binary(self, filename=None):
#         self._backend.save_binary(filename)

from .targets import Target
from .patches import *
from .allocation_management import *

import os
import logging

logger = logging.getLogger(__name__)


class Patcherex:
    def __init__(self, binary_path, target_cls=None) -> None:
        self.binary_path = binary_path
        if target_cls is None:
            self.target = Target.detect_target(self, binary_path)
        else:
            self.target = target_cls(self, binary_path)

        self.symbols = {}
        self.assembler = self.target.get_assembler()
        self.disassembler = self.target.get_disassembler()
        self.compiler = self.target.get_compiler()
        self.binary_analyzer = self.target.get_binary_analyzer()
        self.allocation_manager = self.target.get_allocation_manager()
        self.binfmt_tool = self.target.get_binfmt_tool()
        self.utils = self.target.get_utils()
        self.sypy_info = {"patcherex_added_functions": []}
        self.patches = []

    def apply_patches(self):
        # TODO: sort patches properly
        self.patches.sort(
            key=lambda x: not isinstance(
                x, (ModifyDataPatch, InsertDataPatch, RemoveDataPatch)
            )
        )
        logger.debug(f"Applying patches: {self.patches}")
        for patch in self.patches:
            patch.apply(self)
        self.binfmt_tool.finalize()

    def save_binary(self, filename=None):
        logger.warning(
            "p.save_binary() is deprecated, use p.binfmt_tool.save_binary() instead."
        )
        self.binfmt_tool.save_binary(filename)
