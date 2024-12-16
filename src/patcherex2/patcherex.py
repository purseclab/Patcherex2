# ruff: noqa: F403, F405
from __future__ import annotations

import logging

from .components.binary_analyzers.ghidra import Ghidra
from .patches import *
from .patches import __all__ as all_patches
from .targets import Target

logging.Logger.manager.loggerDict["patcherex"] = logging.Logger.manager.loggerDict[
    "patcherex2"
]
logger = logging.getLogger(__name__)


class Patcherex:
    """
    The main class of the library. This is how you are intended to interact with patches.
    """

    def __init__(
        self,
        binary_path: str,
        target_cls: type[Target] | None = None,
        target_opts: dict[str, str] | None = None,
        components_opts: dict[str, dict[str, str]] | None = None,
    ) -> None:
        """
        Constructor.

        :param binary_path: The path of the binary to patch.
        :param target_cls: Specified architecture class to use, otherwise it is automatically detected, defaults to None
        :param target_opts: Options to specify components for the target, defaults to None
        :param components_opts: Options for configuring each component for the target, defaults to None
        """
        if target_opts is None:
            target_opts = {}
        if components_opts is None:
            components_opts = {}
        self.binary_path = binary_path
        if target_cls is None:
            self.target = Target.detect_target(self, binary_path)
        else:
            self.target = target_cls(self, binary_path)

        self.symbols = {}
        self.sypy_info = {"patcherex_added_functions": []}
        self.patches = []

        # Initialize components
        components = [
            "assembler",
            "disassembler",
            "compiler",
            "binary_analyzer",
            "allocation_manager",
            "binfmt_tool",
            "utils",
            "archinfo",
        ]
        for component in components:
            setattr(
                self,
                component,
                self.target.get_component(
                    component,
                    target_opts.get(component),
                    components_opts.get(component),
                ),
            )

        # Chosen patch order, making sure all are accounted for
        self.patch_order = (
            ModifyRawBytesPatch,
            RemoveDataPatch,
            InsertDataPatch,
            ModifyDataPatch,
            RemoveLabelPatch,
            ModifyLabelPatch,
            InsertLabelPatch,
            RemoveInstructionPatch,
            InsertInstructionPatch,
            ModifyInstructionPatch,
            RemoveFunctionPatch,
            InsertFunctionPatch,
            ModifyFunctionPatch,
        )
        assert len(self.patch_order) == len(all_patches)

    def shutdown(self):
        """
        Shuts down any resources used by Patcherex2.
        This needs to be called when using Ghidra as the binary analyzer when done patching.
        """
        if isinstance(self.binary_analyzer, Ghidra):
            self.binary_analyzer.shutdown()

    def apply_patches(self) -> None:
        """
        Applies all added patches to the binary. Call this when you have added all the patches you want.
        """
        # TODO: sort patches properly
        # self.patches.sort(key=lambda x: self.patch_order.index(type(x)))
        self.patches.sort(
            key=lambda x: not isinstance(
                x, (ModifyDataPatch, InsertDataPatch, RemoveDataPatch)
            )
        )
        logger.debug(f"Applying patches: {self.patches}")
        for patch in self.patches:
            patch.apply(self)
        self.binfmt_tool.finalize()

    def save_binary(self, filename: str = None) -> None:
        """
        Save the patched binary to a file.

        :param filename: Name of file to save to, defaults to '<filename>.patched'
        """
        self.binfmt_tool.save_binary(filename)
