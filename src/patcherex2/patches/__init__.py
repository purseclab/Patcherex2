from .data_patches import InsertDataPatch, ModifyDataPatch, RemoveDataPatch
from .dummy_patches import InsertLabelPatch, ModifyLabelPatch, RemoveLabelPatch
from .function_patches import (
    InsertFunctionPatch,
    ModifyFunctionPatch,
    RemoveFunctionPatch,
)
from .instruction_patches import (
    InsertInstructionPatch,
    ModifyInstructionPatch,
    RemoveInstructionPatch,
)
from .patch import Patch
from .raw_patches import ModifyRawBytesPatch

__all__ = [
    "ModifyDataPatch",
    "InsertDataPatch",
    "RemoveDataPatch",
    "InsertLabelPatch",
    "ModifyLabelPatch",
    "RemoveLabelPatch",
    "ModifyFunctionPatch",
    "InsertFunctionPatch",
    "RemoveFunctionPatch",
    "ModifyInstructionPatch",
    "InsertInstructionPatch",
    "RemoveInstructionPatch",
    "ModifyRawBytesPatch",
]


# Other Patches
class ModifyEntryPointPatch(Patch):
    def __init__(self, addr: int, parent=None) -> None:
        self.addr = addr
        super().__init__(parent)


# Complex Patches
class InsertFunctionWrapperPatch(Patch):
    def __init__(self, addr: int, wrapper_code: str, parent=None) -> None:
        self.addr = addr
        self.wrapper_code = wrapper_code
        super().__init__(parent)
