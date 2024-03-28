from __future__ import annotations

from patcherex2.patches import Patch


class PatchManager:
    def __init__(self) -> None:
        self.patches = []
        self.analyzed = False

    def add_patch(self, patch: Patch) -> None:
        self.analyzed = False
        self.patches.append(patch)

    def add_patches(self, patches: list[Patch]) -> None:
        for patch in patches:
            self.add_patch(patch)

    def export_patches(self, filename: str) -> None:
        raise NotImplementedError()

    def import_patches(self, filename: str) -> None:
        raise NotImplementedError()

    def analyze_patches(self, ignore_conflicts=False) -> None:
        raise NotImplementedError()

    def apply_patches(self, best_effort=False) -> None:
        raise NotImplementedError()
