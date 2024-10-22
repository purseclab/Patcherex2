# ruff: noqa
from .patcherex import Patcherex
from .patches import *
from importlib import metadata

__version__ = metadata.version("patcherex2")

__all__ = ["Patcherex"] + patches.__all__
