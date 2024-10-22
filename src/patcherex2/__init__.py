# ruff: noqa
from importlib import metadata

from .patcherex import Patcherex
from .patches import *

__version__ = metadata.version("patcherex2")

__all__ = ["Patcherex"] + patches.__all__
