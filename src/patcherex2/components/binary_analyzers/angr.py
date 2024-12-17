from __future__ import annotations

import logging
import traceback

import angr
from archinfo import ArchARM

from .binary_analyzer import BinaryAnalyzer

logger = logging.getLogger(__name__)


class Angr(BinaryAnalyzer):
    def __init__(self, binary_path: str, **kwargs) -> None:
        self.binary_path = binary_path
        # self.use_pickle = kwargs.pop("use_pickle", False) # TODO: implement this
        self.angr_kwargs = kwargs.pop("angr_kwargs", {})
        self.angr_cfg_kwargs = kwargs.pop("angr_cfg_kwargs", {})
        self._p = None
        self._cfg = None
        self._load_base = None

    @property
    def load_base(self) -> int:
        if self._load_base is None:
            self._load_base = self.p.loader.main_object.mapped_base
        return self._load_base

    def normalize_addr(self, addr: int) -> int:
        if self.p.loader.main_object.pic:
            return addr - self.load_base
        return addr

    def denormalize_addr(self, addr: int) -> int:
        if self.p.loader.main_object.pic:
            return addr + self.load_base
        return addr

    @property
    def p(self) -> angr.Project:
        if self._p is None:
            logger.info("Loading binary with angr")
            if "load_options" not in self.angr_kwargs:
                self.angr_kwargs["load_options"] = {"auto_load_libs": False}
            self._p = angr.Project(self.binary_path, **self.angr_kwargs)
            logger.info("Loaded binary with angr")
        return self._p

    @property
    def cfg(self) -> angr.analyses.cfg.cfg_fast.CFGFast:
        if self._cfg is None:
            logger.info("Generating CFG with angr")
            if "normalize" not in self.angr_cfg_kwargs:
                # NOTE: This will split basic blocks if another block jumps to the middle of the block
                self.angr_cfg_kwargs["normalize"] = True
            self._cfg = self.p.analyses.CFGFast(**self.angr_cfg_kwargs)
            logger.info("Generated CFG with angr")
        return self._cfg

    def mem_addr_to_file_offset(self, addr: int) -> int:
        addr = self.denormalize_addr(addr)
        file_addr = self.p.loader.main_object.addr_to_offset(addr)
        if file_addr is None:
            logger.error(
                f"Cannot convert memory address {hex(addr)} to file offset, will use the memory address instead"
            )
            return addr
        return file_addr

    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        # NOTE: angr splits basic blocks at call instructions, so we need to handle this
        if self.is_thumb(addr) and addr % 2 == 0:
            addr += 1
        addr = self.denormalize_addr(addr)

        try:
            func = self.p.kb.functions.function(
                self.cfg.model.get_any_node(addr, anyaddr=True).function_address
            )
            ri = self.p.analyses.RegionIdentifier(func)
            graph = ri._graph.copy()
            ri._make_supergraph(graph)

            for multinode in graph.nodes():
                nodes = multinode.nodes if hasattr(multinode, "nodes") else [multinode]
                start = multinode.addr
                size = sum(node.size for node in nodes)
                end = start + size

                instr_addrs = [
                    instr_addr
                    for node in nodes
                    for instr_addr in func.get_block(node.addr).instruction_addrs
                ]

                if addr in instr_addrs:
                    return {
                        "start": self.normalize_addr(start),
                        "end": self.normalize_addr(end),
                        "size": size,
                        "instruction_addrs": [
                            self.normalize_addr(instr_addr)
                            - (
                                1
                                if self.is_thumb(self.normalize_addr(instr_addr))
                                else 0
                            )
                            for instr_addr in instr_addrs
                        ],
                    }
        except Exception:
            logger.error(
                f"angr RegionIdentifier failed for function containing {hex(addr)}, falling back to use cfg nodes\n{traceback.format_exc()}"
            )
            bb = None
            for node in self.cfg.model.nodes():
                if addr in node.instruction_addrs:
                    bb = node
                    break
            assert bb is not None
            return {
                "start": self.normalize_addr(bb.addr),
                "end": self.normalize_addr(bb.addr + bb.size),
                "size": bb.size,
                "instruction_addrs": [
                    self.normalize_addr(addr)
                    - (1 if self.is_thumb(self.normalize_addr(addr)) else 0)
                    for addr in bb.instruction_addrs
                ],
            }

        raise Exception(f"Cannot find a block containing address {hex(addr)}")

    def get_instr_bytes_at(self, addr: int, num_instr=1) -> angr.Block:
        addr += 1 if self.is_thumb(addr) else 0
        addr = self.denormalize_addr(addr)
        # TODO: Special handling for delay slot, when there is a call instr with delay slot
        # angr will return both instrs, even when num_instr is 1
        return self.p.factory.block(addr, num_inst=num_instr).bytes

    def get_unused_funcs(self) -> list[dict[str, int]]:
        logger.info("Getting unused functions with angr")
        unused_funcs = []
        assert self.cfg is not None
        for func in self.p.kb.functions.values():
            if func.size == 0:
                continue
            for dst, _ in self.p.kb.xrefs.xrefs_by_dst.items():
                if dst == func.addr:
                    break
            else:
                unused_funcs.append(
                    {
                        "addr": self.normalize_addr(func.addr)
                        - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                        "size": func.size,
                    }
                )
        return unused_funcs

    def get_all_symbols(self) -> dict[str, int]:
        assert self.cfg is not None
        logger.info("Getting all symbols with angr")
        symbols = {}
        for symbol in self.p.loader.main_object.symbols:
            if not symbol.name or not symbol.is_function:
                continue
            symbols[symbol.name] = self.normalize_addr(symbol.rebased_addr)
        for func in self.p.kb.functions.values():
            # make it compatible with old angr versions
            if func.is_simprocedure or (getattr(func, "is_alignment", func.alignment)):
                continue
            symbols[func.name] = self.normalize_addr(func.addr)
        return symbols

    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        assert self.cfg is not None
        if isinstance(name_or_addr, (str, int)):
            if isinstance(name_or_addr, int):
                name_or_addr += 1 if self.is_thumb(name_or_addr) else 0
                name_or_addr = self.denormalize_addr(name_or_addr)
            if name_or_addr in self.p.kb.functions:
                func = self.p.kb.functions[name_or_addr]
                return {
                    "addr": self.normalize_addr(func.addr)
                    - (1 if self.is_thumb(self.normalize_addr(func.addr)) else 0),
                    "size": func.size,
                }
            return None
        else:
            raise Exception(f"Invalid type for name_or_addr: {type(name_or_addr)}")

    def is_thumb(self, addr: int) -> bool:
        if not isinstance(self.p.arch, ArchARM):
            return False
        addr = self.denormalize_addr(addr)

        for node in self.cfg.model.nodes():
            if addr in node.instruction_addrs:
                return node.thumb
        else:
            if addr % 2 == 0:
                return self.is_thumb(self.normalize_addr(addr + 1))
            else:
                logger.error(f"Cannot find a block containing address {hex(addr)}")
                return False
