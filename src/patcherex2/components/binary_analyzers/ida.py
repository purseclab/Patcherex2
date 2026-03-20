from __future__ import annotations

import logging
import os

from headless_ida import HeadlessIda

from .binary_analyzer import BinaryAnalyzer

logger = logging.getLogger(__name__)


class Ida(BinaryAnalyzer):
    _DEFAULT_LOAD_BASE = 0x0

    def __init__(self, binary_path: str, **kwargs) -> None:
        self.binary_path = binary_path
        self.kwargs = kwargs
        self.ida_installation_path = (
            kwargs["ida_installation_path"]
            if "ida_installation_path" in kwargs
            else os.getenv("IDA_INSTALLATION_PATH")
        )
        self.processor = kwargs["processor"] if "processor" in kwargs else None
        self._headlessida = HeadlessIda(
            self.ida_installation_path, self.binary_path, processor=self.processor
        )
        self._load_base = None
        ida_libs = [
            "idc",
            "idautils",
            "idaapi",
            "ida_funcs",
            "ida_xref",
            "ida_nalt",
            "ida_auto",
            "ida_hexrays",
            "ida_name",
            "ida_expr",
            "ida_typeinf",
            "ida_loader",
            "ida_lines",
            "ida_segment",
            "ida_gdl",
            "ida_ida",
            "ida_segregs",
            "ida_idp",
            "ida_bytes",
            "ida_kernwin",
            "ida_idaapi",
        ]
        for lib in ida_libs:
            setattr(self, lib, self._headlessida.import_module(lib))

    @property
    def load_base(self) -> int:
        if self._load_base is None:
            self._load_base = self.ida_nalt.get_imagebase()
        return self._load_base

    def normalize_addr(self, addr: int) -> int:
        if self.ida_ida.inf_is_dll():
            return addr - self.load_base
        return addr

    def denormalize_addr(self, addr: int) -> int:
        if self.ida_ida.inf_is_dll():
            return addr + self.load_base
        return addr

    def mem_addr_to_file_offset(self, addr: int) -> int:
        file_type = self.ida_loader.get_file_type_name()
        if "intel hex" in file_type.lower():
            return addr
        file_offset = self.ida_loader.get_fileregion_offset(addr)
        return file_offset if file_offset != -1 else None

    def get_basic_block(self, addr: int) -> dict[str, int | list[int]]:
        func = self.ida_funcs.get_func(addr)
        instr_addrs = list(func.code_items())
        assert addr in instr_addrs, "Invalid address"
        flowchart = self.ida_gdl.FlowChart(f=func, flags=self.ida_gdl.FC_PREDS)

        for block in flowchart:
            if block.start_ea <= addr < block.end_ea:
                return {
                    "start": block.start_ea,
                    "end": block.end_ea,
                    "size": block.end_ea - block.start_ea,
                    "instruction_addrs": [
                        ea for ea in instr_addrs if block.start_ea <= ea < block.end_ea
                    ],
                }

    def get_instr_bytes_at(self, addr: int, num_instr: int = 1):
        total_bytes = b""
        current_addr = addr
        for _ in range(num_instr):
            instr_len = self.ida_bytes.get_item_size(current_addr)
            total_bytes += self.ida_bytes.get_bytes(current_addr, instr_len)
            current_addr += instr_len
        return total_bytes

    def get_unused_funcs(self) -> list[dict[str, int]]:
        logger.info("Getting unused functions with IDA")
        unused_funcs = []
        for func in self.ida_funcs.get_func_qty():
            func = self.ida_funcs.getn_func(func)
            if func is None or func.size == 0:
                continue
            for _ in self.ida_xref.XrefsTo(func.start_ea, 0):
                break
            else:
                unused_funcs.append(
                    {
                        "addr": self.normalize_addr(func.start_ea),
                        "size": func.size,
                    }
                )
        return unused_funcs

    def get_all_symbols(self) -> dict[str, int]:
        logger.info("Getting all symbols with IDA")
        symbols = {}
        for symbol in range(self.ida_name.get_nlist_size()):
            name = self.ida_name.get_nlist_name(symbol)
            if not name:
                continue
            addr = self.ida_name.get_nlist_ea(symbol)
            if addr == self.ida_idaapi.BADADDR:
                continue
            if self.ida_funcs.get_func(addr) is None:
                continue
            symbols[name] = self.normalize_addr(addr)
        return symbols

    def get_function(self, name_or_addr: int | str) -> dict[str, int] | None:
        if isinstance(name_or_addr, str):
            addr = self.ida_name.get_name_ea(self.ida_idaapi.BADADDR, name_or_addr)
            if addr == self.ida_idaapi.BADADDR:
                return None
        else:
            addr = self.denormalize_addr(name_or_addr)
        func = self.ida_funcs.get_func(addr)
        if func is None:
            return None
        return {
            "addr": self.normalize_addr(func.start_ea),
            "size": func.size,
        }

    def is_thumb(self, addr: int) -> bool:
        return self.ida_segregs.get_sreg(addr, self.ida_idp.str2reg("T")) == 1
