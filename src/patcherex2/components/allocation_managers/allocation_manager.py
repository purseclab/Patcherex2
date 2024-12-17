from __future__ import annotations

import enum
import logging
from pprint import pformat

logger = logging.getLogger(__name__)


class Block:
    subclasses = []

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        Block.subclasses.append(cls)

    def __init__(self, addr: int, size: int, is_free=True) -> None:
        self.addr = addr
        self.size = size
        self.is_free = is_free

    def __lt__(self, other: Block) -> bool:
        return self.addr < other.addr

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} addr={hex(self.addr)} size={hex(self.size)} is_free={self.is_free}>"

    def coalesce(self, other: Block) -> bool:
        if self.is_free == other.is_free and self.addr + self.size == other.addr:
            self.size += other.size
            return True
        return False


class FileBlock(Block):
    pass


class MemoryBlock(Block):
    def __init__(self, addr: int, size: int, is_free=True) -> None:
        super().__init__(addr, size, is_free)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} addr={hex(self.addr)} size={hex(self.size)} is_free={self.is_free}>"


class MemoryFlag(enum.IntFlag):
    UNDEF = enum.auto()
    R = 0x4
    W = 0x2
    X = 0x1
    RW = R | W
    RX = R | X
    RWX = R | W | X


class MappedBlock(Block):
    def __init__(
        self,
        file_addr: int,
        mem_addr: int,
        size: int,
        is_free=True,
        flag=None,
        load_mem_addr: int = None,
    ) -> None:
        """
        :param file_addr: file address of the block
        :param mem_addr: virtual memory address of the block
        :param size: size of the block
        :param is_free: whether the block is free
        :param flag: memory flag of the block
        :param load_mem_addr: load memory address of the block, if not provided, it will be the same as mem_addr
        """
        super().__init__(None, size, is_free)
        self.file_addr = file_addr
        self.mem_addr = mem_addr
        self.flag = flag
        self.load_mem_addr = load_mem_addr if load_mem_addr else mem_addr

    def __lt__(self, other: MappedBlock) -> bool:
        return self.mem_addr < other.mem_addr

    def __repr__(self) -> str:
        repr = f"<{self.__class__.__name__} file_addr={hex(self.file_addr)} mem_addr={hex(self.mem_addr)} size={hex(self.size)} is_free={self.is_free} flag={str(self.flag)}"
        if self.load_mem_addr != self.mem_addr:
            repr += f" load_mem_addr={hex(self.load_mem_addr)}"
        repr += ">"
        return repr

    def coalesce(self, other: MappedBlock) -> bool:
        if (
            self.flag == other.flag
            and self.is_free == other.is_free
            and self.file_addr + self.size == other.file_addr
            and self.mem_addr + self.size == other.mem_addr
        ):
            self.size += other.size
            return True
        return False


class AllocationManager:
    def __init__(self, p) -> None:
        self.blocks = {cls: [] for cls in Block.subclasses}
        self.p = p
        self.new_mapped_blocks = []

    def add_block(self, block: Block) -> None:
        self.blocks[type(block)].append(block)
        self.blocks[type(block)].sort()
        self.coalesce(self.blocks[type(block)])

    def add_free_space(self, addr: int, size: int, flag: str = "RX") -> None:
        _flag = 0
        if "r" in flag.lower():
            _flag |= MemoryFlag.R
        if "w" in flag.lower():
            _flag |= MemoryFlag.W
        if "x" in flag.lower():
            _flag |= MemoryFlag.X
        block = MappedBlock(
            self.p.binary_analyzer.mem_addr_to_file_offset(addr),
            addr,
            size,
            is_free=True,
            flag=_flag,
        )
        self.p.allocation_manager.add_block(block)

    def _find_in_mapped_blocks(
        self, size: int, flag=MemoryFlag.RWX, align=0x1
    ) -> MappedBlock:
        best_fit = None
        for block in self.blocks[MappedBlock]:
            if block.is_free and block.size >= size and block.flag & flag == flag:
                # check for alignment
                offset = (align - (block.mem_addr % align)) % align
                if block.size >= size + offset:
                    if block.size == size + offset and offset > 0:
                        block.is_free = False
                        return block
                    elif best_fit is None or block.size < best_fit.size:
                        best_fit = block

        if best_fit:
            # Adjust for alignment
            offset = (align - (best_fit.mem_addr % align)) % align
            remaining_size = best_fit.size - size - offset
            allocated_block = MappedBlock(
                best_fit.file_addr + offset,
                best_fit.mem_addr + offset,
                size,
                is_free=False,
                flag=flag,
            )
            self.add_block(allocated_block)
            if offset > 0:
                self.add_block(
                    MappedBlock(
                        best_fit.file_addr,
                        best_fit.mem_addr,
                        offset,
                        is_free=True,
                        flag=flag,
                    )
                )
            best_fit.file_addr += size + offset
            best_fit.mem_addr += size + offset
            best_fit.size = remaining_size
            if best_fit.size == 0:
                self.blocks[MappedBlock].remove(best_fit)
            return allocated_block

    def _create_new_mapped_block(
        self, size: int, flag=MemoryFlag.RWX, align=0x1
    ) -> bool:
        # TODO: currently we won't use available file/mem blocks, instead we create new one at the end of the file
        file_addr = None
        mem_addr = None
        for block in self.blocks[FileBlock]:
            if block.size == -1:
                file_addr = block.addr
                block.addr += 0x10000
        for block in self.blocks[MemoryBlock]:
            if block.size == -1:
                # NOTE: mem_addr % p_align should equal to file_addr % p_align
                # Check `man elf` and search for `p_align` for more information
                # FIXME: shouldn't do any assumption on component type, reimpl in a better way
                # FIXME: even worse, importing ELF will cause circular import
                # TODO: consider merge allocation_manager and binfmt_tool into one component
                if self.p.binfmt_tool.__class__.__name__ == "ELF":
                    max_seg_align = max(
                        [segment["p_align"] for segment in self.p.binfmt_tool._segments]
                        + [0]
                    )
                    mem_addr = block.addr + (file_addr - block.addr) % max_seg_align
                else:
                    mem_addr = block.addr + (file_addr - block.addr) % 0x1000
                block.addr = mem_addr + 0x10000
        if file_addr and mem_addr:
            self.add_block(
                MappedBlock(file_addr, mem_addr, 0x10000, is_free=True, flag=flag)
            )
            self.new_mapped_blocks.append(
                MappedBlock(file_addr, mem_addr, 0x10000, is_free=True, flag=flag)
            )
            return True
        return False

    def allocate(self, size: int, flag=MemoryFlag.RWX, align=0x1) -> MappedBlock:
        logger.debug(
            f"allocating size: {size}, flag: {flag.__repr__()}, align: {align}"
        )
        block = self._find_in_mapped_blocks(size, flag, align)
        if block:
            return block
        logger.debug(
            f"memory_allocate: failed to allocate memory of size {size} with flag {flag.__repr__()}, creating new area and retrying"
        )
        if self._create_new_mapped_block(size, flag, align):
            return self.allocate(size, flag, align)
        else:
            raise MemoryError("Insufficient memory")

    def free(self, block: Block) -> None:
        block.is_free = True
        self.coalesce(self.blocks[type(block)])

    def coalesce(self, blocks: list[Block]) -> None:
        for curr, next in zip(blocks, blocks[1:]):
            if curr.coalesce(next):
                blocks.remove(next)
                self.coalesce(blocks)
                return

    def finalize(self) -> None:
        for block in self.new_mapped_blocks:
            for mapped_block in self.blocks[MappedBlock]:
                if mapped_block.is_free:
                    if (
                        block.mem_addr + block.size
                        == mapped_block.mem_addr + mapped_block.size
                        and block.mem_addr <= mapped_block.mem_addr
                    ):
                        self.blocks[MappedBlock].remove(mapped_block)
                        block.size -= mapped_block.size
                        return self.finalize()

        for block in self.new_mapped_blocks:
            if block.file_addr + block.size > self.p.binfmt_tool.file_size:
                self.p.binfmt_tool.file_size = block.file_addr + block.size

        logger.debug(f"finalized blocks: \n{pformat(list(self.blocks.values()))}")
        logger.debug(f"new mapped blocks: \n{pformat(self.new_mapped_blocks)}")
