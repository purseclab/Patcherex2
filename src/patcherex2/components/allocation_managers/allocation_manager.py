from __future__ import annotations

import enum
import logging
from pprint import pformat

logger = logging.getLogger(__name__)


class Block:
    subclasses = []

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        # dedup so importlib.reload doesn't double-register
        if cls not in Block.subclasses:
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
    pass


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
        super().__init__(None, size, is_free)
        self.file_addr = file_addr
        self.mem_addr = mem_addr
        self.flag = flag
        self.load_mem_addr = load_mem_addr if load_mem_addr is not None else mem_addr

    def __lt__(self, other: MappedBlock) -> bool:
        return self.mem_addr < other.mem_addr

    def __repr__(self) -> str:
        r = (
            f"<{self.__class__.__name__} file_addr={hex(self.file_addr)} "
            f"mem_addr={hex(self.mem_addr)} size={hex(self.size)} "
            f"is_free={self.is_free} flag={self.flag}"
        )
        if self.load_mem_addr != self.mem_addr:
            r += f" load_mem_addr={hex(self.load_mem_addr)}"
        return r + ">"

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
    CHUNK = 0x10000

    def __init__(self, p) -> None:
        self.blocks = {cls: [] for cls in Block.subclasses}
        self.p = p
        self.new_mapped_blocks = []

    def add_block(self, block: Block) -> None:
        self.blocks[type(block)].append(block)
        self.blocks[type(block)].sort()
        self.coalesce(self.blocks[type(block)])

    def add_free_space(
        self, addr: int, size: int, flag: str | MemoryFlag = "RX"
    ) -> None:
        """`flag` accepts a MemoryFlag or short str ("RX", "rw", "RWX"...)."""
        if isinstance(flag, str):
            chars = set(flag.lower())
            unknown = chars - {"r", "w", "x"}
            if unknown or not chars:
                raise ValueError(
                    f"Invalid flag {flag!r}: expected subset of 'r','w','x'"
                )
            # start at 0 -- MemoryFlag.UNDEF would OR an extra bit
            mflag = MemoryFlag(0)
            if "r" in chars:
                mflag |= MemoryFlag.R
            if "w" in chars:
                mflag |= MemoryFlag.W
            if "x" in chars:
                mflag |= MemoryFlag.X
        elif isinstance(flag, MemoryFlag):
            mflag = flag
        else:
            raise TypeError(
                f"flag must be str or MemoryFlag, got {type(flag).__name__}"
            )
        block = MappedBlock(
            self.p.binary_analyzer.mem_addr_to_file_offset(addr),
            addr,
            size,
            is_free=True,
            flag=mflag,
        )
        self.p.allocation_manager.add_block(block)

    def _find_in_mapped_blocks(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
    ) -> MappedBlock | None:
        # Without near_addr: best-fit by size. With near_addr: closest
        # to it. max_dist filters out too-far blocks.
        best, best_metric = None, None
        for block in self.blocks[MappedBlock]:
            if not (block.is_free and block.size >= size and block.flag & flag == flag):
                continue
            offset = (align - (block.mem_addr % align)) % align
            if block.size < size + offset:
                continue
            if near_addr is None and block.size == size + offset and offset > 0:
                block.is_free = False
                return block
            if near_addr is not None:
                metric = abs(block.mem_addr + offset - near_addr)
                if max_dist is not None and metric > max_dist:
                    continue
            else:
                metric = block.size
            if best is None or metric < best_metric:
                best, best_metric = block, metric

        if best is None:
            return None
        offset = (align - (best.mem_addr % align)) % align
        remaining = best.size - size - offset
        allocated = MappedBlock(
            best.file_addr + offset,
            best.mem_addr + offset,
            size,
            is_free=False,
            flag=flag,
        )
        self.add_block(allocated)
        if offset > 0:
            self.add_block(
                MappedBlock(
                    best.file_addr, best.mem_addr, offset, is_free=True, flag=flag
                )
            )
        best.file_addr += size + offset
        best.mem_addr += size + offset
        best.size = remaining
        if best.size == 0:
            self.blocks[MappedBlock].remove(best)
        return allocated

    def _create_new_mapped_block(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
    ) -> bool:
        # The two MappedBlocks below must be distinct objects: self.blocks
        # gets split by subsequent allocate() calls; new_mapped_blocks
        # keeps the original extent for finalize() to size PT_LOAD against.
        page_align = self.p.binfmt_tool.page_alignment()

        if near_addr is not None:
            placement = self._reserve_in_memory_gap(
                size, near_addr, max_dist, page_align
            )
            if placement is not None:
                file_addr, mem_addr, block_size = placement
                self.add_block(
                    MappedBlock(
                        file_addr, mem_addr, block_size, is_free=True, flag=flag
                    )
                )
                self.new_mapped_blocks.append(
                    MappedBlock(
                        file_addr, mem_addr, block_size, is_free=True, flag=flag
                    )
                )
                logger.debug(
                    f"new mapped block near {hex(near_addr)}: "
                    f"file={hex(file_addr)} mem={hex(mem_addr)} size={hex(block_size)}"
                )
                return True
            # With max_dist set, the file-end fallback is guaranteed too
            # far -- give up so allocate() raises instead of looping.
            if max_dist is not None:
                return False

        return self._extend_at_open_end(flag, page_align)

    def _reserve_in_memory_gap(
        self,
        size: int,
        near_addr: int,
        max_dist: int | None,
        page_align: int,
    ) -> tuple[int, int, int] | None:
        # Reserve a chunk from the MemoryBlock whose closest valid mem_addr
        # to near_addr satisfies max_dist. File space comes from file-end
        # with matching p_align residue.
        best, best_dist = None, None
        for mb in self.blocks[MemoryBlock]:
            if mb.size == -1 or mb.size < size:
                continue
            candidate = max(mb.addr, min(near_addr, mb.addr + mb.size - size))
            dist = abs(candidate - near_addr)
            if max_dist is not None and dist > max_dist:
                continue
            if best is None or dist < best_dist:
                best, best_dist = (mb, candidate), dist
        if best is None:
            return None
        mb, mem_addr = best
        available = (mb.addr + mb.size) - mem_addr
        block_size = min(available, self.CHUNK)

        prefix_size = mem_addr - mb.addr
        suffix_addr = mem_addr + block_size
        suffix_size = (mb.addr + mb.size) - suffix_addr
        if prefix_size > 0:
            mb.size = prefix_size
        else:
            self.blocks[MemoryBlock].remove(mb)
        if suffix_size > 0:
            self.blocks[MemoryBlock].append(MemoryBlock(suffix_addr, suffix_size))
            self.blocks[MemoryBlock].sort()

        file_size = self.p.binfmt_tool.file_size
        residue = mem_addr % page_align
        file_addr = ((file_size + page_align - 1) // page_align) * page_align + residue
        for fb in self.blocks[FileBlock]:
            if fb.size == -1:
                fb.addr = max(fb.addr, file_addr + block_size)
        return (file_addr, mem_addr, block_size)

    def _extend_at_open_end(self, flag, page_align: int) -> bool:
        # TODO: reuse finite FileBlock entries (inter-segment file slop).
        file_addr = None
        mem_addr = None
        for block in self.blocks[FileBlock]:
            if block.size == -1:
                file_addr = block.addr
                block.addr += self.CHUNK
        for block in self.blocks[MemoryBlock]:
            if block.size == -1:
                # ELF p_align: mem_addr % p_align == file_addr % p_align
                mem_addr = block.addr + (file_addr - block.addr) % page_align
                block.addr = mem_addr + self.CHUNK
        if file_addr is None or mem_addr is None:
            return False
        self.add_block(
            MappedBlock(file_addr, mem_addr, self.CHUNK, is_free=True, flag=flag)
        )
        self.new_mapped_blocks.append(
            MappedBlock(file_addr, mem_addr, self.CHUNK, is_free=True, flag=flag)
        )
        return True

    def allocate(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
    ) -> MappedBlock:
        # near_addr: prefer blocks close to this addr (PIE PC-rel range).
        # max_dist: reject existing free blocks farther than this; falls
        # through to carving a new LOAD segment in a closer MemoryBlock.
        logger.debug(
            f"allocate size={hex(size)} flag={flag!r} align={hex(align)}"
            + (f" near={hex(near_addr)}" if near_addr is not None else "")
            + (f" max_dist={hex(max_dist)}" if max_dist is not None else "")
        )
        block = self._find_in_mapped_blocks(size, flag, align, near_addr, max_dist)
        if block:
            return block
        if self._create_new_mapped_block(size, flag, align, near_addr, max_dist):
            return self.allocate(
                size, flag, align, near_addr=near_addr, max_dist=max_dist
            )
        raise MemoryError("Insufficient memory")

    def free(self, block: Block) -> None:
        block.is_free = True
        self.coalesce(self.blocks[type(block)])

    def coalesce(self, blocks: list[Block]) -> None:
        for curr, nxt in zip(blocks, blocks[1:]):
            if curr.coalesce(nxt):
                blocks.remove(nxt)
                self.coalesce(blocks)
                return

    def finalize(self) -> None:
        # Trim each new chunk down to its actually-allocated extent: match
        # the chunk's end_addr against a free remainder in self.blocks and
        # shrink. The dual-instance invariant (see _create_new_mapped_block)
        # is what makes this work.
        for block in self.new_mapped_blocks:
            for mapped in self.blocks[MappedBlock]:
                if (
                    mapped.is_free
                    and block.mem_addr + block.size == mapped.mem_addr + mapped.size
                    and block.mem_addr <= mapped.mem_addr
                ):
                    self.blocks[MappedBlock].remove(mapped)
                    block.size -= mapped.size
                    return self.finalize()
        for block in self.new_mapped_blocks:
            if block.file_addr + block.size > self.p.binfmt_tool.file_size:
                self.p.binfmt_tool.file_size = block.file_addr + block.size
        logger.debug(f"finalized blocks:\n{pformat(list(self.blocks.values()))}")
        logger.debug(f"new mapped blocks:\n{pformat(self.new_mapped_blocks)}")
