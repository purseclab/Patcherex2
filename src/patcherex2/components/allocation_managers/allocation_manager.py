from __future__ import annotations

import enum
import logging
from collections.abc import Callable, Iterator
from itertools import pairwise
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
        if self.is_free and other.is_free and self.addr + self.size == other.addr:
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
        load_mem_addr: int | None = None,
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
            self.is_free
            and other.is_free
            and self.flag == other.flag
            and self.file_addr + self.size == other.file_addr
            and self.mem_addr + self.size == other.mem_addr
            and self.load_mem_addr + self.size == other.load_mem_addr
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

    def _add_new_mapped_block(
        self,
        file_addr: int,
        mem_addr: int,
        size: int,
        flag: MemoryFlag,
        load_mem_addr: int | None = None,
    ) -> None:
        self.add_block(
            MappedBlock(
                file_addr,
                mem_addr,
                size,
                is_free=True,
                flag=flag,
                load_mem_addr=load_mem_addr,
            )
        )
        # finalize() needs the original extent, not the object split by allocate().
        self.new_mapped_blocks.append(
            MappedBlock(
                file_addr,
                mem_addr,
                size,
                is_free=True,
                flag=flag,
                load_mem_addr=load_mem_addr,
            )
        )

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
            self.p.binfmt_tool.mem_addr_to_file_offset(addr),
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
        address_validator: Callable[[int], bool] | None = None,
    ) -> MappedBlock | None:
        # near_addr ranks candidates; max_dist rejects distant ones.
        # address_validator applies constraints that distance cannot express.
        best: tuple[MappedBlock, int] | None = None
        best_metric: int | None = None
        for block in self.blocks[MappedBlock]:
            if not (block.is_free and block.size >= size and block.flag & flag == flag):
                continue
            # Inclusive aligned range that can hold the request.
            first = block.mem_addr + (align - block.mem_addr % align) % align
            last_limit = block.mem_addr + block.size - size
            last = last_limit - last_limit % align
            if first > last:
                continue

            # Without near_addr, scan upward from the first valid address.
            reference_addr = first if near_addr is None else near_addr
            allocation_addr = None
            for _, candidate_addr in self._iter_candidates_by_distance(
                first,
                last,
                reference_addr,
                align,
                align,
            ):
                if near_addr is not None:
                    distance = abs(candidate_addr - near_addr)
                    if max_dist is not None and distance > max_dist:
                        break
                if address_validator is not None and not address_validator(
                    candidate_addr
                ):
                    continue
                allocation_addr = candidate_addr
                break
            if allocation_addr is None:
                continue

            metric = (
                block.size if near_addr is None else abs(allocation_addr - near_addr)
            )
            if best_metric is None or metric < best_metric:
                best = (block, allocation_addr)
                best_metric = metric

        if best is None:
            return None
        best_block, allocation_addr = best
        offset = allocation_addr - best_block.mem_addr
        remaining = best_block.size - size - offset
        original_file_addr = best_block.file_addr
        original_mem_addr = best_block.mem_addr
        original_flag = best_block.flag
        original_load_mem_addr = best_block.load_mem_addr
        allocated = MappedBlock(
            original_file_addr + offset,
            allocation_addr,
            size,
            is_free=False,
            flag=original_flag,
            load_mem_addr=original_load_mem_addr + offset,
        )

        if remaining == 0:
            self.blocks[MappedBlock].remove(best_block)
        else:
            best_block.file_addr = original_file_addr + size + offset
            best_block.mem_addr = original_mem_addr + size + offset
            best_block.load_mem_addr = original_load_mem_addr + size + offset
            best_block.size = remaining
        if offset > 0:
            self.add_block(
                MappedBlock(
                    original_file_addr,
                    original_mem_addr,
                    offset,
                    is_free=True,
                    flag=original_flag,
                    load_mem_addr=original_load_mem_addr,
                )
            )
        self.add_block(allocated)
        return allocated

    def _create_new_mapped_block(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> bool:
        page_align = self.p.binfmt_tool.page_alignment()

        if near_addr is not None or address_validator is not None:
            placement = self._reserve_in_memory_gap(
                size,
                align,
                near_addr,
                max_dist,
                page_align,
                address_validator,
            )
            if placement is not None:
                file_addr, mem_addr, block_size = placement
                self._add_new_mapped_block(file_addr, mem_addr, block_size, flag)
                logger.debug(
                    f"new mapped block: file={hex(file_addr)} "
                    f"mem={hex(mem_addr)} size={hex(block_size)}"
                )
                return True
        return self._extend_at_open_end(
            size,
            flag,
            align,
            page_align,
            near_addr=near_addr,
            max_dist=max_dist,
            address_validator=address_validator,
        )

    @staticmethod
    def _iter_candidates_by_distance(
        first: int,
        last: int,
        near_addr: int,
        step: int,
        align: int,
    ) -> Iterator[tuple[int, int]]:
        candidate_count = (last - first) // step + 1

        def addresses(index: int) -> tuple[int, int]:
            candidate = first + index * step
            allocation_addr = candidate + (align - candidate % align) % align
            return candidate, allocation_addr

        # Find the first candidate at or above near_addr.
        low, high = 0, candidate_count
        while low < high:
            middle = (low + high) // 2
            if addresses(middle)[1] < near_addr:
                low = middle + 1
            else:
                high = middle

        left, right = low - 1, low
        # Merge candidates on both sides in distance order.
        while left >= 0 and right < candidate_count:
            left_addresses = addresses(left)
            right_addresses = addresses(right)
            if abs(left_addresses[1] - near_addr) <= abs(
                right_addresses[1] - near_addr
            ):
                yield left_addresses
                left -= 1
            else:
                yield right_addresses
                right += 1
        while left >= 0:
            yield addresses(left)
            left -= 1
        while right < candidate_count:
            yield addresses(right)
            right += 1

    def _reserve_in_memory_gap(
        self,
        size: int,
        align: int,
        near_addr: int | None,
        max_dist: int | None,
        page_align: int,
        address_validator: Callable[[int], bool] | None,
    ) -> tuple[int, int, int] | None:
        # Append at file-end, then choose the closest memory address with the
        # same p_align residue. This avoids alignment padding in the file.
        file_block = next(
            (block for block in self.blocks[FileBlock] if block.size == -1),
            None,
        )
        if file_block is None:
            return None
        file_addr = max(
            getattr(self.p.binfmt_tool, "file_size", file_block.addr), file_block.addr
        )
        residue = file_addr % page_align
        minimum_memory_address = getattr(
            self.p.binfmt_tool,
            "minimum_memory_address_for_new_segment",
            lambda _: None,
        )(file_addr)

        best, best_metric = None, None
        for mb in self.blocks[MemoryBlock]:
            if mb.size == -1 or mb.size < size:
                continue
            lower_bound = max(
                mb.addr,
                minimum_memory_address
                if minimum_memory_address is not None
                else mb.addr,
            )
            first = lower_bound + (residue - lower_bound) % page_align
            last_limit = mb.addr + mb.size - size
            last = last_limit - (last_limit - residue) % page_align
            if first > last:
                continue

            reference_addr = first if near_addr is None else near_addr
            # candidate is the segment start; allocation_addr includes alignment.
            for candidate, allocation_addr in self._iter_candidates_by_distance(
                first,
                last,
                reference_addr,
                page_align,
                align,
            ):
                required_size = allocation_addr - candidate + size
                if candidate + required_size > mb.addr + mb.size:
                    continue
                if near_addr is not None:
                    distance = abs(allocation_addr - near_addr)
                    if max_dist is not None and distance > max_dist:
                        break
                if address_validator is not None and not address_validator(
                    allocation_addr
                ):
                    continue
                metric = mb.size if near_addr is None else distance
                if best_metric is None or metric < best_metric:
                    best, best_metric = (mb, candidate, required_size), metric
                break
        if best is None:
            return None

        mb, mem_addr, required_size = best
        available = (mb.addr + mb.size) - mem_addr
        block_size = min(available, max(self.CHUNK, required_size))
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

        file_block.addr = max(file_block.addr, file_addr + block_size)
        return (file_addr, mem_addr, block_size)

    def _prospective_open_end_size(
        self,
        mem_addr: int,
        size: int,
        align: int,
        near_addr: int | None,
        max_dist: int | None,
        address_validator: Callable[[int], bool] | None,
        max_block_size: int | None = None,
    ) -> int | None:
        first = mem_addr + (align - mem_addr % align) % align
        reference_addr = first if near_addr is None else near_addr
        last_feasible = None
        if max_block_size is not None:
            last_limit = mem_addr + max_block_size - size
            last_feasible = last_limit - last_limit % align
            if first > last_feasible:
                return None

        # Finite distance limits define the complete search range. Otherwise,
        # bound arbitrary validator calls around the closest feasible address.
        search_center = reference_addr
        if last_feasible is not None and max_dist is None:
            search_center = min(max(search_center, first), last_feasible)
        if near_addr is not None and max_dist is not None:
            search_lower = near_addr - max_dist
            search_upper = near_addr + max_dist
        else:
            search_lower = search_center - self.CHUNK
            search_upper = max(first, search_center) + self.CHUNK
        search_start = max(first, search_lower)
        search_start += (align - search_start % align) % align
        search_end = max(first, search_upper)
        search_end -= search_end % align
        if last_feasible is not None:
            search_end = min(search_end, last_feasible)
        if search_start > search_end:
            if near_addr is not None and max_dist is not None:
                return None
            upper_candidate = search_start
            search_start = max(first, search_end)
            search_end = upper_candidate

        search_ranges = [(search_start, search_end)]
        if max_dist is None and search_start > first:
            fallback_end = first + self.CHUNK
            fallback_end -= fallback_end % align
            if last_feasible is not None:
                fallback_end = min(fallback_end, last_feasible)
            search_ranges.append((first, fallback_end))

        for range_start, range_end in search_ranges:
            for _, allocation_addr in self._iter_candidates_by_distance(
                range_start,
                range_end,
                reference_addr,
                align,
                align,
            ):
                if near_addr is not None:
                    distance = abs(allocation_addr - near_addr)
                    if max_dist is not None and distance > max_dist:
                        break
                if address_validator is not None and not address_validator(
                    allocation_addr
                ):
                    continue
                required_size = allocation_addr - mem_addr + size
                if max_block_size is not None and required_size > max_block_size:
                    continue
                block_size = max(self.CHUNK, required_size)
                if max_block_size is not None:
                    block_size = min(block_size, max_block_size)
                return block_size
        return None

    def _extend_at_open_end(
        self,
        size: int,
        flag,
        align: int,
        page_align: int,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> bool:
        # TODO: reuse finite FileBlock entries (inter-segment file slop).
        file_block = next(
            (block for block in self.blocks[FileBlock] if block.size == -1),
            None,
        )
        memory_block = next(
            (block for block in self.blocks[MemoryBlock] if block.size == -1),
            None,
        )
        if file_block is None or memory_block is None:
            return False

        file_addr = file_block.addr
        mem_addr = memory_block.addr + (file_addr - memory_block.addr) % page_align
        block_size = self._prospective_open_end_size(
            mem_addr,
            size,
            align,
            near_addr,
            max_dist,
            address_validator,
        )
        if block_size is None:
            return False

        file_block.addr += block_size
        memory_block.addr = mem_addr + block_size
        self._add_new_mapped_block(file_addr, mem_addr, block_size, flag)
        return True

    def allocate(
        self,
        size: int,
        flag=MemoryFlag.RWX,
        align=0x1,
        near_addr: int | None = None,
        max_dist: int | None = None,
        address_validator: Callable[[int], bool] | None = None,
    ) -> MappedBlock:
        # near_addr: prefer blocks close to this address.
        # max_dist: reject existing free blocks farther than this; falls
        # through to carving a new LOAD segment in a closer MemoryBlock.
        logger.debug(
            f"allocate size={hex(size)} flag={flag!r} align={hex(align)}"
            + (f" near={hex(near_addr)}" if near_addr is not None else "")
            + (f" max_dist={hex(max_dist)}" if max_dist is not None else "")
        )
        created_new_block = False
        while True:
            block = self._find_in_mapped_blocks(
                size,
                flag,
                align,
                near_addr,
                max_dist,
                address_validator,
            )
            if block:
                return block
            if created_new_block:
                raise RuntimeError("New mapped block cannot satisfy allocation")
            if not self._create_new_mapped_block(
                size,
                flag,
                align,
                near_addr,
                max_dist,
                address_validator,
            ):
                raise MemoryError("Insufficient memory")
            created_new_block = True

    def free(self, block: Block) -> None:
        block.is_free = True
        blocks = self.blocks[type(block)]
        blocks.sort()
        self.coalesce(blocks)

    def coalesce(self, blocks: list[Block]) -> None:
        for curr, nxt in pairwise(blocks):
            if curr.coalesce(nxt):
                blocks.remove(nxt)
                self.coalesce(blocks)
                return

    def _discard_free_mapped_range(self, start: int, end: int) -> None:
        remaining_blocks = []
        for block in self.blocks[MappedBlock]:
            block_end = block.mem_addr + block.size
            if not block.is_free or block_end <= start or block.mem_addr >= end:
                remaining_blocks.append(block)
                continue
            if block.mem_addr < start:
                remaining_blocks.append(
                    MappedBlock(
                        block.file_addr,
                        block.mem_addr,
                        start - block.mem_addr,
                        is_free=True,
                        flag=block.flag,
                        load_mem_addr=block.load_mem_addr,
                    )
                )
            if block_end > end:
                offset = end - block.mem_addr
                remaining_blocks.append(
                    MappedBlock(
                        block.file_addr + offset,
                        end,
                        block_end - end,
                        is_free=True,
                        flag=block.flag,
                        load_mem_addr=block.load_mem_addr + offset,
                    )
                )
        remaining_blocks.sort()
        self.blocks[MappedBlock] = remaining_blocks
        self.coalesce(remaining_blocks)

    def finalize(self) -> None:
        allocated_blocks = [
            block for block in self.blocks[MappedBlock] if not block.is_free
        ]
        for block in self.new_mapped_blocks:
            block_end = block.mem_addr + block.size
            used_end = max(
                (
                    min(mapped.mem_addr + mapped.size, block_end)
                    for mapped in allocated_blocks
                    if mapped.mem_addr < block_end
                    and mapped.mem_addr + mapped.size > block.mem_addr
                ),
                default=block.mem_addr,
            )
            if used_end < block_end:
                self._discard_free_mapped_range(used_end, block_end)
            block.size = used_end - block.mem_addr

        self.new_mapped_blocks = [
            block for block in self.new_mapped_blocks if block.size > 0
        ]
        for block in self.new_mapped_blocks:
            self.p.binfmt_tool.file_size = max(
                self.p.binfmt_tool.file_size, block.file_addr + block.size
            )
        logger.debug(f"finalized blocks:\n{pformat(list(self.blocks.values()))}")
        logger.debug(f"new mapped blocks:\n{pformat(self.new_mapped_blocks)}")
