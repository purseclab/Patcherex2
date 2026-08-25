import logging

logger = logging.getLogger(__name__)


class BinFmtTool:
    def __init__(self, p, binary_path: str) -> None:
        self.p = p
        self.binary_path = binary_path

    @property
    def is_position_independent(self) -> bool:
        return False

    def _record_file_update(self, offset: int, new_content: bytes) -> None:
        if offset < 0:
            raise ValueError(f"Cannot update a negative file offset: {offset}")
        new_content = bytes(new_content)
        if not new_content:
            return

        new_end = offset + len(new_content)
        retained_updates = []
        overlapping_updates = []
        for update in self.file_updates:
            old_start = update["offset"]
            old_content = update["content"]
            old_end = old_start + len(old_content)
            if offset >= old_end or old_start >= new_end:
                retained_updates.append(update)
                continue

            overlap_start = max(offset, old_start)
            overlap_end = min(new_end, old_end)
            new_slice = new_content[overlap_start - offset : overlap_end - offset]
            old_slice = old_content[overlap_start - old_start : overlap_end - old_start]
            if new_slice != old_slice:
                raise ValueError(
                    f"Cannot update file interval [{hex(offset)}, {hex(new_end)}) "
                    f"because it conflicts with a previous update interval "
                    f"[{hex(old_start)}, {hex(old_end)})"
                )
            overlapping_updates.append(update)

        if overlapping_updates:
            update = self._merge_file_updates(
                offset,
                new_content,
                overlapping_updates,
            )
        else:
            update = {"offset": offset, "content": new_content}

        retained_updates.append(update)
        retained_updates.sort(key=lambda item: item["offset"])
        self.file_updates = retained_updates
        self.file_size = max(self.file_size, new_end)

    @staticmethod
    def _merge_file_updates(
        offset: int,
        new_content: bytes,
        overlapping_updates: list[dict],
    ) -> dict:
        new_end = offset + len(new_content)
        merged_start = min(
            [offset] + [update["offset"] for update in overlapping_updates]
        )
        merged_end = max(
            [new_end]
            + [
                update["offset"] + len(update["content"])
                for update in overlapping_updates
            ]
        )
        merged_content = bytearray(merged_end - merged_start)
        for update in overlapping_updates:
            start = update["offset"] - merged_start
            end = start + len(update["content"])
            merged_content[start:end] = update["content"]
        start = offset - merged_start
        merged_content[start : start + len(new_content)] = new_content
        return {"offset": merged_start, "content": bytes(merged_content)}

    def _read_size(self, offset: int, size: int) -> int:
        if offset < 0:
            raise ValueError(f"Cannot read a negative file offset: {offset}")
        if size < 0:
            raise ValueError(f"Cannot read a negative size: {size}")
        return min(size, max(0, self.file_size - offset))

    def _overlay_file_updates(self, offset: int, original_content: bytes) -> bytes:
        content = bytearray(original_content)
        read_end = offset + len(content)
        for update in self.file_updates:
            update_start = update["offset"]
            update_end = update_start + len(update["content"])
            overlap_start = max(offset, update_start)
            overlap_end = min(read_end, update_end)

            if overlap_start >= overlap_end:
                continue
            content[overlap_start - offset : overlap_end - offset] = update["content"][
                overlap_start - update_start : overlap_end - update_start
            ]
        return bytes(content)

    def mem_addr_to_file_offset(self, addr: int) -> int:
        return self.p.binary_analyzer.mem_addr_to_file_offset(addr)

    def _init_memory_analysis(self) -> None:
        raise NotImplementedError()

    def save_binary(self, filename=None) -> None:
        raise NotImplementedError()

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        raise NotImplementedError()

    def append_to_binary_content(self, new_content: bytes) -> None:
        raise NotImplementedError()

    def page_alignment(self) -> int:
        # ELF overrides with max segment p_align
        return 0x1000

    def minimum_memory_address_for_new_segment(self, file_offset: int) -> int | None:
        return None
