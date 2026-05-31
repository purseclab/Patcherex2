from __future__ import annotations

import io
import logging
import os
import struct

from elftools.construct.lib import Container
from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile

from ..allocation_managers.allocation_manager import (
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from .binfmt_tool import BinFmtTool

logger = logging.getLogger(__name__)


def pack_rel_entry(
    mem_offset: int,
    r_info_value: int,
    is_64: bool,
    is_le: bool,
    is_rela: bool,
    is_mips64: bool = False,
    addend: int = 0,
) -> bytes:
    """Pack one ELF Rel/Rela entry. r_info layout is arch-specific:

    - 32-bit ELF: r_info = sym<<8 | type
    - 64-bit standard: r_info = sym<<32 | type
    - MIPS n64 (`is_mips64=True`): the 8-byte r_info field is
      structured as sym(4) + ssym(1) + type3(1) + type2(1) + type(1).
      archinfo encodes the four type bytes in r_info_value's low 32
      bits as `type | type2<<8 | type3<<16 | ssym<<24`; sym lives in
      the high 32 bits.

    `addend` is appended only for Rela. For RELATIVE relocs the loader
    sets `*slot = base + addend` (Rela) or `*slot += base` (Rel), so the
    caller is responsible for choosing addend = symbol's static value
    on Rela archs.
    """
    end = "<" if is_le else ">"
    word_fmt = "Q" if is_64 else "I"
    out = struct.pack(f"{end}{word_fmt}", mem_offset)
    if is_mips64:
        sym = (r_info_value >> 32) & 0xFFFFFFFF
        low = r_info_value & 0xFFFFFFFF
        out += struct.pack(f"{end}I", sym)
        # per-byte fields are positional regardless of endianness
        out += bytes(
            [
                (low >> 24) & 0xFF,  # ssym
                (low >> 16) & 0xFF,  # type3
                (low >> 8) & 0xFF,  # type2
                low & 0xFF,  # type
            ]
        )
    else:
        out += struct.pack(f"{end}{word_fmt}", r_info_value)
    if is_rela:
        out += struct.pack(f"{end}{word_fmt}", addend)
    return out


class ELF(BinFmtTool):
    def __init__(self, p, binary_path: str) -> None:
        super().__init__(p, binary_path)
        with open(binary_path, "rb") as f:
            self.original_binary_content = f.read()
        self._file = io.BytesIO(self.original_binary_content)
        self._elf = ELFFile(self._file)
        self._segments = [segment.header for segment in self._elf.iter_segments()]
        self._sections = [section.header for section in self._elf.iter_sections()]
        self.file_updates = []

        self.file_size = os.stat(self.binary_path).st_size
        self.updated_binary_content = self.original_binary_content
        self._pending_dyn_relocs: list[tuple[int, int, int]] = []
        self._init_memory_analysis()

    def page_alignment(self) -> int:
        # max p_align so new blocks satisfy every existing segment
        return max((segment["p_align"] for segment in self._segments), default=0x1000)

    @property
    def little_endian(self) -> bool:
        return self._elf.little_endian

    @property
    def is_pie(self) -> bool:
        return self._elf.header.e_type == "ET_DYN"

    def _find_space_between_sections(self) -> None:
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        alloc_sections = sorted(
            (
                section
                for section in self._elf.iter_sections()
                if section["sh_flags"] & SH_FLAGS.SHF_ALLOC
            ),
            key=lambda x: (x["sh_offset"], x["sh_size"]),
        )

        # Spaces in LOAD segments AND between sections
        for segment in load_segments:
            segment_file_end = segment["p_offset"] + segment["p_filesz"]
            segment_mem_end = segment["p_vaddr"] + segment["p_memsz"]
            for curr_sec, next_sec in zip(alloc_sections, alloc_sections[1:]):
                if segment.section_in_segment(curr_sec) and segment.section_in_segment(
                    next_sec
                ):
                    gap_file_start = curr_sec["sh_offset"] + curr_sec["sh_size"]
                    gap_file_size = next_sec["sh_offset"] - gap_file_start
                    gap_mem_start = curr_sec["sh_addr"] + curr_sec["sh_size"]
                    gap_mem_size = next_sec["sh_addr"] - gap_mem_start
                    if (
                        gap_mem_size > 0
                        and gap_file_size > 0
                        and segment_file_end > gap_file_start
                        and segment_mem_end > gap_mem_start
                    ):
                        flag = (
                            MemoryFlag.RW
                            if segment["p_flags"] & P_FLAGS.PF_W
                            else MemoryFlag.RX
                        )
                        block = MappedBlock(
                            gap_file_start,
                            gap_mem_start,
                            min(gap_file_size, gap_mem_size),
                            is_free=True,
                            flag=flag,
                        )
                        self.p.allocation_manager.add_block(block)
            for sec in alloc_sections:
                if segment.section_in_segment(sec):
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        sec["sh_offset"],
                        sec["sh_addr"],
                        sec["sh_size"],
                        is_free=False,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)

        # of course also before and after the first and last section in a LOAD segment
        for segment in load_segments:
            segment_file_end = segment["p_offset"] + segment["p_filesz"]
            segment_mem_end = segment["p_vaddr"] + segment["p_memsz"]
            first_sec = next(
                (
                    section
                    for section in alloc_sections
                    if segment.section_in_segment(section)
                ),
                None,
            )
            last_sec = next(
                (
                    section
                    for section in reversed(alloc_sections)
                    if segment.section_in_segment(section)
                ),
                None,
            )
            if first_sec:
                gap_file_start = segment["p_offset"]
                gap_file_size = first_sec["sh_offset"] - gap_file_start
                gap_mem_start = segment["p_vaddr"]
                gap_mem_size = first_sec["sh_addr"] - gap_mem_start
                if gap_mem_size > 0 and gap_file_start > 0:
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        gap_file_start,
                        gap_mem_start,
                        min(gap_file_size, gap_mem_size),
                        is_free=True,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)
            if last_sec:
                gap_file_start = last_sec["sh_offset"] + last_sec["sh_size"]
                gap_file_size = segment_file_end - gap_file_start
                gap_mem_start = last_sec["sh_addr"] + last_sec["sh_size"]
                gap_mem_size = segment_mem_end - gap_mem_start
                if (
                    gap_mem_size > 0
                    and gap_file_size > 0
                    and segment_file_end > gap_file_start
                    and segment_mem_end > gap_mem_start
                ):
                    flag = (
                        MemoryFlag.RW
                        if segment["p_flags"] & P_FLAGS.PF_W
                        else MemoryFlag.RX
                    )
                    block = MappedBlock(
                        last_sec["sh_offset"] + last_sec["sh_size"],
                        gap_mem_start,
                        min(gap_file_size, gap_mem_size),
                        is_free=True,
                        flag=flag,
                    )
                    self.p.allocation_manager.add_block(block)

    def _find_space_between_segments(self) -> None:
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        # Find Space Between Segments
        # System mmap granularity for the "is this vaddr already mapped"
        # check -- distinct from p_align (alignment hint). The dynamic
        # loader mmaps each LOAD at system-page granularity regardless
        # of p_align.
        page = 0x1000
        for curr, next in zip(load_segments, load_segments[1:]):
            if next["p_offset"] > (curr["p_offset"] + curr["p_filesz"]):
                block = FileBlock(
                    curr["p_offset"] + curr["p_filesz"],
                    next["p_offset"] - (curr["p_offset"] + curr["p_filesz"]),
                )
                self.p.allocation_manager.add_block(block)
            gap_start = ((curr["p_vaddr"] + curr["p_memsz"]) + (page - 1)) & ~(page - 1)
            gap_end = next["p_vaddr"] & ~(page - 1)
            if gap_end > gap_start:
                block = MemoryBlock(gap_start, gap_end - gap_start)
                self.p.allocation_manager.add_block(block)

    def _add_end_of_file_block(self) -> None:
        load_segments = sorted(
            (
                segment
                for segment in self._elf.iter_segments()
                if segment["p_type"] == "PT_LOAD"
            ),
            key=lambda x: x["p_offset"],
        )

        if len(load_segments) == 0:
            return

        block = FileBlock(self.file_size, -1)
        self.p.allocation_manager.add_block(block)

        addr = load_segments[-1]["p_vaddr"] + load_segments[-1]["p_memsz"]
        # TODO: should we use the max_align of the segments?
        max_align = max([segment["p_align"] for segment in self._segments] + [0])
        addr = (addr + (max_align - 1)) & ~(max_align - 1)  # round up to max_align
        block = MemoryBlock(addr, -1)
        self.p.allocation_manager.add_block(block)

    def _init_memory_analysis(self) -> None:
        self._find_space_between_sections()
        self._find_space_between_segments()
        self._add_end_of_file_block()

        logger.debug(
            "_init_memory_analysis: "
            + "\n".join(map(str, self.p.allocation_manager.blocks.values()))
        )

        # # Is is possible to extend the existing segment?
        # for curr, next in zip(load_segments, load_segments[1:]):
        #     # mem
        #     mem_curr_end = curr['p_vaddr'] + curr['p_memsz']
        #     mem_curr_end_rounded = mem_curr_end + (curr['p_align'] - (mem_curr_end % curr['p_align'])) % curr['p_align']
        #     mem_next_start = next['p_vaddr']
        #     mem_max_extend_size = mem_curr_end_rounded - mem_curr_end
        #     if (mem_next_start - mem_curr_end_rounded) // curr['p_align'] > 0:
        #         mem_max_extend_size += (mem_next_start - mem_curr_end_rounded) // curr['p_align'] * curr['p_align']

        #     # file
        #     file_curr_end = curr['p_offset'] + curr['p_filesz']
        #     file_next_start = next['p_offset']
        #     max_extend_size = min(mem_max_extend_size, file_next_start - file_curr_end)

        #     if curr['p_flags'] & P_FLAGS.PF_R and curr['p_flags'] & P_FLAGS.PF_X:
        #         self.free_space['loaded'].append({
        #             "file_start": file_curr_end,
        #             "mem_start": mem_curr_end,
        #             "size": max_extend_size,
        #             "flag": MemoryFlag.RX,
        #             "callback": self._extend_segment
        #         })

    def add_dynamic_relocations(self, entries) -> None:
        self._pending_dyn_relocs.extend(entries)

    def _scan_dynamic_rel_tags(self):
        """Locate DT_REL[A]/DT_REL[A]SZ/DT_REL[A]ENT and report whether
        the binary uses Rel or Rela format. Raises if .dynamic or the
        relocation tag is missing."""
        dyn_section = self._elf.get_section_by_name(".dynamic")
        if dyn_section is None:
            raise RuntimeError(
                "binary has no .dynamic section; can't add dynamic relocations"
            )
        info = {
            "is_rela": False,
            "addr": None,
            "size": 0,
            "ent": 0,
            "count": None,
            "section": dyn_section,
        }
        for tag in dyn_section.iter_tags():
            t = tag.entry.d_tag
            v = tag.entry.d_val
            if t == "DT_REL":
                info["addr"] = v
            elif t == "DT_RELA":
                info["addr"] = v
                info["is_rela"] = True
            elif t in ("DT_RELSZ", "DT_RELASZ"):
                info["size"] = v
            elif t in ("DT_RELENT", "DT_RELAENT"):
                info["ent"] = v
            elif t in ("DT_RELCOUNT", "DT_RELACOUNT"):
                info["count"] = v
        if info["addr"] is None:
            raise RuntimeError(
                "binary has no DT_REL/DT_RELA tag; can't add dynamic relocations"
            )
        return info

    def _emit_dynamic_relocations(self) -> None:
        """Build a fresh REL/RELA table containing existing entries plus
        our additions, place it in a newly allocated R block, and repoint
        DT_REL[A] + DT_REL[A]SZ in .dynamic."""
        if not self._pending_dyn_relocs:
            return

        is_64 = self._elf.elfclass == 64
        is_le = self._elf.little_endian
        is_mips64 = is_64 and self._elf.header.e_machine == "EM_MIPS"
        info = self._scan_dynamic_rel_tags()
        is_rela = info["is_rela"]
        entry_size = (3 if is_rela else 2) * (8 if is_64 else 4)
        if info["ent"] and info["ent"] != entry_size:
            raise RuntimeError(f"DT_REL[A]ENT={info['ent']} != computed {entry_size}")

        existing_file_off = self.p.binary_analyzer.mem_addr_to_file_offset(info["addr"])
        existing_bytes = self.get_binary_content(existing_file_off, info["size"])

        new_bytes = b"".join(
            pack_rel_entry(off, r_info, is_64, is_le, is_rela, is_mips64, addend=addend)
            for off, r_info, addend in self._pending_dyn_relocs
        )
        # Prepend new RELATIVE entries so they extend the DT_REL[A]COUNT prefix.
        combined = new_bytes + existing_bytes
        new_block = self.p.allocation_manager.allocate(
            len(combined), align=entry_size, flag=MemoryFlag.R
        )
        self.update_binary_content(new_block.file_addr, combined)

        # Patch DT_REL[A], DT_REL[A]SZ, and DT_REL[A]COUNT in-place.
        end = "<" if is_le else ">"
        word_fmt = "Q" if is_64 else "I"
        target_addr_tag = "DT_RELA" if is_rela else "DT_REL"
        target_size_tag = "DT_RELASZ" if is_rela else "DT_RELSZ"
        target_count_tag = "DT_RELACOUNT" if is_rela else "DT_RELCOUNT"
        new_entries_count = len(self._pending_dyn_relocs)
        ent_bytes = (8 if is_64 else 4) * 2
        dyn_file_off = info["section"]["sh_offset"]
        for i, tag in enumerate(info["section"].iter_tags()):
            if tag.entry.d_tag == target_addr_tag:
                new_val = new_block.mem_addr
            elif tag.entry.d_tag == target_size_tag:
                new_val = len(combined)
            elif tag.entry.d_tag == target_count_tag and info["count"] is not None:
                new_val = info["count"] + new_entries_count
            else:
                continue
            val_off = dyn_file_off + i * ent_bytes + (8 if is_64 else 4)
            self.update_binary_content(
                val_off, struct.pack(f"{end}{word_fmt}", new_val)
            )

        logger.debug(
            f"Wrote {len(self._pending_dyn_relocs)} new dynamic relocations; "
            f".rel{'a' if is_rela else ''}.dyn moved to {hex(new_block.mem_addr)} size {len(combined)}"
        )

    def finalize(self) -> None:
        self._emit_dynamic_relocations()
        self.p.allocation_manager.finalize()

        if len(self.p.allocation_manager.new_mapped_blocks) == 0:
            return

        load_segment_count = len(
            [segment for segment in self._segments if segment["p_type"] == "PT_LOAD"]
        )
        max_align = max([segment["p_align"] for segment in self._segments] + [0])

        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            self._segments.append(
                Container(
                    p_type="PT_LOAD",
                    p_offset=block.file_addr,
                    p_filesz=block.size,
                    p_vaddr=block.mem_addr,
                    p_paddr=block.mem_addr,
                    p_memsz=block.size,
                    p_flags=block.flag,
                    p_align=max_align,  # TODO: what could be a good value for this?
                )
            )

        # sort segments by p_offset
        self._segments = sorted(self._segments, key=lambda x: x["p_offset"])

        # try to merge load segments if they are adjacent and have the same flags and same alignment
        # new size = sum of sizes of the two segments + gap between them
        while True:
            new_segments = []
            i = 0
            while i < len(self._segments) - 1:
                prev_seg = self._segments[i]
                next_seg = self._segments[i + 1]
                if (
                    prev_seg["p_type"] == next_seg["p_type"] == "PT_LOAD"
                    and prev_seg["p_offset"] + prev_seg["p_filesz"]
                    == next_seg["p_offset"]
                    and prev_seg["p_vaddr"] + prev_seg["p_memsz"] == next_seg["p_vaddr"]
                    and prev_seg["p_flags"] == next_seg["p_flags"]
                    and prev_seg["p_align"] == next_seg["p_align"]
                ):
                    new_segments.append(
                        Container(
                            p_type="PT_LOAD",
                            p_offset=prev_seg["p_offset"],
                            p_filesz=prev_seg["p_filesz"]
                            + next_seg["p_filesz"]
                            + (
                                next_seg["p_offset"]
                                - (prev_seg["p_offset"] + prev_seg["p_filesz"])
                            ),
                            p_vaddr=prev_seg["p_vaddr"],
                            p_paddr=prev_seg["p_paddr"],
                            p_memsz=prev_seg["p_memsz"]
                            + next_seg["p_memsz"]
                            + (
                                next_seg["p_vaddr"]
                                - (prev_seg["p_vaddr"] + prev_seg["p_memsz"])
                            ),
                            p_flags=prev_seg["p_flags"],
                            p_align=prev_seg["p_align"],
                        )
                    )
                    i += 2
                else:
                    new_segments.append(prev_seg)
                    i += 1
            if i == len(self._segments) - 1:
                new_segments.append(self._segments[i])
            if new_segments == self._segments:
                break
            self._segments = new_segments

        if (
            len(
                [
                    segment
                    for segment in self._segments
                    if segment["p_type"] == "PT_LOAD"
                ]
            )
            <= load_segment_count
        ):
            # just rebuild segment headers, it will be in place so we don't care if there is PHDR or not
            new_phdr = b""
            for segment in self._segments:
                new_phdr += self._elf.structs.Elf_Phdr.build(segment)
            self.p.binfmt_tool.update_binary_content(
                self._elf.header["e_phoff"], new_phdr
            )
            ehdr = self._elf.header
            ehdr["e_phnum"] = len(self._segments)
            new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
            self.p.binfmt_tool.update_binary_content(0, new_ehdr)
        else:
            # create new load segment for phdr (values are undetermined yet)
            phdr_load_segment = Container(
                p_type="PT_LOAD",
                p_offset=0,
                p_filesz=0,
                p_vaddr=0,
                p_paddr=0,
                p_memsz=0,
                p_flags=0x4,
                p_align=0x1000,
            )
            self._segments.append(phdr_load_segment)

            # magic
            # TODO: should we use the max_align of the segments?
            load_segments_rounded = []
            first_load_segment = None
            for segment in self._segments:
                if segment["p_type"] == "PT_LOAD":
                    if first_load_segment is None:
                        first_load_segment = segment
                    load_segments_rounded.append(
                        (
                            # start of the segment, round down to multiple of max_align
                            (segment["p_vaddr"] - first_load_segment["p_vaddr"])
                            - (
                                (segment["p_vaddr"] - first_load_segment["p_vaddr"])
                                % max_align
                            ),
                            # end of the segment, round up to multiple of max_align
                            int(
                                (
                                    segment["p_vaddr"]
                                    + segment["p_memsz"]
                                    - first_load_segment["p_vaddr"]
                                    + max_align
                                    - 1
                                )
                                / max_align
                            )
                            * max_align,
                        )
                    )
            load_segments_rounded = sorted(load_segments_rounded, key=lambda x: x[0])

            # combine overlapping load segments
            while True:
                new_load_segments_rounded = []
                i = 0
                while i < len(load_segments_rounded) - 1:
                    prev_seg = load_segments_rounded[i]
                    next_seg = load_segments_rounded[i + 1]
                    if prev_seg[1] > next_seg[0]:  # two segments overlap
                        new_load_segments_rounded.append(
                            (prev_seg[0], next_seg[1])
                        )  # append combine of two segments
                        i += 2
                    else:
                        new_load_segments_rounded.append(
                            prev_seg
                        )  # append segment without overlap
                        i += 1
                if i == len(load_segments_rounded) - 1:
                    new_load_segments_rounded.append(
                        load_segments_rounded[i]
                    )  # append last segment if without overlapping
                if new_load_segments_rounded == load_segments_rounded:  # if no overlap
                    break
                load_segments_rounded = (
                    new_load_segments_rounded  # combined segments, run again
                )

            for prev_seg, next_seg in zip(
                load_segments_rounded[:-1], load_segments_rounded[1:]
            ):
                # TODO: should we use the max_align of the segments?
                potential_base = (
                    max(prev_seg[1], self.p.binfmt_tool.file_size) + (max_align - 1)
                ) & ~(max_align - 1)  # round up to max_align
                if next_seg[0] - potential_base > self._elf.header["e_phentsize"] * len(
                    self._segments
                ):  # if there is space between segments, put phdr here
                    phdr_start = potential_base
                    break
            else:
                phdr_start = load_segments_rounded[-1][
                    1
                ]  # otherwise put it after the last load segment
            # this is to workaround a weird issue in the dynamic linker of glibc
            # we want to make sure p_vaddr (phdr_start) == p_offset (len(ncontent))
            if phdr_start <= self.p.binfmt_tool.file_size:
                # TODO: should we use the max_align of the segments?
                # p_vaddr <= p_offset: pad the file (p_offset) to page size, and let p_vaddr = p_offset
                self.p.binfmt_tool.file_size = (
                    self.p.binfmt_tool.file_size + (max_align - 1)
                ) & ~(max_align - 1)  # round up to max_align
                phdr_start = self.p.binfmt_tool.file_size

            # update phdr segment and its corresponding load segment
            for segment in self._segments:
                if segment["p_type"] == "PT_PHDR" or segment == phdr_load_segment:
                    segment["p_filesz"] = self._elf.header["e_phentsize"] * len(
                        self._segments
                    )
                    segment["p_memsz"] = self._elf.header["e_phentsize"] * len(
                        self._segments
                    )
                    segment["p_offset"] = phdr_start
                    segment["p_vaddr"] = phdr_start + first_load_segment["p_vaddr"]
                    segment["p_paddr"] = phdr_start + first_load_segment["p_vaddr"]

            # create new phdr segment to be put in the new load segment above
            # make sure PHDR is the first segment
            self._segments = sorted(
                self._segments, key=lambda x: (x["p_type"] != "PT_PHDR", x["p_offset"])
            )
            new_phdr = b""
            for segment in self._segments:
                new_phdr += self._elf.structs.Elf_Phdr.build(segment)
            self.p.binfmt_tool.update_binary_content(phdr_start, new_phdr)

            ehdr = self._elf.header
            ehdr["e_phnum"] = len(self._segments)
            ehdr["e_phoff"] = phdr_start
            new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
            self.p.binfmt_tool.update_binary_content(0, new_ehdr)

    def save_binary(self, filename: str | None = None) -> None:
        # bytearray for in-place edits (was O(N²) bytes-rebuild per update)
        content = bytearray(self.updated_binary_content.ljust(self.file_size, b"\x00"))
        for update in self.file_updates:
            offset = update["offset"]
            data = update["content"]
            end = offset + len(data)
            if end > len(content):
                content.extend(b"\x00" * (end - len(content)))
            content[offset:end] = data
        self.updated_binary_content = bytes(content)
        if filename is None:
            filename = f"{self.binary_path}.patched"
        with open(filename, "wb") as f:
            f.write(self.updated_binary_content)
        os.chmod(filename, 0o755)

    def update_binary_content(self, offset: int, new_content: bytes) -> None:
        logger.debug(
            f"Updating offset {hex(offset)} with content ({len(new_content)} bytes) {new_content.hex()}"
        )
        for update in self.file_updates:
            if offset >= update["offset"] and offset < update["offset"] + len(
                update["content"]
            ):
                raise ValueError(
                    f"Cannot update offset {hex(offset)} with content {new_content}, it overlaps with a previous update"
                )
        self.file_updates.append({"offset": offset, "content": new_content})
        if offset + len(new_content) > self.file_size:
            self.file_size = offset + len(new_content)

    def get_binary_content(self, offset: int, size: int) -> bytes:
        for update in self.file_updates:
            if offset >= update["offset"] and offset + size <= update["offset"] + len(
                update["content"]
            ):
                start = offset - update["offset"]
                return update["content"][start : start + size]
        return self.original_binary_content[offset : offset + size]

    def append_to_binary_content(self, new_content: bytes) -> None:
        self.file_updates.append({"offset": self.file_size, "content": new_content})
        self.file_size += len(new_content)
