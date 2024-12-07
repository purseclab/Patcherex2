from elftools.construct.lib import Container

from ..components.allocation_managers.allocation_manager import (
    FileBlock,
    MemoryBlock,
)
from ..components.binfmt_tools.elf import ELF
from .elf_arm_linux import ElfArmLinux


class CustomElf(ELF):
    def _init_memory_analysis(self):
        """
        Information from NXP's MCUXpresso IDE:
        Flash is code, RAM4 is where data being loaded to

        * For additional code, we can just put them in the free flash space
        * For additional data, we also put them in the free flash space, but
        we need to update ResetISR to copy them to RAM4

        * The flasher (LinkServer) seems only care about segment headers, so
        we can safely ignore the section headers.

        * The IDE will strip the binary then call the flasher, and strip will
        remove the segment we added, so we need to add a fake corresponding
        section to make sure the segment is not removed.

        Type   | Name          | Alias | Location   | Size
        -------|---------------|-------|------------|----------
        Flash  | BOARD_FLASH   | Flash | 0x60000000 | 0x4000000
        RAM    | SRAM_DTC      | RAM   | 0x20000000 | 0x20000
        RAM    | SRAM_ITC      | RAM2  | 0x0        | 0x20000
        RAM    | SRAM_OC       | RAM3  | 0x20200000 | 0x20000
        RAM    | BOARD_SDRAM   | RAM4  | 0x80000000 | 0x1e00000
        RAM    | NCACHE_REGION | RAM5  | 0x81e00000 | 0x200000
        """

        # add free flash space to allocation manager
        flash_start = 0x60000000
        flash_end = 0x64000000
        highest_flash_addr = 0x60000000
        highest_file_offset = 0
        for segment in self._segments:
            seg_start = segment["p_paddr"]
            seg_end = segment["p_paddr"] + segment["p_memsz"]
            if (
                flash_start <= seg_start < flash_end
                and flash_start <= seg_end < flash_end
                and seg_end > highest_flash_addr
            ):
                highest_flash_addr = seg_end

            if segment["p_offset"] + segment["p_filesz"] > highest_file_offset:
                highest_file_offset = segment["p_offset"] + segment["p_filesz"]

        highest_file_offset = (highest_file_offset + 0xFFFF) & ~0xFFFF
        block = FileBlock(highest_file_offset, -1)
        self.p.allocation_manager.add_block(block)
        block = MemoryBlock(highest_flash_addr, -1)
        self.p.allocation_manager.add_block(block)

        return

    def finalize(self):
        self.p.allocation_manager.finalize()
        if len(self.p.allocation_manager.new_mapped_blocks) == 0:
            return

        max_align = max([segment["p_align"] for segment in self._segments] + [0])

        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            self._segments.append(
                Container(
                    **{
                        "p_type": "PT_LOAD",
                        "p_offset": block.file_addr,
                        "p_filesz": block.size,
                        "p_vaddr": block.mem_addr,
                        "p_paddr": block.mem_addr,
                        "p_memsz": block.size,
                        "p_flags": block.flag,
                        "p_align": max_align,
                    }
                )
            )

            self._sections.append(
                Container(
                    **{
                        "sh_name": 0,
                        "sh_type": "SHT_PROGBITS",
                        "sh_flags": 2,
                        "sh_addr": block.mem_addr,
                        "sh_offset": block.file_addr,
                        "sh_size": block.size,
                        "sh_link": 0,
                        "sh_info": 0,
                        "sh_addralign": max_align,
                        "sh_entsize": 0,
                    }
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
                            **{
                                "p_type": "PT_LOAD",
                                "p_offset": prev_seg["p_offset"],
                                "p_filesz": prev_seg["p_filesz"]
                                + next_seg["p_filesz"]
                                + (
                                    next_seg["p_offset"]
                                    - (prev_seg["p_offset"] + prev_seg["p_filesz"])
                                ),
                                "p_vaddr": prev_seg["p_vaddr"],
                                "p_paddr": prev_seg["p_paddr"],
                                "p_memsz": prev_seg["p_memsz"]
                                + next_seg["p_memsz"]
                                + (
                                    next_seg["p_vaddr"]
                                    - (prev_seg["p_vaddr"] + prev_seg["p_memsz"])
                                ),
                                "p_flags": prev_seg["p_flags"],
                                "p_align": prev_seg["p_align"],
                            }
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

        # generate new phdr at end of the file and update ehdr
        last_seg = sorted(self._segments, key=lambda x: x["p_offset"])[-1]
        phdr_start = last_seg["p_offset"] + last_seg["p_filesz"]
        new_phdr = b""
        for segment in self._segments:
            new_phdr += self._elf.structs.Elf_Phdr.build(segment)
        self.p.binfmt_tool.update_binary_content(phdr_start, new_phdr)

        ehdr = self._elf.header
        ehdr["e_phnum"] = len(self._segments)
        ehdr["e_phoff"] = phdr_start

        # generate new shdr at end of the file and update ehdr
        shdr_start = phdr_start + len(new_phdr)
        new_shdr = b""
        for section in self._sections:
            new_shdr += self._elf.structs.Elf_Shdr.build(section)
        self.p.binfmt_tool.update_binary_content(shdr_start, new_shdr)

        ehdr["e_shnum"] = len(self._sections)
        ehdr["e_shoff"] = shdr_start
        new_ehdr = self._elf.structs.Elf_Ehdr.build(ehdr)
        self.p.binfmt_tool.update_binary_content(0, new_ehdr)


class ElfArmMimxrt1052(ElfArmLinux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return CustomElf(self.p, self.binary_path)
        raise NotImplementedError()
