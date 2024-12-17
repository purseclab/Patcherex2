import copy

from elftools.construct.lib import Container

from ..components.allocation_managers.allocation_manager import (
    AllocationManager,
    FileBlock,
    MappedBlock,
    MemoryBlock,
    MemoryFlag,
)
from ..components.binfmt_tools.elf import ELF
from ..patches import InsertInstructionPatch
from .elf_arm_linux import ElfArmLinux


class FlashBlock(MemoryBlock):
    pass


class RamBlock(MemoryBlock):
    pass


class CustomAllocationManager(AllocationManager):
    def _create_new_mapped_block(
        self, size: int, flag=MemoryFlag.RWX, align=0x1
    ) -> bool:
        file_addr = None
        virtual_mem_addr = None
        load_mem_addr = None
        for block in self.blocks[FileBlock]:
            if block.size == -1:
                file_addr = block.addr
                block.addr += 0x10000
        if flag == MemoryFlag.RW:
            for block in self.blocks[RamBlock]:
                if block.size == -1:
                    if self.p.binfmt_tool.__class__.__name__ == "ELF":
                        max_seg_align = max(
                            [
                                segment["p_align"]
                                for segment in self.p.binfmt_tool._segments
                            ]
                            + [0]
                        )
                        virtual_mem_addr = (
                            block.addr + (file_addr - block.addr) % max_seg_align
                        )
                    else:
                        virtual_mem_addr = (
                            block.addr + (file_addr - block.addr) % 0x1000
                        )
                    block.addr = virtual_mem_addr + 0x10000
            for block in self.blocks[FlashBlock]:
                if block.size == -1:
                    if self.p.binfmt_tool.__class__.__name__ == "ELF":
                        max_seg_align = max(
                            [
                                segment["p_align"]
                                for segment in self.p.binfmt_tool._segments
                            ]
                            + [0]
                        )
                        load_mem_addr = (
                            block.addr + (file_addr - block.addr) % max_seg_align
                        )
                    else:
                        load_mem_addr = block.addr + (file_addr - block.addr) % 0x1000
                    block.addr = load_mem_addr + 0x10000
            if file_addr and load_mem_addr and virtual_mem_addr:
                block = MappedBlock(
                    file_addr,
                    virtual_mem_addr,
                    0x10000,
                    is_free=True,
                    flag=flag,
                    load_mem_addr=load_mem_addr,
                )
                self.add_block(copy.deepcopy(block))
                self.new_mapped_blocks.append(copy.deepcopy(block))
                return True
        elif flag == MemoryFlag.RX:
            for block in self.blocks[FlashBlock]:
                if block.size == -1:
                    # NOTE: mem_addr % p_align should equal to file_addr % p_align
                    # Check `man elf` and search for `p_align` for more information
                    # FIXME: shouldn't do any assumption on component type, reimpl in a better way
                    # FIXME: even worse, importing ELF will cause circular import
                    # TODO: consider merge allocation_manager and binfmt_tool into one component
                    if self.p.binfmt_tool.__class__.__name__ == "ELF":
                        max_seg_align = max(
                            [
                                segment["p_align"]
                                for segment in self.p.binfmt_tool._segments
                            ]
                            + [0]
                        )
                        load_mem_addr = (
                            block.addr + (file_addr - block.addr) % max_seg_align
                        )
                    else:
                        load_mem_addr = block.addr + (file_addr - block.addr) % 0x1000
                    block.addr = load_mem_addr + 0x10000
            if file_addr and load_mem_addr:
                block = MappedBlock(
                    file_addr,
                    load_mem_addr,
                    0x10000,
                    is_free=True,
                    flag=flag,
                )
                self.add_block(copy.deepcopy(block))
                self.new_mapped_blocks.append(copy.deepcopy(block))
                return True
        else:
            raise NotImplementedError("Unknown MemoryFlag")
        return False


class CustomElf(ELF):
    def __init__(self, p, binary_path, **kwargs):
        assert (
            "flash_start" in kwargs
            and "flash_end" in kwargs
            and "ram_start" in kwargs
            and "ram_end" in kwargs
            and "insert_points" in kwargs
        )
        self.flash_start = kwargs["flash_start"]
        self.flash_end = kwargs["flash_end"]
        self.ram_start = kwargs["ram_start"]
        self.ram_end = kwargs["ram_end"]
        self.insert_points = kwargs["insert_points"]
        assert isinstance(self.insert_points, list)

        super().__init__(p, binary_path)

    def _init_memory_analysis(self):
        highest_flash_addr = self.flash_start
        highest_ram_addr = self.ram_start
        highest_file_offset = 0
        for segment in self._segments:
            seg_start = segment["p_vaddr"]
            seg_end = segment["p_vaddr"] + segment["p_memsz"]
            if (
                self.flash_start <= seg_start < self.flash_end
                and self.flash_start <= seg_end < self.flash_end
                and seg_end > highest_flash_addr
            ):
                highest_flash_addr = seg_end
            if (
                self.ram_start <= seg_start < self.ram_end
                and self.ram_start <= seg_end < self.ram_end
                and seg_end > highest_ram_addr
            ):
                highest_ram_addr = seg_end

            if segment["p_offset"] + segment["p_filesz"] > highest_file_offset:
                highest_file_offset = segment["p_offset"] + segment["p_filesz"]

        highest_file_offset = (highest_file_offset + 0xFFFF) & ~0xFFFF
        block = FileBlock(highest_file_offset, -1)
        self.p.allocation_manager.add_block(block)
        block = RamBlock(highest_ram_addr, -1)
        self.p.allocation_manager.add_block(block)
        block = FlashBlock(highest_flash_addr, -1)
        self.p.allocation_manager.add_block(block)

    def finalize(self):
        self.p.allocation_manager.finalize()
        if len(self.p.allocation_manager.new_mapped_blocks) == 0:
            return

        max_align = max([segment["p_align"] for segment in self._segments] + [0])

        copy_to_ram = ""
        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            if block.mem_addr != block.load_mem_addr:
                copy_to_ram += f"""
ldr r0, ={hex(block.load_mem_addr)}
ldr r1, ={hex(block.mem_addr)}
ldr r2, ={hex(block.size)}
copy:
ldrb r3, [r0], #1
strb r3, [r1], #1
subs r2, r2, #1
bne copy
"""
        for insert_point in self.insert_points:
            InsertInstructionPatch(insert_point, copy_to_ram, save_context=True).apply(
                self.p
            )
        self.p.allocation_manager.finalize()
        # create new load segment for each new mapped block
        for block in self.p.allocation_manager.new_mapped_blocks:
            self._segments.append(
                Container(
                    **{
                        "p_type": "PT_LOAD",
                        "p_offset": block.file_addr,
                        "p_filesz": block.size,
                        "p_vaddr": block.mem_addr,
                        "p_paddr": block.load_mem_addr,
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


class ElfArmBare(ElfArmLinux):
    @staticmethod
    def detect_target(binary_path):
        return False

    def get_binfmt_tool(self, binfmt_tool, **kwargs):
        binfmt_tool = binfmt_tool or "default"
        if binfmt_tool == "default":
            return CustomElf(self.p, self.binary_path, **kwargs)
        raise NotImplementedError()

    def get_allocation_manager(self, allocation_manager):
        allocation_manager = allocation_manager or "default"
        if allocation_manager == "default":
            return CustomAllocationManager(self.p)
        raise NotImplementedError()
