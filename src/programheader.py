import struct
from elfheader import ELFHeader
from sectionheader import SectionHeader

class ProgramHeader():
    _P_TYPES = {
        0: "NULL",
        1: "LOAD",
        2: "DYNAMIC",
        3: "INTERP",
        4: "NOTE",
        5: "SHLIB",
        6: "PHDR",
        7: "TLS",
        8: "NUM",
        0x6474e550: "GNU_EH_FRAME",
        0x6474e551: "GNU_STACK",
        0x6474e552: "GNU_RELRO",
        0x6474e553: "GNU_PROPERTY",
    }
    
    _P_FLAGS = {
        0x1: "X",
        0x2: "W",
        0x3: "WE",
        0x4: "R",
        0x5: "RE",
        0x6: "RW",
        0x7: "RWE",
    }

    def __init__(self, elf) -> None:
        self.elf = elf
        self.elf.seek(0)
        eh = ELFHeader(elf)
        self.elf.seek(0)
        self.elf_phnum = eh.elf_phnum
        self.elf_phoff = eh.elf_phoff
        self.elf_phentsize = eh.elf_phentsize
        self.elf_class = eh.elf_class
        
        self.p_headers = []
        
        for i in range(self.elf_phnum):
            elf.seek(self.elf_phoff + (i * self.elf_phentsize))
            if self.elf_class == 1:
                tmp = {}
                tmp["p_type"] = struct.unpack("I", elf.read(4))[0] # p_type
                tmp["p_offset"] = struct.unpack("I", elf.read(4))[0] # p_offset
                tmp["p_vaddr"] = struct.unpack("I", elf.read(4))[0] # p_vaddr
                tmp["p_paddr"] = struct.unpack("I", elf.read(4))[0] # p_paddr
                tmp["p_filesz"] = struct.unpack("I", elf.read(4))[0] # p_filesz
                tmp["p_memsz"] = struct.unpack("I", elf.read(4))[0] # p_memsz
                tmp["p_flags"] = struct.unpack("I", elf.read(4))[0] # p_flags
                tmp["p_align"] = struct.unpack("I", elf.read(4))[0] # p_align
                self.p_headers.append(tmp)
            else:
                tmp = {}
                tmp["p_type"] = struct.unpack("I", elf.read(4))[0] # p_type
                tmp["p_flags"] = struct.unpack("I", elf.read(4))[0] # p_flags
                tmp["p_offset"] = struct.unpack("Q", elf.read(8))[0] # p_offset
                tmp["p_vaddr"] = struct.unpack("Q", elf.read(8))[0] # p_vaddr
                tmp["p_paddr"] = struct.unpack("Q", elf.read(8))[0] # p_paddr
                tmp["p_filesz"] = struct.unpack("Q", elf.read(8))[0] # p_filesz
                tmp["p_memsz"] = struct.unpack("Q", elf.read(8))[0] # p_memsz
                tmp["p_align"] = struct.unpack("Q", elf.read(8))[0] # p_align           
                self.p_headers.append(tmp)
                
    def print_program_header(self) -> None:
        print("Program Headers:")
        print("%12s %18s  %18s  %18s  %18s  %18s  %04s  %18s" %("Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align"))
        for i in range(self.elf_phnum):
            print("%12s 0x%016x  0x%016x  0x%016x  0x%016x  0x%016x  %05s  0x%016x" %(self._get_program_type(self.p_headers[i]["p_type"]), self.p_headers[i]["p_offset"], self.p_headers[i]["p_vaddr"], self.p_headers[i]["p_paddr"], self.p_headers[i]["p_filesz"], self.p_headers[i]["p_memsz"], self._get_program_flag(self.p_headers[i]["p_flags"]), self.p_headers[i]["p_align"]))
            if self.p_headers[i]["p_type"] == 0x3:
                print("    [Requesting program interpreter: "+ self._get_interp_name(self.p_headers[i]["p_offset"]) +"]")
        print("")
        print(" Section to Segment mapping:")
        print("  Segment Sections...")
        sections = SectionHeader(self.elf)
        for i in range(self.elf_phnum):
            print("   %02d     " %i, end="")
            for j in range(sections.elf_shnum):
                if sections.s_headers[j]["sh_addr"] >= self.p_headers[i]["p_vaddr"] and sections.s_headers[j]["sh_addr"] < self.p_headers[i]["p_vaddr"] + self.p_headers[i]["p_memsz"]:
                    section_name = sections.get_section_name(sections.s_headers[j]["sh_name"])
                    print("%s " % section_name, end="")
            print()
        print("")
    
    def export_program_header(self) -> dict:
        export = {}
        export["Program Header"] = []
        for i in range(self.elf_phnum):
            tmp = {}
            tmp["Type"] = self._get_program_type(self.p_headers[i]["p_type"])
            tmp["Offset"] = self.p_headers[i]["p_offset"]
            tmp["VirtAddr"] = self.p_headers[i]["p_vaddr"]
            tmp["PhysAddr"] = self.p_headers[i]["p_paddr"]
            tmp["FileSiz"] = self.p_headers[i]["p_filesz"]
            tmp["MemSiz"] = self.p_headers[i]["p_memsz"]
            tmp["Flags"] = self._get_program_flag(self.p_headers[i]["p_flags"])
            tmp["Align"] = self.p_headers[i]["p_align"]
            export["Program Header"].append(tmp)
        
        return export
    
    def _get_interp_name(self, offset) -> str:
        self.elf.seek(offset)
        name = ""
        while True:
            tmp = struct.unpack("c", self.elf.read(1))[0]
            if tmp == b'\x00':
                break
            name += tmp.decode("utf-8")
        return name
            
    def _get_program_type(self, x) -> str:
        if x in self._P_TYPES:
            return self._P_TYPES[x]
        elif x >= 0x60000000 and x <= 0x6fffff00:
            return 'LOOS+%lx' % (x - 0x60000000)
        else :
            return 'Unknown'
        
    def _get_program_flag(self, x) -> str:
        if x in self._P_FLAGS:
            return self._P_FLAGS[x]
        else:
            return 'Unknown'