import struct
from elfheader import ELFHeader

class SectionHeader:
    _SH_FLAGS = {
        0x1 : "W",
        0x2 : "A",
        0x4 : "X",
        0x10 : "M",
        0x20 : "S",
        0x40 : "I",
        0x80 : "L",
        0x100 : "O",
        0x200 : "G",
        0x400 : "T",
        0x80000000 : "E",
        0x800 : "C",
    }
    
    _SH_TYPES = {
        0x0 : "NULL",
        0x1 : "PROGBITS",
        0x2 : "SYMTAB",
        0x3 : "STRTAB",
        0x4 : "RELA",
        0x5 : "HASH",
        0x6 : "DYNAMIC",
        0x7 : "NOTE",
        0x8 : "NOBITS",
        0x9 : "REL",
        0xa : "SHLIB",
        0xb : "DYNSYM",
        0xe : "INIT_ARRAY",
        0xf : "FINI_ARRAY",
        0x10 : "PREINIT_ARRAY",
        0x11 : "GROUP",
        0x12 : "SYMTAB_SHNDX",
        0x13 : "RELR",
        0x60000000 : "LOOS",
        0x6fffffff : "SHT_SUNW_versym"
    }     
        
    def __init__(self, elf) -> None:
        self.elf = elf
        elf.seek(0)
        eh = ELFHeader(elf)
        elf.seek(0)
        self.elf_class = eh.elf_class
        self.elf_shnum = eh.elf_shnum
        self.elf_shoff = eh.elf_shoff
        self.elf_shentsize = eh.elf_shentsize
        
        self.s_headers = []
        
        for i in range(self.elf_shnum):
            elf.seek(self.elf_shoff + i * self.elf_shentsize)
            
            if self.elf_class == 1:
                tmp = {}
                tmp["sh_name"] = struct.unpack("I", elf.read(4))[0] # sh_name
                tmp["sh_type"] = struct.unpack("I", elf.read(4))[0] # sh_type
                tmp["sh_flags"] = struct.unpack("I", elf.read(4))[0] # sh_flags
                tmp["sh_addr"] = struct.unpack("I", elf.read(4))[0] # sh_addr
                tmp["sh_offset"] = struct.unpack("I", elf.read(4))[0] # sh_offset
                tmp["sh_size"] = struct.unpack("I", elf.read(4))[0] # sh_size
                tmp["sh_link"] = struct.unpack("I", elf.read(4))[0] # sh_link
                tmp["sh_info"] = struct.unpack("I", elf.read(4))[0] # sh_info
                tmp["sh_addralign"] = struct.unpack("I", elf.read(4))[0] # sh_addralign
                tmp["sh_entsize"] = struct.unpack("I", elf.read(4))[0] # sh_entsize
                self.s_headers.append(tmp)
            else:
                tmp = {}
                tmp["sh_name"] = struct.unpack("I", elf.read(4))[0] # sh_name
                tmp["sh_type"] = struct.unpack("I", elf.read(4))[0] # sh_type
                tmp["sh_flags"] = struct.unpack("Q", elf.read(8))[0] # sh_flags
                tmp["sh_addr"] = struct.unpack("Q", elf.read(8))[0] # sh_addr
                tmp["sh_offset"] = struct.unpack("Q", elf.read(8))[0] # sh_offset
                tmp["sh_size"] = struct.unpack("Q", elf.read(8))[0] # sh_size
                tmp["sh_link"] = struct.unpack("I", elf.read(4))[0] # sh_link
                tmp["sh_info"] = struct.unpack("I", elf.read(4))[0] # sh_info
                tmp["sh_addralign"] = struct.unpack("Q", elf.read(8))[0] # sh_addralign
                tmp["sh_entsize"] = struct.unpack("Q", elf.read(8))[0] # sh_entsize
                self.s_headers.append(tmp)
    
    def print_section_header(self) -> None:
        print("There are %s section headers, starting at offset 0x%x:" % (self.elf_shnum, self.elf_shoff))
        print(" Section Header:")
        print("  [Nr] Name              Type             Address          Offset   Size             EntSize          Flags  Link  Info  Align")
        for i in range(self.elf_shnum):
            print("  [%02d] %-17s %-16s %016x %08x %016x %016x %5s  %02d    %02d    %02d" % (i, self.get_section_name(self.s_headers[i]["sh_name"])[:17], self._get_section_type(self.s_headers[i]["sh_type"]), self.s_headers[i]["sh_addr"], self.s_headers[i]["sh_offset"], self.s_headers[i]["sh_size"], self.s_headers[i]["sh_entsize"], self._get_section_flag(self.s_headers[i]["sh_flags"]), self.s_headers[i]["sh_link"], self.s_headers[i]["sh_info"], self.s_headers[i]["sh_addralign"]))
        print("Key to Flags:")
        print("  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),")
        print("  C (compressed), E (exclude),")
        print("")
        
    def export_section_header(self) -> dict:
        # export section header to json
        export = {}
        export["Section Header"] = []
        for i in range(self.elf_shnum):
            tmp = {}
            tmp["Nr"] = i
            tmp["Name"] = self.get_section_name(self.s_headers[i]["sh_name"])
            tmp["Type"] = self._get_section_type(self.s_headers[i]["sh_type"])
            tmp["Address"] = self.s_headers[i]["sh_addr"]
            tmp["Offset"] = self.s_headers[i]["sh_offset"]
            tmp["Size"] = self.s_headers[i]["sh_size"]
            tmp["EntSize"] = self.s_headers[i]["sh_entsize"]
            tmp["Flags"] = self._get_section_flag(self.s_headers[i]["sh_flags"])
            tmp["Link"] = self.s_headers[i]["sh_link"]
            tmp["Info"] = self.s_headers[i]["sh_info"]
            tmp["Align"] = self.s_headers[i]["sh_addralign"]
            export["Section Header"].append(tmp)
            
        return export
        
    def _get_section_flag(self, x) -> str:
        flag = ""
        for i in self._SH_FLAGS:
            if x & i:
                flag += self._SH_FLAGS[i]
        return flag
    
    def _get_section_type(self, x) -> str:
        if x in self._SH_TYPES:
            return self._SH_TYPES[x]
        elif x >= 0x60000000 and x <= 0x6fffffff:
            return 'loos+0x%x' % (x - 0x60000000)
    
    def get_section_name(self, sh_name) -> str:
        #print(sh_name)
        offset = self.s_headers[-1]["sh_offset"]
        name = self._find_section_name(offset + sh_name)
        return name.decode("utf-8", errors= "replace") if name else ''
            
    def _find_section_name(self, offset) -> bytes:
        self.elf.seek(offset)
        name = b''
        found = False
        while True:
            chunk = self.elf.read(64)
            end_point = chunk.find(b'\x00')
            if end_point >= 0:
                name += chunk[:end_point]
                found = True
                break
            else:
                name += chunk
        return name if found else None