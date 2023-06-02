import struct
from sectionheader import SectionHeader
from elfheader import ELFHeader

class SymbolTable:
    _ST_TYPE = {
        0x0 : "NOTYPE",
        0x1 : "OBJECT",
        0x2 : "FUNC",
        0x3 : "SECTION",
        0x4 : "FILE",
        0x5 : "COMMON",
        0x6 : "TLS",
        0x7 : "NUM",
        0x8 : "RELC",
        0x9 : "SRELC",
        0xa : "LOOS",
        0xb : "HIOS",
        0xc : "LOPROC",
        0xd : "HIPROC",
    }
    
    def __init__(self, elf) -> None:
        self.elf = elf
        self.sectionHeader = SectionHeader(elf)
        s_header = self.sectionHeader.s_headers
        self.s_header_dic = {}
        for i in s_header:
            name = self.sectionHeader.get_section_name(i["sh_name"])
            self.s_header_dic[name] = i
        
        hasSymSections = {}
        for i in self.s_header_dic:
            if i == ".symtab" or i == ".dynsym":
                hasSymSections[i] = self.s_header_dic[i]
        self.SymTable = self._parse_symbol_table(elf, hasSymSections)      
        
    def _parse_symbol_table(self, elf, s_header) -> dict:
        elfHeader = ELFHeader(elf)
        symTable = {}
        for k, v in s_header.items():
            elf.seek(v["sh_offset"])
            tmp1 = {}
            for i in range(v["sh_size"] // v["sh_entsize"]):
                if elfHeader.elf_class == 1:
                    tmp2 = {}
                    tmp2["st_name"] = struct.unpack("I", elf.read(4))[0]
                    tmp2["st_value"] = struct.unpack("I", elf.read(4))[0]
                    tmp2["st_size"] = struct.unpack("I", elf.read(4))[0]
                    tmp2["st_info"] = struct.unpack("B", elf.read(1))[0]
                    tmp2["st_other"] = struct.unpack("B", elf.read(1))[0]
                    tmp2["st_shndx"] = struct.unpack("H", elf.read(2))[0]
                else:
                    tmp2 = {}
                    tmp2["st_name"] = struct.unpack("I", elf.read(4))[0]
                    tmp2["st_info"] = struct.unpack("B", elf.read(1))[0]
                    tmp2["st_other"] = struct.unpack("B", elf.read(1))[0]
                    tmp2["st_shndx"] = struct.unpack("H", elf.read(2))[0]
                    tmp2["st_value"] = struct.unpack("Q", elf.read(8))[0]
                    tmp2["st_size"] = struct.unpack("Q", elf.read(8))[0]
                tmp1[i] = tmp2
            symTable[k] = tmp1
        return symTable    
    
    def print_symbol_table(self) -> None:
        for k, v in self.SymTable.items():
            print("Symbol table '" + k + "' contains " + str(len(v)) + " entries:")
            print("   Num:    Value         Size Type    Bind   Vis      Ndx Name")
            for i, j in v.items():
                print("%6d: %016x %4x %-7s %-6s %-7s %4s %s" % (i, j["st_value"], j["st_size"], self._get_symbol_type(j["st_info"]), self._get_symbol_bind(j["st_info"]), self._get_symbol_visibility(j["st_other"]), self._get_symbol_Ndx(j["st_shndx"]), self._get_symbol_name(k, j)))
            print("")
            
    def export_symbol_table(self) -> dict:
        export = {}
        export["Symbol Table"] = []
        for k, v in self.SymTable.items():
            tmp = []
            for i, j in v.items():
                tmp.append({})
                tmp[i]["Num"] = i
                tmp[i]["Value"] = j["st_value"]
                tmp[i]["Size"] = j["st_size"]
                tmp[i]["Type"] = self._get_symbol_type(j["st_info"])
                tmp[i]["Bind"] = self._get_symbol_bind(j["st_info"])
                tmp[i]["Vis"] = self._get_symbol_visibility(j["st_other"])
                tmp[i]["Ndx"] = j["st_shndx"]
                tmp[i]["Name"] = self._get_symbol_name(k, j)
            export["Symbol Table"].append({k: tmp})
        return export
    
    def _get_symbol_Ndx(self, x) -> str:
        if x == 0:
            return "UND"
        elif x == 0xfff1:
            return "ABS"
        elif x == 0xfff2:
            return "COM"
        else:
            return str(x)
        
    def _get_symbol_type(self, x) -> str:
        return x
        
    def _get_symbol_bind(self, x) -> str:
        if x >> 4 == 0:
            return "LOCAL"
        elif x >> 4 == 1:
            return "GLOBAL"
        elif x >> 4 == 2:
            return "WEAK"
        elif x >> 4 == 10:
            return "LOOS"
        elif x >> 4 == 12:
            return "HIOS"
        elif x >> 4 == 13:
            return "LOPROC"
        elif x >> 4 == 15:
            return "HIPROC"
        else :
            return x
    
    def _get_symbol_visibility(self, x) -> str:
        if x == 0:
            return "DEFAULT"
        elif x == 1:
            return "INTERNAL"
        elif x == 2:
            return "HIDDEN"
        elif x == 3:
            return "PROTECTED"
        elif x == 4:
            return "EXPORTED"
        elif x == 5:
            return "SINGLETON"
        elif x == 6:
            return "ELIMINATE"
        else :
            return x

    def _get_symbol_name(self, index, sym) -> str:
        if index == ".dynsym":
            offset = self.s_header_dic[".dynstr"]["sh_offset"]
            name = self._find_symbol_name(offset + sym["st_name"])
            return name.decode("utf-8", errors= "replace") if name else ''
        if index == ".symtab":
            offset = self.s_header_dic[".strtab"]["sh_offset"]
            name = self._find_symbol_name(offset + sym["st_name"])
            return name.decode("utf-8", errors= "replace") if name else ''
        return ""
        
    def _find_symbol_name(self, offset) -> bytes:
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