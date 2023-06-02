import struct

class ELFHeader():
    def __init__(self, elf) -> None:
        elf.seek(0)
        self.elf_head16 = struct.unpack('16B', elf.read(16))
        self.elf_magic = self.elf_head16[:4]
        self.elf_class = self.elf_head16[4]
        self.elf_data = self.elf_head16[5]
        self.elf_version = self.elf_head16[6]
        self.elf_osabi = self.elf_head16[7]
        self.elf_abiversion = self.elf_head16[8]
        self.elf_type = struct.unpack('H', elf.read(2))[0]
        self.elf_machine = struct.unpack('H', elf.read(2))[0]
        self.elf_version = struct.unpack('I', elf.read(4))[0]
        if(self.elf_class == 1):
            # 32-bit
            self.elf_entry = struct.unpack('I', elf.read(4))[0]
            self.elf_phoff = struct.unpack('I', elf.read(4))[0]
            self.elf_shoff = struct.unpack('I', elf.read(4))[0]
        else:
            # 64-bit
            self.elf_entry = struct.unpack('Q', elf.read(8))[0]
            self.elf_phoff = struct.unpack('Q', elf.read(8))[0]
            self.elf_shoff = struct.unpack('Q', elf.read(8))[0]
        self.elf_flags = struct.unpack('I', elf.read(4))[0]
        self.elf_ehsize = struct.unpack('H', elf.read(2))[0]
        self.elf_phentsize = struct.unpack('H', elf.read(2))[0]
        self.elf_phnum = struct.unpack('H', elf.read(2))[0]
        self.elf_shentsize = struct.unpack('H', elf.read(2))[0]
        self.elf_shnum = struct.unpack('H', elf.read(2))[0]
        self.elf_shstrndx = struct.unpack('H', elf.read(2))[0]

    def print_elf_header(self) -> None:
        if not (self.elf_magic == (0x7F, 0x45, 0x4C, 0x46)):
            print("Error: Not an ELF file - it has the wrong magic bytes at the start")
        print("ELF Header:")
        print("  Magic:   ", end='')
        for i in range(16):
            hex = format(self.elf_head16[i], 'X')
            print(hex, end=' ')
        print()
        print("  Class:   ", end='')
        print(self._get_class_name(self.elf_class))
        print("  Data:    ", end='')
        print(self._get_data_encoding(self.elf_data))
        print("  Version: ", end='')
        print(self._get_version(self.elf_version))
        print("  OS/ABI:  ", end='')
        print(self._ebl_osabi_name(self.elf_osabi, self.elf_machine))
        print("  ABI Version: ", end='')
        print(self.elf_abiversion)
        print("  Type:    ", end='')
        print(self._get_file_type(self.elf_type))
        print("  Machine: ", end='')
        print(self._get_machine_name(self.elf_machine))
        print("  Version: ", end='')
        print(self._get_version(self.elf_version))
        print("  Entry point address: ", end='')
        print("0x" + format(self.elf_entry, 'X'))
        print("  Start of program headers: ", end='')
        print(str(self.elf_phoff) + " (bytes into file)")
        print("  Start of section headers: ", end='')
        print(str(self.elf_shoff) + " (bytes into file)")
        print("  Flags:   ", end='')
        print("0x" + format(self.elf_flags, 'X'))
        print("  Size of this header: ", end='')
        print(str(self.elf_ehsize) + " (bytes)")
        print("  Size of program headers: ", end='')
        print(str(self.elf_phentsize) + " (bytes)")
        print("  Number of program headers: ", end='')
        print(str(self.elf_phnum))
        print("  Size of section headers: ", end='')
        print(str(self.elf_shentsize) + " (bytes)")
        print("  Number of section headers: ", end='')
        print(str(self.elf_shnum))
        print("  Section header string table index: ", end='')
        print(str(self.elf_shstrndx))
        print("")
    
    def export_elf_header(self) -> dict:
        export = {}
        export["ELF Header"] = {}
        # self.elf_head16 to str
        str_head16 = ""
        for i in range(16):
            str_head16 = str_head16 + format(self.elf_head16[i], 'X') + " "
        str_head16 = str_head16[:-1]
        
        export["ELF Header"]["Magic"] = [self.elf_head16, str_head16]
        export["ELF Header"]["Class"] = [self.elf_class, self._get_class_name(self.elf_class)]
        export["ELF Header"]["Data"] = [self.elf_data, self._get_data_encoding(self.elf_data)]
        export["ELF Header"]["Version"] = [self.elf_version, self._get_version(self.elf_version)]
        export["ELF Header"]["OS/ABI"] = [self.elf_osabi, self._ebl_osabi_name(self.elf_osabi, self.elf_machine)]
        export["ELF Header"]["ABI Version"] = [self.elf_abiversion, self.elf_abiversion]
        export["ELF Header"]["Type"] = [self.elf_type, self._get_file_type(self.elf_type)]
        export["ELF Header"]["Machine"] = [self.elf_machine, self._get_machine_name(self.elf_machine)]
        export["ELF Header"]["Version"] = [self.elf_version, self._get_version(self.elf_version)]
        export["ELF Header"]["Entry point address"] = [self.elf_entry, "0x" + format(self.elf_entry, 'X')]
        export["ELF Header"]["Start of program headers"] = [self.elf_phoff, str(self.elf_phoff) + " (bytes into file)"]
        export["ELF Header"]["Start of section headers"] = [self.elf_shoff, str(self.elf_shoff) + " (bytes into file)"]
        export["ELF Header"]["Flags"] = [self.elf_flags, "0x" + format(self.elf_flags, 'X')]
        export["ELF Header"]["Size of this header"] = [self.elf_ehsize, str(self.elf_ehsize) + " (bytes)"]
        export["ELF Header"]["Size of program headers"] = [self.elf_phentsize, str(self.elf_phentsize) + " (bytes)"]
        export["ELF Header"]["Number of program headers"] = [self.elf_phnum, str(self.elf_phnum)]
        export["ELF Header"]["Size of section headers"] = [self.elf_shentsize, str(self.elf_shentsize) + " (bytes)"]
        export["ELF Header"]["Number of section headers"] = [self.elf_shnum, str(self.elf_shnum)]
        export["ELF Header"]["Section header string table index"] = [self.elf_shstrndx, str(self.elf_shstrndx)]
        return export
    
    def _get_machine_name(self, num) -> str:
        machine_dict ={
            0:  "None",
            1:  "WE32100",
            2:  "Sparc",
            3:  "Intel 80386",
            4:  "MC68000",
            5:  "MC88000",
            6:  "Intel MCU",
            7:  "Intel 80860",
            8:  "MIPS R3000",
            9:  "IBM System/370",
            10:  "MIPS R4000 big-endian",
            11:  "Sparc v9 (old)",
            15:  "HPPA",
            17:  "Fujitsu VPP500",
            18:   "Sparc v8+" ,
            19:  "Intel 80960",
            20:  "PowerPC",
            21:  "PowerPC64",
            22:  "IBM S/390",
            23:  "SPU",
            36:  "Renesas V850 (using RH850 ABI)",
            37:  "Fujitsu FR20",
            38:  "TRW RH32",
            39:  "MCORE",
            40:  "ARM",
            41:  "Digital Alpha (old)",
            42:    "Renesas / SuperH SH",
            43:  "Sparc v9",
            44:  "Siemens Tricore",
            45:  "ARC",
            46:  "Renesas H8/300",
            47:  "Renesas H8/300H",
            48:  "Renesas H8S",
            49:  "Renesas H8/500",
            50:  "Intel IA-64",
            51:  "Stanford MIPS-X",
            52:  "Motorola Coldfire",
            53:  "Motorola M68HC12",
            54:  "Fujitsu MMA Multimedia Accelerator",
            55:  "Siemens PCP",
            56:  "Sony nCPU embedded RISC processor",
            57:  "Denso NDR1 microprocessor",
            58:  "Motorola Star*Core processor",
            59:  "Toyota ME16 processor",
            60:  "STMicroelectronics ST100 processor",
            61:  "Advanced Logic Corp. Tinyj emb.fam",
            62:  "AMD x86-64 architecture",
            63:  "Sony DSP Processor",
            64:  "Digital Equipment Corp. PDP-10",
            65:  "Digital Equipment Corp. PDP-11",
            66:  "Siemens FX66 microcontroller",
            67:  "STMicroelectronics ST9+ 8/16 mc",
            68:  "STMicroelectronics ST7 8 bit mc",
            69:  "Motorola MC68HC16 microcontroller",
            70:  "Motorola MC68HC11 microcontroller",
            71:  "Motorola MC68HC08 microcontroller",
            72:  "Motorola MC68HC05 microcontroller",
            73:  "Silicon Graphics SVx",
            74:  "STMicroelectronics ST19 8 bit mc",
            75:  "Digital VAX",
            76:  "Axis Communications 32-bit embedded processor",
            77:  "Infineon Technologies 32-bit embedded processor",
            78:  "Element 14 64-bit DSP Processor",
            79:  "LSI Logic 16-bit DSP Processor",
            80:  "Donald Knuth's educational 64-bit processor",
            81:  "Harvard University machine-independent object files",
            82:  "SiTera Prism",
            83:  "Atmel AVR 8-bit microcontroller",
            84:  "Fujitsu FR30",
            85:  "Mitsubishi D10V",
            86:  "Mitsubishi D30V",
            87:  "NEC v850",
            88:  "Mitsubishi M32R",
            89:  "Matsushita MN10300",
            90:  "Matsushita MN10200",
            91:  "picoJava",
            92:  "OpenRISC 32-bit embedded processor",
            93:  "ARC International ARCompact processor (old)",
            94:  "Tensilica Xtensa Architecture",
            95:  "Alphamosaic VideoCore processor",
            96:  "Thompson Multimedia General Purpose Processor",
            97:  "National Semiconductor 32000 series",
            98:  "Tenor Network TPC processor",
            99:  "Trebia SNP 1000 processor",
            100:  "STMicroelectronics (www.st.com) ST200 microcontroller",
            101:  "Ubicom IP2xxx microcontroller family",
            102:  "MAX Processor",
            103:  "National Semiconductor CompactRISC microprocessor",
            104:  "Fujitsu F2MC16",
            105:  "Texas Instruments embedded microcontroller msp430",
            106:  "Analog Devices Blackfin (DSP) processor",
            107:  "S1C33 Family of Seiko Epson processors",
            108:  "Sharp embedded microprocessor",
            109:  "Arca RISC Microprocessor",
            110:  "Unicore",
            111:  "eXcess: 16/32/64-bit configurable embedded CPU",
            112:  "Icera Semiconductor Inc. Deep Execution Processor",
            113:  "Altera Nios II",
            114:  "National Semiconductor CRX microprocessor",
            115:  "Motorola XGATE embedded processor",
            117:  "Renesas M16C series microprocessors",
            118:  "Microchip Technology dsPIC30F Digital Signal Controller",
            119:  "Freescale Communication Engine RISC core",
            120:  "Renesas M32c",
            131:  "Altium TSK3000 core",
            132:  "Freescale RS08 embedded processor",
            134:  "Cyan Technology eCOG2 microprocessor",
            135:  "Sunplus S+core",
            136:  "New Japan Radio (NJR) 24-bit DSP Processor",
            137:  "Broadcom VideoCore III processor",
            138:  "Lattice Mico32",
            139:  "Seiko Epson C17 family",
            140:  "Texas Instruments TMS320C6000 DSP family",
            141:  "Texas Instruments TMS320C2000 DSP family",
            142:  "Texas Instruments TMS320C55x DSP family",
            144:  "TI PRU I/O processor",
            160:  "STMicroelectronics 64bit VLIW Data Signal Processor",
            161:  "Cypress M8C microprocessor",
            162:  "Renesas R32C series microprocessors",
            163:  "NXP Semiconductors TriMedia architecture family",
            164:  "QUALCOMM DSP6 Processor",
            165:  "Intel 8051 and variants",
            166:  "STMicroelectronics STxP7x family",
            167:  "Andes Technology compact code size embedded RISC processor family",
            168:  "Cyan Technology eCOG1X family",
            169:  "Dallas Semiconductor MAXQ30 Core microcontrollers",
            170:  "New Japan Radio (NJR) 16-bit DSP Processor",
            171:  "M2000 Reconfigurable RISC Microprocessor",
            172:  "Cray Inc. NV2 vector architecture",
            173:    "Renesas RX",
            174:  "Imagination Technologies Meta processor architecture",
            175:  "MCST Elbrus general purpose hardware architecture",
            176:  "Cyan Technology eCOG16 family",
            178:  "Freescale Extended Time Processing Unit",
            179:  "Infineon Technologies SLE9X core",
            180:  "Intel L1OM",
            181:  "Intel K1OM",
            182:  "Intel (reserved)",
            183:  "AArch64",
            184:  "ARM (reserved)",
            185:  "Atmel Corporation 32-bit microprocessor",
            186:  "STMicroeletronics STM8 8-bit microcontroller",
            187:  "Tilera TILE64 multicore architecture family",
            188:  "Tilera TILEPro multicore architecture family",
            190:  "NVIDIA CUDA architecture",
            191:  "Tilera TILE-Gx multicore architecture family",
            192:  "CloudShield architecture family",
            193:  "KIPO-KAIST Core-A 1st generation processor family",
            194:  "KIPO-KAIST Core-A 2nd generation processor family",
            195:  "ARCv2",
            196:  "Open8 8-bit RISC soft processor core",
            197:  "Renesas RL78",
            198:  "Broadcom VideoCore V processor",
            199:  "Renesas 78K0R",
            200:  "Freescale 56800EX Digital Signal Controller (DSC)",
            201:  "Beyond BA1 CPU architecture",
            202:  "Beyond BA2 CPU architecture",
            203:  "XMOS xCORE processor family",
            204:  "Microchip 8-bit PIC(r) family",
            205:  "Intel Graphics Technology",
            210:  "KM211 KM32 32-bit processor",
            211:  "KM211 KMX32 32-bit processor",
            212:  "KM211 KMX16 16-bit processor",
            213:  "KM211 KMX8 8-bit processor",
            214:  "KM211 KVARC processor",
            215:  "Paneve CDP architecture family",
            216:  "Cognitive Smart Memory Processor",
            217:  "Bluechip Systems CoolEngine",
            218:  "Nanoradio Optimized RISC",
            219:  "CSR Kalimba architecture family",
            220:  "Zilog Z80",
            221:  "CDS VISIUMcore processor",
            222:"FTDI Chip FT32",
            223:    "Moxie",
            224:      "AMD GPU",
            243:      "RISC-V",
            244:  "Lanai 32-bit processor",
            245:  "CEVA Processor Architecture Family",
            246:  "CEVA X2 Processor Family",
            247:  "Linux BPF",
            248:  "Graphcore Intelligent Processing Unit",
            249:  "Imagination Technologies",
            250:  "Netronome Flow Processor",
            251:    "NEC Vector Engine",
            252:  "C-SKY",
            253:  "Synopsys ARCv2.3 64-bit",
            254:  "MOS Technology MCS 6502 processor",
            255:  "Synopsys ARCv2.3 32-bit",
            256:  "Kalray VLIW core of the MPPA processor family",
            257:  "WDC 65816/65C816",
            258:  "LoongArch",
            259:  "ChipON KungFu32",
            9520:  "Morpho Techologies MT processor",
            36902:  "Alpha",
            16727:  "Web Assembly",
            23205:  "OpenDLX",
            44357:  "Sanyo XStormy16 CPU core",
            65210:    "Vitesse IQ2000",
            65211:  "Altera Nios",
            61453:    "Toshiba MeP Media Engine",
            4643:  "Adapteva EPIPHANY",
            21569:  "Fujitsu FR-V",
            19951:"Freescale S12Z"}
        if num in machine_dict:
            return machine_dict[num]
        else:
            return "<unknown>: " + str(num)
    
    def _get_class_name(self, elf_class) -> str:
        if elf_class == 1:
            return "32-bit objects"
        elif elf_class == 2:
            return "64-bit objects"
        else:
            return "Unknown: " + str(elf_class)
    
    def _get_data_encoding(self, encoding) -> str:
        if encoding == 0:
            return "none"
        elif encoding == 1:
            return "2's complement, little endian"
        elif encoding == 2:
            return "2's complement, big endian"
        else:
            return "Unknown: " + str(encoding)

    def _get_version(self, version) -> str:
        if version == 1:
            return "1 (current)"
        else:
            return "Unknown: " + str(version)
        
    def _ebl_osabi_name(self, osabi, machine) -> str:
        OS_dict = {0: "UNIX - System V",
                1: "UNIX - HP-UX",
                    2: "UNIX - NetBSD",
                    3: "UNIX - Linux",
                    6: "UNIX - Solaris",
                    7: "UNIX - AIX",
                    8: "UNIX - IRIX",
                    9: "UNIX - FreeBSD",
                    10: "UNIX - Tru64",
                    11: "Novell - Modesto",
                    12: "UNIX - OpenBSD", 
                    13: "VMS - OpenVMS",
                    14: "HP - Non-Stop Kernel",
                    15: "AROS",
                    16: "Fenix OS",
                    17: "Nuxi CloudABI",
                    18: "Stratus Technologies OpenVOS",
                    97: "ARM",
                    255: "Standalone (embedded) application"
                    }
        if osabi in OS_dict:
            return OS_dict[osabi]
        elif machine == 224:
            if osabi == 64:
                return "AMD HSA"
            elif osabi == 65:
                return "AMD PAL"
            elif osabi == 66:
                return "AMD Masa3D"
        elif machine ==40:
            if osabi == 65:
                return "ARM FDPIC"
            elif osabi == 97:
                return "ARM"
        elif machine == 221 and osabi == 225:
            return "Standalone App"
        elif machine == 140:
            if osabi == 64:
                return "Bare-metal C6000"
            elif osabi == 65:
                return "Linux C6000"
        else:
            return "<unknown: " + str(osabi) + ">"

    def _get_file_type(self, type) -> str:
        ET_LOPROC = 0xff00
        ET_HIPROC = 0xffff
        ET_LOOS = 0xfe00
        ET_HIOS = 0xfeff

        if type == 0:
            return "NONE (None)"
        elif type == 1:
            return "REL (Relocatable file)"
        elif type == 2:
            return "EXEC (Executable file)"
        elif type == 3:
            # is_pie = True
            # return "DYN (Position-Independent Executable file)"
            # is_pie = False
            return "DYN (Shared object file)"
        elif type == 4:
            return "CORE (Core file)"

        elif type >= ET_LOPROC and type <= ET_HIPROC:
            return "Processor Specific: (" + str(type) + ")"
        elif type >= ET_LOOS and type <= ET_HIOS:
            return "OS Specific: (" + str(type) + ")"
        else:
            return "Unknown: (" + str(type) + ")"