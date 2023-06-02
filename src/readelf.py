from os import abort
import argparse
import struct
import json
# refference: binutils
from pprint import pprint

from elfheader import ELFHeader
from programheader import ProgramHeader
from sectionheader import SectionHeader
from symboltable import SymbolTable
            
def print_raw_head(elf, length) -> None:
    print("Output" + str(length) + "bytes of raw data:")
    output = struct.unpack("B"*length, elf.read(length))
    for i in range(length):
        print("%02x" % output[i], end=" ")
    print("\n")
    
def main(elf, args) -> None:
    if args.file_header:
        header = ELFHeader(elf)
        header.print_elf_header()
    if args.program_headers:
        programHeader = ProgramHeader(elf)
        programHeader.print_program_header()
    if args.section_headers:   
        sectionHeader = SectionHeader(elf)
        sectionHeader.print_section_header()
    if args.symbols:
        st = SymbolTable(elf)
        st.print_symbol_table()
    if args.export:
        header = ELFHeader(elf)
        programHeader = ProgramHeader(elf)
        sectionHeader = SectionHeader(elf)
        symbolTable = SymbolTable(elf)
        export = {}
        export = export | header.export_elf_header()
        export = export | programHeader.export_program_header()
        export = export | sectionHeader.export_section_header()
        export = export | symbolTable.export_symbol_table()
        with open(args.export, "w") as f:
            json.dump(export, f, indent=4)
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-eh", "--file-header", help="Display the ELF file header", action="store_true")
    parser.add_argument("-l", "--program-headers", help="Display the program headers", action="store_true")
    parser.add_argument("-S", "--section-headers", help="Display the sections' header", action="store_true")
    parser.add_argument("-e", "--headers", help="Display all headers", action="store_true")
    parser.add_argument("-s", "--symbols", help="Display the symbol table", action="store_true")
    parser.add_argument("--export", metavar="PATH", help="Export the headers to a JSON file")
    parser.add_argument("file", help="The file to read")
    args = parser.parse_args()
    
    if args.headers:
        args.file_header = True
        args.program_headers = True
        args.section_headers = True
    
    with open(args.file, 'rb') as elf:
        main(elf, args)