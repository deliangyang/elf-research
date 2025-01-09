import sys
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str
from capstone import *

def disassemble_elf(filename):
    """
    Disassembles the .text section of an ELF file, similar to 'objdump -d'.
    """
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            
            if not elffile.has_dwarf_info():
                print("No DWARF debug info found. Source code association will not be available.")
            
            # Find the .text section
            text_section = None
            for section in elffile.iter_sections():
                if section.name == '.text':
                    text_section = section
                    break
            
            if text_section is None:
                print("Error: .text section not found.")
                return
                
            # Get text section data and virtual address
            text_data = text_section.data()
            text_vaddr = text_section['sh_addr']
            
            # Determine architecture
            machine = elffile.header['e_machine']
            if machine == 'EM_X86_64':
                arch = CS_ARCH_X86
                mode = CS_MODE_64
            elif machine == 'EM_386':
                arch = CS_ARCH_X86
                mode = CS_MODE_32
            elif machine == 'EM_ARM':
                arch = CS_ARCH_ARM
                mode = CS_MODE_ARM
            elif machine == 'EM_AARCH64':
                arch = CS_ARCH_ARM64
                mode = CS_MODE_ARM
            else:
                print(f"Unsupported architecture: {machine}")
                return
            
            # Initialize Capstone disassembler
            md = Cs(arch, mode)
            
            # Disassemble the code
            print(f"Disassembly of section .text at virtual address {hex(text_vaddr)}:\n")
            for insn in md.disasm(text_data, text_vaddr):
                print(f"  {hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
                
            print("\nELF File Structure (Simplified):")
            print(f"  - Entry point: {hex(elffile.header['e_entry'])}")
            
            # Iterate over Program headers
            if elffile.header['e_type'] == 'ET_EXEC' or elffile.header['e_type'] == 'ET_DYN':
                print("\nProgram Headers:")
                for phdr in elffile.iter_segments():
                   print(f"   - Type: {phdr['p_type']}\n     Offset:{phdr['p_offset']}\n     VirtAddr:{phdr['p_vaddr']}\n     MemSize: {phdr['p_memsz']}\n     Flags: {phdr['p_flags']}\n")

            print("\nSection Headers:")
            for section in elffile.iter_sections():
                print(f"   - Name: {section.name}\n     Address: {hex(section['sh_addr'])}\n     Offset: {section['sh_offset']}\n     Size: {section['sh_size']}\n     Type: {section['sh_type']}\n")

    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
    except Exception as e:
         print(f"Error: {e}")
         

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python script.py <elf_file>")
        sys.exit(1)

    elf_file = sys.argv[1]
    disassemble_elf(elf_file)
