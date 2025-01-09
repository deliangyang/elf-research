import struct

# ELF 文件头结构
ELF64_HEADER_FORMAT = "<16sHHIQQQIHHHHHH"
ELF64_HEADER_SIZE = struct.calcsize(ELF64_HEADER_FORMAT)

# 程序头表项结构
ELF64_PROGRAM_HEADER_FORMAT = "<IIQQQQQQ"
ELF64_PROGRAM_HEADER_SIZE = struct.calcsize(ELF64_PROGRAM_HEADER_FORMAT)

# 节头表项结构
ELF64_SECTION_HEADER_FORMAT = "<IIQQQQIIQQ"
ELF64_SECTION_HEADER_SIZE = struct.calcsize(ELF64_SECTION_HEADER_FORMAT)

# ELF 文件类型
ELF_TYPE = {
    0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"
}

# ELF 机器类型
ELF_MACHINE = {
    0x3E: "x86-64"
}

# 程序头表类型
PROGRAM_HEADER_TYPE = {
    0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE"
}

# 节头表类型
SECTION_HEADER_TYPE = {
    0: "SHT_NULL", 1: "SHT_PROGBITS", 2: "SHT_SYMTAB", 3: "SHT_STRTAB"
}

def parse_elf_header(data):
    """解析 ELF 文件头"""
    header = struct.unpack(ELF64_HEADER_FORMAT, data)
    return {
        "e_ident": header[0],
        "e_type": ELF_TYPE.get(header[1], "UNKNOWN"),
        "e_machine": ELF_MACHINE.get(header[2], "UNKNOWN"),
        "e_version": header[3],
        "e_entry": header[4],
        "e_phoff": header[5],
        "e_shoff": header[6],
        "e_flags": header[7],
        "e_ehsize": header[8],
        "e_phentsize": header[9],
        "e_phnum": header[10],
        "e_shentsize": header[11],
        "e_shnum": header[12],
        "e_shstrndx": header[13]
    }

def parse_program_header(data):
    """解析程序头表项"""
    header = struct.unpack(ELF64_PROGRAM_HEADER_FORMAT, data)
    return {
        "p_type": PROGRAM_HEADER_TYPE.get(header[0], "UNKNOWN"),
        "p_flags": header[1],
        "p_offset": header[2],
        "p_vaddr": header[3],
        "p_paddr": header[4],
        "p_filesz": header[5],
        "p_memsz": header[6],
        "p_align": header[7]
    }

def parse_section_header(data):
    """解析节头表项"""
    header = struct.unpack(ELF64_SECTION_HEADER_FORMAT, data)
    return {
        "sh_name": header[0],
        "sh_type": SECTION_HEADER_TYPE.get(header[1], "UNKNOWN"),
        "sh_flags": header[2],
        "sh_addr": header[3],
        "sh_offset": header[4],
        "sh_size": header[5],
        "sh_link": header[6],
        "sh_info": header[7],
        "sh_addralign": header[8],
        "sh_entsize": header[9]
    }

def read_elf_file(file_path):
    """读取并解析 ELF 文件"""
    with open(file_path, "rb") as f:
        # 读取 ELF 文件头
        elf_header_data = f.read(ELF64_HEADER_SIZE)
        elf_header = parse_elf_header(elf_header_data)
        print("ELF Header:")
        for key, value in elf_header.items():
            print(f"{key}: {value}")

        # 读取程序头表
        f.seek(elf_header["e_phoff"])
        print("\nProgram Headers:")
        for i in range(elf_header["e_phnum"]):
            program_header_data = f.read(ELF64_PROGRAM_HEADER_SIZE)
            program_header = parse_program_header(program_header_data)
            print(f"Program Header {i}:")
            for key, value in program_header.items():
                print(f"  {key}: {value}")

        # 读取节头表
        f.seek(elf_header["e_shoff"])
        print("\nSection Headers:")
        for i in range(elf_header["e_shnum"]):
            section_header_data = f.read(ELF64_SECTION_HEADER_SIZE)
            section_header = parse_section_header(section_header_data)
            print(f"Section Header {i}:")
            for key, value in section_header.items():
                print(f"  {key}: {value}")

if __name__ == "__main__":
    # 替换为你的 ELF 文件路径
    read_elf_file("elf")