import struct
from capstone import *

# ELF 文件头结构
ELF64_HEADER_FORMAT = "<16sHHIQQQIHHHHHH"
ELF64_HEADER_SIZE = struct.calcsize(ELF64_HEADER_FORMAT)

# 节头表项结构
ELF64_SECTION_HEADER_FORMAT = "<IIQQQQIIQQ"
ELF64_SECTION_HEADER_SIZE = struct.calcsize(ELF64_SECTION_HEADER_FORMAT)

def parse_elf_header(data):
    """解析 ELF 文件头"""
    header = struct.unpack(ELF64_HEADER_FORMAT, data)
    return {
        "e_shoff": header[6],  # 节头表偏移量
        "e_shnum": header[12], # 节头表项数量
        "e_shstrndx": header[13] # 节名称字符串表索引
    }

def parse_section_header(data):
    """解析节头表项"""
    header = struct.unpack(ELF64_SECTION_HEADER_FORMAT, data)
    return {
        "sh_name": header[0],   # 节名称索引
        "sh_type": header[1],   # 节类型
        "sh_offset": header[4], # 节在文件中的偏移量
        "sh_size": header[5]    # 节的大小
    }

def read_string_table(f, offset, index):
    """从字符串表中读取字符串"""
    f.seek(offset + index)
    name = b""
    while True:
        char = f.read(1)
        if char == b"\x00" or not char:
            break
        name += char
    return name.decode("utf-8")

def extract_text_section(file_path):
    """提取 .text 节的机器代码"""
    with open(file_path, "rb") as f:
        # 读取 ELF 文件头
        elf_header_data = f.read(ELF64_HEADER_SIZE)
        elf_header = parse_elf_header(elf_header_data)

        # 读取节头表
        f.seek(elf_header["e_shoff"])
        section_headers = []
        for _ in range(elf_header["e_shnum"]):
            section_header_data = f.read(ELF64_SECTION_HEADER_SIZE)
            section_headers.append(parse_section_header(section_header_data))

        # 读取节名称字符串表
        shstrtab_header = section_headers[elf_header["e_shstrndx"]]
        shstrtab_offset = shstrtab_header["sh_offset"]

        # 查找 .text 节
        text_section = None
        for section in section_headers:
            name = read_string_table(f, shstrtab_offset, section["sh_name"])
            if name == ".text":
                text_section = section
                break

        if not text_section:
            print("未找到 .text 节")
            return

        # 读取 .text 节的机器代码
        f.seek(text_section["sh_offset"])
        machine_code = f.read(text_section["sh_size"])

        # 输出机器代码
        print(f".text 节偏移量：{hex(text_section['sh_offset'])}")
        print(f".text 节大小：{hex(text_section['sh_size'])}")
        print("机器代码 (十六进制):")
        print(machine_code.hex())

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for (address, size, mnemonic, op_str) in md.disasm_lite(machine_code, text_section['sh_offset']):
            print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

        # 保存到文件
        with open("text_section.bin", "wb") as out_file:
            out_file.write(machine_code)
        print("机器代码已保存到 text_section.bin")

if __name__ == "__main__":
    # 替换为你的 ELF 文件路径
    extract_text_section("elf")