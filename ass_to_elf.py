import subprocess
import os
import struct

def assemble_to_machine_code():
    """手动将简化汇编代码转换为机器码，并添加 ELF 头部"""

    machine_code = b""
    
    # 定义指令的操作码 (部分)
    opcodes = {
        "mov_rax_imm" : b"\x48\xB8", # mov rax, imm
        "mov_rdi_imm" : b"\x48\xBF", # mov rdi, imm
        "lea_rsi_rel" : b"\x48\x8D\x35", # lea rsi, [rel disp]
        "mov_rdx_imm" : b"\x48\xC7\xC2", # mov rdx, imm
        "syscall"     : b"\x0F\x05", # syscall
    }

    # 将字符串数据放入机器码
    data = b"hello world\n\x00"
    
    # 将数据地址放入机器码
    data_address_disp = len(machine_code) + 18 # 计算地址偏移量，因为指令长度 18
    
    # mov rax, 1 ; syscall number (write)
    machine_code += opcodes["mov_rax_imm"] + (1).to_bytes(8, byteorder='little')
    
    # mov rdi, 1 ; stdout file descriptor
    machine_code += opcodes["mov_rdi_imm"] + (1).to_bytes(8, byteorder='little')
    
    # lea rsi, [rel msg]  ; string address
    machine_code += opcodes["lea_rsi_rel"] + data_address_disp.to_bytes(4, byteorder="little",signed=True)
   
    # mov rdx, 12 ; string length
    machine_code += opcodes["mov_rdx_imm"] + (12).to_bytes(4, byteorder="little")

    # syscall
    machine_code += opcodes["syscall"]

    # mov rax, 60 ; syscall number (exit)
    machine_code += opcodes["mov_rax_imm"] + (60).to_bytes(8, byteorder='little')

    # mov rdi, 0 ; exit code (0)
    machine_code += opcodes["mov_rdi_imm"] + (0).to_bytes(8, byteorder='little')

    # syscall
    machine_code += opcodes["syscall"]

    #将字符串放入机器码
    machine_code += data
    
    
    # ---------------------------------------------------------------------
    # 构建 ELF 头部
    
    # ELF 魔数
    elf_magic = b"\x7fELF\x02\x01\x01" 
    # ELF class 64 bit = 0x02
    # ELF data = little endian = 0x01
    # ELF version = 1 = 0x01
    
    # ABI version = 0
    elf_magic += b"\x00"
    
    # padding = 7 bytes of 0
    elf_magic += b"\x00" * 7

    # ELF type: executable = 0x02
    elf_type = struct.pack("<H", 2)

    # ELF machine x86-64 = 0x3E
    elf_machine = struct.pack("<H", 0x2e)

    # ELF version = 1
    elf_version = struct.pack("<I", 1)

    # entry point (入口点地址，代码段起始地址为 0x400000)
    elf_entry_point = struct.pack("<Q", 0x400000)

    # Program header offset, 64 bytes
    elf_phoff = struct.pack("<Q", 64)

    # Section header offset, 0 bytes
    elf_shoff = struct.pack("<Q", 0)

    # Flags
    elf_flags = struct.pack("<I", 0)

    # ELF header size, 64 bytes
    elf_ehsize = struct.pack("<H", 64)
    
    # program header size, 56 bytes
    elf_phentsize = struct.pack("<H", 56)
    
    # Number of program headers, 1
    elf_phnum = struct.pack("<H", 1)
    
    # Section header size, 0 bytes
    elf_shentsize = struct.pack("<H", 0)
    
    # number of section headers = 0
    elf_shnum = struct.pack("<H", 0)
    
    # section name string index, 0
    elf_shstrndx = struct.pack("<H", 0)


    elf_header = (elf_magic + elf_type + elf_machine + elf_version +
                 elf_entry_point + elf_phoff + elf_shoff + elf_flags +
                 elf_ehsize + elf_phentsize + elf_phnum + elf_shentsize +
                 elf_shnum + elf_shstrndx)
    
    # ---------------------------------------------------------------------
    # 构建 Program Header (用于加载程序代码)
    
    # program type (loadable)
    ph_type = struct.pack("<I", 1)
    
    # flags, R+E
    ph_flags = struct.pack("<I", 5)
    
    # program header offset in file (0 bytes)
    ph_offset = struct.pack("<Q", 0)
    
    #虚拟内存地址 = 0x400000
    ph_vaddr = struct.pack("<Q", 0x400000)
    
     # 物理内存地址 = 0x400000
    ph_paddr = struct.pack("<Q", 0x400000)
    
    # file size (代码段的长度)
    ph_filesz = struct.pack("<Q", len(machine_code))
    
    # mem size (内存大小和文件大小相同)
    ph_memsz = struct.pack("<Q", len(machine_code))
    
    # segment alignment
    ph_align = struct.pack("<Q", 0x1000)

    program_header = (ph_type + ph_flags + ph_offset + ph_vaddr +
                     ph_paddr + ph_filesz + ph_memsz + ph_align)
    
    
    
    # 将头部、程序头和机器码拼接
    elf_executable = elf_header + program_header + machine_code
    
    # 为了让程序可以被执行，需要将文件加载的内存起始地址对齐到 4K，0x400000
    # elf_executable = b"\x00" * 0x400000 + elf_executable
  
    
    return elf_executable



def execute_machine_code(machine_code):
    """执行机器码"""
    
    try:
       # 创建一个临时可执行文件
        with open("temp_exe", "wb") as f:
            f.write(machine_code)

        # 给文件添加执行权限
        os.chmod("temp_exe", 0o755)
        
        #执行文件
        result = subprocess.run(["./temp_exe"],capture_output=True, text=True)

        os.remove("temp_exe")

        if result.returncode != 0:
            print(f"程序执行失败，退出码：{result.returncode}，错误信息：{result.stderr}")
        else:
             print(result.stdout, end="") # 输出到屏幕

    except Exception as e:
      print(f"程序执行过程中出错：{e}")

if __name__ == "__main__":
    machine_code = assemble_to_machine_code()
    if machine_code:
        execute_machine_code(machine_code)