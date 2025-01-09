import subprocess
import os

def assemble_to_machine_code():
    """汇编代码转换为机器码, 使用NASM汇编器."""
    assembly_code = """
    section .data
        msg db "hello world", 10, 0

    section .text
        global _start

    _start:
        ; 调用 write syscall (sys_write: 1)
        mov rax, 1      ; syscall number (write)
        mov rdi, 1      ; stdout file descriptor
        mov rsi, msg    ; string address
        mov rdx, 12     ; string length (including newline)
        syscall

        ; 调用 exit syscall (sys_exit: 60)
        mov rax, 60     ; syscall number (exit)
        mov rdi, 0      ; exit code (0 for normal exit)
        syscall
    """

    # 将汇编代码写入文件
    with open("hello.asm", "w") as f:
        f.write(assembly_code)

    # 使用 NASM 汇编代码
    try:
        subprocess.run(["nasm", "-f", "elf64", "hello.asm", "-o", "hello.o"], check=True)
        subprocess.run(["ld", "hello.o", "-o", "hello"], check=True)
        
        with open("hello", "rb") as f:
           executable_binary = f.read()

        os.remove("hello.asm")
        os.remove("hello.o")
        os.remove("hello")
        
        return executable_binary

    except subprocess.CalledProcessError as e:
        print(f"汇编或链接错误: {e}")
        return None

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
           print(f"程序执行失败, 退出码：{result.returncode}，错误信息：{result.stderr}")
        else:
          print(result.stdout, end="") # 输出到屏幕

    except Exception as e:
      print(f"程序执行过程中出错：{e}")

if __name__ == "__main__":
    machine_code = assemble_to_machine_code()
    if machine_code:
        execute_machine_code(machine_code)