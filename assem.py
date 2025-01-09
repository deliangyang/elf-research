import re

# Token 类型
TOKENS = [
    ('INT', r'int'),
    ('PRINT', r'print'),
    ('ID', r'[a-zA-Z_][a-zA-Z0-9_]*'),
    ('NUMBER', r'\d+'),
    ('ASSIGN', r'='),
    ('SEMICOLON', r';'),
    ('LPAREN', r'\('),
    ('RPAREN', r'\)'),
    ('SKIP', r'[ \t\n]'),  # 跳过空格和换行
]

def lex(code):
    tokens = []
    while code:
        for token_type, pattern in TOKENS:
            match = re.match(pattern, code)
            if match:
                value = match.group(0)
                if token_type != 'SKIP':
                    tokens.append((token_type, value))
                code = code[match.end():]
                break
        else:
            raise SyntaxError(f"Invalid token: {code}")
    return tokens


# AST 节点
class VarDecl:
    def __init__(self, name, value):
        self.name = name
        self.value = value

class Print:
    def __init__(self, value):
        self.value = value

def parse(tokens):
    ast = []
    i = 0
    while i < len(tokens):
        token_type, value = tokens[i]
        if token_type == 'INT':
            name = tokens[i+1][1]
            val = int(tokens[i+3][1])
            ast.append(VarDecl(name, val))
            i += 5  # int x = 10;
        elif token_type == 'PRINT':
            val = tokens[i+2][1]
            ast.append(Print(val))
            i += 4  # print(x);
        else:
            raise SyntaxError(f"Unexpected token: {tokens[i]}")
    return ast


def generate_machine_code(ast):
    machine_code = []

    # ELF 文件头
    elf_header = [
        0x7F, 0x45, 0x4C, 0x46,  # ELF magic number
        0x01,                    # 32-bit
        0x01,                    # Little-endian
        0x01,                    # ELF version
        0x00,                    # OS ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Padding
        0x02, 0x00,              # Executable file
        0x03, 0x00,              # x86
        0x01, 0x00, 0x00, 0x00,  # ELF version
        0x54, 0x00, 0x00, 0x00,  # Entry point address
        0x34, 0x00, 0x00, 0x00,  # Program header offset
        0x00, 0x00, 0x00, 0x00,  # Section header offset
        0x00, 0x00, 0x00, 0x00,  # Flags
        0x34, 0x00,              # ELF header size
        0x20, 0x00,              # Program header size
        0x01, 0x00,              # Number of program headers
        0x00, 0x00,              # Section header size
        0x00, 0x00,              # Number of section headers
        0x00, 0x00,              # Section header string table index
    ]

    # 程序头
    program_header = [
        0x01, 0x00, 0x00, 0x00,  # Loadable segment
        0x00, 0x00, 0x00, 0x00,  # Offset
        0x54, 0x00, 0x00, 0x00,  # Virtual address
        0x00, 0x00, 0x00, 0x00,  # Physical address
        0x1B, 0x00, 0x00, 0x00,  # File size
        0x1B, 0x00, 0x00, 0x00,  # Memory size
        0x05, 0x00, 0x00, 0x00,  # Flags (read and execute)
        0x00, 0x10, 0x00, 0x00,  # Alignment
    ]

    # 机器码
    for node in ast:
        if isinstance(node, VarDecl):
            # mov eax, value
            machine_code.extend([0xB8, node.value & 0xFF, (node.value >> 8) & 0xFF, (node.value >> 16) & 0xFF, (node.value >> 24) & 0xFF])
        elif isinstance(node, Print):
            # int 0x80 (syscall: write)
            machine_code.extend([0xCD, 0x80])

    # 退出系统调用
    machine_code.extend([0xB8, 0x01, 0x00, 0x00, 0x00])  # mov eax, 1 (exit)
    machine_code.extend([0xBB, 0x00, 0x00, 0x00, 0x00])  # mov ebx, 0 (status)
    machine_code.extend([0xCD, 0x80])                    # int 0x80

    # 合并 ELF 头和机器码
    return bytes(elf_header + program_header + machine_code)


def generate_executable(machine_code, output_file):
    with open(output_file, "wb") as f:
        f.write(machine_code)
    import os
    os.chmod(output_file, 0o755)  # 设置为可执行文件


if __name__ == '__main__':
    code = """
int x = 10;
print(x)
"""

    tokens = lex(code)
    ast = parse(tokens)
    machine_code = generate_machine_code(ast)
    generate_executable(machine_code, "output")