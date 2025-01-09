import ctypes
import mmap

class JITCompiler:
    def __init__(self):
        self.memory = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)

    def compile(self, code):
        # 生成机器码（这里以 x86 汇编为例）
        if code.startswith("var"):
            # 例如：var x = 10;
            parts = code.split()
            print(parts)
            value = int(parts[3])
            machine_code = self.generate_machine_code(value)
        else:
            raise NotImplementedError(f"JIT compilation not supported for: {code}")

        # 将机器码写入内存
        self.memory.write(machine_code)
        self.memory.seek(0)

        # 执行机器码
        func = ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(ctypes.c_char.from_buffer(self.memory)))
        result = func()
        print(f"JIT compiled result: {result}")

    def generate_machine_code(self, value):
        # 生成简单的 x86 机器码：返回一个常量值
        # mov eax, value; ret
        return b"\xB8" + value.to_bytes(4, "little") + b"\xC3"
    

class Interpreter:
    def __init__(self):
        self.vars = {}  # 存储变量
        self.jit = JITCompiler()  # JIT 编译器
        self.hot_code = {}  # 记录热点代码

    def run(self, code):
        for line in code.splitlines():
            if not line.strip():
                continue
            self.execute(line)

    def execute(self, line):
        # 解释执行代码
        if line.startswith("var"):
            self.execute_var(line)
        elif line.startswith("print"):
            self.execute_print(line)
        else:
            raise SyntaxError(f"Unknown statement: {line}")

        # 检测热点代码
        self.hot_code[line] = self.hot_code.get(line, 0) + 1
        if self.hot_code[line] > 0:  # 如果某行代码执行超过 3 次，触发 JIT 编译
            self.jit.compile(line)

    def execute_var(self, line):
        parts = line.split()
        name = parts[1]
        value = eval(parts[3], {}, self.vars)  # 支持表达式
        self.vars[name] = value

    def execute_print(self, line):
        var_name = line.split("(")[1].split(")")[0]
        print(self.vars[var_name])


if __name__ == "__main__":
    code = """
var x = 10
var y = x + 5
print(y)
"""
    interpreter = Interpreter()
    interpreter.run(code)