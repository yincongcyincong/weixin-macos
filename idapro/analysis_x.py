import ida_dbg
import ida_bytes
import json

def is_printable_string(data):
    """检查是否是可打印字符串"""
    if not data:
        return False, ""

    # 检查是否以null结尾
    if data[-1] != 0:
        return False, ""

    # 检查所有字符是否可打印
    result = ""
    for byte in data[:-1]:  # 排除结尾的null
        if 32 <= byte <= 126:  # 可打印ASCII
            result += chr(byte)
        else:
            return False, ""

    return True, result

def dereference_recursive(traceMap, addr, struct_size, depth=0, max_depth=5):
    """
    递归解引用指针并打印内容
    :param addr: 地址值
    :param struct_size: 结构体大小（字节）
    :param depth: 当前递归深度
    :param max_depth: 最大递归深度
    """
    mapAddr = f"0x{addr:016X}"
    print(f"mapAddr: {mapAddr}")
    traceMap[mapAddr] = {}
    if depth >= max_depth:
        print("  " * depth + f"[达到最大递归深度 {max_depth}]")
        return

    if addr == 0:
        print("  " * depth + f"[NULL 指针]")
        return

    indent = "  " * depth
    ptr_size = 8

    print(f"{indent}层级 {depth}: 地址 0x{addr:X}")

    # 尝试读取字符串
    try:
        # 尝试读取最多256字节
        max_read = min(256, struct_size)
        data = bytearray()
        for i in range(max_read):
            byte = ida_bytes.get_byte(addr + i)
            data.append(byte)
            if byte == 0:  # 遇到null终止符
                break

        is_str, str_val = is_printable_string(data)
        if is_str and len(str_val) > 0:
            data[addr][str_val] = {}
            print(f"{indent}字符串: \"{str_val}\"")
            return
    except:
        pass

    # 打印原始内存内容（前64字节）
    try:
        bytes_to_show = min(64, struct_size)
        print(f"{indent}内存内容 ({bytes_to_show} 字节):")

        hex_line = indent + "  "
        ascii_line = indent + "  "

        for i in range(bytes_to_show):
            if i > 0 and i % 16 == 0:
                print(f"{hex_line}  {ascii_line}")
                hex_line = indent + "  "
                ascii_line = indent + "  "

            byte = ida_bytes.get_byte(addr + i)
            hex_line += f"{byte:02X} "
            ascii_line += chr(byte) if 32 <= byte <= 126 else "."

        # 打印最后一行
        if hex_line.strip():
            print(f"{hex_line:50}  {ascii_line}")
    except Exception as e:
        print(f"{indent}读取内存失败: {e}")
        return

    print(f"ptr_size {ptr_size} struct_size {struct_size}")
    # 检查是否可能是指针数组
    if struct_size >= ptr_size:
        # 如果 ptr_size < struct_size，则连续读取多个 QWORD
        ptr_count = struct_size // ptr_size     # 能读取多少个 qword
        for i in range(ptr_count):
            cur_addr = addr + i * ptr_size

            try:
                ptr_value = ida_bytes.get_qword(cur_addr)
                print(f"{indent}指针[{i}] @ 0x{cur_addr:X} -> 0x{ptr_value:X}")
                if ptr_value != 0 and ptr_value != cur_addr:
                    print(f"{indent}可能是指针，指向: 0x{ptr_value:X}")

                    nextAddr = f"0x{ptr_value:016X}"
                    print(f"nextAddr: {nextAddr}")
                    traceMap[mapAddr][nextAddr] = {}
                    dereference_recursive(traceMap[mapAddr], ptr_value, struct_size, depth + 1, max_depth)

            except Exception as e:
                print(f"{indent}读取失败: 0x{cur_addr:X}, err={e}")
                continue

def print_register_struct(reg_name, struct_size=64, max_depth=3):
    """
    打印寄存器内容（递归解引用）
    :param reg_name: 寄存器名称（如 "X0", "RAX"）
    :param struct_size: 假设的结构体大小
    :param max_depth: 最大递归深度
    """
    print(f"\n{'='*60}")
    print(f"分析寄存器: {reg_name}")
    print(f"结构体大小: {struct_size} 字节")
    print(f"{'='*60}")

    traceMap = {}
    try:
        # 获取寄存器值
        reg_value = ida_dbg.get_reg_val(reg_name)
        print(f"寄存器 {reg_name} = 0x{reg_value:X} ({reg_value})")

        if reg_value == 0:
            print("寄存器值为0 (NULL)")
            return

        # 递归分析
        dereference_recursive(traceMap, reg_value, struct_size, 0, max_depth)

    except Exception as e:
        print(f"错误: {e}")
    print(json.dumps(traceMap, indent=4))


# =========== 使用示例函数 ===========

# def example_usage():
#     """使用示例 - 在断点处调用这些函数"""

    # 示例1: 分析X0寄存器（ARM64）
    # print_register_struct("X0", 64, 3)

    # 示例2: 分析RCX寄存器（x64）
    # print_register_struct("RCX", 32, 2)

    # 示例3: 分析特定大小的结构
    # print_register_struct("X1", 128, 4)

# =========== 常用快捷函数 ===========

# def analyze_args_arm64():
#     """分析ARM64的前4个参数寄存器"""
#     print("\n分析ARM64函数参数:")
#     for i, reg in enumerate(["X0", "X1", "X2", "X3"]):
#         print(f"\n--- 参数 {i+1} ({reg}) ---")
#         print_register_struct(reg, 64, 2)
#
#
# def analyze_all_args(struct_size=64, max_depth=2):
#     """根据架构分析所有参数寄存器"""
#     regs = ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]
#
#     print(f"\n分析函数参数 ({inf.procname}):")
#     for reg in regs:
#         try:
#             value = ida_dbg.get_reg_val(reg)
#             if value != 0:
#                 print(f"\n--- 寄存器 {reg} (0x{value:X}) ---")
#                 print_register_struct(reg, struct_size, max_depth)
#         except:
#             pass

# =========== 如何在断点中使用 ===========

"""
使用方法：
1. 在IDA中设置断点
2. 断点触发时，打开Python控制台
3. 调用以下任一函数：

# 分析单个寄存器
# print_register_struct("X0", 64, 3)

# 或分析所有参数
analyze_all_args()

# 或直接运行示例
example_usage()
"""

print_register_struct("X0", 64, 3)