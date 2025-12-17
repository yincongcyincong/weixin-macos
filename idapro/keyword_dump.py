import ida_bytes
import ida_dbg


def is_printable_string(data):
    if not data:
        return False, ""

    result = ""
    is_str = True
    for byte in data[:-1]:
        if 32 <= byte <= 126:
            result += chr(byte)
        else:
            result += "."
            is_str = False

    return is_str, result


def print_register_struct(reg_name, struct_size=64, max_depth=3):
    # 获取寄存器值
    try:
        reg_value = ida_dbg.get_reg_val(reg_name)
    except:
        print(f"无法读取寄存器 {reg_name}")
        return

    # print(f"寄存器 {reg_name} = 0x{reg_value:X} 结构体大小: {struct_size} 字节 最大深度: {max_depth}")

    if reg_value == 0:
        print("寄存器值为0 (NULL)")
        return

    # 开始递归打印
    print_str(reg_value, struct_size, max_depth, 0)
    print(f"{'=' * 60}")


def print_str(addr, struct_size, max_depth, current_depth):
    """递归打印字符串或指针内容"""
    if current_depth >= max_depth:
        print(f"达到最大递归深度 {max_depth}")
        return

    indent = "  " * current_depth

    try:
        # 尝试读取最多256字节
        max_read = min(256, struct_size)
        data = bytearray()

        for i in range(max_read):
            byte = ida_bytes.get_byte(addr + i)
            data.append(byte)
            if byte == 0:  # 遇到null终止符
                break

        # 检查是否为可打印字符串
        is_str, str_val = is_printable_string(data)

        if is_str and len(str_val) > 0:
            # if str_val.find('http') != -1:
            print(f"0x{addr:X} {indent}字符串: \"{str_val}\"")
        else:
            # 不是字符串，尝试作为指针处理
            try:
                ptr_value = ida_bytes.get_qword(addr)
                # 检查指针是否有效（非空且对齐）
                if ptr_value != 0 and ptr_value % 8 == 0:
                    # 递归检查下一层
                    print_str(ptr_value, struct_size, max_depth, current_depth + 1)
                else:
                    # 显示原始数据
                    print(f"0x{addr:X} {indent}原始数据: {data.hex()}")
            except:
                # 无法读取指针，显示原始数据
                print(f"0x{addr:X} {indent}原始数据: {data.hex()}")

    except Exception as e:
        print(f"{indent}读取地址 0x{addr:X} 失败: {e}")


print_register_struct("X2", 64, 5)
