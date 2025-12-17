import ida_dbg
import ida_kernwin
import ida_bytes
import random

# --- 配置 ---
TARGET_FUNC_EA = 0x1006DDE48  # 目标函数的虚拟地址 (EA)
STRUCT_SIZE = 4 * 8  # 4 个 8 字节指针 = 32 字节

# 假设您已经知道这 4 个指针应该指向的目标地址
# 这里的地址应该是目标程序内存中已有的有效地址
PTR1_TARGET_VA = 0x108276190
PTR2_TARGET_VA = 0x1082f6288
PTR3_TARGET_VA = 0x0000600000614820 # 对应内存中的 P3
PTR4_TARGET_VA = 0x0000000032AAAAA7 # 对应内存中的 P4 (如果它是地址的话)

def create_and_set_pointer_arg():
    """在目标进程中创建结构体，并将其地址设置为 X0 参数"""

    # 1. 在目标进程中分配内存 (例如 32 字节)
    # flag 0x01表示分配内存，返回分配内存的起始地址
    struct_addr = ida_dbg.alloc_dealloc_memory(STRUCT_SIZE, 0x01)
    if struct_addr == ida_idaapi.BADADDR:
        ida_kernwin.msg("错误：无法在目标进程中分配内存。")
        return

    ida_kernwin.msg(f"已在 0x{struct_addr:X} 处分配 {STRUCT_SIZE} 字节内存。")

    # 2. 写入 4 个指针的值 (QWORD - 8 字节)
    try:
        ida_bytes.patch_qword(struct_addr + 0, PTR1_TARGET_VA)
        ida_bytes.patch_qword(struct_addr + 8, PTR2_TARGET_VA)
        ida_bytes.patch_qword(struct_addr + 16, PTR3_TARGET_VA)
        ida_bytes.patch_qword(struct_addr + 24, PTR4_TARGET_VA)
        ida_kernwin.msg("已成功写入 4 个指针到新分配的内存。")
    except Exception as e:
        ida_kernwin.msg(f"写入内存失败: {e}")
        ida_dbg.alloc_dealloc_memory(struct_addr, 0) # 清理内存
        return

    # 3. 设置 X0 寄存器为这个结构体的地址
    ida_dbg.set_reg("X0", struct_addr)
    ida_kernwin.msg(f"已设置 X0 = 结构体指针地址: 0x{struct_addr:X}")

    # 返回地址，供后续调用函数使用
    return struct_addr

# --- 完整的调用函数 ---
def remote_call_with_pointer():
    # ... (省略检查和上下文保存代码，与之前相同)

    # 1. 创建并设置指针参数
    arg_x0_ptr = create_and_set_pointer_arg()
    if arg_x0_ptr is None:
        return

    # 2. 设置其他参数 (如果需要)
    # ida_dbg.set_reg("X1", other_arg_value)

    # 3. 执行函数调用 (X0 已经设置完毕)
    ida_dbg.call_user_func(TARGET_FUNC_EA, [], ida_dbg.CUF_WAIT)

    # 4. 获取返回值 (X0)
    return_value = ida_dbg.get_reg("X0")

    # 5. 恢复寄存器上下文 (与之前相同)
    # ...

    # 6. 清理新分配的内存
    ida_dbg.alloc_dealloc_memory(arg_x0_ptr, 0) # flag 0x00表示释放内存
    ida_kernwin.msg(f"已释放分配的内存: 0x{arg_x0_ptr:X}")

    ida_kernwin.msg(f"返回值 (X0): {return_value} (0x{return_value:X})")
    ida_dbg.run_requests()

# remote_call_with_pointer()