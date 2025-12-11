# IDAPython Breakpoint Action Script

import idc
import ida_dbg
import idautils

# ----------------------------------------------------
# 步骤 1: 定义获取和打印堆栈的函数
# ----------------------------------------------------
def print_call_stack():
    """获取当前的调用堆栈地址，并将其打印到 IDA 消息窗口。"""

    # 获取当前线程 ID，通常是获取堆栈的第一步
    tid = idc.get_current_thread()
    if tid == -1:
        print("[!] 脚本错误: 无法获取当前线程 ID。")
        return

    print("=" * 40)
    print(f"✅ 断点触发于地址: 0x{idc.get_screen_ea():X}")
    print(f"➡️ **调用堆栈 (Call Stack) 地址:**")

    # idautils.get_current_caller_frame() 可获取调用堆栈信息
    # 它返回一个列表，其中每个元素都是一个 (返回地址, 帧指针/栈指针) 的元组。

    # 遍历堆栈帧并打印返回地址
    frame_count = 0

    # 注意: 在 64 位 ARM (AArch64) 上，栈操作可能与 x86 不同
    # 我们使用 idautils.get_call_stack 尝试获取更标准的堆栈信息。
    # idautils.get_call_stack() 可能会返回一系列的 (地址, 描述) 元组
    stack_info = ida_dbg.collect_stack_trace()

    if stack_info:
        for frame_count, (return_address, _) in enumerate(stack_info):
            # 获取函数名（如果有的话）
            func_name = idc.get_func_name(return_address)

            # 如果函数名获取失败或地址在外部库，则使用原始地址
            if not func_name or func_name.startswith("loc_"):
                name = ""
            else:
                name = f" <{func_name}>"

            print(f"   [{frame_count:02d}] 0x{return_address:X}{name}")

    else:
        # 如果 idautils.get_call_stack 失败，尝试使用更底层的方法（不推荐，但作为备选）
        # 实际调试中，推荐依赖 IDA 调试器自动提供的堆栈视图。
        print("   [!] 警告: 自动堆栈追踪失败，请检查 IDA Stack View.")

    print(f"   --- 堆栈深度: {frame_count + 1} 层 ---")
    print("=" * 40)


# ----------------------------------------------------
# 步骤 2: 调用主函数
# ----------------------------------------------------
# 在断点被命中时，执行堆栈打印
print_call_stack()

# ----------------------------------------------------
# 步骤 3: 控制程序流 (重要!)
# ----------------------------------------------------
# 要让程序在打印堆栈后继续执行，必须返回 0 或不返回 (即让 IDA 默认继续)。
# 但是，如果希望程序在打印后暂停 (即执行普通断点的动作)，则返回 1 (但这不是本脚本的目的)。
# 如果你想继续执行（Trace Breakpoint），请确保 Action 下一步是 Resume
return 0