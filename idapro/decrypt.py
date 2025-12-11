import idc

# ====================================================================
# 【请务必修改以下参数】
# ====================================================================

# 1. 你想开始执行的代码段的起始地址
# 示例：假设你想从函数 sub_1000 开始执行
START_ADDRESS = 0x1024C6614

# 2. 你想执行的步数（单步执行的次数）
# 例如：执行 5 条指令
STEPS_TO_EXECUTE = 5

# ====================================================================

def execute_code_snippet(start_addr, num_steps):
    # 1. 获取当前线程 ID
    tid = idc.get_current_thread()
    if tid == -1:
        print("[!] 错误：无法获取当前线程 ID。")
        return

    # 2. 设置指令指针 (PC/RIP/EIP) 到起始地址
    # 寄存器名称取决于架构 (ARM64用'PC', x64用'RIP', x86用'EIP')
    architecture = idc.get_inf_attr(idc.INF_PROCNAME)

    if "arm" in architecture.lower():
        pc_reg = "PC"
    elif "x64" in architecture.lower():
        pc_reg = "RIP"
    else: # 默认为 x86
        pc_reg = "EIP"

    print(f"--- 准备执行代码片段 ({architecture}, PC={pc_reg}) ---")

    # 获取当前 PC/RIP/EIP 的值（用于后续打印）
    original_pc = idc.get_reg_value(pc_reg)

    # 设置新的 PC/RIP/EIP 值
    if idc.set_reg_value(start_addr, pc_reg):
        print(f"✅ PC/RIP/EIP 成功设置为起始地址: 0x{start_addr:X}")
    else:
        print(f"[!] 警告：无法设置 PC/RIP/EIP 到 0x{start_addr:X}。请检查地址有效性。")
        return

    # 3. 单步执行指定的步数
    print(f"🚀 开始单步执行 {num_steps} 条指令...")

    for i in range(num_steps):
        # 使用 Step Over (跨过函数调用)
        # 如果需要进入函数，请使用 idc.step_into()
        if not idc.step_over():
            print(f"[!] 警告：第 {i+1} 步执行失败或遇到程序结束。")
            break

        current_pc = idc.get_reg_value(pc_reg)
        disasm = idc.generate_disasm_line(current_pc, 0)

        # 打印当前执行的指令和新的 PC 地址
        print(f"   [Step {i+1}/{num_steps}] -> 0x{current_pc:X}: {disasm}")

    # 4. 执行完毕后的状态
    final_pc = idc.get_reg_value(pc_reg)
    print("----------------------------------------")
    print(f"执行完毕。")
    print(f"起始 PC/RIP/EIP (设置前): 0x{original_pc:X}")
    print(f"当前 PC/RIP/EIP (执行后): 0x{final_pc:X}")
    print(f"📢 **程序处于暂停状态，请手动恢复 (F9) 或检查状态。**")

# ----------------------------------------------------
# 执行主函数
# ----------------------------------------------------
execute_code_snippet(START_ADDRESS, STEPS_TO_EXECUTE)