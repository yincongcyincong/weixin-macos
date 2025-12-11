import idc

# -----------------
# 步骤 1: 确定你要读取的 ARM64 寄存器名称
# -----------------
# 注意: 寄存器名称必须是大写字符串，例如 'X0', 'X19', 'PC', 'SP' 等
register_name = 'X0'  # X0 通常用于存放函数返回值或第一个参数

# -----------------
# 步骤 2: 在脚本中调用函数获取值
# -----------------
try:
    # idc.get_reg_value() 只在动态调试且程序暂停时有效
    reg_value = idc.get_reg_value(register_name)

    print(f"程序暂停在断点处。")
    print(f"ARM64 寄存器 **{register_name}** 的当前值为：")
    print(f"十进制: {reg_value}")
    print(f"十六进制: 0x{reg_value:X}")

except Exception as e:
    print("错误：无法读取寄存器值。")
    print("请确保你已：1. 配置并启动了调试器 (Debugger)。2. 程序已运行并暂停在某个断点上。")