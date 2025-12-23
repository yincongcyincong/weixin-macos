import time

import ida_bytes
import idc


def get_varint_timestamp_bytes():
    """
    获取当前时间戳并编码为 Protobuf Varint 字节流 (bytes类型)
    """
    ts = int(time.time())
    encoded_bytes = bytearray()
    temp_ts = ts & 0xFFFFFFFF  # 32位无符号整数
    while True:
        byte = temp_ts & 0x7F
        temp_ts >>= 7
        if temp_ts:
            encoded_bytes.append(byte | 0x80)
        else:
            encoded_bytes.append(byte)
            break
    return bytes(encoded_bytes)


def run_patch_script():
    # --- 1. 设置目标空内存地址 ---
    x1_addr = idc.get_reg_value("X1")
    print(f"[*] 原始 X1 指向地址: {hex(x1_addr)}")

    # --- 2. 构造 Payload ---
    # 前缀部分
    payload = (
        b"\x08\x01\x12\x5E\x0A\x15\x0A\x13"  # 0x00 第一个字段头部 + 接收人id头部
        b"\x77\x78\x69\x64\x5F\x37\x77\x64"  # 0x08 (接收人id wxid_xxxx)
        b"\x31\x65\x63\x65\x39\x39\x66\x37"  # 0x10 (接收人id wxid_xxxx)
        b"\x69\x32\x31\x12\x03\x38\x38\x38"  # 0x18 (接收人id wxid_xxxx + 第二个字段头部 + 字符串长度+字符串内容)
        b"\x18\x01\x20"  # 0x20 (第三个字段时间戳头部+时间戳)
    )

    # 动态插入时间戳 (bytes + bytes)
    payload += get_varint_timestamp_bytes()

    # 后缀部分
    payload += (
        b"\x28\xD1\xF7\xA6\xE6\x0c"  # (某个id的头部和值)
        b"\x32\x32\x3C"  # 0x28 (第四个字段时间戳头部)
        b"\x6D\x73\x67\x73\x6F\x73\x75\x72"  # 0x30 (msgsour)
        b"\x63\x65\x3E\x3C\x61\x6C\x6E\x6F"  # 0x38 (ce><alno)
        b"\x64\x65\x3E\x3C\x66\x72\x3E\x31"  # 0x40 (de><fr>1)
        b"\x3C\x2F\x66\x72\x3E\x3C\x2F\x61"  # 0x48 (</fr></a)
        b"\x6C\x6E\x6F\x64\x65\x3E\x3C\x2F"  # 0x50 (lnode></)
        b"\x6D\x73\x67\x73\x6F\x73\x75\x72"  # 0x58 (msgsour)
        b"\x63\x65\x3E\x00"  # 0x60 (ce>.)
    )

    # --- 4. 写入内存 ---
    # 使用 ida_bytes.patch_bytes 写入完整 payload
    ida_bytes.patch_bytes(x1_addr, payload)

    # --- 5. 设置寄存器 ---
    # 将 X1 指向我们刚刚填充好的内存地址
    if idc.set_reg_value(x1_addr, "X1"):
        print(f"[*] 成功: 数据已写入 {hex(x1_addr)}")
    else:
        print("[-] 错误: 无法设置 X1 寄存器，请检查寄存器名称。")


# 启动脚本
run_patch_script()
