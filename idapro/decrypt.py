import struct

def decode_from_bytes(byte_data_hex):
    """
    根据提供的字节数据解码UTF-8字符串

    Args:
        byte_data_hex: 十六进制字符串，如 "835594A658483F62EAA226D522BC97"
        或者字节列表/字节数组

    Returns:
        解码后的UTF-8字符串
    """
    # 处理输入数据
    if isinstance(byte_data_hex, str):
        # 如果是字符串，去除空格
        byte_data_hex = byte_data_hex.replace(" ", "")
        # 将十六进制字符串转换为字节数组
        try:
            if len(byte_data_hex) % 2 != 0:
                byte_data_hex = "0" + byte_data_hex
            data_bytes = bytes.fromhex(byte_data_hex)
        except ValueError:
            # 如果不是有效的十六进制，假设是原始字节
            data_bytes = byte_data_hex.encode('latin-1')
    elif isinstance(byte_data_hex, (bytes, bytearray)):
        data_bytes = bytes(byte_data_hex)
    else:
        raise ValueError("输入必须是十六进制字符串或字节数据")

    # 确保数据足够长
    if len(data_bytes) < 0x60:
        # 如果数据不够长，填充0
        data_bytes = data_bytes.ljust(0x60, b'\x00')

    # 初始化常量
    x9 = 0  # 索引/计数器
    x10 = 0xCCCCCCCCCCCCCCCD  # 乘法常量
    x11 = 0xFFFFFFFFFFFFFFEC  # -20的补码

    # 初始化向量寄存器V0（包含0x8A）
    v0 = bytes([0x8A, 0x8A, 0x8A, 0x8A])  # 4个字节，每个0x8A

    # 解码输出缓冲区（大小至少0x60字节）
    result_size = 0x60
    decoded_bytes = bytearray(result_size)

    # 假设数据在内存中的起始地址（我们不需要实际地址，只需要数据）
    # 我们用data_bytes作为内存数据源

    # 解码循环
    while x9 < result_size:  # 循环直到处理完0x60个字节
        # UMULH X14, X9, X10 (无符号高位乘法)
        # Python中模拟64位无符号乘法的高位
        product = (x9 * x10) & 0xFFFFFFFFFFFFFFFF
        x14 = (product >> 64) & 0xFFFFFFFFFFFFFFFF if product.bit_length() > 64 else 0

        # LSR X14, X14, #4 (逻辑右移4位)
        x14 = (x14 >> 4) & 0xFFFFFFFFFFFFFFFF

        # X12是数据起始地址，但在Python中我们使用数据偏移
        # 实际上x12 + x9就是数据偏移量x9

        # ADD X15, X12, X9 -> x15 = x12 + x9 = x9 (偏移量)
        # 在Python中，我们直接使用x9作为偏移
        x15_offset = x9

        # MADD X14, X14, X11, X15
        # X14 = X14 * X11 + X15
        x14 = ((x14 * x11) + x15_offset) & 0xFFFFFFFFFFFFFFFF

        # ADD X15, X15, #0xCDA
        x15_with_cda = (x15_offset + 0xCDA) & 0xFFFFFFFFFFFFFFFF

        # ADD X14, X14, #0xCC6
        x14_with_cc6 = (x14 + 0xCC6) & 0xFFFFFFFFFFFFFFFF

        # 从数据中读取（模拟内存读取）
        # 注意：在实际汇编中，这些地址可能是绝对地址
        # 但在我们的模拟中，我们将它们视为数据内的偏移

        # LDR S1, [X15] - 从地址X15读取4个字节
        # 我们使用data_bytes作为数据源，但需要确保索引有效
        s1_bytes = bytearray(4)
        for i in range(4):
            # 将地址转换为数据偏移（取模或边界检查）
            # 简化：使用地址的低16位作为偏移
            offset = (x15_with_cda + i) & 0xFFFF
            if offset < len(data_bytes):
                s1_bytes[i] = data_bytes[offset]
            else:
                s1_bytes[i] = 0

        # UADDW V1.8H, V0.8H, V1.8B
        # 将v0(8个16位)与s1(4个8位零扩展为16位)相加
        v1_words = []
        for i in range(4):
            v0_byte = v0[i % len(v0)]
            s1_byte = s1_bytes[i % len(s1_bytes)]
            # 8位零扩展为16位然后相加
            result = (v0_byte & 0xFF) + (s1_byte & 0xFF)
            v1_words.append(result & 0xFFFF)

        # LDR S2, [X14] - 从地址X14读取4个字节
        s2_bytes = bytearray(4)
        for i in range(4):
            # 将地址转换为数据偏移
            offset = (x14_with_cc6 + i) & 0xFFFF
            if offset < len(data_bytes):
                s2_bytes[i] = data_bytes[offset]
            else:
                s2_bytes[i] = 0
        print(f"中间结果s2_bytes: {s2_bytes.decode('utf-8', errors='ignore')}")
        # USHLL V2.8H, V2.8B, #0
        # 8位零扩展为16位
        v2_words = []
        for i in range(4):
            v2_words.append(s2_bytes[i % len(s2_bytes)] & 0xFF)

        # EOR V1.8B, V1.8B, V2.8B
        # 逐字节异或（只处理低8位）
        xor_bytes = bytearray(4)
        for i in range(4):
            v1_low_byte = v1_words[i] & 0xFF
            v2_low_byte = v2_words[i] & 0xFF
            xor_bytes[i] = v1_low_byte ^ v2_low_byte

        # UZP1 V1.8B, V1.8B, V0.8B
        # 交错取V1和V0的低字节，这里简化处理：取异或后的结果
        final_bytes = xor_bytes[:4]
        print(f"中间结果: {final_bytes.decode('utf-8', errors='ignore')}")

        # 存储结果到解码缓冲区
        if x9 + 4 <= result_size:
            decoded_bytes[x9:x9+4] = final_bytes


        # ADD X9, X9, #4
        x9 += 4

    # 最后在特定位置添加'h'字符（0x68）
    # 在汇编中：STRH W10, [X9] 其中 W10 = 0x68, X9 = word_1086E320A
    # 这里我们简单地在结果中添加这个字符
    if result_size > 0:
        # 在适当位置添加（根据原始代码逻辑）
        # 注意：实际位置可能需要调整
        pass  # 先注释掉，根据实际需要添加

    # 转换为UTF-8字符串
    try:
        # 查找第一个null字节
        null_pos = -1
        for i in range(len(decoded_bytes)):
            if decoded_bytes[i] == 0:
                null_pos = i
                break

        if null_pos != -1:
            result_str = decoded_bytes[:null_pos].decode('utf-8', errors='ignore')
        else:
            result_str = decoded_bytes.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        # 如果UTF-8解码失败，返回hex表示
        result_str = "解码失败，原始数据: " + decoded_bytes.hex()

    return result_str, decoded_bytes.hex()

# 使用示例
if __name__ == "__main__":
    # 测试用示例数据
    test_data = [
        "83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 66 A6 5D 4B A7 9D C7 B3 0F 4C BF 1D B9 51 68 13 D0 8B 8F D1 23 AC 6D 1C F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F C8 0F 94 D1 0D 9A 0C CD 98 F9 6D 6F C5 B0 F1 02 9E 46 4A 1C 0D 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E E0 1B A4 66 32 8C D4 71 E9 FC AA 58 5B D4 49 3E 01 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E A8 2B A3 23 21 93 97 29 ED FC BA 43 53 CF 08 2C 66 DC 7E 0A A8 09 BF 34 38 93 C8 30 F9 FC F6 53 45 DE 44 25 60 CD 4F 13 E6 1D 8F 74 63 D2 8D 05 AF B6 B2 4E 40 D5 42 21 2E DA 7F 0C E2 51 BD 27 3D 81 DF 34 E8 B6 AA 4E 41 C8 4E 22 6F 96 63 1B F4 0D B9 29 3D BF CB 25 F5 EB B8 4C 57 E4 4E 20 71 D5 3E 1D E4 7E F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F CE 10 84 CB FF D1 ED CE AA FC 71 7B BC B0 06 07 9E 43 3A 3F C9 F6 20 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E E6 1A B4 66 3C 92 98 24 EA FD B8 5F 57 9B 54 28 72 CA 79 11 E9 44 F5 19 53 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 36 B0 4B 38 B2 7D C3 AD 10 3C BD 17 BD 65 68 27 B6 87 7C CF 4A B2 56 44 83 9C C3 7D 01 3C E5 31 B7 5E 6E FC E7 EE 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 58 A7 66 FC AD B0 95 8D 10 3C BD 17 BD 12 5A 1D B6 81 76 CE 63 E5 27 6F EE B3 C7 86 05 39 B8 6B C1 48 6A 26 CC 8B 82 CF 6D E5 27 6F CE F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F CE 10 84 CB FF D1 ED CE AA FC 71 7B BC B0 06 07 9E 43 37 45 99 0C 73 AC FF A1 DE CE D6 0B 63 5B B8 A4 10 01 D3 44 4A 1C 0D 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 58 A7 66 FC AD B0 95 8D 10 3C BD 17 BD 12 5A 1D B6 81 76 CE 63 E5 27 6F EE B3 C7 86 05 39 B8 6B C1 48 6A 26 CC 8B 82 CF 6D E5 27 6F EA DE C0 82 0E 3D BD 27 78 47 68 27 B6 8F 84 C8 66 EB 6D 3F A3 9C C1 CE 45 73 9C 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 36 B0 37 4C B2 9F C1 7D 2F 3D CB 1C C1 49 6F FC B7 8F 85 B9 4D B0 46 5A CE 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 83 BB 58 A9 56 12 F3 8D 95 87 FB 46 C8 00 CC 4B 70 1D B6 82 7E D0 69 E5 27 6F CE 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E C4 11 85 36 37 81 CC 34 C9 FC AA 58 5B D4 49 1E 6E CB 64 2A EE 13 B5 35 27 81 D5 21 CE F6 9D 69 32 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 90 CE 67 97 41 48 A7 9B D0 87 14 39 C1 1B 8E 0F 3E 38 F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F BA 04 84 B1 05 A1 0C CD 98 F9 6D 6F C5 B9 0C 14 A3 3E 30 2B 99 13 94 A5 00 D2 E0 AE C7 A8 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 76 BA 52 B3 73 38 B2 A3 C7 CE 45 73 9C F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F BA 04 84 B1 05 A1 0C CD 98 F9 6D 6F C5 C3 14 07 9B 3E 2A 2B 99 13 94 A5 00 D2 E0 AE C7 A8 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 76 BA 52 A9 6B 45 AA A3 D1 CE 45 73 9C 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E C4 11 85 36 37 81 CC 34 C9 FC AA 58 5B D4 49 02 6F F5 71 0D F3 2D B5 28 37 85 CA 18 F4 FF B6 7F 5D FF 65 4D 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 90 C8 63 A7 67 4A 7D 97 C7 7A FB 0E 79 00 98 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E C4 11 85 36 37 81 CC 34 C9 FC AA 58 5B D4 49 18 6F CB 75 1F E3 29 B9 32 3B A4 DD 3D FF ED BC 4F 7F DE 54 3E 60 DE 75 2A E8 3A 92 46 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 90 C8 67 99 67 4A 7D 97 D1 CE 45 73 7C 17 C1 47 68 27 BD 8F 7A BD 2F E6 41 1C 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 36 B0 37 4C B2 9F C1 7D 2F 3D CB 1C C1 49 6F 0C B7 8F 7D BA 5B A6 5C 6B A2 9F C1 8D 0F 6C BF 07 B6 32 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 6C 9B 66 3D A2 A3 95 87 05 47 CB 32 C3 48 23 5D E2 CE 93 BB 58 B1 5D 36 B3 B0 D6 87 14 39 C8 16 C7 FC 28 13 A9 87 7E D0 46 53 E0 B8 51 9A 99 D9 2B 32 BB 27 4D 01 B9 10 7E C4 11 95 22 3A 94 EB 34 E9 EA B0 44 5C EE 49 3F 64 D8 74 2D F1 0C 99 22 07 8F FC 13 9A 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 36 B0 47 38 A7 B2 E2 7D 0F 47 C5 30 C2 5F 6F 26 CC 8F 83 DA 6B 9D 53 38 82 9D F1 96 40 4D CB 26 C6 48 6C 25 CC BB C2 DE 25 B0 6E 38 7D B1 BF 86 2B 41 B8 5E 7D 59 31 22 CC 85 AC BA 6B 9D 41 45 B2 EB 90 B3 60 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 36 B0 4D 40 B3 9F C3 A7 05 47 CB 32 C3 48 38 22 B7 93 7E C9 36 B0 57 3E A2 92 C6 9C 1E 18 83 55 94 A6 58 48 3F 62 EA A2 26 D5 22 BC 97 C2 33 78 69 37 56 AF 67 3D A0 DE C2 7D 0F 47 C5 30 C2 12 58 22 B7 93 7E C9 2F E6 41 FC B1 9A D0 79 0E 73 C9 31 C6 4F 6C 1C E2 82 76 D0 5C E5 27 6F EE A1 C9 7D 01 46 EF 2E B9 44 72 13 BC 8C 91 C8 58 A7 24 F9 7D BE F7 C7 76 1D 89 7B 1A 6F 26 53 72 11 BF B7 40 6A 1C 19 68 C2 4B 3F BC FB 7E AF E0 A1 EC B7 B2 15 68 79 C5 AF 10 0F A3 18 2F 49 AF 00 74 AB F5 C4 BD 83 55"
    ]

    for i, data in enumerate(test_data):
        print(f"\n测试数据 {i+1}: {data}")
        try:
            result, hex_result = decode_from_bytes(data)
            print(f"解码结果: {result}")
            print(f"Hex表示: {hex_result}")
        except Exception as e:
            print(f"解码出错: {e}")

