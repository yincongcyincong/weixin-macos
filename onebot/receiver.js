var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

function setReceiver() {
    var buf2RespAddr = baseAddr.add(0x347BD44);
    console.log("[+] buf2RespAddr WeChat Base: " + baseAddr + "[+] Attaching to: " + buf2RespAddr);

    // 3. 开始拦截
    Interceptor.attach(buf2RespAddr, {
        onEnter: function (args) {

            const currentPtr = this.context.x1;
            let start = 0x1e;
            let senderLen = currentPtr.add(start).readU8();
            if (senderLen !== 0x14 && senderLen !== 0x13) {
                start = 0x1d;
                let senderLen = currentPtr.add(start).readU8();
                if (senderLen !== 0x14 && senderLen !== 0x13) {
                    return
                }
            }

            const x2 = this.context.x2.toInt32();
            const fields = getProtobufRawBytes(currentPtr, x2)
            console.log(JSON.stringify(fields));


            //
            // console.log("[+] Entered Receive Function: 0x1023B5348");
            //
            // let senderPtr = currentPtr.add(start + 1);
            // let sender = senderPtr.readUtf8String(senderLen);
            //
            // let receiverLenPtr = senderPtr.add(senderLen).add(3);
            // let receiverLen = receiverLenPtr.readU8();
            // let receiverStrPtr = receiverLenPtr.add(1);
            // let receiver = receiverStrPtr.readUtf8String(receiverLen);
            //
            // let contentLenPtr = receiverStrPtr.add(receiverLen).add(6);
            // // 判断是否等于 0x77 ('w'), 如果是，则是短字段
            // if (isPrintableOrChinese(contentLenPtr, 1)) {
            //     contentLenPtr = contentLenPtr.add(-1);
            // }
            // const contentLenValue = readVarint(contentLenPtr)
            // let contentPtr = contentLenPtr.add(contentLenValue.byteLength);
            // var content = contentPtr.readUtf8String(contentLenValue.value);
            //
            // var selfId = receiver
            // var msgType = "private"
            // var groupId = ""
            // var senderUser = sender
            // var messages = [];
            // messages.push({type: "text", data: {text: content}});
            //
            // if (sender.includes("@chatroom")) {
            //     msgType = "group"
            //     groupId = sender
            //     let splitIndex = -1;
            //     for (let i = 0; i < content.length; i++) {
            //         if (content[i] === ':') {
            //             splitIndex = i;
            //             break;
            //         }
            //     }
            //
            //     senderUser = content.substring(0, splitIndex).trim();
            //     content = content.substring(splitIndex + 2).trim();
            //
            //     messages = [];
            //     const parts = content.split('\u2005');
            //     for (let part of parts) {
            //         part = part.trim();
            //         if (!part.startsWith("@")) {
            //             messages.push({type: "text", data: {text: part}});
            //         }
            //     }
            //
            //     const xmlPtr = contentPtr.add(contentLenValue.value).add(15);
            //     const xmlLenValue = readVarint(xmlPtr)
            //     const xml = xmlPtr.add(xmlLenValue.byteLength).readUtf8String(xmlLenValue.value);
            //     const atUserMatch = xml.match(/<atuserlist>([\s\S]*?)<\/atuserlist>/);
            //     const atUser = atUserMatch ? atUserMatch[1] : null;
            //     if (atUser) {
            //         messages.push({type: "at", data: {qq: atUser}});
            //     }
            // }
            //
            // send({
            //     message_type: msgType,
            //     user_id: senderUser, // 发送人的 ID
            //     self_id: selfId, // 接收人的 ID
            //     group_id: groupId, // 群 ID
            //     message_id: generateAESKey(),
            //     type: "send",
            //     raw: {peerUid: generateAESKey()},
            //     message: messages
            // })
        },
    });
}

// 使用 setImmediate 确保在模块加载后执行
setImmediate(setReceiver)

function readVarint(addr) {
    let value = 0;
    let shift = 0;
    let count = 0;

    while (true) {
        let byte = addr.add(count).readU8();
        // 取低7位进行累加
        value |= (byte & 0x7f) << shift;
        count++; // 消耗了一个字节

        // 如果最高位是0，跳出循环
        if ((byte & 0x80) === 0) break;

        shift += 7;
        if (count > 5) return -1; // 安全校验，防止死循环
    }

    return {
        value: value,      // 最终长度数值 (例如 251)
        byteLength: count  // 长度字段占用的字节数 (例如 2)
    };
}

function isPrintableOrChinese(startPtr, maxScanLength) {
    let offset = 0;
    while (offset < maxScanLength) {
        let b = startPtr.add(offset).readU8();

        if (b === 0) {
            // 扫描到 \0，且之前没有发现异常字节
            return offset > 0; // 如果第一个就是 \0，视为非字符串（可能是空指针）
        }

        // 判定逻辑：
        // 1. 可见 ASCII (32-126) 或 换行/制表符 (9, 10, 13)
        let isAscii = (b >= 32 && b <= 126) || (b === 9 || b === 10 || b === 13);

        // 2. 汉字 UTF-8 特征：第一个字节通常 >= 0x80 (128)
        // 严谨点：UTF-8 汉字首字节通常在 0xE4-0xE9 之间，后续字节在 0x80-0xBF 之间
        // 这里简化处理：如果是高位字符，我们暂时放行，由 readUtf8String 最终处理
        let isHighBit = (b >= 0x80);

        if (!isAscii && !isHighBit) {
            // 发现既不是 ASCII 也不是高位字节（如 0x01-0x1F 的控制字符），判定为指针
            return false;
        }
        offset++;
    }
    return true;
}

function generateAESKey() {
    const chars = 'abcdef0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}


function getProtobufRawBytes(pBuffer, scanSize) {
    const tags = [0x12, 0x1A, 0x2A, 0x52];
    let uint8Array;

    try {
        const mem = pBuffer.readByteArray(scanSize);
        if (!mem) return [];
        uint8Array = new Uint8Array(mem);
    } catch (e) {
        console.error("读取内存失败: " + e);
        return [];
    }

    let finalResults = [];

    let i = 0x1b;
    tags.forEach(targetTag => {
        let found = false;
        for (; i < uint8Array.length; i++) {
            if (uint8Array[i] === targetTag) {
                // 1. 解析 Varint 长度 (支持 1-5 字节长度标识)
                let length = 0;
                let shift = 0;
                let bytesReadForLen = 0;
                i = i + 1;

                while (i < uint8Array.length) {
                    let b = uint8Array[i];
                    length |= (b & 0x7F) << shift;
                    bytesReadForLen++;
                    i++;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }

                // 2. 截取原始 Byte 数据
                if (i + length <= uint8Array.length) {
                    let rawData = uint8Array.slice(i, i + length);
                    finalResults.push(getCleanString(rawData));
                    i += length;
                } else {
                    finalResults.push(null); // 长度越界
                }

                found = true;
                break; // 找到第一个匹配的 Tag 就跳出
            }
        }
        if (!found) finalResults.push(null); // 未找到该 Tag
    });

    return finalResults;
}

function getCleanString(uint8Array) {
    var out = "";
    var i = 0;
    var len = uint8Array.length;

    while (i < len) {
        var c = uint8Array[i++];

        // 1. 处理单字节 (ASCII: 0xxxxxxx)
        if (c < 0x80) {
            // 只保留可见字符 (Space 32 到 ~ 126)
            if (c >= 32 && c <= 126) {
                out += String.fromCharCode(c);
            }
        }
        // 2. 处理双字节 (110xxxxx 10xxxxxx)
        else if ((c & 0xE0) === 0xC0 && i < len) {
            var c2 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80) {
                // 这种通常是特殊拉丁字母等，按需保留
                var charCode = ((c & 0x1F) << 6) | (c2 & 0x3F);
                out += String.fromCharCode(charCode);
            }
        }
        // 3. 处理三字节 (1110xxxx 10xxxxxx 10xxxxxx) -> 绝大多数汉字在此
        else if ((c & 0xF0) === 0xE0 && i + 1 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80) {
                var charCode = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
                // 判断是否在汉字区间
                if (charCode >= 0x4E00 && charCode <= 0x9FA5 || charCode === 0x2005) {
                    out += String.fromCharCode(charCode);
                }
            }
        }
        else if ((c & 0xF8) === 0xF0 && i + 2 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            var c4 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80 && (c4 & 0xC0) === 0x80) {
                // 计算 Unicode 码点
                var codePoint = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);

                // Emoji 范围通常在 U+1F000 到 U+1F9FF 之间
                if (codePoint >= 0x1F000 && codePoint <= 0x1FADF) {
                    // 使用 fromCodePoint 处理 4 字节字符
                    out += String.fromCodePoint(codePoint);
                }
            }
        }
    }
    return out;
}