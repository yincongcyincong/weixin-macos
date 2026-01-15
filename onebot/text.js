// 1. 获取微信主模块的基地址
var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

// -------------------------基础函数分区-------------------------
function toVarint(n) {
    let res = [];
    while (n >= 128) {
        res.push((n & 0x7F) | 0x80); // 取后7位，最高位置1
        n = n >> 7;                 // 右移7位
    }
    res.push(n); // 最后一位最高位为0
    return res;
}


function stringToHexArray(str) {
    var utf8Str = unescape(encodeURIComponent(str));
    var arr = [];
    for (var i = 0; i < utf8Str.length; i++) {
        arr.push(utf8Str.charCodeAt(i)); // 获取字符的 ASCII 码 (即十六进制值)
    }
    return arr;
}


function generateRandom5ByteVarint() {
    let res = [];

    // 前 4 个字节：最高位(bit 7)必须是 1，低 7 位随机
    for (let i = 0; i < 4; i++) {
        let random7Bit = Math.floor(Math.random() * 128);
        res.push(random7Bit | 0x80); // 强制设置最高位为 1
    }

    // 第 5 个字节：最高位必须是 0，为了确保不变成 4 字节，低 7 位不能全为 0
    let lastByte = Math.floor(Math.random() * 127) + 1;
    res.push(lastByte & 0x7F); // 确保最高位为 0

    return res;
}


// 辅助函数：Protobuf Varint 编码 (对应 get_varint_timestamp_bytes)
function getVarintTimestampBytes() {
    let ts = Math.floor(Date.now() / 1000);
    let encodedBytes = [];
    let tempTs = ts >>> 0; // 强制转为 32位 无符号整数

    while (true) {
        let byte = tempTs & 0x7F;
        tempTs >>>= 7;
        if (tempTs !== 0) {
            encodedBytes.push(byte | 0x80);
        } else {
            encodedBytes.push(byte);
            break;
        }
    }
    return encodedBytes;
}

function patchString(addr, plainStr) {
    const bytes = [];
    for (let i = 0; i < plainStr.length; i++) {
        bytes.push(plainStr.charCodeAt(i));
    }

    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0);
}
// -------------------------基础函数分区-------------------------

// -------------------------全局变量分区-------------------------

// 文本消息全局变量
var sendTextFuncAddr = baseAddr.add(0x448A858); // 这个必须是绝对位置
var protobufAddr = baseAddr.add(0x227EC70);
var patchTextProtobufAddr = baseAddr.add(0x227EC4C);
var PatchTextProtobufDeleteAddr = baseAddr.add(0x227EC88);
var textCgiAddr = ptr(0);
var sendTextMessageAddr = ptr(0);
var textMessageAddr = ptr(0);
var contentAddr = ptr(0);
var insertTextMsgAddr = ptr(0);
var textProtoX1PayloadAddr = ptr(0);
var sendMessageCallbackFunc = ptr(0);
var messageCallbackFunc1 = baseAddr.add(0x7fa1050);


// req2buf全局变量
var triggerX1Payload = ptr(0x175ED6600);
var req2bufEnterAddr = baseAddr.add(0x34566C0);
var req2bufExitAddr = baseAddr.add(0x34577D8);

// 图片消息全局变量


// 发送消息的全局变量
var taskIdGlobal = 0x20000090 // 最好比较大，不和原始的微信消息重复
var receiverGlobal = "wxid_"
var contentGlobal = "";
var senderGlobal = "wxid_"
var lastSendTime = 0;

// -------------------------全局变量分区-------------------------


// -------------------------发送文本消息分区-------------------------


// 初始化进行内存的分配
function setupSendTextMessageDynamic() {
    console.log("[+] Starting Dynamic Message Patching...");

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    textCgiAddr = Memory.alloc(128);
    sendTextMessageAddr = Memory.alloc(256);
    textMessageAddr = Memory.alloc(256);
    contentAddr = Memory.alloc(16);

    // A. 写入字符串内容
    patchString(textCgiAddr, "/cgi-bin/micromsg-bin/newsendmsg");
    patchString(contentAddr, " ");

    // B. 构建 sendTextMessageAddr 结构体 (X24 基址位置)
    sendTextMessageAddr.add(0x00).writeU64(0);
    sendTextMessageAddr.add(0x08).writeU64(0);
    sendTextMessageAddr.add(0x10).writePointer(sendMessageCallbackFunc);
    sendTextMessageAddr.add(0x18).writeU64(1);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x28).writePointer(textMessageAddr); // 指向动态分配的 Message

    console.log(" [+] sendTextMessageAddr Object: ", hexdump(sendTextMessageAddr, {
        offset: 0,
        length: 48,
        header: true,
        ansi: true
    }));

    // C. 构建 Message 结构体
    textMessageAddr.add(0x00).writePointer(messageCallbackFunc1);
    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    textMessageAddr.add(0x0c).writeU32(0x20a);
    textMessageAddr.add(0x10).writeU64(0x3);
    textMessageAddr.add(0x18).writePointer(textCgiAddr);
    textMessageAddr.add(0x20).writeU64(uint64("0x20"));

    console.log(" [+] textMessageAddr Object: ", hexdump(textMessageAddr, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }));

    console.log("[+] Dynamic Memory Setup Complete. - Message Object: " + textMessageAddr);
}

setImmediate(setupSendTextMessageDynamic);


function patchTextProtoBuf() {
    Memory.patchCode(patchTextProtobufAddr, 4, code => {
        const cw = new Arm64Writer(code, {pc: patchTextProtobufAddr});
        cw.putNop();
        cw.flush();
    });

    console.log("[+] Patching BL to NOP at " + patchTextProtobufAddr + " completed.");

    Memory.patchCode(PatchTextProtobufDeleteAddr, 4, code => {
        const cw = new Arm64Writer(code, {pc: PatchTextProtobufDeleteAddr});
        cw.putNop();
        cw.flush();
    });

    console.log("[+] Patching BL DELETE to NOP at " + PatchTextProtobufDeleteAddr + " completed.");
}

setImmediate(patchTextProtoBuf);

function triggerSendTextMessage(taskId, receiver, content) {
    console.log("[+] Manual Trigger Started...");
    if (!taskId || !receiver || !content) {
        console.error("[!] taskId or Receiver or Content is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    lastSendTime = timestamp
    taskIdGlobal = taskId;
    receiverGlobal = receiver;
    contentGlobal = content;

    textMessageAddr.add(0x08).writeU32(taskIdGlobal);
    sendTextMessageAddr.add(0x20).writeU32(taskIdGlobal);

    console.log("start init payload")

    const payloadData = [
        0x0A, 0x02, 0x00, 0x00,                         // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08
        0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // 0x10
        0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, // 0x18
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x28
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // 0x38
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0x40
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA, // 0x48
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, // 0x50
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58
        0x0A, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D, // 0x68 default-
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, // 0x70 longlink
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10, // 0x78
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xB0
        0xC0, 0x66, 0xED, 0x75, 0x01, 0x00, 0x00, 0x00, // 0xB8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x130
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x140
        0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // 0x188
        0x98, 0x67, 0xED, 0x75, 0x01, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
    ];

    // 从 0x175ED6604 开始写入 Payload
    triggerX1Payload.writeU32(taskIdGlobal);
    triggerX1Payload.add(0x04).writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(textCgiAddr);

    console.log("finished init payload")

    const MMStartTask = new NativeFunction(sendTextFuncAddr, 'int64', ['pointer']);

    // 5. 调用函数
    try {
        // const arg1 = globalMessagePtr; // 第一个指针参数
        const arg2 = triggerX1Payload; // 第二个参数 0x175ED6600
        console.log(`[+] Calling MMStartTask  at ${sendTextFuncAddr} with args: (${arg2})`);
        const result = MMStartTask(arg2);
        console.log("[+] Execution MMStartTask  Success. Return value: " + result);
        return "ok";
    } catch (e) {
        console.error("[!] Error trigger function  during execution: " + e);
        return "fail";
    }
}

// 拦截 SendTextProto 编码逻辑，注入自定义 Payload
function attachSendTextProto() {
    console.log("[+] proto注入拦截目标地址: " + protobufAddr);
    textProtoX1PayloadAddr = Memory.alloc(1024);
    console.log("[+] Frida 分配的 Payload 地址: " + textProtoX1PayloadAddr);

    Interceptor.attach(protobufAddr, {
        onEnter: function (args) {
            console.log("[+] Protobuf 拦截命中");

            var sp = this.context.sp;
            var firstValue = sp.readU32();
            if (firstValue !== taskIdGlobal) {
                console.log("[+] Protobuf 拦截未命中，跳过...");
                return;
            }
            console.log("[+] 正在注入 Protobuf Payload...");

            const type = [0x08, 0x01, 0x12]
            const receiverHeader = [0x0A, receiverGlobal.length + 2, 0x0A, receiverGlobal.length];
            const receiverProto = stringToHexArray(receiverGlobal);
            const contentProto = stringToHexArray(contentGlobal);
            const contentHeader = [0x12, ...toVarint(contentProto.length)];
            const tsHeader = [0x18, 0x01, 0x20];
            const tsBytes = getVarintTimestampBytes();
            const msgIdHeader = [0x28]
            const msgId = generateRandom5ByteVarint()

            const suffix = [
                0x32, 0x32, 0x3C,                               // 0x28 头部
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x30 msgsour
                0x63, 0x65, 0x3E, 0x3C, 0x61, 0x6C, 0x6E, 0x6F, // 0x38 ce><alno
                0x64, 0x65, 0x3E, 0x3C, 0x66, 0x72, 0x3E, 0x31, // 0x40 de><fr>1
                0x3C, 0x2F, 0x66, 0x72, 0x3E, 0x3C, 0x2F, 0x61, // 0x48 </fr></a
                0x6C, 0x6E, 0x6F, 0x64, 0x65, 0x3E, 0x3C, 0x2F, // 0x50 lnode></
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x58 msgsour
                0x63, 0x65, 0x3E, 0x00                          // 0x60 ce>.
            ];

            const valueLen = toVarint(receiverHeader.length + receiverProto.length + contentHeader.length +
                contentProto.length + tsHeader.length + tsBytes.length + msgIdHeader.length + msgId.length + suffix.length)

            // 合并数组
            const finalPayload = type.concat(valueLen).concat(receiverHeader).concat(receiverProto).concat(contentHeader).concat(contentProto).concat(tsHeader).concat(tsBytes).concat(msgIdHeader).concat(msgId).concat(suffix);

            console.log("[+] Payload 准备写入");
            textProtoX1PayloadAddr.writeByteArray(finalPayload);
            console.log("[+] Payload 已写入，长度: " + finalPayload.length);

            this.context.x1 = textProtoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            console.log("[+] 寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(textProtoX1PayloadAddr, {
                offset: 0,
                length: 128,
                header: true,
                ansi: true
            }));
        },
    });
}

setImmediate(attachSendTextProto);


rpc.exports = {
    triggerSendTextMessage: triggerSendTextMessage
};

// -------------------------发送文本消息分区-------------------------



// -------------------------Req2Buf公共部分分区-------------------------
function attachReq2buf() {
    console.log("[+] Target Req2buf enter Address: " + req2bufEnterAddr);

    // 2. 开始拦截
    Interceptor.attach(req2bufEnterAddr, {
        onEnter: function (args) {
            if (!this.context.x1.equals(taskIdGlobal)) {
                return;
            }

            console.log("[+] 已命中目标Req2Buf地址:0x1033EE8E8 taskId:" + taskIdGlobal + "base:" + baseAddr);

            // 3. 获取 X24 寄存器的值
            const x24_base = this.context.x24;
            insertTextMsgAddr = x24_base.add(0x60);
            console.log("[+] 当前 Req2Buf X24 基址: " + x24_base);


            // todo 修改为判断是发送图片还是文本
            if (typeof sendTextMessageAddr !== 'undefined') {
                insertTextMsgAddr.writePointer(sendTextMessageAddr);
                console.log("[+] 成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendTextMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertTextMsgAddr);
            } else {
                console.error("[!] 错误: 变量 sendTextMessageAddr 未定义，请确保已运行分配逻辑。");
            }
        }
    });

    // 在出口处拦截req2buf，把insertTextMsgAddr设置为0，避免被垃圾回收导致整个程序崩溃
    console.log("[+] Target Req2buf leave Address: " + req2bufExitAddr);
    Interceptor.attach(req2bufExitAddr, {
        onEnter: function (args) {
            if (!this.context.x25.equals(taskIdGlobal)) {
                return;
            }
            insertTextMsgAddr.writeU64(0x0);
            console.log("[+] 清空写入后内存预览: " + insertTextMsgAddr.readPointer());
            taskIdGlobal = 0;
            receiverGlobal = "";
            senderGlobal = "";
            contentGlobal = "";
            send({
                type: "finish",
            })
        }
    });
}

setImmediate(attachReq2buf);

// -------------------------Req2Buf公共部分分区-------------------------

