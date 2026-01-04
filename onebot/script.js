// 1. 获取微信主模块的基地址
var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

// 触发函数地址,不同版本的地址看wechat_version 中的json文件复制过来
var triggerFuncAddr = baseAddr.add({{.triggerFuncAddr}});
var sendMessageCallbackFunc = baseAddr.add({{.sendMessageCallbackFunc}});
var messageCallbackFunc1 = baseAddr.add({{.messageCallbackFunc1}});
var messageCallbackFunc2 = baseAddr.add({{.messageCallbackFunc2}});
var messageCallbackFunc3 = baseAddr.add({{.messageCallbackFunc3}});
var messageCallbackFunc4 = baseAddr.add({{.messageCallbackFunc4}});
var messageCallbackFunc5 = baseAddr.add({{.messageCallbackFunc5}});
var messageCallbackFunc6 = baseAddr.add({{.messageCallbackFunc6}});

// 这个必须是绝对位置
var triggerX1Payload = ptr({{.triggerX1Payload}});
var req2bufEnterAddr = baseAddr.add({{.req2bufEnterAddr}});
var req2bufExitAddr = baseAddr.add({{.req2bufExitAddr}});
var protobufAddr = baseAddr.add({{.protobufAddr}});
var receiveAddr = baseAddr.add({{.receiveAddr}});

// // 触发函数地址,不同版本的地址看wechat_version 中的json文件复制过来
// var triggerFuncAddr = baseAddr.add(0x444A99C);
// var sendMessageCallbackFunc = baseAddr.add(0xEDB4678);
// var messageCallbackFunc1 = baseAddr.add(0x7f04f70);
// var messageCallbackFunc2 = baseAddr.add(0x7f04fc8);
// var messageCallbackFunc3 = baseAddr.add(0x7f96918);
// var messageCallbackFunc4 = baseAddr.add(0x7f96a08);
// var messageCallbackFunc5 = baseAddr.add(0x7f968a0);
// var messageCallbackFunc6 = baseAddr.add(0x7f9dfe0);
//
// // 这个必须是绝对位置
// var triggerX1Payload = ptr(0x175ED6600);
// var req2bufEnterAddr = baseAddr.add(0x33EE8E8);
// var req2bufExitAddr = baseAddr.add(0x33EFA00);
// var protobufAddr = baseAddr.add(0x223EF58);
// var receiveAddr = baseAddr.add(0x23B5348);

// 触发函数X0参数地址
var globalMessagePtr = ptr(0);

// 消息体的一些指针地址
var cgiAddr = ptr(0);
var callBackFuncAddr = ptr(0);
var sendMessageAddr = ptr(0);
var messageAddr = ptr(0);
var messageContentAddr = ptr(0);
var messageAddrAddr = ptr(0);
var contentAddr = ptr(0);
var insertMsgAddr = ptr(0);
var receiverAddr = ptr(0);
var htmlContentAddr = ptr(0);
var protoX1PayloadAddr = ptr(0);
var protoX1PayloadLen = 1024;

// 消息的taskId
var taskIdGlobal = 0x20000090 // 最好比较大，不和原始的微信消息重复
var receiverGlobal = "wxid_"
var contentGlobal = "";
var lastSendTime = 0;

// 打印消息的地址，便于查询问题
function printAddr() {
    console.log("[+] Addresses:");
    console.log("    - cgiAddr: " + cgiAddr);
    console.log("    - callBackFuncAddr: " + callBackFuncAddr);
    console.log("    - sendMessageAddr: " + sendMessageAddr);
    console.log("    - messageAddr: " + messageAddr);
    console.log("    - messageContentAddr: " + messageContentAddr);
    console.log("    - messageAddrAddr: " + messageAddrAddr);
    console.log("    - contentAddr: " + contentAddr);
    console.log("    - globalMessagePtr: " + globalMessagePtr);
    console.log("    - triggerX1Payload: " + triggerX1Payload);
}

// 辅助函数：写入 Hex 字符串
function patchHex(addr, hexStr) {
    const bytes = hexStr.split(' ').map(h => parseInt(h, 16));
    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0); // 终止符
}

// 初始化进行内存的分配
function setupSendMessageDynamic() {
    console.log("[+] Starting Dynamic Message Patching...");

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    cgiAddr = Memory.alloc(128);
    callBackFuncAddr = Memory.alloc(16);
    sendMessageAddr = Memory.alloc(256);
    messageAddr = Memory.alloc(512);
    messageContentAddr = Memory.alloc(32);
    messageAddrAddr = Memory.alloc(64);
    contentAddr = Memory.alloc(255);
    receiverAddr = Memory.alloc(24);
    htmlContentAddr = Memory.alloc(24);


    // A. 写入字符串内容
    patchHex(cgiAddr, "2F 63 67 69 2D 62 69 6E 2F 6D 69 63 72 6F 6D 73 67 2D 62 69 6E 2F 6E 65 77 73 65 6E 64 6D 73 67");
    patchHex(contentAddr, " ");

    // B. 构建 SendMessage 结构体 (X24 基址位置)
    sendMessageAddr.add(0x00).writeU64(0);
    sendMessageAddr.add(0x08).writeU64(0);
    sendMessageAddr.add(0x10).writePointer(sendMessageCallbackFunc); // 虚表地址通常仍需硬编码或从模块基址计算
    sendMessageAddr.add(0x18).writeU64(1);
    sendMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendMessageAddr.add(0x28).writePointer(messageAddr); // 指向动态分配的 Message

    console.log(" [+] sendMessageAddr Object: ", hexdump(sendMessageAddr, {
        offset: 0,
        length: 48,
        header: true,
        ansi: true
    }));

    // C. 构建 Message 结构体
    messageAddr.add(0x00).writePointer(messageCallbackFunc1);
    messageAddr.add(0x08).writeU32(taskIdGlobal);
    messageAddr.add(0x0c).writeU32(0x20a);
    messageAddr.add(0x10).writeU64(0x3);
    messageAddr.add(0x18).writePointer(cgiAddr);

    // 设置一些固定值
    messageAddr.add(0x20).writeU64(uint64("0x20"));
    messageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    messageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));
    messageAddr.add(0x58).writeU64(uint64("0x0101010100000001"));

    // 处理回调地址
    callBackFuncAddr.writePointer(messageCallbackFunc2);
    messageAddr.add(0x98).writePointer(callBackFuncAddr);

    // 设置内容指针
    messageAddr.add(0xb8).writePointer(messageCallbackFunc3);
    messageAddr.add(0xc0).writePointer(messageContentAddr);
    messageAddr.add(0xc8).writeU64(uint64("0x0000000100000001"));
    messageAddr.add(0xd0).writeU64(0x4);
    messageAddr.add(0xd8).writeU64(0x1);
    messageAddr.add(0xe0).writeU64(0x1);
    messageAddr.add(0xe8).writePointer(messageCallbackFunc4);


    messageContentAddr.writePointer(messageAddrAddr);
    messageAddrAddr.writePointer(messageCallbackFunc5);
    receiverAddr.writePointer(messageCallbackFunc6);
    receiverAddr.add(0x08).writePointer(contentAddr);
    messageAddrAddr.add(0x08).writePointer(receiverAddr);
    messageAddrAddr.add(0x10).writePointer(contentAddr);
    messageAddrAddr.add(0x18).writeU32(1);
    messageAddrAddr.add(0x20).writeU32(Math.floor(Date.now() / 1000));
    htmlContentAddr.writePointer(contentAddr);
    messageAddrAddr.add(0x28).writePointer(htmlContentAddr);

    console.log(" [+] messageAddr Object: ", hexdump(messageAddr, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }));

    console.log(" [+] Dynamic Memory Setup Complete. - Message Object: " + messageAddr);
}

setImmediate(setupSendMessageDynamic);

// 设置trigger函数的x0参数
function setTriggerAttach() {
    console.log("[+] WeChat Base: " + baseAddr + "[+] Attaching to: " + triggerFuncAddr);

    // 3. 开始拦截
    Interceptor.attach(triggerFuncAddr, {
        onEnter: function (args) {
            console.log("[+] Entered Function: 0x10444A99C");

            if (!globalMessagePtr.isNull()) {
                return;
            }

            globalMessagePtr = this.context.x0;
            console.log("[+] globalMessagePtr 当前 X0 的指针值: " + globalMessagePtr);
        },
        onLeave: function (retval) {
        }
    });
}

// 使用 setImmediate 确保在模块加载后执行
setImmediate(setTriggerAttach);


function manualTrigger(taskId, receiver, content) {
    console.log("[+] Manual Trigger Started...");
    if (globalMessagePtr.isNull()) {
        console.error("[!] globalMessagePtr is NULL, cannot trigger!");
        return "fail";
    }

    if (!taskId || !receiver || !content) {
        console.error("[!] taskId or Receiver or Content is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    // 全局变量不为空，并且上次发送时间小于1s，不给发送
    if ((taskIdGlobal !== 0 || receiverGlobal !== "" || contentGlobal !== "") && lastSendTime + 1 > timestamp) {
        console.error("[!] taskId or receiver or content is not empty!");
        return "fail";
    }

    lastSendTime = timestamp
    taskIdGlobal = taskId;
    receiverGlobal = receiver;
    contentGlobal = content;

    messageAddr.add(0x08).writeU32(taskIdGlobal);
    sendMessageAddr.add(0x20).writeU32(taskIdGlobal);
    messageAddrAddr.add(0x18).writeU32(timestamp);

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
    triggerX1Payload.add(0x18).writePointer(cgiAddr);

    const sub_10444A99C = new NativeFunction(triggerFuncAddr, 'uint64', ['pointer', 'pointer']);

    // 5. 调用函数
    try {
        const arg1 = globalMessagePtr; // 第一个指针参数
        const arg2 = triggerX1Payload; // 第二个参数 0x175ED6600
        console.log(`[+] Calling trigger function  at ${triggerFuncAddr} with args: (${arg1}, ${arg2})`);
        const result = sub_10444A99C(arg1, arg2);
        console.log("[+] Execution trigger function  Success. Return value: " + result);
        return "ok";
    } catch (e) {
        console.error("[!] Error trigger function  during execution: " + e);
        return "fail";
    }
}


// ReqBuf 进行拦截，替换入参数的消息指针
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
            insertMsgAddr = x24_base.add(0x60);

            console.log("[+] 当前 Req2Buf X24 基址: " + x24_base);
            console.log("[+] 准备修改位置 Req2Buf (X24 + 0x60): " + insertMsgAddr, hexdump(insertMsgAddr, {
                offset: 0,
                length: 16,
                header: true,
                ansi: true
            }));

            if (typeof sendMessageAddr !== 'undefined') {
                insertMsgAddr.writePointer(sendMessageAddr);
                console.log("[+] 成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
                console.log(hexdump(insertMsgAddr, {
                    offset: 0,
                    length: 16,
                    header: true,
                    ansi: true
                }))
                console.log(hexdump(sendMessageAddr, {
                    offset: 0,
                    length: 48,
                    header: true,
                    ansi: true
                }))
            } else {
                console.error("[!] 错误: 变量 sendMessageAddr 未定义，请确保已运行分配逻辑。");
            }
        }
    });

    // 在出口处拦截req2buf，把insertMsgAddr设置为0，避免被垃圾回收导致整个程序崩溃
    console.log("[+] Target Req2buf leave Address: " + req2bufExitAddr);
    Interceptor.attach(req2bufExitAddr, {
        onEnter: function (args) {
            if (!this.context.x25.equals(taskIdGlobal)) {
                return;
            }
            insertMsgAddr.writeU64(0x0);
            console.log("[+] 0x1033EFA00 清空写入后内存预览: " + insertMsgAddr.readPointer());
            taskIdGlobal = 0;
            receiverGlobal = "";
            contentGlobal = "";
            send({
                type: "finish",
            })
        }
    });
}

setImmediate(attachReq2buf);

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

// 拦截 Protobuf 编码逻辑，注入自定义 Payload
function attachProto() {
    console.log("[+] proto注入拦截目标地址: " + protobufAddr);
    protoX1PayloadAddr = Memory.alloc(protoX1PayloadLen);
    console.log("[+] Frida 分配的 Payload 地址: " + protoX1PayloadAddr);

    Interceptor.attach(protobufAddr, {
        onEnter: function (args) {
            console.log("[+] Protobuf 拦截命中");

            var sp = this.context.sp;
            console.log("[+] Protobuf 拦截命中，SP: " + sp, hexdump(sp, {
                offset: 0,
                length: 16,
                header: true,
                ansi: true
            }));


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
            protoX1PayloadAddr.writeByteArray(finalPayload);
            console.log("[+] Payload 已写入，长度: " + finalPayload.length);

            this.context.x1 = protoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            console.log("[+] 寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(protoX1PayloadAddr, {
                offset: 0,
                length: 128,
                header: true,
                ansi: true
            }));
        }
    });
}

function toVarint(n) {
    let res = [];
    while (n >= 128) {
        res.push((n & 0x7F) | 0x80); // 取后7位，最高位置1
        n = n >> 7;                 // 右移7位
    }
    res.push(n); // 最后一位最高位为0
    return res;
}

setImmediate(attachProto);

function setReceiver() {
    console.log("[+] setReceiver WeChat Base: " + baseAddr + "[+] Attaching to: " + receiveAddr);

    // 3. 开始拦截
    Interceptor.attach(receiveAddr, {
        onEnter: function (args) {
            console.log("[+] Entered Receive Function: 0x1023B5348");
            const x1 = this.context.x1;
            var sender = x1.add(0x18).readUtf8String();
            var receiver = x1.add(0x30).readUtf8String();
            var selfId = x1.add(0x48).readUtf8String();

            // 3. 从 0xd0 开始处理
            var d0Pos = x1.add(0xd0);
            var strD0 = "";

            if (isPrintableOrChinese(d0Pos)) {
                strD0 = d0Pos.readUtf8String();
                console.log("[+] 0xd0 处不是指针，直接读取完毕");
            } else {
                // 情况 B：不符合特征（如包含乱码位或指针特征），视为指针
                var ptrD0 = d0Pos.readPointer();
                if (!ptrD0.isNull() && Process.findRangeByAddress(ptrD0)) {
                    strD0 = ptrD0.readUtf8String();
                    console.log("[+] 0xd0 识别为：指针跳转读取");
                } else {
                    strD0 = "Invalid Data/Pointer";
                }
            }

            var msgType = "private"
            var groupId = ""
            if (receiver.includes("@chatroom")) {
                msgType = "group"
                groupId = receiver
            }

            var parts = strD0.split('\u2005');
            var messages = [];
            for (let part of parts) {
                if (part.startsWith("@")) {
                    messages.push({type: "at", data: {qq: selfId}});
                } else {
                    messages.push({type: "text", data: {text: part}});
                }
            }

            send({
                message_type: msgType,
                user_id: sender,
                self_id: selfId,
                group_id: groupId,
                message_id: taskIdGlobal,
                type: "send",
                raw: {peerUid: receiver},
                message: messages
            })
        },
    });
}

// 使用 setImmediate 确保在模块加载后执行
setImmediate(setReceiver)

/**
 * 扫描内存直到 \0，判断中间内容是否全部为可见字符或汉字
 */
function isPrintableOrChinese(startPtr) {
    let offset = 0;
    const maxScanLength = 8;

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


rpc.exports = {
    manualTrigger: manualTrigger
};