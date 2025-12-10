const FUNCTION_RVA = 0x10250D878; // 目标函数 sendMsg_10250D878 的 RVA

const STRUCT_SIZE = 0x50;

const module = Process.getModuleByName("WeChat");
const baseAddress = module.base;
console.log(`Base: ${baseAddress}, size: ${module.base.add(module.size)}`)

const targetAddress = baseAddress.add(FUNCTION_RVA - 0x100000000);
console.log(`Target Address: ${targetAddress}`)

let resent = true;
let arg0;

function sendMessageWechat() {
    const funcAddr_1 = baseAddress.add(0x10817DF48 - 0x100000000); // 示例计算
    const funcAddr_2 = baseAddress.add(0x108177ED0 - 0x100000000); // 示例计算
    const funcAddr_3 = baseAddress.add(0x10816AFD8 - 0x100000000); // 示例计算
    const funcAddr_4 = baseAddress.add(0x10817C298 - 0x100000000); // 示例计算


    // --- 2. 构造数据结构体的内存 ---
    const structPointer = Memory.alloc(STRUCT_SIZE);

    // --- 3. 构造 wxid 字符串 (参数 5) ---
    const WXID_STRING = "wxid_7wd1ece99f7i21";

    structPointer.writePointer(funcAddr_1);
    console.log(`Function 1 Address: ${funcAddr_1}`);

    // 结构体偏移 0x08: 参数 2 的第一级指针 (0x60000151F948)
    // 这里需要构造二级指针。由于无法分配静态地址 0x6000...，我们只能构造一个新链。

    // 构造二级指针的目标函数 sub_1023D8204
    const funcPtr_2_tmp1 = Memory.alloc(Process.pointerSize);
    const funcPtr_2_tmp2 = Memory.alloc(Process.pointerSize);
    funcPtr_2_tmp1.writePointer(funcPtr_2_tmp2);
    funcPtr_2_tmp2.writePointer(funcAddr_2);
    structPointer.add(0x08).writePointer(funcPtr_2_tmp1);
    console.log(`Function 2 Address: ${funcAddr_2}, tmp1: ${funcPtr_2_tmp1}, tmp2: ${funcPtr_2_tmp2}`);

    // 结构体偏移 0x10: 参数 3 的第一级指针 (0x600003F41C20 -> sub_1021D5E48)
    const funcPtr_3 = Memory.alloc(Process.pointerSize);
    funcPtr_3.writePointer(funcAddr_3);
    structPointer.add(0x10).writePointer(funcPtr_3);
    console.log(`Function 3 Address: ${funcAddr_3}, tmp: ${funcPtr_3}`);

    const funcPtr_4 = Memory.alloc(Process.pointerSize);
    funcPtr_4.writePointer(funcAddr_4);
    structPointer.add(0x18).writePointer(funcPtr_4);
    console.log(`Function 4 Address: ${funcAddr_3}, tmp: ${funcPtr_4}`);

    // 结构体偏移 0x20: 参数 5 (wxid_7wd1ece99f7i21)
    structPointer.add(0x20).writeUtf8String(WXID_STRING);
    console.log(`WXID String Address: ${WXID_STRING}`);

    // 填充剩余部分（假设为 NULL 或 0）
    structPointer.add(0x28).writePointer(NULL);
    structPointer.add(0x30).writePointer(NULL);

    console.log(`Structure constructed at: ${structPointer}`);


    // --- 5. 定义函数签名并调用 ---
    try {

        const sendMsgFunc = new NativeFunction(
            targetAddress,
            'void',
            ['pointer']  // 参数类型为 'pointer'
        );

        console.log(`Attempting to call the function with constructed structure...: ${targetAddress}`);

        // 调用函数，传入主结构体的地址
        sendMsgFunc(structPointer);

        console.log(`Function called successfully!`);

    } catch (e) {
        console.error(`Error calling function: ${e.message}`);
        console.error(`Error details: ${e.stack}`);
    }
}

Interceptor.attach(targetAddress, {
    onEnter: function (args) {
        console.log(`[ENTER] sendMsg called with a1 = ${args[0]}`);

        // 检查传入的结构
        const a1 = args[0]
        console.log(`  a1:  ${a1.readPointer()}`);
        console.log(`  a1+8:  ${a1.add(0x08).readPointer()}`);
        console.log(` a1+16: ${a1.add(0x10).readPointer()}`);
        console.log(`  a1+24: ${a1.add(0x18).readPointer()}`);
        console.log(`  a1+32: ${a1.add(0x20).readPointer()}`);
        if (resent) {
            resent = false;
            arg0 = a1;
            // resend()
            Thread.sleep(100);
        }
        console.log(`[ENTER] sendMsg called with a1 = ${args[0]}`);

    },
    onLeave: function (retval) {
        console.log(`[LEAVE] sendMsg returned`);
    }
});

function resend() {
    console.log(`Resending structure...`);
    console.log(` resend a1:  ${arg0.readPointer()}`);
    console.log(` resend a1+8:  ${arg0.add(0x08).readPointer()}`);
    console.log(` resend a1+16: ${arg0.add(0x10).readPointer()}`);
    console.log(` resend a1+24: ${arg0.add(0x18).readPointer()}`);
    console.log(` resend a1+32: ${arg0.add(0x20).readPointer()}`);
    const structPointer = Memory.alloc(STRUCT_SIZE);

    // --- 3. 构造 wxid 字符串 (参数 5) ---
    const WXID_STRING = "wxid_7wd1ece99f7i21";

    structPointer.writePointer(arg0.readPointer());
    structPointer.add(0x08).writePointer(arg0.add(0x08).readPointer());
    structPointer.add(0x10).writePointer(arg0.add(0x10).readPointer());
    structPointer.add(0x18).writePointer(arg0.add(0x18).readPointer());
    structPointer.add(0x20).writeUtf8String(WXID_STRING);
    structPointer.add(0x28).writePointer(NULL);
    structPointer.add(0x30).writePointer(NULL);
    console.log(`Resent structure constructed at: ${structPointer}`);

    try {

        const sendMsgFunc = new NativeFunction(
            targetAddress,
            'void',
            ['pointer']  // 参数类型为 'pointer'
        );

        console.log(`Attempting to call the function with constructed structure...: ${targetAddress}`);

        // 调用函数，传入主结构体的地址
        sendMsgFunc(structPointer);

        console.log(`Function called successfully!`);

    } catch (e) {
        console.error(`Error calling function: ${e.message}`);
        console.error(`Error details: ${e.stack}`);
    }
}