// 1. 获取微信主模块的基地址
var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

var sendFuncAddr = baseAddr.add(0x4683540);

Interceptor.attach(sendFuncAddr, {
    onEnter: function (args) {
        // 获取 x0 的值
        var x0_ptr = args[0];
        console.log("[+] Register x0: " + x0_ptr);

        // 检查 x0 是否为合法指针，防止访问 0x1 导致崩溃
        try {
            if (x0_ptr.isNull()) {
                console.log("[!] x0 is NULL");
            } else if (parseInt(x0_ptr) < 0x1000) {
                console.log("[!] x0 looks like an invalid small pointer (potential error code): " + x0_ptr);
            } else {
                // 打印 x0 指向的内存数据（例如前 32 字节）
                console.log("[+] Memory at x0:\n" + hexdump(x0_ptr, {
                    offset: 0,
                    length: 256,
                    header: true,
                    ansi: true
                }));
            }
        } catch (e) {
            console.error("[!] Failed to read memory at x0: " + e.message);
        }
    }
})