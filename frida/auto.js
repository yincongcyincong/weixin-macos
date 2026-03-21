var moduleName = "wechat.dylib";
var module = Process.findModuleByName(moduleName);
var baseAddr = module.base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

function scanPatterns() {
    myPatterns.forEach((item, index) => {
        const { name, pattern } = item;

        Memory.scan(baseAddr, module.size, pattern, {
            onMatch: function(address, size) {
                const offset = address.sub(baseAddr);
                switch (name) {
                    case "cndOnCompleteAddr":
                        console.log(`"${name}": "${offset.sub(0xCC)}", 绝对地址: ${address.sub(0xCC)}`);
                        break;
                    case "uploadGetCallbackWrapperAddr":
                        console.log(`"${name}": "${offset}", 绝对地址: ${address}`);
                        break;
                    case "req2bufEnterAddr":
                        console.log(`"${name}": "${offset}", 绝对地址: ${address}`);
                        break;
                    case "downloadFileAddr":
                        console.log(`"${name}": "${offset.sub(0x3c)}", 绝对地址: ${address.sub(0x3c)}`);
                        break;
                    case "downloadImageAddr":
                        console.log(`"${name}": "${offset.sub(0x18)}", 绝对地址: ${address.sub(0x18)}`);
                        break;
                    case "uploadImageAddr":
                        console.log(`"${name}": "${offset.sub(0x30)}", 绝对地址: ${address.sub(0x30)}`);
                        break;
                    case "sendFuncAddr":
                        console.log(`"${name}": "${offset.sub(0x44)}", 绝对地址: ${address.sub(0x44)}`);
                        break;
                    case "buf2RespAddr":
                        console.log(`"${name}": "${offset.sub(0x10)}", 绝对地址: ${address.sub(0x10)}`);
                        break;
                    case "startDownloadMedia":
                        console.log(`"${name}": "${offset.sub(0x28)}", 绝对地址: ${address.sub(0x28)}`);
                        break;
                    case "downloadVideoAddr":
                        console.log(`"${name}": "${offset.sub(0x2c)}", 绝对地址: ${address.sub(0x2c)}`);
                        break;
                    case "startUploadMedia":
                        console.log(`"${name}": "${offset.sub(0x30)}", 绝对地址: ${address.sub(0x30)}`);
                        break;
                }
            },
            onError: function(reason) {
                console.error(`[-] 扫描 [${name}] 时出错: ${reason}`);
            },
        });
    });
}


// 特征码数组：? 代表通配符，空格可选
const myPatterns = [
    {
        name: "cndOnCompleteAddr",
        pattern: "68 42 00 91 29 00 80 52 08 01 29 F8 88 12 40 B9"
    },
    {
        name: "uploadGetCallbackWrapperAddr",
        pattern: "08 09 40 F9 E1 03 15 AA E2 03 14 AA E3 03 13 AA 00 01 3F D6 F3 07 40 F9 B3 00 00 B4"
    },
    {
        name: "req2bufEnterAddr",
        pattern: "09 0F 46 F8 C9 01 00 B4 E8 03 18 AA 2A 21 40 B9"
    },
    {
        name: "downloadFileAddr",
        pattern: "F5 03 00 AA  68 4A 41 F9 08 41 46 39 60 22 01 91 69 52 41 F9"
    },
    {
        name: "downloadImageAddr",
        pattern: "68 52 41 F9 19 8D 41 F9 1A 00 14 8B 5F 03 19 EB"
    },
    {
        name: "uploadImageAddr",
        pattern: "08 01 40 F9 A8 83 1A F8  28 9C 40 B9 1F 0D 00 71",
    },
    {
        name: "sendFuncAddr",
        pattern: "E0 03 00 91 21 00 80 52 E5 03 03 AA 26 85 80 52 07 00 80 D2"
    },
    {
        name: "buf2RespAddr",
        pattern: "3C 00 80 52 E0 C3 00 91"
    },
    {
        name: "startDownloadMedia",
        pattern: "08 01 40 F9 A8 83 1C F8 28 7C 42 39 09 1D 00 13 2A 48 40 F9"
    },
    {
        name: "downloadVideoAddr",
        pattern: "E0 03 07 91 01 00 80 52 45 C1 80 52 06 00 80 52 07 00 80 D2"
    },
    {
        name: "startUploadMedia",
        pattern: "08 01 40 F9 A8 83 1A F8  28 9C 40 B9 1F 0D 00 71"
    }
];

// 执行扫描
scanPatterns();
