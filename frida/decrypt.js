const mod = Process.getModuleByName("WeChat");
const realAddr = ptr("0x102BAA1E0").sub("0x100000000").add(mod.base);

console.log("[+] Real Function Address:", realAddr);

Interceptor.attach(realAddr, {
    onEnter(args) {
        for (let i = 0; i < 20; i++) {
            try {
                if (args[i].isNull()) {
                    continue;
                }

                console.log(`\n[+] arg${i} ${args[i]}`);
                if (args[i].compare(ptr("0x600000000000")) >= 0 && args[i].compare(ptr("0x700000000000")) < 0 && args[i].and(0x7).isNull()) {
                    const buf = args[i].readByteArray(128)
                    if (!buf) {
                        continue;
                    }
                    let s = "";
                    const u8 = new Uint8Array(buf);
                    for (let b of u8) {
                        if (b >= 0x20 && b <= 0x7E) {
                            s += String.fromCharCode(b);
                        } else {
                            s += ".";
                        }
                    }

                    console.log(s);
                }
            } catch (e) {
                console.log("Enter Error:", e);
            }
        }


    },

    onLeave(retval) {
        console.log("===== sub_105808800 LEAVE =====");
        console.log("Return value:", retval);
        // try {
        //     console.log("Return hexdump:");
        //     console.log(hexdump(retval, {
        //         offset: 0,
        //         length: 128
        //     }));
        // } catch (_) {
        // }
    }
});

