# weixin-macos
使用frida进行逆向       
frida -f /Applications/WeChat.app/Contents/MacOS/WeChat -l script.js        
删除__handler__文件夹格外重要

### 第一次尝试，根据关键字失败
报错：Failed to attach: unable to access process with pid 43649 from the current user account    
重启,长按开关进入recovery模式，然后关闭安全模式    

frida-trace -p 进程号 -i "*Message*" --decorate 比较好用 
```
frida-trace -p 10677 -i '*send*'  -x '*objc_msgSend_noarg*' -x '*objc_msgSend_debug*' -x '*objc_msgSend*' -x "*_HIDisableSuddenTerminationForSendEvent*" -x "*_HIEnableSuddenTerminationForSendEvent*" -x "*SendEventToEventTarget*" -x "*s10RTCUtility10XPCMessageV4dictAA16RTCXPCDictionaryVvg*" -x "*MTLMessageContextEnd*" -x "*ictAA16RTCXPCDictionaryVvg*" -x "*_MTLMessageContextBegin_*" -x "*CFMachMessageCheckForAndDestroyUnsentMessag*" -x "*SLEventCopyAuthenticationMessage*" -x "*SendTextInputEvent_WithCompletionHandler*" -x '*mach_msg_send*' -x "*dispatch_mach_send_with_result_and_async_reply_4libxpc*" -x "*dispatch_mach_send_with_result_and_async_reply_4libxpc*" -x "*dispatch_mach_send_with_result*" --decorate --ui-port 60000     
```

打印上游调用
```
defineHandler({
  onEnter(log, args, state) {
    const connectionPtr = args[0];
    const messagePtr = args[1];
    const targetqPtr = args[2];
    const handlerPtr = args[3];

    // --- 1. 打印函数调用信息 ---
    log(`\n======================================================`);
    log(`[HOOKED] xpc_connection_send_message_with_reply 被调用`);

    // --- 2. 打印调用栈（最重要的一步，用于定位上层应用函数）---
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n');
    log("调用栈 (寻找上游应用函数):");
    log(backtrace); 
    log("------------------------------------------------------");

    // --- 3. 打印指针参数 ---
    log(`[Arg 1] Connection (xpc_connection_t): ${connectionPtr}`);
    log(`[Arg 2] Message (xpc_object_t):       ${messagePtr}`);
    log(`[Arg 3] Target Queue (dispatch_queue_t): ${targetqPtr}`);
    log(`[Arg 4] Reply Handler:                ${handlerPtr}`);
    log("------------------------------------------------------");

    // --- 4. 打印 XPC 消息的 HexDump 预览 ---
    if (messagePtr.isNull() === false) {
        log(`[Arg 2] Message 原始数据预览 (32 Bytes):`);
        
        // 注意：这里我们使用 hexdump()，然后将结果作为一个字符串打印到 log() 中
        const hexDumpOutput = hexdump(messagePtr, { length: 32 });
        log(hexDumpOutput); 
    }
    
    log(`======================================================`);
  },

  onLeave(log, retval, state) {
    // 留空，或在这里打印返回值，例如：
    // log(`xpc_connection_send_message_with_reply 返回: ${retval}`);
  }
});
```

会有一个http页面，进去之后，会有一些微信的代码，这些代码中能分析出微信是怎么发送消息的

### 第二次尝试，根据mac的系统函数
注意权限问题，找一个文件夹有权限的    

```
cd go/src/github.com/yincongcyincong/nixiang
frida-trace -p 17649 -i "*_send*" -i "*_sendto*" -i "*_write*" -x "*xpc_connection_send_message*" -x '*objc_msgSend_noarg*' -x '*objc_msgSend_debug*' -x '*objc_msgSend*' -x "*_HIDisableSuddenTerminationForSendEvent*" -x "*_HIEnableSuddenTerminationForSendEvent*" -x "*SendEventToEventTarget*" -x "*s10RTCUtility10XPCMessageV4dictAA16RTCXPCDictionaryVvg*" -x "*MTLMessageContextEnd*" -x "*ictAA16RTCXPCDictionaryVvg*" -x "*_MTLMessageContextBegin_*" -x "*CFMachMessageCheckForAndDestroyUnsentMessag*" -x "*SLEventCopyAuthenticationMessage*" -x "*SendTextInputEvent_WithCompletionHandler*" -x '*mach_msg_send*' -x "*dispatch_mach_send_with_result_and_async_reply_4libxpc*" -x "*dispatch_mach_send_with_result_and_async_reply_4libxpc*" -x "*dispatch_mach_send_with_result*" -x "xpc_*" --decorate --ui-port 60000
```
```
defineHandler({
  onEnter(log, args, state) {
    // 1. 打印函数调用和时间
    log('__write_nocancel() [libsystem_kernel.dylib] 被调用');
    
    // 2. 关键步骤：打印调用栈
    log("调用栈 (寻找上游应用函数):");
    
    // 使用 Thread.backtrace() 捕获当前线程的堆栈
    // 然后用 DebugSymbol.fromAddress() 将地址转换为符号（函数名+偏移量）
    const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n');
    
    log(backtrace);
    log("-----------------------------------------");

    // 3. (可选) 打印写入的数据参数
    const fd = args[0].toInt32();        // 文件描述符 (File Descriptor)
    const bufferPtr = args[1];           // 数据缓冲区地址
    const length = args[2].toUInt32();   // 写入的数据长度

    log(`文件描述符 (FD): ${fd}, 长度: ${length} 字节`);
    
    if (length > 0) {
        log("原始写入数据预览 (HexDump):");
        // 打印前 64 字节
        log(hexdump(bufferPtr, { length: Math.min(length, 64) }));
    }
  },

  onLeave(log, retval, state) {
    // 可选：打印返回值，即实际写入的字节数
    // log(`__write_nocancel() 返回: ${retval}`);
  }
});
```

通过这里成功定位到    
```
__write_nocancel() [libsystem_kernel.dylib] 被调用

调用栈 (寻找上游应用函数):

0x18b2e2764 libsystem_c.dylib!__swrite
0x18b2c4734 libsystem_c.dylib!_swrite
0x18b2c28bc libsystem_c.dylib!__sflush
0x18b2d0da0 libsystem_c.dylib!fclose
0x1068a307c WeChat!0x462307c (0x10462307c)
0x1068a1b90 WeChat!0x4621b90 (0x104621b90)
0x106864b3c WeChat!0x45e4b3c (0x1045e4b3c)
```

明显看到代码被混淆，下一步使用 Interceptor.attach() 对内存进行hook 
```
cd go/src/github.com/yincongcyincong/nixiang
frida  -p 79464 -l ./script.js 
```

能打印 send
```
const wechat = Process.getModuleByName("WeChat");
Interceptor.attach(wechat.findExportByName("recv"), {
    onEnter(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            console.log("=== Recv Data ===");
            console.log(hexdump(this.buf, { length: retval.toInt32() }));
        }
    }
});


Interceptor.attach(wechat.findExportByName("read"), {
    onEnter(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            console.log("=== Read Data ===");
            console.log(hexdump(this.buf, { length: retval.toInt32() }));
        }
    }
});


Interceptor.attach(wechat.findExportByName("send"), {
    onEnter(args) {
        console.log("=== Send Data ===");
        console.log(hexdump(args[1], { length: args[2].toInt32() }));
    },
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            console.log("=== Send Data ===");
            console.log(hexdump(this.buf, { length: retval.toInt32() }));
        }
    }
});

Interceptor.attach(wechat.findExportByName("write"), {
    onEnter(args) {
        let fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        dump("WRITE", this.buf, this.len);
    }
});


```

拦截发送库  
```
const libc = Process.getModuleByName("libSystem.B.dylib");

Interceptor.attach(libc.findExportByName("read"), {
    onEnter(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            console.log("=== Read Data ===");
            console.log(hexdump(this.buf, { length: retval.toInt32() }));
            console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress).join("\n"));
        }
    }
});

Interceptor.attach(libc.findExportByName("write"), {
    onEnter(args) {
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave(retval) {
        if (retval.toInt32() > 0) {
            console.log("=== Write Data ===");
            console.log(hexdump(this.buf, { length: retval.toInt32() }));
            console.log(Thread.backtrace(this.context, Backtracer.FUZZY)
                .map(DebugSymbol.fromAddress).join("\n"));
        }
    }
});

```
