基于微信4.1.5.17版本

注意点
1. 需要让frida启动微信才能通过内存地址找到代码位置        
```
MemoryAccessMonitor.enable(
    {
        base: ptr("0x60000173BCDA"),
        size: 0x200  // buffer 大小
    },
    {
        onAccess(details) {
            console.log("Access by:", DebugSymbol.fromAddress(details.from));
            console.log("Operation:", details.operation);
        }
    }
);
```

2. 通过ce确定内存位置        
![image](https://github.com/user-attachments/assets/5980e46a-d5b7-4556-b291-a9beca0cbf47)


3. 可以看到打印日志        
```
Access by: 0x10dc28ccc libGLESv2.dylib!0x250ccc (0x250ccc)
Operation: read
Access by: 0x10a08083c WeChat!0x580883c (0x10580883c)
Operation: read
7                  Access by: 0x18b233444 libsystem_malloc.dylib!nanov2_malloc
Operation: read
Access by: 0x10a08083c WeChat!0x580883c (0x10580883c)
Operation: read

定位到函数sub_105808800
```

sub_104622628 应该是日志打印的函数        
0x1057ee3a8 会打印输入框的文字        
0x105B7E990 QNSView handleKeyEvent:eventType 键盘事件        
 sub_104A15520 -> sub_1049FB5BC -> sub_1049FB958->sub_1049FF850 -> sub_1049E9E68 -> sub_10461CE50 -> write 发送消息的方法
