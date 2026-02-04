# WeChat 4.0 Message hook
本代码库中的所有代码、示例、文档及相关内容（以下简称“本项目”）仅供学习、研究和技术交流之目的使用。使用本项目所产生的任何风险（包括但不限于数据丢失、系统崩溃、安全问题、法律风险等）均由使用者自行承担。

我hook的是微信三端最底层的发消息能力，这块代码是开源的，感兴趣google tencent/mars    
怎么使用,如果你的mac已经关闭了SIP
```
frida -f /Applications/WeChat.app/Contents/MacOS/WeChat -l frida/succ.js
triggerSendTextMessage(0x20000095, "wxid_xxxx", "hi")
```

没有关闭SIP，查看文件 https://github.com/yincongcyincong/weixin-macos/blob/main/frida-gadget/readme.md    
把每一步都执行完成，然后启动微信    
```
frida -H 127.0.0.1:27042 -n Gadget -l ./frida/succ.js
triggerSendTextMessage(0x20000095, "wxid_xxxx", "hi")
```

![image](https://github.com/user-attachments/assets/401de4b8-5d10-48d9-8dcf-eecc8ae8682a)

hook1是触发函数，和用户回车行为一样，触发startTask。

hook2是对Req2Buf这个函数进行消息体注入，因为hook1触发的时候我其实没有给消息体，但是我注入的这个消息体，在protobuf过程中一直失败，全是指针，根本看不懂。

所以在hook3处我直接注入protobuf的内容，然后进行发送。

hook4是在Req2Buf，清除掉消息体的内容，因为后序在OnTaskEnd会回收内存，如果我这边消息体还在整个的指针上就会被清除，但是这个线程不认识这块内存，整个程序就会crash。

查看：./frida/succ.js

## 图片消息
```
发送一张图片,为了让函数找到X0寄存器的数据。

mkdir -p "/Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/"
cp /Users/yincong/Desktop/1.png /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/xxx.jpg


triggerUploadImg("wxid_7wd1ece99f7i21", "8dd4755e12e052fa5647a883e6bf0783", "/Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/xxx.jpg")
triggerSendImgMessage(0x20000199, "wxid_xxx","wxid_xxx")

```

## 支持onebot协议 （http接口）
https://github.com/yincongcyincong/weixin-macos/blob/main/onebot/readme.md    

## 交流群
https://t.me/+yBnP4fxkoCIzZjRl
