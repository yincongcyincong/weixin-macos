触发 STNManager__MMStartTask 
图片hook: startUploadMedia, OnUploadCompleted
Req2Buf 构造消息的buffer入口，其中X4是消息内容，输出的是压缩后的protobuf
Pack是打包函数，消息内容 cgi等信息打包进入
InitClientChannel， DoHandShakeLoop 是建立mmtls链接最重要的函数
DoSendEarlyAppData 是消息体函数，可以看到你发的消息体
__RunReadWrite 这条日志打印后的 “task socket send sock:%_, %_ http len:%" 一个BL X8里面有send命令进行发送

老图和新图发送的还不一样
有个映射