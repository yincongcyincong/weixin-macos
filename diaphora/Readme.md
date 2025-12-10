# 注意

libcomm__xlogger.cc.sqlite 
libcomm__xloggerbase.c.sqlite 
用这个sqlite文件


通过关键字 DoTypeSafeFormat 定位到sub_1046385AC打日志函数

下面准备解字符串

unk_1083E89B8 有下面的常量
1083D1F88 aEarlierNotific 常量，怎么使用

108260910 -> 108260918 -> unk_1083E89B8 -> 1083E89C8 -> 1083D1F88

AddMessageSendContext 关键字 1024C10E8 函数

需要先发一条消息
sub_102480484 -> checkPrepareShowMsg_102482A74 -> sub_1024C4CB4
sub_102480484->
StartSendMessageSerial sub_1024C4CB4 发消息的函数
CoSendMessageWithUploadInfo sub_1023E8108
CoAddSendMessageToDb  sub_1023C09D0
CoPrepareShowSendMessage  sub_1023BC4E0

关键字send finish找到 sub_1024C7FB4
sub_1024C7FB4 断点找到sub_102481CA0


sendfinish sub_1024C7FB4
具体发的函数：sub_102481CA0

sub_10250D878 发消息的整体入口
sub_1024C7FB4 -> sub_102481CA0 -> sub_105268848 

sub_102A7581C 一直在循环调用 sub_105268B48 -> sub_105268848
sub_1023D5FE0 处理消息的函数


