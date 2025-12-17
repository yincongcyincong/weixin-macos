装填数据，发到jobqueue是他们的目地，我感觉重点是在这里
sub_1032003B0 -> sub_1024803E4 -> sub_1024C6354 可能是统一入口
sub_10237997C image_handler.cc
sub_1023E73E8 text_handler.cc ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_
sub_102363BB0 file_handler.cc 
sub_100400950 装填消息
每次都是这个175ED5D10指针装填数据

sub_10250D878 是整体的发消息入口有多个阶段来自这里
StartSendMessageSerial sub_1024C4CB4
CoSendMessageWithUploadInfo sub_1023E8108
CoAddSendMessageToDb  sub_1023C09D0
CoPrepareShowSendMessage  sub_1023BC4E0



键盘事件触发
sub_10064DD2C 里面有铭文的数据，看看怎么把这个数据传输到下层，估计是
sub_100662CC4 处理消息的关键函数
sub_100662CC4 -> sub_100668580 -> sub_10064DD2C
sub_100662CC4 -> sub_10063F318 -> sub_1006DDDBC 处理发送消息结构体
sub_1006DDDBC 消息体在这个函数 X1的第一个指针式utf16的发送值，X0不知道是啥,并且X1都是一个地址，追查一下地址 16FDFD688

100179130 可以增加字段 和 sub_105A25B30 获取值的函数
16FDFD6F0 指针


真正的发送阶段
sub_1024C7FB4 -> sub_102481CA0 -> sub_105268848
sub_1024C7FB4 sendMessage 入口


sub_1023BB1F0->sub_1023990EC->realSendMsg_10239B4C4 发消息的真正函数
又调用了sendMsgCoroutine_105261924 进行一步操作但是这个好像是只有发消息才会走的核心coroutine