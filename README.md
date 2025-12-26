# WeChat 4.0 Message hook
![image](https://github.com/user-attachments/assets/401de4b8-5d10-48d9-8dcf-eecc8ae8682a)

hook1是触发函数，和用户回车行为一样，触发startTask。

hook2是对Req2Buf这个函数进行消息体注入，因为hook1触发的时候我其实没有给消息体，但是我注入的这个消息体，在protobuf过程中一直失败，全是指针，根本看不懂。

所以在hook3处我直接注入protobuf的内容，然后进行发送。

hook4是在Req2Buf，清除掉消息体的内容，因为后序在OnTaskEnd会回收内存，如果我这边消息体还在整个的指针上就会被清除，但是这个线程不认识这块内存，整个程序就会crash。

查看：./frida/succ.js
