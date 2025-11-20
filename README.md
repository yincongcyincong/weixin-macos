# weixin-macos
使用frida进行逆向       
frida -f /Applications/WeChat.app/Contents/MacOS/WeChat -l script.js        

### 报错：Failed to attach: unable to access process with pid 43649 from the current user account
重启进入recovery模式，然后关闭安全模式    

frida-trace -p 进程号 -i "*Message*" --decorate 比较好用 
```
frida-trace -p 22374 -i '*Message*' -i "*Msg*"  -x '*objc_msgSend_noarg*' -x '*objc_msgSend_debug*' -x '*objc_msgSend*' -x "*_HIDisableSuddenTerminationForSendEvent*" -x "*_HIEnableSuddenTerminationForSendEvent*" -x "*SendEventToEventTarget*" -x "*s10RTCUtility10XPCMessageV4dictAA16RTCXPCDictionaryVvg*" -x "*MTLMessageContextEnd*" -x "*ictAA16RTCXPCDictionaryVvg*" -x "*_MTLMessageContextBegin_*" -x "*CFMachMessageCheckForAndDestroyUnsentMessag*" -x "*SLEventCopyAuthenticationMessage*" -x "*SendTextInputEvent_WithCompletionHandler*"  --decorate    
```

会有一个http页面，进去之后，会有一些微信的代码，这些代码中能分析出微信是怎么发送消息的

