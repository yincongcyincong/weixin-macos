## 如何使用onebot的http接口

### 使用方式和脚本基本一致：        
   1. 编译main.go或者直接下载编译好的onebot二进制文件       
   2. 如果不想关闭SIP直接使用,需要找到自己的图片位置：./onebot -type=gadget -image_path='/Users/xx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/'
   3. 如果关闭了SIP， 直接使用pid即可，./onebot -wechat_pid=18835 -image_path='/Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_xxx/temp/xxx/2026-01/Img/'
   4. 发送一张图片，如果失败证明已经patch成功，可以正常使用。
   5. 启动onebot服务，默认监听127.0.0.1:58080，可以通过http接口发送消息。
   6. 会把收到的消息通过 http://127.0.0.1:36060/onebot 其他参数可用./onebot -h查看


### 接口信息
私聊是send_private_msg     
群聊是send_group_msg       

```
curl -i -X POST \
   -H "Content-Type:application/json" \
   -d \
'{
  "message" : [{
    "data" : {
      "text" : "🚀successfully delete!"
    },
    "type" : "text"
  },{
    "data" : {
      "file" : "base64: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"
    },
    "type" : "image"
  } ],
  "user_id" : "wxid_xxx"
}' \
 'http://127.0.0.1:58080/send_private_msg'
 
返回结果：
{"status":"ok"}

```