package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/template"
	
	"github.com/frida/frida-go/frida"
)

// 全局变量，保持 Frida 脚本对象
var (
	fridaScript *frida.Script
	session     *frida.Session
	taskId      = int64(0x20000000)
	myWechatId  = ""
	
	msgChan    = make(chan *SendMsg, 10)
	finishChan = make(chan struct{})
	
	config = &Config{}
	
	userID2NicknameMap sync.Map
)

type WechatMessage struct {
	GroupId   string     `json:"group_id"`
	SelfID    string     `json:"self_id"`
	UserID    string     `json:"user_id"`
	Sender    *Sender    `json:"sender"`
	Time      int64      `json:"time"`
	PostType  string     `json:"post_type"`
	MessageId string     `json:"message_id"`
	Message   []*Message `json:"message"`
}

type Sender struct {
	UserID   string `json:"user_id"`
	Nickname string `json:"nickname"`
}

type SendMsg struct {
	UserId  string
	GroupID string
	Content string
	Type    string
	AtUser  string
}

// SendRequest 请求结构体
type SendRequest struct {
	Message []*Message `json:"message"`
	UserID  string     `json:"user_id"`
	GroupID string     `json:"group_id"`
}

type Message struct {
	Type string           `json:"type"`
	Data *SendRequestData `json:"data"`
}

type SendRequestData struct {
	Id    string `json:"id"`
	Text  string `json:"text"`
	File  string `json:"file"`
	URL   string `json:"url"`
	QQ    string `json:"qq"`
	Media []byte `json:"media"`
}

type Config struct {
	FridaType       string `json:"frida_type"`
	SendURL         string `json:"send_url"`
	ReceiveHost     string `json:"receive_host"`
	FridaGadgetAddr string `json:"frida_gadget_addr"`
	WechatPid       int    `json:"wechat_pid"`
	OnebotToken     string `json:"onebot_token"`
	ImagePath       string `json:"image_path"`
	ConnType        string `json:"conn_type"`
	SendInterval    int    `json:"send_interval"`
	
	WechatConf string `json:"wechat_conf"`
}

func main() {
	initFlag()
	if config.FridaType == "gadget" {
		initFridaGadget()
	} else {
		initFrida()
	}
	go SendWorker()
	
	http.HandleFunc("/send_private_msg", sendHandler)
	http.HandleFunc("/send_group_msg", sendHandler)
	
	http.HandleFunc("/ws", handleWebSocket)
	http.HandleFunc("/test_ws", testWebSocket)
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-stop
		log.Fatalf("\n正在释放 Frida 资源并退出...")
	}()
	
	// 3. 启动服务
	fmt.Printf("HTTP 服务启动在 %s", config.ReceiveHost)
	if err := http.ListenAndServe(config.ReceiveHost, nil); err != nil {
		log.Printf("服务启动失败: %v\n", err)
	}
	
}

func initFlag() {
	flag.StringVar(&config.FridaType, "type", "local", "frida 类型: local | gadget")
	flag.StringVar(&config.SendURL, "send_url", "http://127.0.0.1:36060/onebot", "发送消息的 URL: http://127.0.0.1:36060/onebot")
	flag.StringVar(&config.ReceiveHost, "receive_host", "127.0.0.1:58080", "接收消息的地址: 127.0.0.1:58080")
	flag.StringVar(&config.FridaGadgetAddr, "gadget_addr", "127.0.0.1:27042", "Gadget 地址: 127.0.0.1:27042 仅当 type 为 gadget 时有效")
	flag.IntVar(&config.WechatPid, "wechat_pid", 0, "微信进程 ID: 58183, 仅当 type 为 local 时有效")
	flag.StringVar(&config.OnebotToken, "token", "MuseBot", "OneBot Token: MuseBot")
	flag.StringVar(&config.ImagePath, "image_path", "", "图片路径: /Users/xxx/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/xxx/temp/xxx/2026-01/Img/")
	flag.StringVar(&config.WechatConf, "wechat_conf", "../wechat_version/4_1_7_55_mac.json", "微信配置文件路径: ../wechat_version/4_1_6_12_mac.json")
	flag.StringVar(&config.ConnType, "conn_type", "http", "连接类型: http | websocket")
	flag.IntVar(&config.SendInterval, "send_interval", 1000, "发送间隔: ms")
	
	flag.Parse()
	
	fmt.Println("FridaType", config.FridaType)
	fmt.Println("SendURL", config.SendURL)
	fmt.Println("ReceiveHost", config.ReceiveHost)
	fmt.Println("FridaGadgetAddr", config.FridaGadgetAddr)
	fmt.Println("WechatPid", config.WechatPid)
	fmt.Println("OnebotToken", config.OnebotToken)
	fmt.Println("ImagePath", config.ImagePath)
	fmt.Println("WechatConf", config.WechatConf)
	
	EnsureDir("./audio")
}

func initFridaGadget() {
	mgr := frida.NewDeviceManager()
	// 连接到 Gadget 默认端口
	device, err := mgr.AddRemoteDevice(config.FridaGadgetAddr, frida.NewRemoteDeviceOptions())
	if err != nil {
		log.Fatalf("❌ 无法连接 Gadget: %v\n", err)
	}
	
	session, err = device.Attach("Gadget", nil)
	if err != nil {
		log.Fatalf("❌ 附加失败: %v\n", err)
	}
	
	loadJs()
	
}

func initFrida() {
	// 1. 获取本地设备管理器
	mgr := frida.NewDeviceManager()
	
	// 2. 枚举并获取本地设备 (TypeLocal)
	device, err := mgr.DeviceByType(frida.DeviceTypeLocal)
	if err != nil {
		log.Fatalf("无法获取本地设备: %v", err)
	}
	
	fmt.Printf("正在尝试 Attach 到微信...")
	session, err = device.Attach(config.WechatPid, nil)
	if err != nil {
		log.Fatalf("Attach 失败 (请检查 SIP 状态或权限): %v", err)
	}
	
	loadJs()
}

func loadJs() {
	jsonData, err := os.ReadFile(config.WechatConf)
	if err != nil {
		log.Fatalf("读取文件失败: %v\n", err)
	}
	
	// 2. 将 JSON 解析为 Map
	var wechatHookConf map[string]interface{}
	if err := json.Unmarshal(jsonData, &wechatHookConf); err != nil {
		log.Fatalf("解析 JSON 失败: %v\n", err)
	}
	
	codeTemplate, err := os.ReadFile("./script.js")
	if err != nil {
		log.Fatalf("读取脚本失败: %v\n", err)
	}
	
	tmpl, err := template.New("fridaScript").Parse(string(codeTemplate))
	if err != nil {
		fmt.Printf("解析模板失败: %v\n", err)
		return
	}
	
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, wechatHookConf)
	if err != nil {
		log.Fatalf("执行模板失败: %v\n", err)
	}
	
	script, err := session.CreateScript(buf.String())
	if err != nil {
		log.Fatalf("❌ 创建脚本失败: %v\n", err)
	}
	
	// 打印 JS 里的 console.log
	script.On("message", func(rawMsg string) {
		var msg map[string]interface{}
		json.Unmarshal([]byte(rawMsg), &msg)
		
		msgType := msg["type"].(string)
		
		switch msgType {
		case "send":
			if p, ok := msg["payload"]; ok {
				if pMap, ok := p.(map[string]interface{}); ok {
					if t, ok := pMap["type"]; ok {
						switch t.(string) {
						case "send":
							if config.ConnType == "http" {
								go SendHttpReq(msg)
							} else {
								go SendWebSocketMsg(msg)
							}
						case "finish":
							finishChan <- struct{}{}
						case "upload":
							if selfId, ok := pMap["self_id"]; ok && myWechatId == "" {
								fmt.Printf("✅ 检测到微信登录，当前账号: %s\n", selfId.(string))
								myWechatId = selfId.(string)
							}
						case "upload_finish":
							m := &SendMsg{
								Type: "send_image",
							}
							if targetIdInter, ok := pMap["target_id"]; ok {
								targetIdStr := targetIdInter.(string)
								if strings.Contains(targetIdStr, "wxid_") {
									m.UserId = targetIdStr
								} else {
									m.GroupID = targetIdStr
								}
							}
							msgChan <- m
						}
						
					}
				}
			}
		case "log":
			// 这里处理 console.log
			log.Printf("[JS日志] %s\n", msg["payload"])
		case "error":
			// 这里处理 JS 脚本报错
			log.Printf("[❌脚本报错] %s\n", msg["description"])
		}
	})
	
	if err := script.Load(); err != nil {
		log.Fatalf("❌ 加载脚本失败: %v\n", err)
	}
	
	fridaScript = script
	fmt.Printf("✅ Frida 已就绪，微信控制通道已打通")
}
