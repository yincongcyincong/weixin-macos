package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/template"
	"time"
	
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
	GroupId string  `json:"group_id"`
	SelfID  string  `json:"self_id"`
	UserID  string  `json:"user_id"`
	Sender  *Sender `json:"sender"`
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
	Id   string `json:"id"`
	Text string `json:"text"`
	File string `json:"file"`
	QQ   string `json:"qq"`
}

type Config struct {
	FridaType       string `json:"frida_type"`
	SendURL         string `json:"send_url"`
	ReceiveHost     string `json:"receive_host"`
	FridaGadgetAddr string `json:"frida_gadget_addr"`
	WechatPid       int    `json:"wechat_pid"`
	OnebotToken     string `json:"onebot_token"`
	ImagePath       string `json:"image_path"`
	
	WechatConf string `json:"wechat_conf"`
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
	
	flag.Parse()
	
	fmt.Println("FridaType", config.FridaType)
	fmt.Println("SendURL", config.SendURL)
	fmt.Println("ReceiveHost", config.ReceiveHost)
	fmt.Println("FridaGadgetAddr", config.FridaGadgetAddr)
	fmt.Println("WechatPid", config.WechatPid)
	fmt.Println("OnebotToken", config.OnebotToken)
	fmt.Println("ImagePath", config.ImagePath)
	fmt.Println("WechatConf", config.WechatConf)
	
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
							go SendHttpReq(msg)
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

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	
	req := new(SendRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "无效的 JSON", http.StatusBadRequest)
		return
	}
	
	// 参数校验
	if len(req.Message) == 0 || (req.UserID == "" && req.GroupID == "") {
		http.Error(w, "参数缺失", http.StatusBadRequest)
		return
	}
	
	sendContent := ""
	atUserID := ""
	for _, v := range req.Message {
		if v.Type == "text" {
			sendContent += v.Data.Text
		} else if v.Type == "at" {
			if req.GroupID != "" {
				if nicknameInter, ok := userID2NicknameMap.Load(req.GroupID + "_" + v.Data.QQ); ok {
					sendContent += fmt.Sprintf("@%s\u2005", nicknameInter.(string))
					atUserID += v.Data.QQ + ","
				}
			}
			
		} else if v.Type == "image" {
			msgChan <- &SendMsg{
				UserId:  req.UserID,
				GroupID: req.GroupID,
				Content: v.Data.File,
				Type:    v.Type,
			}
		}
	}
	
	if sendContent != "" {
		msgChan <- &SendMsg{
			UserId:  req.UserID,
			GroupID: req.GroupID,
			Content: sendContent,
			Type:    "text",
			AtUser:  strings.TrimRight(atUserID, ","),
		}
	}
	
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
	})
}

func SendWorker() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("💥 SendWorker 异常: %v\n", err)
			go SendWorker()
		}
	}()
	
	for {
		select {
		case <-finishChan:
			fmt.Printf("收到完成信号 \n")
		case m, ok := <-msgChan:
			if !ok {
				return
			}
			SendWechatMsg(m)
		}
	}
}

func SendWechatMsg(m *SendMsg) {
	time.Sleep(1 * time.Second)
	currTaskId := atomic.AddInt64(&taskId, 1)
	log.Printf("📩 收到任务: %d\n", currTaskId)
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	targetId := m.UserId
	if m.GroupID != "" && targetId == "" {
		targetId = m.GroupID
	}
	
	switch m.Type {
	case "text":
		result := fridaScript.ExportsCall("triggerSendTextMessage", currTaskId, targetId, m.Content, m.AtUser)
		log.Printf("📩 发送文本任务执行结果：%s, 参数：currTaskId: %d, targetId: %s, content: %s, atUser: %s\n",
			result, currTaskId, targetId, m.Content, m.AtUser)
	case "image":
		targetPath, md5Str, err := SaveBase64Image(m.Content)
		if err != nil {
			log.Printf("保存图片失败: %v\n", err)
			return
		}
		
		result := fridaScript.ExportsCall("triggerUploadImg", targetId, md5Str, targetPath)
		log.Printf("📩 上传图片任务执行结果%s, 参数：targetId: %s, md5Str: %s, targetPath: %s\n", result, targetId, md5Str, targetPath)
	case "send_image":
		result := fridaScript.ExportsCall("triggerSendImgMessage", currTaskId, myWechatId, targetId)
		log.Printf("📩 发送图片任务执行结果%s, 参数：currTaskId: %d, myWechatId: %s, targetId: %s\n", result, currTaskId, myWechatId, targetId)
	}
	
	select {
	case <-ctx.Done():
		log.Printf("任务 %d 执行超时！\n", currTaskId)
	case <-finishChan:
		log.Printf("收到完成信号，任务 %d 完成\n", currTaskId)
	}
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

func SendHttpReq(msg map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v\n", r)
		}
	}()
	
	time.Sleep(1 * time.Second)
	// 这里处理你的 X1 数据
	jsonData, err := json.Marshal(msg["payload"])
	if err != nil {
		log.Printf("JSON 序列化失败: %v\n", err)
		return
	}
	
	fmt.Printf("发送数据: %s\n", string(jsonData))
	if myWechatId == "" {
		m := new(WechatMessage)
		err = json.Unmarshal(jsonData, m)
		if err != nil {
			log.Printf("解析消息失败: %v\n", err)
			return
		}
		myWechatId = m.SelfID
		
		if m.GroupId != "" {
			userID2NicknameMap.Store(m.GroupId+"_"+m.UserID, m.Sender.Nickname)
		}
	}
	
	// 4. 创建 POST 请求
	req, err := http.NewRequest("POST", config.SendURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	
	// 5. 设置 Header (OneBot 接口通常要求 application/json)
	h := hmac.New(sha1.New, []byte(config.OnebotToken))
	h.Write(jsonData)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", "sha1="+hex.EncodeToString(h.Sum(nil)))
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	// 6. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求执行失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	// 7. 读取返回结果
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取响应失败: %v\n", err)
		return
	}
	
	fmt.Printf("状态码: %d 返回内容: %s\n", resp.StatusCode, string(body))
}

func SaveBase64Image(base64Data string) (string, string, error) {
	rawContents := base64Data
	if strings.HasPrefix(base64Data, "base64://") {
		rawContents = strings.TrimPrefix(base64Data, "base64://")
	} else if idx := strings.Index(base64Data, ","); idx != -1 {
		rawContents = base64Data[idx+1:]
	}
	
	data, err := base64.StdEncoding.DecodeString(rawContents)
	if err != nil {
		return "", "", fmt.Errorf("base64 decode failed: %v", err)
	}
	salt := []byte(fmt.Sprintf("\n#md5_salt_%d_%d#", time.Now().UnixNano(), rand.Intn(10000)))
	data = append(data, salt...)
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomNumber := r.Intn(1000) // 生成 0-999 的随机数
	timestamp := time.Now().Unix()
	fileName := fmt.Sprintf("%d_%d.%s", randomNumber, timestamp, DetectImageFormat(data))
	targetPath := config.ImagePath + fileName
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", "", fmt.Errorf("create directory failed: %v", err)
	}
	
	err = os.WriteFile(targetPath, data, 0644)
	if err != nil {
		return "", "", fmt.Errorf("write file failed: %v", err)
	}
	
	md5Str, err := GetFileMD5(targetPath)
	if err != nil {
		return "", "", fmt.Errorf("get file md5 failed: %v", err)
	}
	
	return targetPath, md5Str, nil
}

func GetFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func DetectImageFormat(data []byte) string {
	if len(data) < 12 {
		return "unknown"
	}
	
	switch {
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "jpg"
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}):
		return "png"
	case bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a")):
		return "gif"
	case bytes.HasPrefix(data, []byte{0x42, 0x4D}):
		return "bmp"
	case bytes.HasPrefix(data, []byte("RIFF")) && bytes.HasPrefix(data[8:], []byte("WEBP")):
		return "webp"
	default:
		return "unknown"
	}
}
