package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

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

func SendHttpReq(msg map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v, %v\n", r, string(debug.Stack()))
		}
	}()
	
	time.Sleep(time.Duration(config.SendInterval) * time.Millisecond)
	// 这里处理你的 X1 数据
	jsonData, err := json.Marshal(msg["payload"])
	if err != nil {
		log.Printf("JSON 序列化失败: %v\n", err)
		return
	}
	
	fmt.Printf("发送数据: %s\n", string(jsonData))
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
