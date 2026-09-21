package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"oclink/internal/client"
	"oclink/internal/proto"
)

// ProfileInfo 是 A 端目标列表里的一项（对应 ~/.config/oc-link/config.json 的 profiles）。
type ProfileInfo struct {
	Name       string `json:"name"`
	Hub        string `json:"hub"`
	DeviceID   string `json:"deviceId,omitempty"`
	Token      bool   `json:"token"`
	CanOperate bool   `json:"canOperate"`
}

type aProfile struct {
	Hub         string
	Key         string
	DeviceID    string
	ClientID    string
	Fingerprint string
	Token       string
	Insecure    bool
	CanOperate  bool
}

func readADoc() map[string]any {
	m := map[string]any{}
	raw, err := os.ReadFile(aConfigPath())
	if err != nil {
		return m
	}
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func writeADoc(m map[string]any) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(aConfigPath(), raw, 0o600)
}

func aProfilesOf(m map[string]any, create bool) map[string]any {
	ps, _ := m["profiles"].(map[string]any)
	if ps == nil && create {
		ps = map[string]any{}
		m["profiles"] = ps
	}
	return ps
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func profileOf(doc map[string]any, name string) (aProfile, bool) {
	ps := aProfilesOf(doc, false)
	raw, ok := ps[name].(map[string]any)
	if !ok {
		return aProfile{}, false
	}
	p := aProfile{
		Hub:         strOf(raw["hub"]),
		Key:         strOf(raw["key"]),
		DeviceID:    strOf(raw["deviceId"]),
		ClientID:    strOf(raw["clientId"]),
		Fingerprint: strOf(raw["fingerprint"]),
		Token:       strOf(raw["token"]),
		Insecure:    raw["insecure"] == true,
		CanOperate:  true,
	}
	if v, ok := raw["canOperate"].(bool); ok {
		p.CanOperate = v
	}
	if p.Hub == "" || p.Key == "" || p.ClientID == "" {
		return aProfile{}, false
	}
	return p, true
}

// ListProfiles 列出 A 端目标（展示 DeviceID 前 12 位，不显示密钥）。
func (a *App) ListProfiles() []ProfileInfo {
	doc := readADoc()
	ps := aProfilesOf(doc, false)
	names := make([]string, 0, len(ps))
	for n := range ps {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]ProfileInfo, 0, len(names))
	for _, n := range names {
		p, ok := profileOf(doc, n)
		if !ok {
			continue
		}
		info := ProfileInfo{Name: n, Hub: p.Hub, Token: p.Token != "", CanOperate: p.CanOperate}
		if p.DeviceID != "" {
			id := p.DeviceID
			if len(id) > 12 {
				id = id[:12]
			}
			info.DeviceID = id
		}
		out = append(out, info)
	}
	return out
}

// AddProfile 用连接码新增一个控制目标，返回最终使用的名字。
func (a *App) AddProfile(code string) (string, error) {
	code = strings.TrimSpace(code)
	p, name, err := client.DecodeLink(code)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "设备"
	}
	doc := readADoc()
	ps := aProfilesOf(doc, true)
	base := name
	for i := 2; ps[name] != nil; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	ps[name] = map[string]any{
		"hub":         p.Hub,
		"key":         p.Key,
		"deviceId":    p.DeviceID,
		"clientId":    p.ClientID,
		"fingerprint": p.Fingerprint,
	}
	if err := writeADoc(doc); err != nil {
		return "", err
	}
	a.act.add(ActivityEntry{Kind: "import", Detail: "新增控制目标: " + name})
	return name, nil
}

// DeleteProfile 删除一个控制目标（只删本机配置，不影响被控端）。
func (a *App) DeleteProfile(name string) error {
	doc := readADoc()
	ps := aProfilesOf(doc, false)
	if ps[name] == nil {
		return errors.New("未找到目标: " + name)
	}
	delete(ps, name)
	if err := writeADoc(doc); err != nil {
		return err
	}
	a.act.add(ActivityEntry{Kind: "info", Detail: "删除控制目标: " + name})
	return nil
}

// managerRequest 尝试通过本机连接管理器（OpenChamber 插件进程）发请求，
// 避免与面板里的长连接互相顶掉。返回 (响应, 是否已由管理器处理, 错误)。
func managerRequest(name string, req proto.Request, timeout time.Duration) (proto.Response, bool, error) {
	var resp proto.Response
	raw, err := os.ReadFile(filepath.Join(configDir(), "manager.json"))
	if err != nil {
		return resp, false, nil
	}
	var info struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Port == 0 || info.Token == "" {
		return resp, false, nil
	}
	body, _ := json.Marshal(map[string]any{"name": name, "request": req, "timeoutMs": timeout.Milliseconds()})
	httpReq, err := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/request", info.Port), bytes.NewReader(body))
	if err != nil {
		return resp, false, nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+info.Token)
	hc := &http.Client{Timeout: timeout + 5*time.Second}
	r, err := hc.Do(httpReq)
	if err != nil {
		return resp, false, nil // 管理器不在（连接被拒）→ 回退直连
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if r.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("连接管理器错误 HTTP %d", r.StatusCode)
		}
		return resp, true, errors.New(e.Error)
	}
	if json.Unmarshal(data, &resp) != nil {
		return resp, true, errors.New("连接管理器响应解析失败")
	}
	return resp, true, nil
}

// clientNameOf 读取控制端名字（config.json 的 clientName，默认本机计算机名）。
func clientNameOf(doc map[string]any) string {
	if v, ok := doc["clientName"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "控制端"
	}
	return h
}

// GetClientName 返回控制端名字（B 端会显示）。
func (a *App) GetClientName() string {
	return clientNameOf(readADoc())
}

// SetClientName 修改控制端名字；B 端重连后显示新名字。
func (a *App) SetClientName(name string) error {
	name = strings.TrimSpace(name)
	if len([]rune(name)) > 24 {
		return errors.New("名字最多 24 个字符")
	}
	doc := readADoc()
	if name == "" {
		delete(doc, "clientName")
	} else {
		doc["clientName"] = name
	}
	return writeADoc(doc)
}

// friendlyClientError 把底层错误翻译成用户能看懂的提示。
func friendlyClientError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "设备不存在"):
		return errors.New("设备在中继上不存在：B 端可能重新登记过或被删除，请在 B 端重新生成邀请码，并在「控制端」删掉旧目标后重新添加")
	case strings.Contains(msg, "控制端凭证无效或已被吊销"):
		return errors.New("邀请码已失效：B 端已删除这个控制端，请在 B 端重新生成邀请码")
	case strings.Contains(msg, "控制端未携带凭证"):
		return errors.New("这是旧连接码（OCL1 已停用）：请在 B 端重新生成邀请码")
	case strings.Contains(msg, "已被中继禁用"):
		return errors.New("该设备已被中继管理员禁用（在管理台「启用」后恢复）")
	case strings.Contains(msg, "对端不在线"), strings.Contains(msg, "对端离线"):
		return errors.New("B 端当前不在线：请确认那台电脑的客户端在运行并已接入中继")
	}
	return err
}

// TestProfile 对目标发一次 ping，返回 "在线 · xx ms"。
func (a *App) TestProfile(name string) (string, error) {
	doc := readADoc()
	p, ok := profileOf(doc, name)
	if !ok {
		return "", errors.New("未找到目标: " + name)
	}
	req := proto.Request{Op: "ping", ID: "desktop"}
	start := time.Now()
	resp, handled, err := managerRequest(name, req, 20*time.Second)
	if !handled {
		resp, err = client.Request(client.Profile{
			Hub:         p.Hub,
			Key:         p.Key,
			DeviceID:    p.DeviceID,
			ClientID:    p.ClientID,
			Fingerprint: p.Fingerprint,
			Token:       p.Token,
			DisplayName: clientNameOf(doc),
			Insecure:    p.Insecure,
		}, req, 20*time.Second)
	}
	if err != nil {
		return "", friendlyClientError(err)
	}
	ms := time.Since(start).Milliseconds()
	if !resp.OK {
		if resp.Error != "" {
			return "", errors.New(resp.Error)
		}
		return "", errors.New("对端返回失败")
	}
	return fmt.Sprintf("在线 · %d ms", ms), nil
}
