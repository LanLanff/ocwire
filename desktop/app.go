package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	qrcode "rsc.io/qr"

	"oclink/internal/agent"
	"oclink/internal/client"
	"oclink/internal/proto"
)

const desktopVersion = "0.2.0"

// State 是前端需要的完整状态。
type State struct {
	Activated  bool   `json:"activated"`
	Name       string `json:"name"`
	DeviceID   string `json:"deviceId,omitempty"`
	Hub        string `json:"hub,omitempty"`
	Running    bool   `json:"running"`
	Connected  bool   `json:"connected"`
	PeerName   string `json:"peerName,omitempty"`
	Autostart  bool   `json:"autostart"`
	Disabled   bool   `json:"disabled"`
	LastError  string `json:"lastError,omitempty"`
	DefaultHub string `json:"defaultHub"`
	Version    string `json:"version"`
	ReadOnly   bool   `json:"readonly"`
}

// App 是 Wails 绑定对象。
type App struct {
	ctx context.Context

	mu        sync.Mutex
	cfg       Config
	act       *activityLog
	ag        *agent.Agent
	running   bool
	runDone   chan struct{}
	connected bool
	peerName  string
	autostart bool
	disabled  bool
	lastError string
	lastRereg      time.Time
	clientsSynced  bool // 本机控制端凭证是否已补登记到当前中继（删除登记后靠它恢复）

	clientOnline map[string]bool // 控制端 ID -> 是否正在连接本机

	quit chan struct{}

	enrolling bool
}

func NewApp() *App {
	cfg := loadConfig()
	return &App{cfg: cfg, act: newActivityLog(), quit: make(chan struct{}), disabled: cfg.Disabled, clientOnline: map[string]bool{}}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.autostart = getAutostart()
	if a.cfg.Autostart != a.autostart {
		_ = setAutostart(a.cfg.Autostart)
		a.autostart = getAutostart()
	}
	a.debugLog("启动: name=%q hub=%q activated=%v", a.cfg.Name, a.cfg.Hub, a.cfg.Key != "")
	if a.cfg.RecoveredKey {
		_ = saveConfig(a.cfg)
		a.debugLog("配置损坏，但密钥已从原文恢复（原文件留档 desktop.json.recovered）")
		a.act.add(ActivityEntry{Kind: "info", Detail: "本地配置损坏，密钥已自动恢复（原文件已留档）"})
	}
	if a.cfg.BrokenIdentity {
		a.debugLog("配置损坏且密钥无法恢复：本次将登记为全新身份")
		a.act.add(ActivityEntry{Kind: "error", Detail: "本地配置损坏且密钥无法恢复（原文件已备份为 desktop.json.broken-*）：本机将登记为新身份，之前配对的控制端需要用新邀请码重新添加"})
		a.emitState()
	}
	go a.heartbeatLoop()
	a.emitState()
	if a.cfg.Key != "" {
		_ = a.startAgent()
	} else {
		// 默认自动接入：首次打开自动登记到内置中继，无需手动激活
		go a.autoActivate()
	}
}

// autoActivate 首次启动自动登记（内置中继）；失败时前端会显示重试入口。
func (a *App) autoActivate() {
	if _, err := a.SelfRegister("", ""); err != nil {
		a.debugLog("自动接入失败: %v", err)
		a.act.add(ActivityEntry{Kind: "error", Detail: "自动接入中继失败: " + err.Error()})
		a.emitState()
		return
	}
	a.debugLog("已自动接入中继")
}

func (a *App) shutdown(context.Context) {
	close(a.quit)
	a.mu.Lock()
	ag := a.ag
	a.mu.Unlock()
	if ag != nil {
		ag.Stop()
	}
}

// debugLog 追加一行诊断日志（排查“运行一段时间后卡死”用；文件超过 2MB 会清空）。
func (a *App) debugLog(format string, args ...any) {
	path := filepath.Join(configDir(), "desktop-debug.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintf(f, time.Now().Format("2006-01-02 15:04:05")+" "+format+"\n", args...)
	f.Close()
}

// heartbeatLoop 每 30 秒记录一次运行状态。
func (a *App) heartbeatLoop() {
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(30 * time.Second):
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		a.mu.Lock()
		running, connected, peer := a.running, a.connected, a.peerName
		a.mu.Unlock()
		a.debugLog("心跳: 运行=%v 连接=%v 对端=%q goroutines=%d heap=%.1fMB sys=%.1fMB",
			running, connected, peer, runtime.NumGoroutine(), float64(ms.HeapAlloc)/1e6, float64(ms.Sys)/1e6)
		if st, err := os.Stat(filepath.Join(configDir(), "desktop-debug.log")); err == nil && st.Size() > 2<<20 {
			_ = os.Remove(filepath.Join(configDir(), "desktop-debug.log"))
		}
	}
}

// ---- 状态 ----

func (a *App) GetState() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stateLocked()
}

func (a *App) stateLocked() State {
	st := State{
		Activated:  a.cfg.Key != "",
		Name:       a.cfg.Name,
		Hub:        a.cfg.Hub,
		Running:    a.running,
		Connected:  a.connected,
		PeerName:   a.peerName,
		Autostart:  a.autostart,
		Disabled:   a.disabled,
		LastError:  a.lastError,
		DefaultHub: agent.DefaultHub,
		Version:    desktopVersion,
		ReadOnly:   a.cfg.ReadOnly,
	}
	if a.cfg.Key != "" {
		if key, err := proto.ParsePairingKey(a.cfg.Key); err == nil {
			st.DeviceID = proto.DeviceID(key)
		}
	}
	return st
}

func (a *App) emitState() {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, "state", a.GetState())
}

// ---- B 端运行 ----

// Start 启动被控端（接入中继，等待控制端连接）。
func (a *App) Start() error { return a.startAgent() }

// Stop 停止被控端。
func (a *App) Stop() error {
	a.stopAgent(3 * time.Second)
	return nil
}

func (a *App) startAgent() error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil
	}
	if a.cfg.Key == "" {
		a.mu.Unlock()
		return errors.New("尚未激活")
	}
	key, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		a.mu.Unlock()
		return fmt.Errorf("配对密钥无效: %w", err)
	}
	cfg := a.cfg
	a.mu.Unlock()

	ag := agent.New(agent.Config{
		Hub:          cfg.Hub,
		Key:          key,
		Fingerprint:  cfg.Fingerprint,
		ReadOnly:     cfg.ReadOnly,
		Root:         cfg.Root,
		Name:         cfg.Name,
		OnEvent:         a.onAgentEvent,
		ClientEncKey:    a.clientEncKey,
		OnMissingDevice: a.reRegister,
	})
	done := make(chan struct{})
	a.mu.Lock()
	a.ag = ag
	a.running = true
	a.runDone = done
	a.mu.Unlock()

	go func() {
		defer close(done)
		ag.Run()
		a.mu.Lock()
		if a.ag == ag {
			a.ag = nil
			a.running = false
			a.connected = false
			a.peerName = ""
		}
		a.mu.Unlock()
		a.emitState()
	}()
	a.emitState()
	return nil
}

func (a *App) stopAgent(wait time.Duration) {
	a.mu.Lock()
	ag := a.ag
	done := a.runDone
	a.mu.Unlock()
	if ag == nil {
		return
	}
	ag.Stop()
	if done != nil {
		select {
		case <-done:
		case <-time.After(wait):
		}
	}
}

// clientEncKey 按控制端凭证 ID 推导该客户端的端到端密钥（只在本机推导，中继永远没有）。
func (a *App) clientEncKey(clientID string) ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.cfg.Clients {
		if c.ID == clientID {
			if c.Disabled {
				return nil, false // 被禁用：拒绝建立会话
			}
			key, err := proto.ParsePairingKey(a.cfg.Key)
			if err != nil {
				return nil, false
			}
			return proto.EncKey(proto.ClientKey(key, clientID)), true
		}
	}
	return nil, false
}

// ClientInfo 是前端要显示的一个控制端凭证。
type ClientInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
	Used      bool   `json:"used"`
	Disabled  bool   `json:"disabled"`
	Online    bool   `json:"online"`
}

// ListClients 列出本机已授权的控制端（含在线/禁用状态）。
func (a *App) ListClients() []ClientInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ClientInfo, 0, len(a.cfg.Clients))
	for _, c := range a.cfg.Clients {
		out = append(out, ClientInfo{
			ID: c.ID, Label: c.Label, CreatedAt: c.CreatedAt,
			Used: c.Used, Disabled: c.Disabled, Online: a.clientOnline[c.ID],
		})
	}
	return out
}

// SetClientDisabled 禁用/启用某个控制端（本机执行：禁用后无法建立会话，并立刻断开当前连接）。
func (a *App) SetClientDisabled(clientID string, disabled bool) error {
	a.mu.Lock()
	found := false
	for i := range a.cfg.Clients {
		if a.cfg.Clients[i].ID == clientID {
			a.cfg.Clients[i].Disabled = disabled
			found = true
		}
	}
	if !found {
		a.mu.Unlock()
		return errors.New("控制端不存在")
	}
	online := a.clientOnline[clientID]
	_ = saveConfig(a.cfg)
	ag := a.ag
	a.mu.Unlock()
	if disabled && online && ag != nil {
		_ = ag.KickClient()
	}
	word := "已启用控制端: "
	if disabled {
		word = "已禁用控制端: "
	}
	a.act.add(ActivityEntry{Kind: "info", Detail: word + clientID})
	a.emitState()
	return nil
}

// CreateInvite 生成一个新的控制端凭证 + 邀请码（一码一机，可单独吊销）。
func (a *App) CreateInvite(label string) (string, error) {
	label = strings.TrimSpace(label)
	a.mu.Lock()
	if a.cfg.Key == "" {
		a.mu.Unlock()
		return "", errors.New("尚未激活")
	}
	deviceKey, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		a.mu.Unlock()
		return "", err
	}
	hub, fp, name := a.cfg.Hub, a.cfg.Fingerprint, a.cfg.Name
	wasRunning := a.running
	a.mu.Unlock()

	clientID, err := proto.NewClientID()
	if err != nil {
		return "", err
	}
	clientKey := proto.ClientKey(deviceKey, clientID)
	authKeyB64 := base64.StdEncoding.EncodeToString(proto.AuthKey(clientKey))

	// 先停掉在线连接，再用一次独立的已鉴权连接登记凭证（避免互相顶掉）
	if wasRunning {
		a.stopAgent(3 * time.Second)
	}
	if err := agent.ProvisionClient(hub, fp, false, deviceKey, clientID, authKeyB64, label); err != nil {
		if wasRunning {
			_ = a.startAgent()
		}
		return "", err
	}
	a.mu.Lock()
	a.clientsSynced = false // 新凭证已登记，后续连接时再整体补同步也无害
	a.cfg.Clients = append(a.cfg.Clients, ClientRec{ID: clientID, Label: label, CreatedAt: time.Now().Format(time.RFC3339)})
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	_ = a.startAgent()

	link := client.EncodeInvite(hub, proto.FormatPairingKey(clientKey), fp, name, proto.DeviceID(deviceKey), clientID, label)
	a.act.add(ActivityEntry{Kind: "info", Detail: "已生成邀请码: " + label + "（" + clientID + "）"})
	a.emitState()
	return link, nil
}

// InviteLink 重新显示某个已授权控制端的邀请码（密钥可以随时从设备密钥推导出来）。
func (a *App) InviteLink(clientID string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.Key == "" {
		return "", errors.New("尚未激活")
	}
	found := false
	label := ""
	for _, c := range a.cfg.Clients {
		if c.ID == clientID {
			found = true
			label = c.Label
			break
		}
	}
	if !found {
		return "", errors.New("控制端不存在")
	}
	deviceKey, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		return "", err
	}
	clientKey := proto.ClientKey(deviceKey, clientID)
	return client.EncodeInvite(a.cfg.Hub, proto.FormatPairingKey(clientKey), a.cfg.Fingerprint, a.cfg.Name, proto.DeviceID(deviceKey), clientID, label), nil
}

// RemoveClient 吊销一个控制端（中继立即失效并断开它的在线连接）。
// 如果中继上本来就查不到这条凭证（清过库/换过中继），本地也直接移除。
func (a *App) RemoveClient(clientID string) error {
	a.mu.Lock()
	if a.cfg.Key == "" {
		a.mu.Unlock()
		return errors.New("尚未激活")
	}
	deviceKey, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	hub, fp := a.cfg.Hub, a.cfg.Fingerprint
	wasRunning := a.running
	a.mu.Unlock()

	if wasRunning {
		a.stopAgent(3 * time.Second)
	}
	if err := agent.RevokeClient(hub, fp, false, deviceKey, clientID); err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "控制端不存在") && !strings.Contains(msg, "设备不存在") {
			if wasRunning {
				_ = a.startAgent()
			}
			return err
		}
	}
	a.mu.Lock()
	a.clientsSynced = false // 凭证已变化，同步标记重置
	kept := a.cfg.Clients[:0]
	for _, c := range a.cfg.Clients {
		if c.ID != clientID {
			kept = append(kept, c)
		}
	}
	a.cfg.Clients = kept
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	_ = a.startAgent()
	a.act.add(ActivityEntry{Kind: "revoke", Detail: "已吊销控制端: " + clientID})
	a.emitState()
	return nil
}

// reRegister 中继上设备不存在时自动重新登记（用同一把密钥；被拉黑则失败）。
func (a *App) reRegister() error {
	a.mu.Lock()
	if a.cfg.Key == "" {
		a.mu.Unlock()
		return errors.New("尚未激活")
	}
	if time.Since(a.lastRereg) < 20*time.Second {
		a.mu.Unlock()
		return errors.New("登记太频繁，稍后重试")
	}
	a.lastRereg = time.Now()
	key, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	hub, fp, name := a.cfg.Hub, a.cfg.Fingerprint, a.cfg.Name
	a.mu.Unlock()

	if err := agent.RegisterSelf(hub, fp, false, key, name); err != nil {
		a.act.add(ActivityEntry{Kind: "error", Detail: "自动重新登记失败: " + err.Error()})
		return err
	}
	a.mu.Lock()
	a.clientsSynced = false // 记录是新登记的，凭证需要补同步
	a.mu.Unlock()
	a.act.add(ActivityEntry{Kind: "info", Detail: "设备在中继上被删除，已自动重新登记"})
	a.emitState()
	return nil
}

// syncClientsToHub 把本机保存的控制端凭证补登记到中继（进程内只做一次；凭证变化后重置）。
func (a *App) syncClientsToHub() {
	a.mu.Lock()
	if a.clientsSynced || a.cfg.Key == "" || a.cfg.Hub == "" {
		a.mu.Unlock()
		return
	}
	key, err := proto.ParsePairingKey(a.cfg.Key)
	if err != nil {
		a.mu.Unlock()
		return
	}
	hub, fp := a.cfg.Hub, a.cfg.Fingerprint
	clients := append([]ClientRec(nil), a.cfg.Clients...)
	a.clientsSynced = true
	a.mu.Unlock()
	for _, c := range clients {
		authKeyB64 := base64.StdEncoding.EncodeToString(proto.AuthKey(proto.ClientKey(key, c.ID)))
		if err := agent.ProvisionClient(hub, fp, false, key, c.ID, authKeyB64, c.Label); err != nil {
			a.mu.Lock()
			a.clientsSynced = false // 失败下轮重试
			a.mu.Unlock()
			return
		}
	}
}

// onAgentEvent 把 agent 事件写成活动记录并推给前端。
func (a *App) onAgentEvent(ev agent.Event) {
	a.mu.Lock()
	switch ev.Type {
	case "peer-up":
		a.connected = true
		a.peerName = ev.Peer
		if ev.ClientID != "" {
			a.clientOnline[ev.ClientID] = true
			// A 端连上来时会自报名字：自动回填到控制端列表（不用手动起名）；并标记邀请码已使用
			for i := range a.cfg.Clients {
				changed := false
				if strings.TrimSpace(ev.Peer) != "" && a.cfg.Clients[i].ID == ev.ClientID && a.cfg.Clients[i].Label != ev.Peer {
					a.cfg.Clients[i].Label = ev.Peer
					changed = true
				}
				if a.cfg.Clients[i].ID == ev.ClientID && !a.cfg.Clients[i].Used {
					a.cfg.Clients[i].Used = true
					changed = true
				}
				if changed {
					_ = saveConfig(a.cfg)
				}
			}
		}
	case "peer-down":
		a.connected = false
		a.peerName = ""
		if ev.ClientID != "" {
			delete(a.clientOnline, ev.ClientID)
		}
	case "disconnected":
		a.clientOnline = map[string]bool{}
	case "request":
		if ev.ClientID != "" {
			a.clientOnline[ev.ClientID] = true
		}
	case "disabled":
		a.disabled = true
		a.lastError = ev.Error
		a.connected = false
		a.peerName = ""
		if !a.cfg.Disabled {
			a.cfg.Disabled = true
			_ = saveConfig(a.cfg)
		}
	case "enabled":
		a.disabled = false
		a.lastError = ""
		if a.cfg.Disabled {
			a.cfg.Disabled = false
			_ = saveConfig(a.cfg)
		}
	case "connected":
		a.lastError = ""
	}
	a.mu.Unlock()

	if ev.Type == "connected" {
		go a.syncClientsToHub() // 中继上的设备记录若被删除重建，把本机凭证补登记回去
	}

	entry := ActivityEntry{
		Time:     ev.Time.Format(time.RFC3339),
		Kind:     ev.Type,
		Peer:     ev.Peer,
		ClientID: ev.ClientID,
		Op:       ev.Op,
		Detail: ev.Detail,
		OK:     ev.OK,
		MS:     ev.Millis,
		Bytes:  int(ev.Bytes),
		Error:  ev.Error,
	}
	switch ev.Type {
	case "connected":
		entry.Detail = "已接入中继"
	case "disconnected":
		entry.Detail = "与中继断开，自动重连中"
	}
	a.act.add(entry)
	if a.ctx != nil {
		wruntime.EventsEmit(a.ctx, "activity", entry)
	}
	// 只有连接状态变化才推 state；普通请求只记活动，降低界面负担。
	if ev.Type != "request" {
		a.emitState()
	}
}

// SetName 改设备名（重启连接以让中继同步显示名）。
func (a *App) SetName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("名字不能为空")
	}
	if len([]rune(name)) > 24 {
		return errors.New("名字最多 24 个字符")
	}
	a.mu.Lock()
	a.cfg.Name = name
	err := saveConfig(a.cfg)
	running := a.running
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if running {
		a.stopAgent(3 * time.Second)
		return a.startAgent()
	}
	a.emitState()
	return nil
}

// DisconnectNow 请求中继断开当前控制端（本机保持在线）。
func (a *App) DisconnectNow() error {
	a.mu.Lock()
	ag := a.ag
	peer := a.peerName
	a.mu.Unlock()
	if ag == nil {
		return errors.New("本机未运行")
	}
	if err := ag.KickClient(); err != nil {
		return err
	}
	a.act.add(ActivityEntry{Kind: "kick", Peer: peer, Detail: "已请求断开当前控制端"})
	return nil
}

// Revoke 吊销配对：通知中继删除本设备，停止运行，清除本机密钥。
func (a *App) Revoke(deleteHistory bool) error {
	a.mu.Lock()
	ag := a.ag
	a.mu.Unlock()

	hubAck := false
	if ag != nil {
		if err := ag.Unregister(); err == nil {
			hubAck = true
			time.Sleep(600 * time.Millisecond) // 等中继处理回执
		}
	}
	a.stopAgent(3 * time.Second)

	a.mu.Lock()
	a.cfg.Hub, a.cfg.Key, a.cfg.Fingerprint = "", "", ""
	_ = saveConfig(a.cfg)
	a.connected = false
	a.peerName = ""
	a.mu.Unlock()

	detail := "已删除设备，本机密钥已清除"
	if ag != nil && !hubAck {
		detail += "（中继未确认，设备条目可能仍在）"
	}
	a.act.add(ActivityEntry{Kind: "revoke", Detail: detail})
	if deleteHistory {
		a.act.clear()
	}
	a.emitState()
	return nil
}

type importCfg struct {
	Hub         string `json:"hub"`
	Key         string `json:"key"`
	DeviceID    string `json:"deviceId"`
	ClientID    string `json:"clientId"`
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ReadOnly    bool   `json:"readonly"`
	Root        string `json:"root"`
}

// ImportConfig 导入 agent.json 内容（B 端身份）；邀请码请到「控制端 → 添加设备」粘贴。
func (a *App) ImportConfig(text string) (State, error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "OCL2:") {
		return a.GetState(), errors.New("这是控制端邀请码：请在「控制端 → 添加设备」里粘贴")
	}
	if strings.HasPrefix(text, "OCL1:") {
		return a.GetState(), errors.New("旧连接码已停用：请在 B 端「生成连接码」重新配对")
	}
	var ic importCfg
	if err := json.Unmarshal([]byte(text), &ic); err != nil {
		return a.GetState(), errors.New("无法识别：请粘贴 agent.json 内容")
	}
	hub, key, fp := ic.Hub, ic.Key, ic.Fingerprint
	name := ic.Name
	if name == "" {
		name = ic.DisplayName
	}
	if hub == "" || key == "" {
		return a.GetState(), errors.New("配置缺少 hub 或 key")
	}
	a.mu.Lock()
	a.cfg.Hub, a.cfg.Key, a.cfg.Fingerprint = hub, key, fp
	if strings.TrimSpace(name) != "" {
		a.cfg.Name = strings.TrimSpace(name)
	}
	err := saveConfig(a.cfg)
	wasRunning := a.running
	a.mu.Unlock()
	if err != nil {
		return a.GetState(), err
	}
	a.act.add(ActivityEntry{Kind: "import", Detail: "导入设备配置: " + a.cfg.Name})
	if wasRunning {
		a.stopAgent(3 * time.Second)
		if err := a.startAgent(); err != nil {
			return a.GetState(), err
		}
	}
	a.emitState()
	return a.GetState(), nil
}

// ---- 设备流激活 / 自助配对 ----

// SelfRegister 自助配对（全盲）：本机生成密钥，只把校验子键登记到中继，立刻拿到连接码。
// 不需要管理台；中继拿不到密钥，A 端凭连接码即可连接。
func (a *App) SelfRegister(target, fingerprint string) (State, error) {
	a.mu.Lock()
	if a.enrolling {
		a.mu.Unlock()
		return a.GetState(), errors.New("正在处理中，请稍候")
	}
	a.enrolling = true
	hub := strings.TrimSpace(target)
	fp := strings.TrimSpace(fingerprint)
	if hub == "" {
		hub = agent.DefaultHub
		if fp == "" {
			fp = agent.DefaultFingerprint
		}
	}
	name := a.cfg.Name
	wasRunning := a.running
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.enrolling = false
		a.mu.Unlock()
	}()

	if hub == "" {
		return a.GetState(), errors.New("缺少中继地址")
	}
	if fp == "" {
		return a.GetState(), errors.New("缺少证书指纹：自建中继请在「高级」里填写")
	}
	key, _, err := proto.NewPairingKey()
	if err != nil {
		return a.GetState(), err
	}
	if err := agent.RegisterSelf(hub, fp, false, key, name); err != nil {
		return a.GetState(), err
	}
	keyText := proto.FormatPairingKey(key)
	a.mu.Lock()
	a.cfg.Hub, a.cfg.Key, a.cfg.Fingerprint = hub, keyText, fp
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	a.act.add(ActivityEntry{Kind: "enroll", Detail: "已生成连接码（自助登记）: " + name})
	// 换了密钥就把旧连接停掉，用新身份重新上线
	if wasRunning {
		a.stopAgent(3 * time.Second)
	}
	_ = a.startAgent()
	a.emitState()
	return a.GetState(), nil
}

// ---- 二维码 / 活动记录 / 自启 ----

// QRImage 把连接码生成二维码（返回 data URL，失败返回空串）。
func (a *App) QRImage(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	code, err := qrcode.Encode(text, qrcode.M)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
}

func (a *App) GetActivity(limit int) []ActivityEntry {
	if limit <= 0 {
		limit = 100
	}
	if limit > 200 {
		limit = 200
	}
	return a.act.tail(limit)
}

// GetActivityBefore 加载更早的记录（beforeMs=当前最旧一条的时间戳毫秒；一次最多 200 条）。
func (a *App) GetActivityBefore(beforeMs int64, limit int) []ActivityEntry {
	return a.act.page(beforeMs, limit)
}

func (a *App) ClearActivity() error {
	a.act.clear()
	return nil
}

// SetAutostart 开机自启开关。
func (a *App) SetAutostart(on bool) (State, error) {
	if err := setAutostart(on); err != nil {
		return a.GetState(), err
	}
	a.mu.Lock()
	a.cfg.Autostart = on
	a.autostart = on
	_ = saveConfig(a.cfg)
	a.mu.Unlock()
	a.emitState()
	return a.GetState(), nil
}
