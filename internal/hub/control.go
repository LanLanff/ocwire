package hub

import (
	"time"

	"oclink/internal/proto"
)

// 设备连接状态查询与强制断开（供管理页显示“在线 / 占用 / 最近活动”和“断开占用”）。

// DeviceStatus 表示一台设备的连接情况。
type DeviceStatus struct {
	Agent       bool      `json:"agent"`      // B 端是否在线
	Client      bool      `json:"client"`     // A 端是否正在占用
	ClientID    string    `json:"clientId"`   // 当前占用的控制端凭证 ID（在线期间可见）
	ClientName  string    `json:"clientName"` // 当前控制端名字（临时连接，仅在线期间可见）
	ClientSince time.Time `json:"clientSince"`
	Present      bool      `json:"present"`   // A 引擎在线待命（心跳连接，未占用控制通道）
	PresentID    string    `json:"presentId"` // 待命的控制端凭证 ID
	PresentName  string    `json:"presentName"`
	PresentSince time.Time `json:"presentSince"`
	CooldownUntil time.Time `json:"cooldownUntil"` // 管理台「断开占用」后的冷却截止时间
	CooldownID    string    `json:"cooldownId"`    // 冷却针对的控制端凭证
	LastActive  time.Time `json:"lastActive"` // 最近一次有指令流量经过的时间
}

// SetCooldown 设置「断开占用」冷却：冷却期内拒绝该设备的控制端（含待命）重连。
func (t *Tunnel) SetCooldown(deviceID, clientID string, d time.Duration) {
	t.mu.Lock()
	t.cooldowns[deviceID] = coolEntry{clientID: clientID, until: time.Now().Add(d)}
	t.mu.Unlock()
}

// ClearCooldown 取消冷却，允许控制端立即重连。
func (t *Tunnel) ClearCooldown(deviceID string) bool {
	t.mu.Lock()
	_, ok := t.cooldowns[deviceID]
	delete(t.cooldowns, deviceID)
	t.mu.Unlock()
	return ok
}

func (t *Tunnel) cooldown(deviceID string) (coolEntry, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cd, ok := t.cooldowns[deviceID]
	return cd, ok
}

// Status 返回所有已连接设备的状态。
func (t *Tunnel) Status() map[string]DeviceStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := make(map[string]DeviceStatus)
	for id := range t.agents {
		s := m[id]
		s.Agent = true
		m[id] = s
	}
	for id, ep := range t.clients {
		s := m[id]
		s.Client = true
		s.ClientID = ep.clientID
		s.ClientName = ep.name
		s.ClientSince = ep.connectedAt
		m[id] = s
	}
	for id, ep := range t.presences {
		s := m[id]
		s.Present = true
		s.PresentID = ep.clientID
		s.PresentName = ep.name
		s.PresentSince = ep.connectedAt
		m[id] = s
	}
	now := time.Now()
	for id, cd := range t.cooldowns {
		if now.Before(cd.until) {
			s := m[id]
			s.CooldownUntil = cd.until
			s.CooldownID = cd.clientID
			m[id] = s
		}
	}
	for id, ts := range t.lastActive {
		s := m[id]
		s.LastActive = ts
		m[id] = s
	}
	return m
}

// touch 记录某设备最近一次“有流量经过”的时间。
// 中继只看到“有消息要转发”，并不知道内容（密文）。
func (t *Tunnel) touch(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastActive[deviceID] = time.Now()
}

// Kick 强制断开某设备的某个角色连接（管理页“断开占用”用）。
// 返回是否确实断开了一个连接。
func (t *Tunnel) Kick(deviceID, role string) bool {
	t.mu.Lock()
	var ep *endpoint
	if role == "agent" {
		ep = t.agents[deviceID]
	} else {
		ep = t.clients[deviceID]
	}
	t.mu.Unlock()
	if ep == nil {
		return false
	}
	_ = ep.conn.Close()
	return true
}

// KickClientByID 断开某设备上指定凭证的控制端连接（吊销/禁用后立即生效）。
func (t *Tunnel) KickClientByID(deviceID, clientID string) bool {
	t.mu.Lock()
	ep := t.clients[deviceID]
	t.mu.Unlock()
	if ep != nil && ep.clientID == clientID {
		_ = ep.conn.Close()
		return true
	}
	return false
}

// KickPresenceByID 断开某设备的待命连接（clientID 为空表示任意凭证；禁用时立即生效）。
func (t *Tunnel) KickPresenceByID(deviceID, clientID string) bool {
	t.mu.Lock()
	ep := t.presences[deviceID]
	t.mu.Unlock()
	if ep != nil && (clientID == "" || ep.clientID == clientID) {
		_ = ep.conn.Close()
		return true
	}
	return false
}

// NotifyAgent 给在线 B 端推一条状态通知（OK=true 表示已启用，false 表示被禁用）。
func (t *Tunnel) NotifyAgent(deviceID string, enabled bool, msg string) {
	t.mu.Lock()
	ep := t.agents[deviceID]
	t.mu.Unlock()
	if ep == nil {
		return
	}
	env := proto.Envelope{Type: "notice", OK: enabled}
	if !enabled {
		env.Error = msg
	}
	_ = ep.send(env)
}
