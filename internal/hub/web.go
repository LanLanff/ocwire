package hub

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AdminHandler 是管理台（设备状态 / 审计 / 发布下载）。
// 全盲模式：没有用户、没有密钥保管，登录只用管理密码。
type AdminHandler struct {
	password string
	store    *Store
	tunnel   *Tunnel
	audit    *Auditor
	releases *ReleaseServer

	mu          sync.Mutex
	sessions    map[string]time.Time
	loginGuards map[string]*loginGuard
}

type loginGuard struct {
	fails        int
	blockedUntil time.Time
}

// NewAdminHandler 创建管理台。
func NewAdminHandler(store *Store, tunnel *Tunnel, password string) *AdminHandler {
	return &AdminHandler{
		password:    password,
		store:       store,
		tunnel:      tunnel,
		sessions:    map[string]time.Time{},
		loginGuards: map[string]*loginGuard{},
	}
}

// SetOps 挂上审计与发布服务（启动时调用一次）。
func (h *AdminHandler) SetOps(audit *Auditor, releases *ReleaseServer) {
	h.audit = audit
	h.releases = releases
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	p := r.URL.Path
	switch {
	case p == "/" && r.Method == http.MethodGet:
		h.page(w, r)
	case p == "/api/login" && r.Method == http.MethodPost:
		h.login(w, r)
	case p == "/api/logout" && r.Method == http.MethodPost:
		h.logout(w, r)
	case p == "/api/me" && r.Method == http.MethodGet:
		h.me(w, r)
	case p == "/health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "oc-link-hub", "devices": len(h.store.List())})
	case p == "/api/devices" && r.Method == http.MethodGet:
		h.list(w, r)
	case p == "/api/clients" && r.Method == http.MethodGet:
		h.clients(w, r)
	case strings.HasPrefix(p, "/api/clients/"):
		if strings.HasSuffix(p, "/disable") && r.Method == http.MethodPost {
			h.clientSetDisabled(w, r, true)
		} else if strings.HasSuffix(p, "/enable") && r.Method == http.MethodPost {
			h.clientSetDisabled(w, r, false)
		} else {
			http.NotFound(w, r)
		}
	case strings.HasPrefix(p, "/api/devices/"):
		if strings.HasSuffix(p, "/kick") && r.Method == http.MethodPost {
			h.kick(w, r)
		} else if strings.HasSuffix(p, "/allow") && r.Method == http.MethodPost {
			h.allow(w, r)
		} else if strings.HasSuffix(p, "/forget") && r.Method == http.MethodPost {
			h.forget(w, r)
		} else if strings.HasSuffix(p, "/disable") && r.Method == http.MethodPost {
			h.disable(w, r)
		} else if strings.HasSuffix(p, "/enable") && r.Method == http.MethodPost {
			h.enable(w, r)
		} else {
			http.NotFound(w, r)
		}
	case p == "/api/audit" && r.Method == http.MethodGet:
		h.auditList(w, r)
	case p == "/api/agent/latest" && r.Method == http.MethodGet:
		if h.releases == nil {
			http.NotFound(w, r)
			return
		}
		h.releases.ServeLatest(w, r)
	case p == "/api/agent/latest.sig" && r.Method == http.MethodGet:
		if h.releases == nil {
			http.NotFound(w, r)
			return
		}
		h.releases.ServeSig(w, r)
	case strings.HasPrefix(p, "/api/agent/files/"):
		if h.releases == nil {
			http.NotFound(w, r)
			return
		}
		h.releases.ServeFile(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- 会话 ----

func (h *AdminHandler) authed(r *http.Request) bool {
	c, err := r.Cookie("ocl_session")
	if err != nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	exp, ok := h.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(h.sessions, c.Value)
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *AdminHandler) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	ip := clientIP(r)
	now := time.Now()
	h.mu.Lock()
	g := h.loginGuards[ip]
	if g == nil {
		g = &loginGuard{}
		h.loginGuards[ip] = g
	}
	if now.Before(g.blockedUntil) {
		h.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "尝试次数过多，请稍后再试"})
		return
	}
	h.mu.Unlock()

	// 账号固定为 admin，密码是管理密码
	userOK := strings.EqualFold(strings.TrimSpace(body.Username), "admin")
	passOK := subtle.ConstantTimeCompare([]byte(body.Password), []byte(h.password)) == 1
	if !userOK || !passOK {
		h.mu.Lock()
		g.fails++
		if g.fails >= 5 {
			g.blockedUntil = now.Add(30 * time.Second)
			g.fails = 0
		}
		h.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "账号或密码错误"})
		return
	}

	h.mu.Lock()
	g.fails = 0
	token := make([]byte, 24)
	_, _ = rand.Read(token)
	id := base64.RawURLEncoding.EncodeToString(token)
	h.sessions[id] = time.Now().Add(24 * time.Hour)
	h.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "ocl_session",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *AdminHandler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("ocl_session"); err == nil {
		h.mu.Lock()
		delete(h.sessions, c.Value)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "ocl_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *AdminHandler) me(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": "admin", "role": "owner", "isAdmin": true})
}

// ---- 设备 API ----

func (h *AdminHandler) list(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	st := h.tunnel.Status()
	type row struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		AgentOnline   bool   `json:"agentOnline"`
		ClientOnline  bool   `json:"clientOnline"`
		ClientName    string `json:"clientName,omitempty"`
		ClientSince   string `json:"clientSince,omitempty"`
		CooldownUntil string `json:"cooldownUntil,omitempty"`
		CooldownID    string `json:"cooldownId,omitempty"`
		CreatedAt     string `json:"createdAt"`
		LastSeen      string `json:"lastSeen"`
		LastActive    string `json:"lastActive"`
		Disabled      bool   `json:"disabled"`
	}
	out := []row{}
	for _, d := range h.store.List() {
		s := st[d.ID]
		item := row{
			ID: d.ID, Name: d.Name,
			AgentOnline: s.Agent, ClientOnline: s.Client,
			CreatedAt: d.CreatedAt.Format(time.RFC3339),
			Disabled:  h.store.IsBanned(d.ID),
		}
		if !d.LastSeen.IsZero() {
			item.LastSeen = d.LastSeen.Format(time.RFC3339)
		}
		if s.Client {
			item.ClientName = s.ClientName
			if !s.ClientSince.IsZero() {
				item.ClientSince = s.ClientSince.Format(time.RFC3339)
			}
		}
		if !s.CooldownUntil.IsZero() {
			item.CooldownUntil = s.CooldownUntil.Format(time.RFC3339)
			item.CooldownID = s.CooldownID
		}
		if !s.LastActive.IsZero() {
			item.LastActive = s.LastActive.Format(time.RFC3339)
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// clients 列出每台设备已授权的控制端凭证（只含公开信息，绝不返回校验子键）。
func (h *AdminHandler) clients(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	st := h.tunnel.Status()
	type clientRow struct {
		ID            string `json:"id"`
		Label         string `json:"label,omitempty"`
		Name          string `json:"name,omitempty"`
		CreatedAt     string `json:"createdAt,omitempty"`
		LastSeen      string `json:"lastSeen,omitempty"`
		Since         string `json:"since,omitempty"`
		CooldownUntil string `json:"cooldownUntil,omitempty"`
		Online        bool   `json:"online"`
		Controlling   bool   `json:"controlling"`
		Disabled      bool   `json:"disabled"`
	}
	type deviceRow struct {
		ID      string      `json:"id"`
		Name    string      `json:"name"`
		Clients []clientRow `json:"clients"`
	}
	out := []deviceRow{}
	for _, d := range h.store.List() {
		if len(d.Clients) == 0 {
			continue
		}
		s := st[d.ID]
		row := deviceRow{ID: d.ID, Name: d.Name, Clients: []clientRow{}}
		for _, c := range d.Clients {
			controlling := s.Client && s.ClientID == c.ID
			present := s.Present && s.PresentID == c.ID
			cr := clientRow{ID: c.ID, Label: c.Label, Online: controlling || present, Controlling: controlling, Disabled: c.Disabled}
			if controlling {
				cr.Name = s.ClientName
				if !s.ClientSince.IsZero() {
					cr.Since = s.ClientSince.Format(time.RFC3339)
				}
			} else if present {
				cr.Name = s.PresentName
				if !s.PresentSince.IsZero() {
					cr.Since = s.PresentSince.Format(time.RFC3339)
				}
			}
			if !c.CreatedAt.IsZero() {
				cr.CreatedAt = c.CreatedAt.Format(time.RFC3339)
			}
			if !c.LastSeen.IsZero() {
				cr.LastSeen = c.LastSeen.Format(time.RFC3339)
			}
			if !s.CooldownUntil.IsZero() && s.CooldownID == c.ID {
				cr.CooldownUntil = s.CooldownUntil.Format(time.RFC3339)
			}
			row.Clients = append(row.Clients, cr)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// clientSetDisabled 禁用/启用某个控制端凭证（禁用时立即踢下线）。
func (h *AdminHandler) clientSetDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	deviceID, clientID := parts[0], parts[1]
	if err := h.store.SetClientDisabled(deviceID, clientID, disabled); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	devName := ""
	for _, d := range h.store.List() {
		if d.ID == deviceID {
			devName = d.Name
			break
		}
	}
	if disabled {
		h.tunnel.KickClientByID(deviceID, clientID)
		h.tunnel.KickPresenceByID(deviceID, clientID)
	}
	if h.audit != nil {
		action := "client-disable"
		if !disabled {
			action = "client-enable"
		}
		h.audit.Log(AuditEntry{Action: action, Device: deviceID, DeviceName: devName, Detail: clientID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *AdminHandler) kick(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/kick")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少设备ID"})
		return
	}
	ok := false
	st := h.tunnel.Status()[id]
	if st.Client {
		// 踢下线并进入 5 分钟冷却：期间拒绝该设备的控制端重连，避免「秒回来」
		h.tunnel.SetCooldown(id, st.ClientID, 5*time.Minute)
	}
	ok = h.tunnel.Kick(id, "client")
	if h.audit != nil {
		h.audit.Log(AuditEntry{Action: "kick", Device: id, Detail: "管理台断开占用（冷却 5 分钟）"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "cooldownSeconds": 300})
}

// allow 取消「断开占用」冷却，允许控制端立即重连。
func (h *AdminHandler) allow(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/allow")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少设备ID"})
		return
	}
	ok := h.tunnel.ClearCooldown(id)
	if h.audit != nil {
		h.audit.Log(AuditEntry{Action: "device-allow", Device: id, Detail: "管理台允许重连"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

// forget 从登记表彻底删除一台离线设备。
// 设备若仍在用，下次上线会自动重新登记（但控制端凭证会失效，需要在 B 端重新生成邀请码）；被禁用的设备删除后仍保持封禁。
func (h *AdminHandler) forget(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/forget")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少设备ID"})
		return
	}
	if st := h.tunnel.Status()[id]; st.Agent || st.Client || st.Present {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "设备仍在线，请先让它离线后再删除"})
		return
	}
	dev := h.store.Get(id)
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "设备不存在"})
		return
	}
	if err := h.store.Delete(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.tunnel.ClearCooldown(id)
	if h.audit != nil {
		h.audit.Log(AuditEntry{Action: "device-forget", Device: id, DeviceName: dev.Name, Detail: "管理台删除离线登记"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// disable 禁用一台设备：保留记录，拒绝其连接与重新登记（可再启用）。
func (h *AdminHandler) disable(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/disable")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少设备ID"})
		return
	}
	dev := h.store.Get(id)
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "设备不存在"})
		return
	}
	if err := h.store.Ban(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// 被禁用仍可在线：只断开控制端，并通知 B 端状态
	_ = h.tunnel.Kick(id, "client")
	h.tunnel.KickPresenceByID(id, "")
	h.tunnel.NotifyAgent(id, false, "设备已被中继禁用（控制端无法连接）")
	if h.audit != nil {
		h.audit.Log(AuditEntry{Action: "device-disable", Device: id, DeviceName: dev.Name, Detail: "管理台禁用"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "disabled": true})
}

// enable 启用（解除禁用）。
func (h *AdminHandler) enable(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/enable")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少设备ID"})
		return
	}
	if err := h.store.Unban(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	h.tunnel.NotifyAgent(id, true, "")
	if h.audit != nil {
		h.audit.Log(AuditEntry{Action: "device-enable", Device: id, Detail: "管理台启用"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "disabled": false})
}

func (h *AdminHandler) auditList(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		var parsed int
		if _, err := fmt.Sscanf(v, "%d", &parsed); err == nil && parsed > 0 {
			n = parsed
			if n > 200 {
				n = 200
			}
		}
	}
	before := time.Time{}
	if v := r.URL.Query().Get("before"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			before = t
		}
	}
	entries := []AuditEntry{}
	if h.audit != nil {
		entries = h.audit.TailBefore(n, before)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
