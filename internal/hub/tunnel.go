package hub

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"oclink/internal/proto"
	"oclink/internal/wire"
)

const handshakeTimeout = 15 * time.Second

// endpoint 是一条已鉴权的连接（agent=B 或 client=A）。
type endpoint struct {
	role        string
	dev         *Device
	name        string // 控制端自报名字（管理台显示用）
	clientID    string // 控制端凭证 ID（每个 A 端一把）
	presence    bool   // true=待命心跳连接（不占控制通道、不打扰 B 端）
	conn        net.Conn
	connectedAt time.Time
	mu          sync.Mutex // 串行化写，避免并发写帧互相穿插
}

func (e *endpoint) send(env proto.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return wire.WriteFrame(e.conn, data)
}

// Tunnel 是中继核心：鉴权、配对（独占）、只转发密文。
// 全盲：它没有、也永远不会有任何配对密钥；只有 deviceId 和校验子键。
type Tunnel struct {
	store   *Store
	version string
	audit   *Auditor

	selfRegister bool
	regMu        sync.Mutex
	regLog       map[string][]time.Time // IP -> 最近登记时间（限速）

	mu         sync.Mutex
	agents     map[string]*endpoint
	clients    map[string]*endpoint
	presences  map[string]*endpoint
	cooldowns  map[string]coolEntry
	lastActive map[string]time.Time
}

// coolEntry 记录「管理台断开占用」后的冷却：冷却期内拒绝该设备的控制端重连。
type coolEntry struct {
	clientID string
	until    time.Time
}

// SetAudit 挂上审计（启动时调用一次；可为 nil）。
func (t *Tunnel) SetAudit(a *Auditor) { t.audit = a }

// SetSelfRegister 开启/关闭自助登记（全盲模式默认开启）。
func (t *Tunnel) SetSelfRegister(on bool) { t.selfRegister = on }

// allowRegister 每 IP 限速：每小时最多 10 次登记，防止公网端口被刷。
func (t *Tunnel) allowRegister(ip string) bool {
	t.regMu.Lock()
	defer t.regMu.Unlock()
	if t.regLog == nil {
		t.regLog = map[string][]time.Time{}
	}
	cut := time.Now().Add(-time.Hour)
	var keep []time.Time
	for _, ts := range t.regLog[ip] {
		if ts.After(cut) {
			keep = append(keep, ts)
		}
	}
	if len(keep) >= 10 {
		t.regLog[ip] = keep
		return false
	}
	t.regLog[ip] = append(keep, time.Now())
	return true
}

// NewTunnel 创建中继。
func NewTunnel(store *Store, version string) *Tunnel {
	return &Tunnel{
		store:      store,
		version:    version,
		agents:     map[string]*endpoint{},
		clients:    map[string]*endpoint{},
		presences:  map[string]*endpoint{},
		cooldowns:  map[string]coolEntry{},
		lastActive: map[string]time.Time{},
		regLog:     map[string][]time.Time{},
	}
}

// Serve 处理一条新连接：先握手鉴权，然后进入转发循环。
func (t *Tunnel) Serve(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("connection handler panic: %v", r)
			_ = conn.Close()
		}
	}()
	defer conn.Close()
	// TCP 层保活：对端断网/睡眠导致连接半死时，约 1 分钟内由内核探测断开
	if tc, ok := conn.(*tls.Conn); ok {
		if nc := tc.NetConn(); nc != nil {
			if tcp, ok := nc.(*net.TCPConn); ok {
				_ = tcp.SetKeepAlive(true)
				_ = tcp.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3})
			}
		}
	}
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	first, err := readEnvelope(conn)
	if err != nil {
		log.Printf("握手失败(%s): %v", conn.RemoteAddr(), err)
		return
	}
	// 自助登记：B 端自己生成密钥，只把 deviceId+authKey 登记到中继（全盲，无需管理台）
	if first.Type == "register" {
		t.handleRegister(conn, first)
		return
	}
	ep, err := t.handshakeWithHello(conn, first)
	if err != nil {
		log.Printf("握手失败(%s): %v", conn.RemoteAddr(), err)
		_ = writeEnvelope(conn, proto.Envelope{Type: "error", Error: err.Error()})
		return
	}
	_ = conn.SetDeadline(time.Time{})
	t.register(ep)
	if ep.role == "client" && !ep.presence && t.audit != nil {
		t.audit.Log(AuditEntry{Action: "connect", Device: ep.dev.ID, DeviceName: ep.dev.Name, Detail: ep.name})
	}
	if ep.presence {
		log.Printf("设备 %s（控制端待命）上线", ep.dev.Name)
	} else {
		log.Printf("设备 %s（%s）上线", ep.dev.Name, ep.role)
	}
	defer func() {
		t.unregister(ep)
		if ep.role == "client" && !ep.presence && t.audit != nil {
			t.audit.Log(AuditEntry{Action: "disconnect", Device: ep.dev.ID, DeviceName: ep.dev.Name, Detail: ep.name, DurationMs: time.Since(ep.connectedAt).Milliseconds()})
		}
		if ep.presence {
			log.Printf("设备 %s（控制端待命）下线", ep.dev.Name)
		} else {
			log.Printf("设备 %s（%s）下线", ep.dev.Name, ep.role)
		}
	}()

	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		var env proto.Envelope
		if err := json.Unmarshal(frame, &env); err != nil {
			continue
		}
		switch env.Type {
		case "ping":
			_ = ep.send(proto.Envelope{Type: "pong"})
		case "msg":
			t.touch(ep.dev.ID)
			peer := t.peer(ep)
			if peer == nil {
				_ = ep.send(proto.Envelope{Type: "error", Error: "对端不在线"})
				continue
			}
			if err := peer.send(env); err != nil {
				// 对端连接已死：立即摘掉它，并给发送方明确答复（别让 A 干等到超时）
				log.Printf("转发失败，摘除对端 %s（%s）: %v", peer.dev.Name, peer.role, err)
				_ = peer.conn.Close()
				_ = ep.send(proto.Envelope{Type: "error", Error: "对端不在线"})
			}
		case "ctrl":
			// 仅被控端（agent）可发控制指令：断开控制端 / 自删设备条目
			if ep.role != "agent" {
				continue
			}
			switch env.Cmd {
			case "kick-client":
				t.Kick(ep.dev.ID, "client")
				if t.audit != nil {
					t.audit.Log(AuditEntry{Action: "kick", Device: ep.dev.ID, DeviceName: ep.dev.Name, Detail: "被控端断开控制端"})
				}
				_ = ep.send(proto.Envelope{Type: "ctrl", Cmd: env.Cmd, OK: true})
			case "unregister":
				name := ep.dev.Name
				_ = t.store.Delete(ep.dev.ID)
				if t.audit != nil {
					t.audit.Log(AuditEntry{Action: "device-delete", Device: ep.dev.ID, DeviceName: name, Detail: "被控端自删（删除设备）"})
				}
				_ = t.Kick(ep.dev.ID, "client")
				_ = ep.send(proto.Envelope{Type: "ctrl", Cmd: env.Cmd, OK: true})
				return // 断开本连接
			}
		case "client-add", "client-del":
			// 仅被控端（agent）可管理控制端凭证
			if ep.role != "agent" {
				continue
			}
			raw, derr := base64.StdEncoding.DecodeString(env.Data)
			if derr != nil {
				_ = ep.send(proto.Envelope{Type: "client-ack", OK: false, Error: "载荷格式错误"})
				continue
			}
			var body struct {
				ID      string `json:"id"`
				AuthKey string `json:"authKey"`
				Label   string `json:"label"`
			}
			if json.Unmarshal(raw, &body) != nil || strings.TrimSpace(body.ID) == "" {
				_ = ep.send(proto.Envelope{Type: "client-ack", OK: false, Error: "载荷格式错误"})
				continue
			}
			cid := strings.TrimSpace(body.ID)
			var cerr error
			if env.Type == "client-add" {
				cerr = t.store.AddClient(ep.dev.ID, cid, body.AuthKey, strings.TrimSpace(body.Label))
				if cerr == nil && t.audit != nil {
					t.audit.Log(AuditEntry{Action: "client-add", Device: ep.dev.ID, DeviceName: ep.dev.Name, Detail: cid})
				}
			} else {
				cerr = t.store.RemoveClient(ep.dev.ID, cid)
				if cerr == nil {
					t.KickClientByID(ep.dev.ID, cid)
				}
				if cerr == nil && t.audit != nil {
					t.audit.Log(AuditEntry{Action: "client-del", Device: ep.dev.ID, DeviceName: ep.dev.Name, Detail: cid})
				}
			}
			resp := proto.Envelope{Type: "client-ack", ClientID: cid, OK: cerr == nil}
			if cerr != nil {
				resp.Error = cerr.Error()
			}
			_ = ep.send(resp)
		default:
			// 其它类型忽略（中继只认控制/转发）
		}
	}
}

// handshakeWithHello 执行 challenge → auth 两步，验证对端确实持有配对密钥。
func (t *Tunnel) handshakeWithHello(conn net.Conn, hello proto.Envelope) (*endpoint, error) {
	if hello.Type != "hello" {
		return nil, errors.New("需要 hello")
	}
	if hello.Role != "agent" && hello.Role != "client" {
		return nil, errors.New("角色非法")
	}
	if hello.Version != t.version {
		return nil, errors.New("版本不一致")
	}
	if hello.Role == "client" && t.store.IsBanned(hello.DeviceID) {
		return nil, errors.New("设备已被中继禁用")
	}
	if hello.Role == "client" {
		if cd, ok := t.cooldown(hello.DeviceID); ok && time.Now().Before(cd.until) {
			return nil, errors.New("已被管理台断开（冷却中），请稍后再接入")
		}
	}
	dev := t.store.Get(hello.DeviceID)
	if dev == nil {
		return nil, errors.New("设备不存在")
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if err := writeEnvelope(conn, proto.Envelope{Type: "challenge", Nonce: base64.StdEncoding.EncodeToString(nonce)}); err != nil {
		return nil, err
	}

	auth, err := readEnvelope(conn)
	if err != nil {
		return nil, err
	}
	if auth.Type != "auth" {
		return nil, errors.New("需要 auth")
	}
	proof, err := base64.StdEncoding.DecodeString(auth.Proof)
	if err != nil {
		return nil, err
	}
	clientID := ""
	if hello.Role == "agent" {
		// B 端：用设备校验子键验证
		if !t.store.VerifyProof(dev.ID, hello.Role, nonce, proof) {
			return nil, errors.New("身份校验失败")
		}
	} else {
		// A 端：必须携带自己的客户端凭证 ID，用该凭证的校验子键验证
		clientID = strings.TrimSpace(hello.ClientID)
		if clientID == "" {
			return nil, errors.New("控制端未携带凭证（请使用 B 端新生成的邀请码）")
		}
		if t.store.IsClientDisabled(dev.ID, clientID) {
			return nil, errors.New("控制端凭证已被中继禁用")
		}
		if !t.store.VerifyClientProof(dev.ID, clientID, nonce, proof) {
			return nil, errors.New("控制端凭证无效或已被吊销")
		}
		t.store.MarkClientSeen(dev.ID, clientID, hello.Name)
	}
	t.store.MarkSeen(dev.ID)
	// 设备自报名字（改名同步）
	if hello.Role == "agent" && strings.TrimSpace(hello.Name) != "" {
		_ = t.store.Rename(dev.ID, strings.TrimSpace(hello.Name))
	}

	if err := writeEnvelope(conn, proto.Envelope{Type: "ready", OK: true, DeviceID: dev.ID}); err != nil {
		return nil, err
	}
	// 把“是否被禁用”的状态同步给 B 端（被禁用仍可在线，只是中继不转发控制端）
	if hello.Role == "agent" {
		banned := t.store.IsBanned(dev.ID)
		notice := proto.Envelope{Type: "notice", OK: !banned}
		if banned {
			notice.Error = "设备已被中继禁用（控制端无法连接）"
		}
		_ = writeEnvelope(conn, notice)
	}
	// A 端自报名字（管理台显示「谁在占用」用；只是标签，不涉及密钥）
	clientName := strings.TrimSpace(hello.Name)
	if rs := []rune(clientName); len(rs) > 24 {
		clientName = string(rs[:24])
	}
	return &endpoint{role: hello.Role, dev: dev, name: clientName, clientID: clientID, presence: hello.Presence && hello.Role == "client", conn: conn, connectedAt: time.Now()}, nil
}

// handleRegister 处理自助登记：B 端本机生成密钥，只上交 deviceId + authKey 校验子键。
// 中继据此能校验后续 HMAC 应答，但永远拿不到配对密钥，也无法解密任何内容。
func (t *Tunnel) handleRegister(conn net.Conn, env proto.Envelope) {
	fail := func(msg string) { _ = writeEnvelope(conn, proto.Envelope{Type: "registered", Error: msg}) }
	if !t.selfRegister {
		fail("中继未开启自助登记")
		return
	}
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !t.allowRegister(ip) {
		fail("登记太频繁，请稍后再试")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		fail("载荷格式错误")
		return
	}
	var body struct {
		DeviceID string `json:"deviceId"`
		AuthKey  string `json:"authKey"`
		Name     string `json:"name"`
		OS       string `json:"os"`
	}
	if json.Unmarshal(raw, &body) != nil {
		fail("载荷格式错误")
		return
	}
	authKey, err := base64.StdEncoding.DecodeString(body.AuthKey)
	if err != nil {
		fail("authKey 格式错误")
		return
	}
	if len(t.store.List()) >= 2000 {
		fail("设备数量达到上限，请先清理")
		return
	}
	id := strings.TrimSpace(body.DeviceID)
	if t.store.IsBanned(id) {
		fail("设备已被中继禁用（请在管理台启用后重试）")
		return
	}
	dev, err := t.store.RegisterSelf(id, authKey, strings.TrimSpace(body.Name))
	if err != nil {
		fail(err.Error())
		return
	}
	if t.audit != nil {
		t.audit.Log(AuditEntry{Action: "device-self-register", Device: dev.ID, DeviceName: dev.Name, Detail: body.OS})
	}
	log.Printf("自助登记设备 %s（%s）", dev.Name, dev.ID)
	_ = writeEnvelope(conn, proto.Envelope{Type: "registered", OK: true, DeviceID: dev.ID})
}

// peer 返回某端点的对端（agent 对 client，client 对 agent）。
func (t *Tunnel) peer(ep *endpoint) *endpoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ep.role == "agent" {
		return t.clients[ep.dev.ID]
	}
	return t.agents[ep.dev.ID]
}

// register 登记端点。同一设备同一角色只保留最新连接（旧连接被关闭），
// 从而保证“同一时间只有一个连接”，同时也让网络抖动后的重连能顶掉旧的。
func (t *Tunnel) register(ep *endpoint) {
	// 待命心跳：只登记「A 引擎在线」，不占用控制通道、不打扰 B 端
	if ep.role == "client" && ep.presence {
		t.mu.Lock()
		old := t.presences[ep.dev.ID]
		t.presences[ep.dev.ID] = ep
		t.mu.Unlock()
		if old != nil && old != ep {
			_ = old.conn.Close()
		}
		return
	}
	t.mu.Lock()
	var old *endpoint
	var peerOnline bool
	if ep.role == "agent" {
		old = t.agents[ep.dev.ID]
		t.agents[ep.dev.ID] = ep
		peerOnline = t.clients[ep.dev.ID] != nil
	} else {
		old = t.clients[ep.dev.ID]
		t.clients[ep.dev.ID] = ep
		peerOnline = t.agents[ep.dev.ID] != nil
	}
	t.mu.Unlock()

	if old != nil && old != ep {
		_ = old.send(proto.Envelope{Type: "error", Error: "replaced by a newer connection"})
		_ = old.conn.Close()
	}
	if peerOnline {
		_ = ep.send(proto.Envelope{Type: "peer", Peer: "up"})
		if p := t.peer(ep); p != nil {
			_ = p.send(proto.Envelope{Type: "peer", Peer: "up"})
		}
	}
}

func (t *Tunnel) unregister(ep *endpoint) {
	if ep.role == "client" && ep.presence {
		t.mu.Lock()
		if t.presences[ep.dev.ID] == ep {
			delete(t.presences, ep.dev.ID)
		}
		t.mu.Unlock()
		return
	}
	t.mu.Lock()
	if ep.role == "agent" && t.agents[ep.dev.ID] == ep {
		delete(t.agents, ep.dev.ID)
	}
	if ep.role == "client" && t.clients[ep.dev.ID] == ep {
		delete(t.clients, ep.dev.ID)
	}
	t.mu.Unlock()

	if p := t.peer(ep); p != nil {
		_ = p.send(proto.Envelope{Type: "peer", Peer: "down"})
	}
}

// Devices 返回设备列表（按名字排序，供管理台）。
func (t *Tunnel) Devices() []*Device {
	list := t.store.List()
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func readEnvelope(conn net.Conn) (proto.Envelope, error) {
	var env proto.Envelope
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(frame, &env)
	return env, err
}

func writeEnvelope(conn net.Conn, env proto.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, data)
}
