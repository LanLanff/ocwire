// Package agent 是 oc-link 的 B 端：主动连中继、握手鉴权、端到端加密、执行请求。
//
// 安全要点：
//   - 主动外连，不需要开端口、不需要装 VPN；
//   - TLS 证书用“指纹固定”校验，防中间人；
//   - 与 A 之间用 X25519 + AES-256-GCM 端到端加密，中继看不懂内容。
package agent

import (
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"oclink/internal/proto"
	"oclink/internal/tlscert"
	"oclink/internal/wire"
)

// Data 载荷首字节标记：1=握手（明文公钥） 2=密文。
// 中继完全不需要理解它，只负责转发。
const (
	tagHandshake = 1
	tagData      = 2
)

// Event 是 agent 运行期间产生的可观察事件（桌面端用来展示"谁连了、做了什么"）。
type Event struct {
	Type     string    `json:"type"`               // connected|disconnected|peer-up|peer-down|request
	Time     time.Time `json:"time"`               //
	Peer     string    `json:"peer,omitempty"`     // 对端（A 端）显示名
	ClientID string    `json:"clientId,omitempty"` // 对端凭证 ID（用于把名字回填到控制端列表）
	Op       string    `json:"op,omitempty"`       // 请求类型
	Detail   string    `json:"detail,omitempty"`   // 命令或文件路径
	OK       bool      `json:"ok,omitempty"`
	Millis   int64     `json:"millis,omitempty"`
	Bytes    int64     `json:"bytes,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Config 是 agent 运行配置。
type Config struct {
	Hub         string      // host:port
	Key         []byte      // 配对密钥
	Fingerprint string      // 服务器证书 SHA-256 指纹（大写、冒号分隔）
	Insecure    bool        // 跳过指纹校验（仅本地测试用）
	ReadOnly    bool        // 只读模式：禁 exec/write
	Root        string      // 文件操作限定目录（空表示不限制）
	Name        string      // 设备名（上报中继 + 日志）
	OnEvent     func(Event) // 事件回调（可为空）
	// ClientEncKey 按控制端凭证 ID 返回该客户端的端到端密钥（B 端本地推导，可吊销）。
	// 返回 false 表示该凭证未授权（拒绝会话建立）。
	ClientEncKey func(clientID string) ([]byte, bool)
	// OnMissingDevice 当中继说“设备不存在”时调用（B 端可借此自动重新登记）；
	// 返回 nil 表示已重新登记，连接会立即重试。
	OnMissingDevice func() error
}

// Agent 维持与中继的连接。
type Agent struct {
	cfg      Config
	deviceID string
	authKey  []byte
	encKey   []byte

	ephem        *ecdh.PrivateKey
	session      *proto.Session
	peerName     string
	peerClientID string

	mu       sync.Mutex
	conn     net.Conn
	stopped  bool
	stopCh   chan struct{}
	writeMu  sync.Mutex
	disabled bool // 中继管理员禁用了本机
}

// New 创建 agent。
func New(cfg Config) *Agent {
	return &Agent{
		cfg:      cfg,
		deviceID: proto.DeviceID(cfg.Key),
		authKey:  proto.AuthKey(cfg.Key),
		encKey:   proto.EncKey(cfg.Key),
		stopCh:   make(chan struct{}),
	}
}

func (a *Agent) emit(ev Event) {
	if a.cfg.OnEvent == nil {
		return
	}
	ev.Time = time.Now()
	a.cfg.OnEvent(ev)
}

// Stop 停止运行（关闭当前连接，Run 会退出）。
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return
	}
	a.stopped = true
	close(a.stopCh)
	if a.conn != nil {
		_ = a.conn.Close()
	}
}

func (a *Agent) isStopped() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stopped
}

func (a *Agent) setConn(c net.Conn) {
	a.mu.Lock()
	a.conn = c
	a.mu.Unlock()
}

func (a *Agent) clearConn(c net.Conn) {
	a.mu.Lock()
	if a.conn == c {
		a.conn = nil
	}
	a.mu.Unlock()
}

// write 串行化写帧（事件推送与主循环可能并发写）。
func (a *Agent) write(conn net.Conn, env proto.Envelope) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return writeEnvelope(conn, env)
}

// KickClient 请求中继断开当前控制端（B 端"断开连接"按钮）。
func (a *Agent) KickClient() error { return a.sendCtrl("kick-client") }

// Unregister 请求中继删除本设备条目（B 端"吊销配对"按钮）。
func (a *Agent) Unregister() error { return a.sendCtrl("unregister") }

func (a *Agent) sendCtrl(cmd string) error {
	a.mu.Lock()
	conn := a.conn
	a.mu.Unlock()
	if conn == nil {
		return errors.New("未连接")
	}
	return a.write(conn, proto.Envelope{Type: "ctrl", Cmd: cmd})
}

// Run 持续运行：断线自动重连（指数退避，最长 30 秒），收到 Stop 后退出。
func (a *Agent) Run() {
	backoff := 2 * time.Second
	for {
		if a.isStopped() {
			return
		}
		err := a.connectOnce()
		if a.isStopped() {
			return
		}
		if err != nil {
			msg := err.Error()
			// 被中继禁用：明确标记并向界面通报，放慢重试（等在管理台启用）
			if strings.Contains(msg, "已被中继禁用") {
				if !a.disabled {
					a.disabled = true
					a.emit(Event{Type: "disabled", Error: msg})
				}
				log.Printf("已被中继禁用，稍后重试: %v", err)
				select {
				case <-a.stopCh:
					return
				case <-time.After(15 * time.Second):
				}
				continue
			}
			// 中继说设备不存在：尝试自动重新登记（拉黑时会失败，保持离线）
			if strings.Contains(msg, "设备不存在") && a.cfg.OnMissingDevice != nil {
				if rerr := a.cfg.OnMissingDevice(); rerr == nil {
					log.Printf("设备在中继上不存在，已自动重新登记")
					continue
				} else {
					log.Printf("自动重新登记失败: %v", rerr)
				}
			}
			log.Printf("连接中断: %v（%s 后重连）", err, backoff)
		}
		select {
		case <-a.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) connectOnce() error {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if !a.cfg.Insecure {
		want := a.cfg.Fingerprint
		if want == "" {
			return errors.New("未提供证书指纹（测试可用 -insecure）")
		}
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("对端没有证书")
			}
			got := tlscert.Fingerprint(rawCerts[0])
			if !strings.EqualFold(got, want) {
				return fmt.Errorf("证书指纹不匹配（拿到 %s）", got)
			}
			return nil
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", a.cfg.Hub, conf)
	if err != nil {
		return err
	}
	defer conn.Close()
	a.setConn(conn)
	defer a.clearConn(conn)

	// 1) 握手鉴权：hello -> challenge -> auth -> ready
	if err := a.write(conn, proto.Envelope{Type: "hello", Role: "agent", DeviceID: a.deviceID, Version: proto.Version, Name: a.cfg.Name}); err != nil {
		return err
	}
	env, err := readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "challenge" {
		return fmt.Errorf("期望 challenge，收到 %q %s", env.Type, env.Error)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return err
	}
	proof := proto.Proof(a.authKey, nonce, "agent", a.deviceID)
	if err := a.write(conn, proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proof)}); err != nil {
		return err
	}
	env, err = readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "ready" {
		return fmt.Errorf("鉴权失败: %s", env.Error)
	}
	log.Printf("已接入中继 %s（设备 %s）", a.cfg.Hub, a.deviceID)
	a.emit(Event{Type: "connected"})
	defer a.emit(Event{Type: "disconnected"})
	return a.loop(conn)
}

func (a *Agent) loop(conn net.Conn) error {
	for {
		env, err := readEnvelope(conn)
		if err != nil {
			return err
		}
		switch env.Type {
		case "peer":
			if env.Peer == "up" {
				a.newEphemeral()
				if err := a.sendHandshake(conn); err != nil {
					return err
				}
		} else {
			ev := Event{Type: "peer-down", Peer: a.peerName, ClientID: a.peerClientID}
			a.session = nil
			a.peerName = ""
			a.peerClientID = ""
			a.emit(ev)
		}
		case "msg":
			if err := a.onMessage(conn, env); err != nil {
				log.Printf("消息处理失败: %v", err)
			}
		case "ctrl":
			// 控制指令回执（kick-client / unregister）
			if !env.OK && env.Error != "" {
				log.Printf("控制指令失败: %s", env.Error)
			}
		case "notice":
			// 中继同步“是否被禁用”（被禁用仍在线，只是中继不转发控制端）
			if env.OK {
				if a.disabled {
					a.disabled = false
					a.emit(Event{Type: "enabled"})
				}
			} else if !a.disabled {
				a.disabled = true
				a.emit(Event{Type: "disabled", Error: env.Error})
			}
		case "pong":
			// 心跳应答
		}
	}
}

func (a *Agent) newEphemeral() {
	priv, _, err := proto.NewEphemeral()
	if err != nil {
		log.Printf("生成临时密钥失败: %v", err)
		return
	}
	a.ephem = priv
	a.session = nil
}

func (a *Agent) sendHandshake(conn net.Conn) error {
	if a.ephem == nil {
		return errors.New("临时密钥未生成")
	}
	body, _ := json.Marshal(map[string]string{
		"pub":  base64.StdEncoding.EncodeToString(a.ephem.PublicKey().Bytes()),
		"name": a.cfg.Name,
	})
	payload := append([]byte{tagHandshake}, body...)
	return a.write(conn, proto.Envelope{Type: "msg", Data: base64.StdEncoding.EncodeToString(payload)})
}

func (a *Agent) onMessage(conn net.Conn, env proto.Envelope) error {
	payload, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil || len(payload) == 0 {
		return errors.New("载荷为空")
	}
	switch payload[0] {
	case tagHandshake:
		var hs struct {
			Pub  string `json:"pub"`
			Name string `json:"name"`
			CID  string `json:"cid"`
		}
		if err := json.Unmarshal(payload[1:], &hs); err != nil {
			return err
		}
		pub, err := base64.StdEncoding.DecodeString(hs.Pub)
		if err != nil {
			return err
		}
		if a.ephem == nil {
			a.newEphemeral()
		}
		encKey := a.encKey
		if hs.CID != "" {
			if a.cfg.ClientEncKey == nil {
				return errors.New("收到未授权的控制端连接")
			}
			k, ok := a.cfg.ClientEncKey(hs.CID)
			if !ok {
				return errors.New("控制端凭证未授权或已被删除")
			}
			encKey = k
		}
		sess, err := proto.DeriveSession(a.ephem, pub, encKey)
		if err != nil {
			return err
		}
		a.session = sess
		a.peerName = strings.TrimSpace(hs.Name)
		a.peerClientID = strings.TrimSpace(hs.CID)
		log.Printf("端到端会话已建立")
		a.emit(Event{Type: "peer-up", Peer: a.peerName, ClientID: a.peerClientID})
		return nil

	case tagData:
		if a.session == nil {
			return errors.New("会话未建立")
		}
		nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
		if err != nil {
			return err
		}
		plain, err := a.session.Open(env.Seq, nonce, payload[1:])
		if err != nil {
			return err
		}
		var req proto.Request
		if err := json.Unmarshal(plain, &req); err != nil {
			return err
		}
		resp := handleRequestSafe(a.cfg, req)
		// 上报活动事件（供 B 端界面展示）
		ev := Event{Type: "request", Peer: a.peerName, ClientID: a.peerClientID, Op: req.Op, OK: resp.OK, Millis: resp.DurationMs, Error: resp.Error}
		switch req.Op {
		case "exec":
			ev.Detail = req.Cmd
		case "read", "write", "list", "edit":
			ev.Detail = req.Path
			if req.Op == "read" {
				ev.Bytes = resp.Size
			} else if req.Op == "write" {
				ev.Bytes = int64(resp.Bytes)
			}
		case "grep", "glob":
			ev.Detail = req.Pattern + "  (" + req.Path + ")"
		default:
			ev.Detail = req.Op
		}
		a.emit(ev)
		raw, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		seq, nonce2, ct, err := a.session.Seal(raw)
		if err != nil {
			return err
		}
		out := append([]byte{tagData}, ct...)
		return a.write(conn, proto.Envelope{
			Type:  "msg",
			Seq:   seq,
			Nonce: base64.StdEncoding.EncodeToString(nonce2),
			Data:  base64.StdEncoding.EncodeToString(out),
		})

	default:
		return fmt.Errorf("未知载荷类型 %d", payload[0])
	}
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
