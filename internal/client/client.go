// Package client 是 A 端（控制端）核心实现（Go 版）。
//
// Node 版在 plugin/client.mjs（opencode 插件用）；本包供命令行工具与桌面客户端复用。
// 流程：TLS（指纹固定）→ 挑战应答鉴权 → X25519 端到端加密 → 发一条请求拿响应。
package client

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"oclink/internal/proto"
	"oclink/internal/wire"
)

// Profile 是一个目标设备的连接信息（P5：key 是控制端自己的独立密钥）。
type Profile struct {
	Hub         string `json:"hub"`
	Key         string `json:"key"`
	DeviceID    string `json:"deviceId,omitempty"` // 设备公开 ID（邀请码里携带）
	ClientID    string `json:"clientId,omitempty"` // 控制端凭证 ID（每个 A 端一把）
	Fingerprint string `json:"fingerprint"`
	Token       string `json:"token,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Insecure    bool   `json:"insecure,omitempty"`
}

// Request 连接目标设备并执行一次请求（同步，返回响应或错误）。
func Request(p Profile, req proto.Request, timeout time.Duration) (proto.Response, error) {
	var resp proto.Response
	key, err := proto.ParsePairingKey(p.Key)
	if err != nil {
		return resp, fmt.Errorf("配对密钥无效: %w", err)
	}
	deviceID := p.DeviceID
	if deviceID == "" {
		deviceID = proto.DeviceID(key)
	}
	authKey := proto.AuthKey(key)
	encKey := proto.EncKey(key)

	conf := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if !p.Insecure {
		want := strings.ToUpper(strings.TrimSpace(p.Fingerprint))
		if want == "" {
			return resp, errors.New("缺少证书指纹（本机测试可设置 insecure）")
		}
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("对端没有证书")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := formatFingerprint(sum[:])
			if got != want {
				return fmt.Errorf("证书指纹不匹配（拿到 %s）", got)
			}
			return nil
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", p.Hub, conf)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 鉴权（控制端凭证）
	if err := writeEnv(conn, proto.Envelope{Type: "hello", Role: "client", DeviceID: deviceID, ClientID: p.ClientID, Version: proto.Version, Name: p.DisplayName, Token: p.Token}); err != nil {
		return resp, err
	}
	env, err := readEnv(conn)
	if err != nil {
		return resp, err
	}
	if env.Type != "challenge" {
		return resp, fmt.Errorf("握手失败: %s %s", env.Type, env.Error)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return resp, err
	}
	proof := proto.ProofFor(authKey, nonce, "client", deviceID, p.ClientID)
	if err := writeEnv(conn, proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proof)}); err != nil {
		return resp, err
	}
	env, err = readEnv(conn)
	if err != nil {
		return resp, err
	}
	if env.Type != "ready" {
		return resp, fmt.Errorf("鉴权失败: %s", env.Error)
	}

	// 端到端握手
	priv, pub, err := proto.NewEphemeral()
	if err != nil {
		return resp, err
	}
	hsBody, _ := json.Marshal(map[string]string{"pub": base64.StdEncoding.EncodeToString(pub), "name": p.DisplayName, "cid": p.ClientID})
	hsPayload := append([]byte{1}, hsBody...)
	if err := writeEnv(conn, proto.Envelope{Type: "msg", Data: base64.StdEncoding.EncodeToString(hsPayload)}); err != nil {
		return resp, err
	}

	var sess *proto.Session
	sentReq := false
	for {
		env, err := readEnv(conn)
		if err != nil {
			return resp, fmt.Errorf("连接结束: %w", err)
		}
		switch env.Type {
		case "error":
			return resp, fmt.Errorf("中继错误: %s", env.Error)
		case "peer":
			if env.Peer == "down" {
				return resp, errors.New("对端离线")
			}
		case "msg":
			payload, err := base64.StdEncoding.DecodeString(env.Data)
			if err != nil || len(payload) == 0 {
				continue
			}
			switch payload[0] {
			case 1: // 对端握手公钥
				var hs struct {
					Pub string `json:"pub"`
				}
				_ = json.Unmarshal(payload[1:], &hs)
				peerPub, err := base64.StdEncoding.DecodeString(hs.Pub)
				if err != nil {
					return resp, err
				}
				sess, err = proto.DeriveSession(priv, peerPub, encKey)
				if err != nil {
					return resp, fmt.Errorf("会话建立失败: %w", err)
				}
				if !sentReq {
					raw, _ := json.Marshal(req)
					seq, n2, ct, err := sess.Seal(raw)
					if err != nil {
						return resp, err
					}
					out := append([]byte{2}, ct...)
					if err := writeEnv(conn, proto.Envelope{
						Type:  "msg",
						Seq:   seq,
						Nonce: base64.StdEncoding.EncodeToString(n2),
						Data:  base64.StdEncoding.EncodeToString(out),
					}); err != nil {
						return resp, err
					}
					sentReq = true
				}
			case 2: // 密文响应
				if sess == nil {
					continue
				}
				n2, _ := base64.StdEncoding.DecodeString(env.Nonce)
				plain, err := sess.Open(env.Seq, n2, payload[1:])
				if err != nil {
					return resp, fmt.Errorf("解密失败: %w", err)
				}
				_ = json.Unmarshal(plain, &resp)
				return resp, nil
			}
		}
	}
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}

func readEnv(conn net.Conn) (proto.Envelope, error) {
	var env proto.Envelope
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(frame, &env)
	return env, err
}

func writeEnv(conn net.Conn, env proto.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, data)
}

// ---- 邀请码（把 A 端需要的全部信息压成一串，方便扫码/粘贴）----

// LinkPayload 是邀请码（OCL2）里的内容：每个控制端一把独立密钥。
type LinkPayload struct {
	V           int    `json:"v"`
	Hub         string `json:"h"`
	Key         string `json:"k"`
	Fingerprint string `json:"f"`
	Name        string `json:"n"`
	DeviceID    string `json:"d"`
	ClientID    string `json:"c"`
	Label       string `json:"l,omitempty"`
}

// EncodeInvite 生成邀请码：OCL2:<base64url(JSON)>。
func EncodeInvite(hub, key, fingerprint, name, deviceID, clientID, label string) string {
	raw, _ := json.Marshal(LinkPayload{V: 2, Hub: hub, Key: key, Fingerprint: fingerprint, Name: name, DeviceID: deviceID, ClientID: clientID, Label: label})
	return "OCL2:" + base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeLink 解析邀请码，返回 profile 和建议的名字。
func DecodeLink(code string) (Profile, string, error) {
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, "OCL1:") {
		return Profile{}, "", errors.New("旧连接码已停用：请在 B 端「控制端」页重新生成邀请码")
	}
	if !strings.HasPrefix(code, "OCL2:") {
		return Profile{}, "", errors.New("邀请码格式不对（应以 OCL2: 开头）")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "OCL2:"))
	if err != nil {
		return Profile{}, "", errors.New("邀请码内容损坏")
	}
	var lp LinkPayload
	if err := json.Unmarshal(raw, &lp); err != nil {
		return Profile{}, "", errors.New("邀请码内容损坏")
	}
	if lp.Hub == "" || lp.Key == "" || lp.DeviceID == "" || lp.ClientID == "" {
		return Profile{}, "", errors.New("邀请码缺少必要信息")
	}
	name := lp.Name
	if strings.TrimSpace(name) == "" {
		name = lp.Label
	}
	return Profile{Hub: lp.Hub, Key: lp.Key, Fingerprint: lp.Fingerprint, DeviceID: lp.DeviceID, ClientID: lp.ClientID}, name, nil
}
