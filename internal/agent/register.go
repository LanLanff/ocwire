package agent

// 自助登记（全盲配对）：B 端本机生成密钥，只把 deviceId + authKey 校验子键登记到中继。
// 中继不保存配对密钥本身，无法解密、也无法事后恢复；
// A 端拿到 B 端生成的邀请码（OCL2:…）即可连接，全程不需要管理台。

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
	"runtime"
	"strings"
	"time"

	"oclink/internal/proto"
)

// dialPinned 连接中继并校验证书指纹（insecure=true 时跳过，仅本地测试）。
func dialPinned(addr, fingerprint string, insecure bool) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	if fingerprint == "" && !insecure {
		return nil, errors.New("缺少证书指纹")
	}
	if fingerprint != "" {
		want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("服务器没有提供证书")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != want {
				return fmt.Errorf("证书指纹不匹配（服务器 %s）", formatFingerprint(sum[:]))
			}
			return nil
		}
	}
	return tls.DialWithDialer(d, "tcp", addr, cfg)
}

func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}

func tunnelRoundTrip(conn net.Conn, env proto.Envelope, timeout time.Duration) (proto.Envelope, error) {
	if err := writeEnvelope(conn, env); err != nil {
		return proto.Envelope{}, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	return readEnvelope(conn)
}

// ProvisionClient 用设备密钥与中继建立一次已鉴权的 agent 连接，
// 登记一个控制端凭证（clientId + 校验子键），等待中继确认。
func ProvisionClient(addr, fingerprint string, insecure bool, deviceKey []byte, clientID, authKeyB64, label string) error {
	return provision(addr, fingerprint, insecure, deviceKey, "client-add", clientID, authKeyB64, label)
}

// RevokeClient 吊销一个控制端凭证（中继会立即断开该凭证的在线连接）。
func RevokeClient(addr, fingerprint string, insecure bool, deviceKey []byte, clientID string) error {
	return provision(addr, fingerprint, insecure, deviceKey, "client-del", clientID, "", "")
}

func provision(addr, fingerprint string, insecure bool, deviceKey []byte, action, clientID, authKeyB64, label string) error {
	if addr == "" {
		return errors.New("缺少中继地址")
	}
	conn, err := dialPinned(addr, fingerprint, insecure)
	if err != nil {
		return fmt.Errorf("连接中继失败: %w", err)
	}
	defer conn.Close()
	deviceID := proto.DeviceID(deviceKey)
	deviceAuthKey := proto.AuthKey(deviceKey)

	// 1) 以 B 端身份完成握手鉴权
	if err := writeEnvelope(conn, proto.Envelope{Type: "hello", Role: "agent", DeviceID: deviceID, Version: proto.Version}); err != nil {
		return err
	}
	env, err := readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "challenge" {
		return fmt.Errorf("握手失败: %s", env.Error)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return err
	}
	proof := proto.Proof(deviceAuthKey, nonce, "agent", deviceID)
	if err := writeEnvelope(conn, proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proof)}); err != nil {
		return err
	}
	env, err = readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "ready" {
		return fmt.Errorf("鉴权失败: %s", env.Error)
	}

	// 2) 发送凭证变更并等待确认（跳过 ready 后中继推送的 notice）
	body, _ := json.Marshal(map[string]string{"id": clientID, "authKey": authKeyB64, "label": label})
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := writeEnvelope(conn, proto.Envelope{Type: action, Data: base64.StdEncoding.EncodeToString(body)}); err != nil {
		return err
	}
	for {
		env, err = readEnvelope(conn)
		if err != nil {
			return fmt.Errorf("等待中继确认失败: %w", err)
		}
		if env.Type == "notice" || env.Type == "pong" {
			continue
		}
		break
	}
	if env.Type != "client-ack" {
		return fmt.Errorf("中继返回异常: %s", env.Type)
	}
	if !env.OK {
		if env.Error == "" {
			return errors.New("中继拒绝了请求")
		}
		return errors.New(env.Error)
	}
	return nil
}

// UnregisterSelf 通知中继删除本设备条目（自助注销，用于测试/清理；管理台没有删除功能）。
func UnregisterSelf(addr, fingerprint string, insecure bool, deviceKey []byte) error {
	conn, err := dialPinned(addr, fingerprint, insecure)
	if err != nil {
		return fmt.Errorf("连接中继失败: %w", err)
	}
	defer conn.Close()
	deviceID := proto.DeviceID(deviceKey)
	if err := writeEnvelope(conn, proto.Envelope{Type: "hello", Role: "agent", DeviceID: deviceID, Version: proto.Version}); err != nil {
		return err
	}
	env, err := readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "challenge" {
		return fmt.Errorf("握手失败: %s", env.Error)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return err
	}
	proof := proto.Proof(proto.AuthKey(deviceKey), nonce, "agent", deviceID)
	if err := writeEnvelope(conn, proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proof)}); err != nil {
		return err
	}
	env, err = readEnvelope(conn)
	if err != nil {
		return err
	}
	if env.Type != "ready" {
		return fmt.Errorf("鉴权失败: %s", env.Error)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeEnvelope(conn, proto.Envelope{Type: "ctrl", Cmd: "unregister"}); err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		env, err = readEnvelope(conn)
		if err != nil {
			break
		}
		if env.Type == "notice" || env.Type == "pong" {
			continue
		}
		break
	}
	return nil
}

// RegisterSelf 向中继登记一把配对密钥的校验信息。addr 为隧道地址 host:port。
func RegisterSelf(addr, fingerprint string, insecure bool, key []byte, name string) error {
	if addr == "" {
		return errors.New("缺少中继地址")
	}
	if len(key) != 32 {
		return errors.New("配对密钥无效")
	}
	conn, err := dialPinned(addr, fingerprint, insecure)
	if err != nil {
		return fmt.Errorf("连接中继失败: %w", err)
	}
	defer conn.Close()
	body, _ := json.Marshal(map[string]string{
		"deviceId": proto.DeviceID(key),
		"authKey":  base64.StdEncoding.EncodeToString(proto.AuthKey(key)),
		"name":     name,
		"os":       runtime.GOOS,
	})
	env, err := tunnelRoundTrip(conn, proto.Envelope{Type: "register", Data: base64.StdEncoding.EncodeToString(body)}, 20*time.Second)
	if err != nil {
		return fmt.Errorf("登记失败: %w", err)
	}
	if env.Type == "error" {
		return errors.New(env.Error)
	}
	if env.Type != "registered" {
		return fmt.Errorf("中继返回异常: %s", env.Type)
	}
	if !env.OK {
		if env.Error == "" {
			return errors.New("登记失败")
		}
		return errors.New(env.Error)
	}
	return nil
}
