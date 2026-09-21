// octest 是 oc-link 的测试客户端（A 端参考实现）。
//
// 正式 A 端是 opencode 插件；这个工具用来在命令行验证中继/agent 是否打通：
//
//	octest -hub 127.0.0.1:21122 -key OCL-... -op exec -arg "echo hi" [-token 用户令牌]
//
// 托管设备（有归属）必须带 -token；未托管设备可省略。
package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"oclink/internal/proto"
	"oclink/internal/wire"
)

func main() {
	hub := flag.String("hub", "127.0.0.1:21122", "中继地址")
	keyStr := flag.String("key", "", "配对密钥")
	insecure := flag.Bool("insecure", true, "跳过证书校验（本地测试）")
	op := flag.String("op", "exec", "exec|read|write|list|ping")
	arg := flag.String("arg", "echo hello", "命令或路径")
	timeout := flag.Duration("timeout", 30*time.Second, "总超时")
	token := flag.String("token", "", "用户令牌（托管设备必填）")
	flag.Parse()

	key, err := parseKey(*keyStr)
	check(err)
	deviceID := proto.DeviceID(key)
	authKey := proto.AuthKey(key)
	encKey := proto.EncKey(key)

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", *hub, &tls.Config{InsecureSkipVerify: *insecure, MinVersion: tls.VersionTLS13})
	check(err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))

	check(writeEnv(conn, proto.Envelope{Type: "hello", Role: "client", DeviceID: deviceID, Version: proto.Version, Token: *token}))
	env, err := readEnv(conn)
	check(err)
	if env.Type != "challenge" {
		fatal("握手失败: %s %s", env.Type, env.Error)
	}
	nonce, _ := base64.StdEncoding.DecodeString(env.Nonce)
	check(writeEnv(conn, proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proto.Proof(authKey, nonce, "client", deviceID))}))
	env, err = readEnv(conn)
	check(err)
	if env.Type != "ready" {
		fatal("鉴权失败: %s %s", env.Type, env.Error)
	}
	fmt.Println("[client] 已接入中继，等待 agent...")

	priv, pub, err := proto.NewEphemeral()
	check(err)
	hsBody, _ := json.Marshal(map[string]string{"pub": base64.StdEncoding.EncodeToString(pub)})
	hsPayload := append([]byte{1}, hsBody...)
	check(writeEnv(conn, proto.Envelope{Type: "msg", Data: base64.StdEncoding.EncodeToString(hsPayload)}))

	var sess *proto.Session
	sentReq := false
	req := buildRequest(*op, *arg)

	for {
		env, err := readEnv(conn)
		if err != nil {
			fatal("连接结束: %v", err)
		}
		switch env.Type {
		case "error":
			fatal("中继错误: %s", env.Error)
		case "peer":
			if env.Peer == "down" {
				fatal("对端离线")
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
				check(err)
				sess, err = proto.DeriveSession(priv, peerPub, encKey)
				if err != nil {
					fatal("会话建立失败: %v", err)
				}
				fmt.Println("[client] 端到端会话已建立")
				if !sentReq {
					raw, _ := json.Marshal(req)
					seq, n2, ct, err := sess.Seal(raw)
					check(err)
					out := append([]byte{2}, ct...)
					check(writeEnv(conn, proto.Envelope{
						Type:  "msg",
						Seq:   seq,
						Nonce: base64.StdEncoding.EncodeToString(n2),
						Data:  base64.StdEncoding.EncodeToString(out),
					}))
					sentReq = true
				}
			case 2: // 密文响应
				if sess == nil {
					continue
				}
				n2, _ := base64.StdEncoding.DecodeString(env.Nonce)
				plain, err := sess.Open(env.Seq, n2, payload[1:])
				if err != nil {
					fatal("解密失败: %v", err)
				}
				var resp proto.Response
				_ = json.Unmarshal(plain, &resp)
				pretty, _ := json.MarshalIndent(resp, "", "  ")
				fmt.Println("[client] 收到响应:")
				fmt.Println(string(pretty))
				if !resp.OK {
					os.Exit(3)
				}
				return
			}
		}
	}
}

func parseKey(s string) ([]byte, error) { return proto.ParsePairingKey(s) }

func buildRequest(op, arg string) proto.Request {
	r := proto.Request{Op: op, ID: "1"}
	switch op {
	case "exec":
		r.Cmd = arg
	case "read", "list":
		r.Path = arg
	case "write":
		r.Path = arg
		r.DataB64 = base64.StdEncoding.EncodeToString([]byte("hello from octest\n"))
	case "ping":
	default:
	}
	return r
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

func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[client] 错误: "+format+"\n", args...)
	os.Exit(1)
}
