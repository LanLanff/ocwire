package main

// 桌面端端到端测试（需要本地中继在 127.0.0.1:21223/10003，密码 testpass123）。
// 启动方式见测试文件顶部注释；用 `go test -run TestDesktopEndToEnd -v` 运行。
//
// 覆盖：导入配置 → 启动 B → A 端 ping（E2EE）→ 活动记录 → A 端目标管理 →
// 改名同步到中继 → 断开控制端（kick）→ 吊销配对（中继删设备 + 本地清密钥）。

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"

	"oclink/internal/agent"
	"oclink/internal/client"
	"oclink/internal/proto"
	"oclink/internal/wire"
)

var (
	e2eHubAddr  = envOr("E2E_HUB", "127.0.0.1:21223")
	e2eAdminURL = envOr("E2E_ADMIN", "http://127.0.0.1:10003")
	e2ePass     = envOr("E2E_PASS", "testpass123")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type adminAPI struct {
	t   *testing.T
	c   *http.Client
	url string
}

func newAdminAPI(t *testing.T) *adminAPI {
	jar, _ := cookiejar.New(nil)
	return &adminAPI{t: t, c: &http.Client{Timeout: 10 * time.Second, Jar: jar}, url: e2eAdminURL}
}

func (a *adminAPI) do(method, path string, body any, out any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, a.url+path, rd)
	if err != nil {
		a.t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.c.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		a.t.Fatalf("%s %s HTTP %d: %s", method, path, resp.StatusCode, buf.String())
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatalf("%s %s 解析失败: %v", method, path, err)
		}
	}
}

type deviceRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AgentOnline bool   `json:"agentOnline"`
}

func (a *adminAPI) devices() []deviceRow {
	var d struct {
		Devices []deviceRow `json:"devices"`
	}
	a.do("GET", "/api/devices", nil, &d)
	return d.Devices
}

func (a *adminAPI) waitDeviceName(id, name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, d := range a.devices() {
			if d.ID == id && d.Name == name {
				return true
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

func (a *adminAPI) waitDeviceGone(id string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		found := false
		for _, d := range a.devices() {
			if d.ID == id {
				found = true
			}
		}
		if !found {
			return true
		}
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

// holdClient 建立一个保持不动的 A 端连接（用于验证 kick）。
// 返回连接、错误通道、就绪通道（B 端握手公钥到达后关闭）。
func holdClient(t *testing.T, hub, clientKeyText, deviceID, clientID string) (net.Conn, <-chan error, <-chan struct{}) {
	t.Helper()
	keyBytes, err := proto.ParsePairingKey(clientKeyText)
	if err != nil {
		t.Fatalf("密钥无效: %v", err)
	}
	authKey := proto.AuthKey(keyBytes)
	encKey := proto.EncKey(keyBytes)

	conf := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err = tls.Dial("tcp", hub, conf)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("连接中继失败: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}

	writeEnv := func(env proto.Envelope) {
		raw, _ := json.Marshal(env)
		if err := wire.WriteFrame(conn, raw); err != nil {
			t.Fatalf("写帧失败: %v", err)
		}
	}
	readEnv := func() proto.Envelope {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			t.Fatalf("读帧失败: %v", err)
		}
		var env proto.Envelope
		_ = json.Unmarshal(frame, &env)
		return env
	}

	writeEnv(proto.Envelope{Type: "hello", Role: "client", DeviceID: deviceID, ClientID: clientID, Version: proto.Version, Name: "e2e-A"})
	ch := readEnv()
	if ch.Type != "challenge" {
		t.Fatalf("期望 challenge，得到 %s %s", ch.Type, ch.Error)
	}
	nonce, _ := base64.StdEncoding.DecodeString(ch.Nonce)
	proof := proto.ProofFor(authKey, nonce, "client", deviceID, clientID)
	writeEnv(proto.Envelope{Type: "auth", Proof: base64.StdEncoding.EncodeToString(proof)})
	if env := readEnv(); env.Type != "ready" {
		t.Fatalf("鉴权失败: %s %s", env.Type, env.Error)
	}

	priv, pub, err := proto.NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"pub": base64.StdEncoding.EncodeToString(pub), "name": "e2e-A", "cid": clientID})
	payload := append([]byte{1}, body...)
	writeEnv(proto.Envelope{Type: "msg", Data: base64.StdEncoding.EncodeToString(payload)})

	errCh := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		_ = conn.SetReadDeadline(time.Time{})
		var sess *proto.Session
		for {
			frame, err := wire.ReadFrame(conn)
			if err != nil {
				errCh <- err
				return
			}
			var env proto.Envelope
			if json.Unmarshal(frame, &env) != nil {
				continue
			}
			if env.Type == "error" {
				errCh <- fmt.Errorf("中继返回: %s", env.Error)
				return
			}
			if env.Type != "msg" {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(env.Data)
			if err != nil || len(data) == 0 {
				continue
			}
			if data[0] == 1 && sess == nil {
				var hs struct {
					Pub string `json:"pub"`
				}
				_ = json.Unmarshal(data[1:], &hs)
				peerPub, err := base64.StdEncoding.DecodeString(hs.Pub)
				if err != nil {
					continue
				}
				sess, err = proto.DeriveSession(priv, peerPub, encKey)
				if err != nil {
					errCh <- err
					return
				}
				close(ready)
			}
		}
	}()
	return conn, errCh, ready
}

// fingerprintOf 连接中继并现算证书指纹（供测试用）。
func fingerprintOf(t *testing.T, hub string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", hub, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("连接中继失败: %v", err)
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":")
}

type testDevice struct {
	ID          string
	Name        string
	Key         string
	Hub         string
	Fingerprint string
}

func TestDesktopEndToEnd(t *testing.T) {
	hub := envOr("E2E_HUB", e2eHubAddr)
	fp := fingerprintOf(t, hub)

	// 0. B 端：自助登记 + 生成一个控制端邀请码（P5：一码一机）
	t.Setenv("OCLINK_CONFIG_DIR", t.TempDir())
	app := NewApp()
	st0, err := app.SelfRegister(hub, fp)
	if err != nil {
		t.Fatalf("自助登记失败: %v", err)
	}
	if !st0.Activated || st0.DeviceID == "" {
		t.Fatalf("登记后状态不对: %+v", st0)
	}
	dev := testDevice{ID: st0.DeviceID, Name: st0.Name, Hub: hub, Fingerprint: fp}
	t.Logf("B 端已登记: %s (%s)", dev.Name, dev.ID)

	invite, err := app.CreateInvite("e2e-A")
	if err != nil {
		t.Fatalf("生成邀请码失败: %v", err)
	}
	prof, _, err := client.DecodeLink(invite)
	if err != nil {
		t.Fatalf("邀请码解析失败: %v", err)
	}
	if app.QRImage(invite) == "" {
		t.Error("二维码生成失败")
	}

	// 1. 启动 B 端（SelfRegister 已自动启动，这里确认状态）
	if err := app.Start(); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	defer app.Stop()

	var lastErr error
	ok := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Request(prof, proto.Request{Op: "ping", ID: "e2e"}, 5*time.Second)
		if err == nil && resp.OK {
			ok = true
			break
		}
		if err == nil && !resp.OK {
			lastErr = fmt.Errorf("对端拒绝: %s", resp.Error)
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("A 端 ping 失败: %v", lastErr)
	}
	t.Log("A 端 ping 成功（端到端加密会话正常）")

	// 控制端名字应自动回填到 B 端列表（不用手动起名）
	time.Sleep(400 * time.Millisecond)
	labeled := false
	for _, c := range app.ListClients() {
		if c.Label == "e2e-A" {
			labeled = true
		}
	}
	if !labeled {
		t.Errorf("控制端名字未自动回填: %+v", app.ListClients())
	} else {
		t.Log("控制端名字已自动回填")
	}

	// 3. 活动记录：peer-up + request
	act := app.GetActivity(200)
	hasPeerUp, hasReq := false, false
	for _, e := range act {
		if e.Kind == "peer-up" {
			hasPeerUp = true
		}
		if e.Kind == "request" && e.Op == "ping" && e.OK {
			hasReq = true
		}
	}
	if !hasPeerUp {
		t.Error("活动记录缺少 peer-up")
	}
	if !hasReq {
		t.Error("活动记录缺少 ping 请求")
	}

	// 4. A 端目标管理（列表 / 测试 / 删除）
	name, err := app.AddProfile(invite)
	if err != nil {
		t.Fatalf("添加目标失败: %v", err)
	}
	if _, err := app.TestProfile(name); err != nil {
		t.Fatalf("测试目标失败: %v", err)
	}
	found := false
	for _, p := range app.ListProfiles() {
		if p.Name == name {
			found = true
		}
	}
	if !found {
		t.Error("目标列表里没有新增目标")
	}
	if err := app.DeleteProfile(name); err != nil {
		t.Fatalf("删除目标失败: %v", err)
	}
	t.Log("A 端目标管理正常")

	// 5. 改名同步到中继
	api := newAdminAPI(t)
	api.do("POST", "/api/login", map[string]string{"username": "admin", "password": e2ePass}, nil)
	if err := app.SetName("改名桌面机"); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if !api.waitDeviceName(dev.ID, "改名桌面机", 10*time.Second) {
		t.Error("改名未同步到中继")
	} else {
		t.Log("改名已同步到中继")
	}

	// 6. 断开控制端（kick）
	conn, errCh, ready := holdClient(t, dev.Hub, prof.Key, dev.ID, prof.ClientID)
	select {
	case <-ready:
	case <-time.After(8 * time.Second):
		t.Fatal("A 端握手超时")
	}

	// 管理台应能看到当前控制端名字
	var adminDevices struct {
		Devices []struct {
			ID           string `json:"id"`
			ClientOnline bool   `json:"clientOnline"`
			ClientName   string `json:"clientName"`
		} `json:"devices"`
	}
	api.do("GET", "/api/devices", nil, &adminDevices)
	foundClient := false
	for _, d := range adminDevices.Devices {
		if d.ID == dev.ID {
			foundClient = true
			if !d.ClientOnline {
				t.Error("管理台应显示控制端在线")
			}
			if d.ClientName != "e2e-A" {
				t.Errorf("管理台控制端名字应为 e2e-A，得到 %q", d.ClientName)
			}
		}
	}
	if !foundClient {
		t.Error("管理台设备列表里没找到测试设备")
	} else {
		t.Log("管理台已显示当前控制端名字")
	}

	if err := app.DisconnectNow(); err != nil {
		t.Fatalf("断开失败: %v", err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("连接应被关闭")
		} else {
			t.Logf("控制端已被中继断开: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("kick 后连接未关闭")
	}
	conn.Close()

	// 7. 吊销配对：中继删设备 + 本地清密钥
	if err := app.Revoke(false); err != nil {
		t.Fatalf("吊销失败: %v", err)
	}
	if !api.waitDeviceGone(dev.ID, 10*time.Second) {
		t.Error("吊销后中继仍存在该设备")
	}
	if app.GetState().Activated {
		t.Error("吊销后本地应变为未激活")
	}
	t.Log("吊销后中继设备已删除、本地密钥已清除")
}

// TestDisableFlow 禁用语义：B 端保持在线（不被踢下线），但控制端连不上；
// 启用后立即恢复。管理台只显示在线设备，所以禁用设备仍会显示。
func TestDisableFlow(t *testing.T) {
	hub := envOr("E2E_HUB", e2eHubAddr)
	fp := fingerprintOf(t, hub)
	t.Setenv("OCLINK_CONFIG_DIR", t.TempDir())
	app := NewApp()
	st0, err := app.SelfRegister(hub, fp)
	if err != nil {
		t.Fatalf("自助登记失败: %v", err)
	}
	defer app.Stop()
	invite, err := app.CreateInvite("e2e-A")
	if err != nil {
		t.Fatalf("生成邀请码失败: %v", err)
	}
	prof, _, err := client.DecodeLink(invite)
	if err != nil {
		t.Fatalf("邀请码解析失败: %v", err)
	}

	api := newAdminAPI(t)
	api.do("POST", "/api/login", map[string]string{"username": "admin", "password": e2ePass}, nil)
	agentOnline := func() bool {
		var d2 struct {
			Devices []struct {
				ID          string `json:"id"`
				AgentOnline bool   `json:"agentOnline"`
				Disabled    bool   `json:"disabled"`
			} `json:"devices"`
		}
		api.do("GET", "/api/devices", nil, &d2)
		for _, x := range d2.Devices {
			if x.ID == st0.DeviceID {
				return x.AgentOnline
			}
		}
		return false
	}
	pingOK := func(timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			resp, err := client.Request(prof, proto.Request{Op: "ping", ID: "dis"}, 5*time.Second)
			if err == nil && resp.OK {
				return true
			}
			time.Sleep(500 * time.Millisecond)
		}
		return false
	}
	if !pingOK(15 * time.Second) {
		t.Fatal("初始 ping 失败")
	}

	// 控制端单独禁用（由 B 端本机执行，中继不参与）
	if err := app.SetClientDisabled(prof.ClientID, true); err != nil {
		t.Fatalf("禁用控制端失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := client.Request(prof, proto.Request{Op: "ping", ID: "cd"}, 6*time.Second); err == nil {
		t.Fatal("禁用控制端后不应能建立会话")
	}
	t.Log("控制端被禁用后无法建立会话")
	if err := app.SetClientDisabled(prof.ClientID, false); err != nil {
		t.Fatalf("启用控制端失败: %v", err)
	}
	if !pingOK(15 * time.Second) {
		t.Fatal("启用控制端后 ping 未恢复")
	}
	t.Log("控制端启用后恢复")

	// 禁用：B 端仍在线，但控制端连不上
	api.do("POST", "/api/devices/"+st0.DeviceID+"/disable", nil, nil)
	time.Sleep(2 * time.Second)
	if !agentOnline() {
		t.Fatal("禁用后 B 端不应掉线（应保持在线）")
	}
	if !app.GetState().Disabled {
		t.Error("B 端状态应显示已禁用")
	} else {
		t.Log("禁用后：B 端保持在线，状态显示已禁用")
	}
	if _, err := client.Request(prof, proto.Request{Op: "ping", ID: "no"}, 6*time.Second); err == nil {
		t.Fatal("禁用后控制端不应能连上")
	}
	t.Log("禁用后：控制端被拒绝")

	// 启用：恢复
	api.do("POST", "/api/devices/"+st0.DeviceID+"/enable", nil, nil)
	time.Sleep(2 * time.Second)
	if app.GetState().Disabled {
		t.Error("启用后禁用状态应清除")
	}
	if !pingOK(15 * time.Second) {
		t.Fatal("启用后 ping 未恢复")
	}
	t.Log("启用后：控制端恢复")

	// 清理（自助注销）
	_ = app.Revoke(false)
}

// TestBanFlow 管理台「禁用」：禁用后拒绝重新登记，启用后恢复。
func TestBanFlow(t *testing.T) {
	hub := envOr("E2E_HUB", e2eHubAddr)
	fp := fingerprintOf(t, hub)
	key, _, err := proto.NewPairingKey()
	if err != nil {
		t.Fatal(err)
	}
	id := proto.DeviceID(key)
	if err := agent.RegisterSelf(hub, fp, false, key, "禁用测试"); err != nil {
		t.Fatalf("登记失败: %v", err)
	}
	api := newAdminAPI(t)
	api.do("POST", "/api/login", map[string]string{"username": "admin", "password": e2ePass}, nil)

	// 禁用
	api.do("POST", "/api/devices/"+id+"/disable", nil, nil)
	if err := agent.RegisterSelf(hub, fp, false, key, "禁用测试"); err == nil {
		t.Fatal("禁用后仍能重新登记")
	}
	t.Log("禁用后重新登记被拒绝")

	// 启用后恢复
	api.do("POST", "/api/devices/"+id+"/enable", nil, nil)
	if err := agent.RegisterSelf(hub, fp, false, key, "禁用测试"); err != nil {
		t.Fatalf("启用后登记失败: %v", err)
	}
	t.Log("启用后登记成功")

	// 清理（自助注销）
	_ = agent.UnregisterSelf(hub, fp, false, key)
}

// TestSelfRegisterEndToEnd 验证「全盲自助配对」：
// B 端本机生成密钥 → 只把校验子键登记到中继（无需管理台）→ A 端凭连接码直接连。
func TestSelfRegisterEndToEnd(t *testing.T) {
	hub := envOr("E2E_HUB", e2eHubAddr)

	// 从 TLS 连接现算证书指纹
	conn, err := tls.Dial("tcp", hub, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("连接中继失败: %v", err)
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	fp := strings.Join(parts, ":")

	t.Setenv("OCLINK_CONFIG_DIR", t.TempDir())
	app := NewApp()
	st, err := app.SelfRegister(hub, fp)
	if err != nil {
		t.Fatalf("自助登记失败: %v", err)
	}
	if !st.Activated || st.DeviceID == "" {
		t.Fatalf("登记后状态不对: %+v", st)
	}
	t.Logf("自助登记成功: %s", st.DeviceID)
	invite, err := app.CreateInvite("e2e-A")
	if err != nil {
		t.Fatalf("生成邀请码失败: %v", err)
	}

	// 幂等：同一密钥重复登记应当成功
	key2, _, err := proto.NewPairingKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RegisterSelf(hub, fp, false, key2, "幂等测试"); err != nil {
		t.Fatalf("首次登记失败: %v", err)
	}
	if err := agent.RegisterSelf(hub, fp, false, key2, "幂等测试2"); err != nil {
		t.Fatalf("重复登记应当成功: %v", err)
	}

	// A 端凭连接码直接 ping
	prof, _, err := client.DecodeLink(invite)
	if err != nil {
		t.Fatalf("连接码解析失败: %v", err)
	}
	ok := false
	var lastErr error
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Request(prof, proto.Request{Op: "ping", ID: "selfreg"}, 5*time.Second)
		if err == nil && resp.OK {
			ok = true
			break
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("A 端凭连接码 ping 失败: %v", lastErr)
	}
	t.Log("A 端凭连接码直接连通（端到端加密）")

	// 清理：两台测试设备都自助注销
	_ = app.Revoke(false)
	_ = agent.UnregisterSelf(hub, fp, false, key2)
	app.Stop()
}

// TestRestartReconnect 复现用户场景：「B 关掉再打开，A 拿原来的邀请码根本连不上」。
// 并且按最坏情况构造：重启期间中继上的设备登记也被删（凭证一起消失）。
// 期望：B 重开后自动重新登记 + 自动补登记本机凭证，A 用原邀请码自动恢复，无需重新配对。
func TestRestartReconnect(t *testing.T) {
	hub := envOr("E2E_HUB", e2eHubAddr)
	fp := fingerprintOf(t, hub)
	t.Setenv("OCLINK_CONFIG_DIR", t.TempDir())

	app := NewApp()
	st0, err := app.SelfRegister(hub, fp)
	if err != nil {
		t.Fatalf("自助登记失败: %v", err)
	}
	invite, err := app.CreateInvite("e2e-restart")
	if err != nil {
		t.Fatalf("生成邀请码失败: %v", err)
	}
	prof, _, err := client.DecodeLink(invite)
	if err != nil {
		t.Fatalf("邀请码解析失败: %v", err)
	}
	pingOK := func(timeout time.Duration) bool {
		for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
			resp, err := client.Request(prof, proto.Request{Op: "ping", ID: "rr"}, 5*time.Second)
			if err == nil && resp.OK {
				return true
			}
			time.Sleep(500 * time.Millisecond)
		}
		return false
	}
	if !pingOK(15 * time.Second) {
		t.Fatal("首次连接失败")
	}
	t.Log("第一次连接成功")

	// ——「关了再打开」：停掉 B；并把中继上的设备登记删掉（最坏情况）——
	app.Stop()
	time.Sleep(1500 * time.Millisecond)
	api := newAdminAPI(t)
	api.do("POST", "/api/login", map[string]string{"username": "admin", "password": e2ePass}, nil)
	api.do("POST", "/api/devices/"+st0.DeviceID+"/forget", nil, nil)
	t.Log("B 已关闭，中继登记已删除")

	// 用同一份配置（同一密钥）重新打开
	app2 := NewApp()
	defer app2.Stop()
	if err := app2.Start(); err != nil {
		t.Fatalf("重开被控端失败: %v", err)
	}
	if !pingOK(90 * time.Second) {
		t.Fatal("B 重启后 A 用原邀请码一直连不上（问题仍在）")
	}
	t.Log("B 重启（登记被删）后：A 用原邀请码自动恢复")
	_ = app2.Revoke(false)
}
