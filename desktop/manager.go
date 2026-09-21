package main

// A 端（控制端）界面对接：客户端不自己持有长连接，而是连到常驻的插件引擎
// （opencode 插件进程里的连接管理器，见 plugin/client.mjs）。
// 引擎地址与令牌写在 ~/.config/oc-link/manager.json。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type managerInfo struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

func readManagerInfo() (managerInfo, bool) {
	var info managerInfo
	raw, err := os.ReadFile(filepath.Join(configDir(), "manager.json"))
	if err != nil {
		return info, false
	}
	if json.Unmarshal(raw, &info) != nil || info.Port == 0 || info.Token == "" {
		return info, false
	}
	return info, true
}

func managerCall(info managerInfo, method, path string, body any, out any, timeout time.Duration) error {
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", info.Port, path), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+info.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("引擎错误 HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ManagerTarget 是引擎里的一个目标状态。
type ManagerTarget struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Peer     string `json:"peer"`
	Error    string `json:"error"`
	Requests int    `json:"requests"`
}

// ManagerStateView 返回给前端：引擎是否运行 + 目标状态。
type ManagerStateView struct {
	Running    bool            `json:"running"`
	ClientName string          `json:"clientName,omitempty"`
	Targets    []ManagerTarget `json:"targets"`
}

// ManagerState 读取常驻引擎状态（引擎没运行返回 running=false）。
func (a *App) ManagerState() ManagerStateView {
	view := ManagerStateView{Targets: []ManagerTarget{}}
	info, ok := readManagerInfo()
	if !ok {
		return view
	}
	var st struct {
		OK         bool            `json:"ok"`
		ClientName string          `json:"clientName"`
		Targets    []ManagerTarget `json:"targets"`
	}
	if err := managerCall(info, "GET", "/state", nil, &st, 3*time.Second); err != nil {
		return view
	}
	view.Running = true
	view.ClientName = st.ClientName
	if st.Targets != nil {
		view.Targets = st.Targets
	}
	return view
}

// ManagerConnect 让常驻引擎对某个目标开启长连接（断线自动重连）。
func (a *App) ManagerConnect(name string) error {
	info, ok := readManagerInfo()
	if !ok {
		return fmt.Errorf("常驻引擎未运行（请先启动 oc 壳子）")
	}
	return managerCall(info, "POST", "/connect", map[string]string{"name": name}, nil, 8*time.Second)
}

// ManagerDisconnect 断开某个目标的长连接。
func (a *App) ManagerDisconnect(name string) error {
	info, ok := readManagerInfo()
	if !ok {
		return fmt.Errorf("常驻引擎未运行（请先启动 oc 壳子）")
	}
	return managerCall(info, "POST", "/disconnect", map[string]string{"name": name}, nil, 8*time.Second)
}
