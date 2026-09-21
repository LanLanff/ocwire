package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ClientRec 是本机授权的控制端凭证（B 端本地表：只存 id/标签/时间/是否禁用）。
type ClientRec struct {
	ID        string `json:"id"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
	Used      bool   `json:"used,omitempty"`     // 这个邀请码是否已被使用过（A 连上过）
	Disabled  bool   `json:"disabled,omitempty"` // 禁用后：该控制端无法建立会话
}

// Config 是桌面客户端的本地配置（B 端身份 + 设置）。
// 密钥只保存在本机：~/.config/oc-link/desktop.json
type Config struct {
	Name        string      `json:"name"`
	Hub         string      `json:"hub,omitempty"`
	Key         string      `json:"key,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Clients     []ClientRec `json:"clients,omitempty"` // 已授权的控制端（每个 A 一把独立钥匙）
	Disabled    bool        `json:"disabled,omitempty"` // 上次已知的“被中继禁用”状态（用于立即显示）
	ReadOnly    bool        `json:"readonly,omitempty"`
	Root        string      `json:"root,omitempty"`
	Autostart   bool        `json:"autostart,omitempty"`
}

func configDir() string {
	if v := os.Getenv("OCLINK_CONFIG_DIR"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".config", "oc-link")
}

func desktopConfigPath() string { return filepath.Join(configDir(), "desktop.json") }
func aConfigPath() string       { return filepath.Join(configDir(), "config.json") }
func agentConfigPath() string   { return filepath.Join(configDir(), "agent.json") }

func exeDirFile(name string) string {
	exe, err := os.Executable()
	if err != nil {
		return name
	}
	return filepath.Join(filepath.Dir(exe), name)
}

// loadConfig 读取桌面配置；没有则尝试从 agent.json（配置目录 → exe 同目录）导入。
func loadConfig() Config {
	var c Config
	if raw, err := os.ReadFile(desktopConfigPath()); err == nil {
		_ = json.Unmarshal(raw, &c)
	}
	if c.Key == "" {
		for _, p := range []string{agentConfigPath(), exeDirFile("agent.json")} {
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var ac Config
			if json.Unmarshal(raw, &ac) == nil && ac.Key != "" {
				c.Hub, c.Key, c.Fingerprint = ac.Hub, ac.Key, ac.Fingerprint
				if c.Name == "" {
					c.Name = ac.Name
				}
				c.ReadOnly, c.Root = ac.ReadOnly, ac.Root
				break
			}
		}
	}
	if c.Name == "" {
		c.Name = hostName()
	}
	return c
}

func saveConfig(c Config) error {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := desktopConfigPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, desktopConfigPath())
}

// ---- 设备名：默认取本机计算机名，可在「设置」里改 ----

func hostName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "设备"
}
