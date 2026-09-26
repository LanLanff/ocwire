package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"oclink/internal/proto"
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

	// 以下仅在内存中使用，标识配置文件异常（不参与序列化）
	BrokenIdentity bool `json:"-"` // 配置损坏且密钥无法恢复：本次将登记为全新身份
	RecoveredKey   bool `json:"-"` // 配置损坏但密钥已从原文抢救回来
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

// 从损坏的 JSON 原文里抢救关键字段（正则；只用于恢复身份，不用于正常读取）
var (
	reKeyField = regexp.MustCompile(`"key"\s*:\s*"([^"]+)"`)
	reHubField = regexp.MustCompile(`"hub"\s*:\s*"([^"]+)"`)
	reFpField  = regexp.MustCompile(`"fingerprint"\s*:\s*"([^"]+)"`)
)

func rescueField(re *regexp.Regexp, raw []byte) string {
	m := re.FindSubmatch(raw)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// loadConfig 读取桌面配置；没有则尝试从 agent.json（配置目录 → exe 同目录）导入。
// 配置损坏时先尝试抢救密钥——绝不能静默换掉设备身份（否则已配对的控制端将永久连不上）。
func loadConfig() Config {
	var c Config
	if raw, err := os.ReadFile(desktopConfigPath()); err == nil {
		parseErr := json.Unmarshal(raw, &c)
		if parseErr != nil || strings.TrimSpace(c.Key) == "" {
			if k := rescueField(reKeyField, raw); k != "" {
				if _, perr := proto.ParsePairingKey(k); perr == nil {
					c.Key = k
					if c.Hub == "" {
						c.Hub = rescueField(reHubField, raw)
					}
					if c.Fingerprint == "" {
						c.Fingerprint = rescueField(reFpField, raw)
					}
					c.RecoveredKey = true
					_ = os.WriteFile(desktopConfigPath()+".recovered", raw, 0o600)
				}
			}
			if strings.TrimSpace(c.Key) == "" {
				// 密钥真的救不回来了：备份坏文件并标记；本次会登记为新身份（前端/日志会明确提示）
				bak := desktopConfigPath() + ".broken-" + time.Now().Format("20060102-150405")
				_ = os.WriteFile(bak, raw, 0o600)
				c.BrokenIdentity = true
			}
		}
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
