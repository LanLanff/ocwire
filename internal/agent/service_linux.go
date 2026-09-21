//go:build linux

package agent

// Linux 服务化：写 systemd unit 并 enable --now。

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const linuxUnitPath = "/etc/systemd/system/oclink-agent.service"

// RunServiceMode Linux 下服务即前台进程（由 systemd 托管）。
func RunServiceMode(run func(stop <-chan struct{})) error {
	run(make(chan struct{}))
	return nil
}

// InstallService 安装 systemd 服务（需要 root）。
func InstallService(exePath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("需要 root 权限：请用 sudo 运行 %s install", exePath)
	}
	unit := fmt.Sprintf(`[Unit]
Description=oc-link agent (encrypted remote control)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, exePath)
	if err := os.WriteFile(linuxUnitPath, []byte(unit), 0o644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if out, err := exec.Command("systemctl", "enable", "--now", "oclink-agent").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl 启用失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UninstallService 停止并删除 systemd 服务。
func UninstallService() error {
	_, _ = exec.Command("systemctl", "disable", "--now", "oclink-agent").CombinedOutput()
	_ = os.Remove(linuxUnitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// ServiceStatusText 查询服务状态。
func ServiceStatusText() (string, error) {
	if _, err := os.Stat(linuxUnitPath); err != nil {
		return "", errors.New("服务未安装")
	}
	out, _ := exec.Command("systemctl", "is-active", "oclink-agent").CombinedOutput()
	return strings.TrimSpace(string(out)), nil
}

// underServiceEnv 是否运行在 systemd 服务里（INVOCATION_ID 由 systemd 注入）。
func underServiceEnv() bool { return os.Getenv("INVOCATION_ID") != "" }
