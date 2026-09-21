//go:build darwin

package agent

// macOS：服务化暂未内置（用 launchd 手动配置），此处给出提示与占位。

import (
	"errors"
	"fmt"
)

// RunServiceMode macOS 下服务即前台进程。
func RunServiceMode(run func(stop <-chan struct{})) error {
	run(make(chan struct{}))
	return nil
}

// InstallService 暂未内置 launchd 安装。
func InstallService(exePath string) error {
	return fmt.Errorf("macOS 暂未内置服务安装；可手动创建 launchd plist，ExecStart=%s", exePath)
}

// UninstallService 占位。
func UninstallService() error {
	return errors.New("macOS 暂未内置服务安装")
}

// ServiceStatusText 占位。
func ServiceStatusText() (string, error) {
	return "", errors.New("macOS 暂未内置服务安装")
}

func underServiceEnv() bool { return false }
