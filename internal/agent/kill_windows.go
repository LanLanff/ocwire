//go:build windows

package agent

import (
	"os/exec"
	"strconv"
)

// setupProcAttr：Windows 下无需特殊属性。
func setupProcAttr(cmd *exec.Cmd) {}

// killTree：用 taskkill /T 杀掉整棵进程树（含子孙），避免超时后子进程残留。
func killTree(pid int) {
	_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid)).Run()
}
