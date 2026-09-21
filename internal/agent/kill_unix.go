//go:build !windows

package agent

import (
	"os/exec"
	"syscall"
)

// setupProcAttr：Linux/Unix 下让子进程自成一个进程组，便于整组清理。
func setupProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killTree：向整个进程组发 SIGKILL（含子孙）。
func killTree(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
