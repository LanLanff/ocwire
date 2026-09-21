//go:build windows

package agent

// Windows 服务宿主（纯 syscall 实现，不依赖第三方包）。
// agent -service 由 SCM 启动时进入这里；install/uninstall 用 sc.exe。

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32                          = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
)

const (
	svcWin32OwnProcess = 0x00000010
	svcStopped         = 0x00000001
	svcStartPending    = 0x00000002
	svcStopPending     = 0x00000003
	svcRunning         = 0x00000004
	svcAcceptStop      = 0x00000001
	svcAcceptShutdown  = 0x00000004
	svcControlStop     = 0x00000001
	svcControlShutdown = 0x00000005
)

// ServiceName 是 Windows 服务名。
const ServiceName = "oclink-agent"

const serviceDisplay = "oc-link agent (encrypted remote control)"

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceTableEntry struct {
	ServiceName *uint16
	ServiceProc uintptr
}

var (
	statusHandle  uintptr
	currentStatus serviceStatus
	gStopCh       chan struct{}
	gDone         chan struct{}
)

func setServiceStatus(state, accepted uint32) {
	currentStatus.ServiceType = svcWin32OwnProcess
	currentStatus.CurrentState = state
	currentStatus.ControlsAccepted = accepted
	procSetServiceStatus.Call(statusHandle, uintptr(unsafe.Pointer(&currentStatus)))
}

func serviceCtrlHandler(ctrl, eventType uint32, eventData, context uintptr) uintptr {
	switch ctrl {
	case svcControlStop, svcControlShutdown:
		setServiceStatus(svcStopPending, 0)
		select {
		case <-gStopCh:
		default:
			close(gStopCh)
		}
	}
	return 0
}

func serviceMain(argc uint32, argv **uint16) uintptr {
	namePtr, _ := syscall.UTF16PtrFromString(ServiceName)
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(namePtr)), syscall.NewCallback(serviceCtrlHandler), 0)
	statusHandle = uintptr(h)
	if statusHandle == 0 {
		return 1
	}
	setServiceStatus(svcStartPending, 0)
	setServiceStatus(svcRunning, svcAcceptStop|svcAcceptShutdown)
	<-gDone
	setServiceStatus(svcStopped, 0)
	return 0
}

// RunServiceMode 进入服务模式（-service 时调用）。run 在停服时会收到 close(stop)。
func RunServiceMode(run func(stop <-chan struct{})) error {
	gStopCh = make(chan struct{})
	gDone = make(chan struct{})
	go func() {
		run(gStopCh)
		close(gDone)
	}()
	namePtr, _ := syscall.UTF16PtrFromString(ServiceName)
	table := []serviceTableEntry{
		{ServiceName: namePtr, ServiceProc: syscall.NewCallback(serviceMain)},
		{ServiceName: nil, ServiceProc: 0},
	}
	ret, _, err := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if ret == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcher 失败: %v", err)
	}
	return nil
}

// InstallService 安装为 Windows 服务并启动（崩溃自动拉起，也用于自动更新后的重启）。
func InstallService(exePath string) error {
	bin := fmt.Sprintf("\"%s\" -service", exePath)
	if out, err := exec.Command("sc", "create", ServiceName, "binPath=", bin, "start=", "auto", "DisplayName=", serviceDisplay).CombinedOutput(); err != nil {
		msg := string(out)
		if !strings.Contains(msg, "1057") && !strings.Contains(msg, "已存在") && !strings.Contains(msg, "already exists") {
			return fmt.Errorf("sc create 失败: %v (%s)", err, strings.TrimSpace(msg))
		}
	}
	_, _ = exec.Command("sc", "failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000").CombinedOutput()
	out, err := exec.Command("sc", "start", ServiceName).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "1056") {
		return fmt.Errorf("sc start 失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UninstallService 停止并删除 Windows 服务。
func UninstallService() error {
	_, _ = exec.Command("sc", "stop", ServiceName).CombinedOutput()
	out, err := exec.Command("sc", "delete", ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete 失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ServiceStatusText 查询服务状态。
func ServiceStatusText() (string, error) {
	out, err := exec.Command("sc", "query", ServiceName).CombinedOutput()
	if err != nil {
		return "", errors.New("服务未安装")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "STATE") {
			return strings.TrimSpace(line), nil
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// RunningAsWindowsService 判断当前是否由 SCM 启动（供更新后自重启逻辑使用）。
func RunningAsWindowsService() bool {
	return statusHandle != 0
}

// underServiceEnv 其它平台的占位（保持跨平台编译）。
func underServiceEnv() bool { return RunningAsWindowsService() }

var _ = os.Getpid
