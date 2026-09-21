package hub

// 审计日志：JSONL 追加写，记录 谁/哪台设备/何时/时长。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// auditKeepDays 审计保留天数（超期自动清理，避免文件无限膨胀）。
const auditKeepDays = 3

// AuditEntry 是一条审计记录。
type AuditEntry struct {
	Time       string `json:"time"`
	Action     string `json:"action"` // connect|disconnect|kick|enroll|device-create|device-delete|user-create|share
	Device     string `json:"device,omitempty"`
	DeviceName string `json:"deviceName,omitempty"`
	User       string `json:"user,omitempty"`
	Role       string `json:"role,omitempty"`
	Detail     string `json:"detail,omitempty"`
	DurationMs int64  `json:"durationMs,omitempty"`
}

// Auditor 追加写审计文件。
type Auditor struct {
	path      string
	mu        sync.Mutex
	lastPrune time.Time
}

// NewAuditor 创建审计器（启动时先清理过期记录）。
func NewAuditor(path string) *Auditor {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	a := &Auditor{path: path}
	a.pruneLocked()
	return a
}

// pruneLocked 删除保留期之外的记录（调用方需持有 a.mu；NewAuditor 启动阶段无并发）。
func (a *Auditor) pruneLocked() {
	a.lastPrune = time.Now()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return
	}
	cut := time.Now().AddDate(0, 0, -auditKeepDays)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	keep := make([]string, 0, len(lines))
	dropped := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			dropped++
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.Before(cut) {
			dropped++
			continue
		}
		keep = append(keep, line)
	}
	if dropped == 0 {
		return
	}
	tmp := a.path + ".tmp"
	if os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, a.path)
}

// Log 写入一条记录（失败静默，不影响主流程）。
func (a *Auditor) Log(e AuditEntry) {
	if a == nil {
		return
	}
	if e.Time == "" {
		e.Time = time.Now().Format(time.RFC3339)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.lastPrune) > time.Hour {
		a.pruneLocked()
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

// Tail 返回最后 n 条记录（新的在前）。
func (a *Auditor) Tail(n int) []AuditEntry { return a.TailBefore(n, time.Time{}) }

// TailBefore 返回 before 之前（不含）的最后 n 条记录（新的在前）；before 为零值表示不限。
func (a *Auditor) TailBefore(n int, before time.Time) []AuditEntry {
	if a == nil || n <= 0 {
		return []AuditEntry{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return []AuditEntry{}
	}
	// 只扫最后 2MB，避免大文件
	const maxScan = 2 << 20
	if len(data) > maxScan {
		cut := len(data) - maxScan
		for cut < len(data) && data[cut] != '\n' {
			cut++
		}
		data = data[cut:]
	}
	lines := []string{}
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	out := []AuditEntry{}
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var e AuditEntry
		if json.Unmarshal([]byte(lines[i]), &e) != nil {
			continue
		}
		if !before.IsZero() {
			if t, err := time.Parse(time.RFC3339, e.Time); err == nil && !t.Before(before) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}
