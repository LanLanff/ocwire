package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ActivityEntry 是活动记录里的一条（JSONL 持久化）。
// 规则：指令记全文；文件只记路径/大小/方向，不记内容。
type ActivityEntry struct {
	Time     string `json:"t"`
	Kind     string `json:"kind"` // connected|disconnected|peer-up|peer-down|request|kick|revoke|enroll|info
	Peer     string `json:"peer,omitempty"`
	ClientID string `json:"clientId,omitempty"`
	Op       string `json:"op,omitempty"`
	Detail   string `json:"detail,omitempty"`
	OK       bool   `json:"ok,omitempty"`
	MS       int64  `json:"ms,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Error    string `json:"error,omitempty"`
}

type activityLog struct {
	mu      sync.Mutex
	path    string
	buf     []ActivityEntry
	max     int
	keepDay int
}

func newActivityLog() *activityLog {
	l := &activityLog{
		path:    filepath.Join(configDir(), "activity.jsonl"),
		max:     1000,
		keepDay: 3,
	}
	l.load()
	return l
}

// load 读取历史并做保留期清理（顺带压缩文件）。
func (l *activityLog) load() {
	f, err := os.Open(l.path)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	cut := time.Now().AddDate(0, 0, -l.keepDay)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e ActivityEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.Before(cut) {
			continue
		}
		l.buf = append(l.buf, e)
	}
	f.Close()
	if len(l.buf) > l.max {
		l.buf = l.buf[len(l.buf)-l.max:]
	}
	l.rewrite()
}

func (l *activityLog) rewrite() {
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return
	}
	f, err := os.Create(l.path)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, e := range l.buf {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		w.Write(raw)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
}

func (l *activityLog) add(e ActivityEntry) {
	if e.Time == "" {
		e.Time = time.Now().Format(time.RFC3339)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, e)
	if len(l.buf) > l.max {
		l.buf = l.buf[len(l.buf)-l.max:]
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	raw, err := json.Marshal(e)
	if err == nil {
		f.Write(raw)
		f.Write([]byte("\n"))
	}
	f.Close()
}

// tail 返回最近 n 条（按时间正序，最新的在最后）。
func (l *activityLog) tail(n int) []ActivityEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.buf) {
		n = len(l.buf)
	}
	out := make([]ActivityEntry, n)
	copy(out, l.buf[len(l.buf)-n:])
	return out
}

// page 返回 before 毫秒时间戳之前（不含）的最近 n 条（按时间正序）；before<=0 表示不限。
func (l *activityLog) page(beforeMs int64, n int) []ActivityEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []ActivityEntry{}
	if n <= 0 || n > 200 {
		n = 100
	}
	for i := len(l.buf) - 1; i >= 0 && len(out) < n; i-- {
		e := l.buf[i]
		if beforeMs > 0 {
			if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.UnixMilli() >= beforeMs {
				continue
			}
		}
		out = append(out, e)
	}
	// 收集时是新→旧，反转成时间正序
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (l *activityLog) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = nil
	_ = os.Remove(l.path)
}
