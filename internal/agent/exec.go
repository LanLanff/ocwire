package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"oclink/internal/proto"
)

const (
	defaultTimeoutMs = 120_000
	maxOutputBytes   = 200 * 1024
	maxReadBytes     = 4 << 20
)

// HandleRequest 在 B 上执行一条请求。文件路径会经过 root 校验（若配置了 root）。
func HandleRequest(cfg Config, req proto.Request) proto.Response {
	if req.Op != "ping" {
		log.Printf("收到请求: %s", requestSummary(req))
	}
	resp := proto.Response{Op: req.Op, ID: req.ID}
	switch req.Op {
	case "ping":
		resp.OK = true
	case "exec":
		if cfg.ReadOnly {
			resp.Error = "该设备为只读模式，禁止执行命令"
			return resp
		}
		return doExec(cfg, req)
	case "read":
		return doRead(cfg, req)
	case "write":
		if cfg.ReadOnly {
			resp.Error = "该设备为只读模式，禁止写入"
			return resp
		}
		return doWrite(cfg, req)
	case "list":
		return doList(cfg, req)
	case "edit":
		return handleEdit(cfg, req)
	case "grep":
		return doGrep(cfg, req)
	case "glob":
		return doGlob(cfg, req)
	default:
		resp.Error = "未知操作: " + req.Op
	}
	return resp
}

// requestSummary 生成一行请求摘要，供 B 端窗口日志显示（内容已转义，保证单行）。
func requestSummary(req proto.Request) string {
	switch req.Op {
	case "exec":
		s := fmt.Sprintf("exec cmd=%q", req.Cmd)
		if req.Cwd != "" {
			s += fmt.Sprintf(" cwd=%q", req.Cwd)
		}
		return s
	case "read", "list":
		return fmt.Sprintf("%s path=%q", req.Op, req.Path)
	case "write":
		return fmt.Sprintf("write path=%q 约%d字节", req.Path, base64.StdEncoding.DecodedLen(len(req.DataB64)))
	case "edit":
		return fmt.Sprintf("edit path=%q", req.Path)
	case "grep", "glob":
		return fmt.Sprintf("%s pattern=%q path=%q", req.Op, req.Pattern, req.Path)
	default:
		return req.Op
	}
}

func doExec(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	if strings.TrimSpace(req.Cmd) == "" {
		resp.Error = "命令为空"
		return resp
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeoutMs * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	shell, args := shellFor(req.Shell, req.Cmd)
	cmd := exec.CommandContext(ctx, shell, args...)
	setupProcAttr(cmd)
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			killTree(cmd.Process.Pid)
		}
		return nil
	}
	if req.Cwd != "" {
		dir, err := safePath(cfg, req.Cwd)
		if err != nil {
			resp.Error = err.Error()
			return resp
		}
		cmd.Dir = dir
	}
	outW := &limitWriter{max: maxOutputBytes}
	errW := &limitWriter{max: maxOutputBytes}
	cmd.Stdout = outW
	cmd.Stderr = errW

	start := time.Now()
	err := cmd.Run()
	resp.DurationMs = time.Since(start).Milliseconds()
	resp.Stdout = outW.String()
	resp.Stderr = errW.String()
	resp.Truncated = outW.truncated || errW.truncated

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		resp.Error = "命令超时"
	case err != nil:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			resp.ExitCode = ee.ExitCode()
		} else {
			resp.Error = err.Error()
		}
	default:
		resp.OK = true
	}
	if resp.Error != "" {
		log.Printf("命令结束: exit=%d 用时=%dms 错误=%q", resp.ExitCode, resp.DurationMs, resp.Error)
	} else {
		log.Printf("命令结束: exit=%d 用时=%dms", resp.ExitCode, resp.DurationMs)
	}
	return resp
}

// shellFor 选择执行命令的外壳。默认：Windows=PowerShell，其它=/bin/sh。
func shellFor(shell, cmd string) (string, []string) {
	psCmd := "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd
	switch shell {
	case "cmd":
		if runtime.GOOS == "windows" {
			return "cmd", []string{"/C", cmd}
		}
	case "sh":
		return "/bin/sh", []string{"-c", cmd}
	case "powershell", "pwsh":
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", psCmd}
	}
	if runtime.GOOS == "windows" {
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-Command", psCmd}
	}
	return "/bin/sh", []string{"-c", cmd}
}

func doRead(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	path, err := safePath(cfg, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	st, err := os.Stat(path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	if st.IsDir() {
		resp.Error = "这是一个目录，请用 list"
		return resp
	}
	limit := req.MaxBytes
	if limit <= 0 || limit > maxReadBytes {
		limit = maxReadBytes
	}
	data := make([]byte, limit)
	f, err := os.Open(path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	defer f.Close()
	n, err := io.ReadFull(f, data)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		resp.Error = err.Error()
		return resp
	}
	data = data[:n]
	resp.Size = st.Size()
	resp.Truncated = st.Size() > int64(n)
	resp.Path = path
	if utf8.Valid(data) {
		resp.Encoding = "utf8"
		resp.Content = string(data)
	} else {
		resp.Encoding = "base64"
		resp.Content = base64.StdEncoding.EncodeToString(data)
	}
	resp.OK = true
	return resp
}

func doWrite(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		resp.Error = "内容解码失败"
		return resp
	}
	path, err := safePath(cfg, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	if req.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			resp.Error = err.Error()
			return resp
		}
	}
	// 先写临时文件再改名：原子替换，避免写一半崩掉。
	tmp := path + ".oclink.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		resp.Error = err.Error()
		return resp
	}
	if err := os.Rename(tmp, path); err != nil {
		resp.Error = err.Error()
		return resp
	}
	resp.OK = true
	resp.Bytes = len(data)
	resp.Path = path
	return resp
}

func doList(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	path, err := safePath(cfg, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	resp.Path = path
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		resp.Entries = append(resp.Entries, proto.Entry{
			Name:    e.Name(),
			Dir:     e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}
	resp.OK = true
	return resp
}

// safePath 规范化路径；如果配置了 root，则不允许越界（防目录穿越）。
func safePath(cfg Config, p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("路径为空")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if cfg.Root == "" {
		return abs, nil
	}
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("路径超出允许范围")
	}
	return abs, nil
}

// limitWriter 限制输出大小，超出部分丢弃并标记 truncated。
type limitWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.max {
		w.truncated = true
		return len(p), nil
	}
	room := w.max - w.buf.Len()
	if len(p) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *limitWriter) String() string { return w.buf.String() }
