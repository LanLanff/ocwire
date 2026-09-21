package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"oclink/internal/proto"
)

const (
	maxEditBytes     = 8 << 20 // 编辑文件大小上限
	maxGrepFileBytes = 1 << 20 // 参与 grep 的单文件上限
	maxScanFiles     = 20000   // 单次扫描文件数上限
	maxMatches       = 500     // 单次返回条数上限
)

// handleEdit：先查只读模式，再执行编辑。
func handleEdit(cfg Config, req proto.Request) proto.Response {
	if cfg.ReadOnly {
		return proto.Response{Op: req.Op, ID: req.ID, Error: "该设备为只读模式，禁止修改文件"}
	}
	return doEdit(cfg, req)
}

// doEdit 在远端文件里做精确字符串替换（对齐本地 edit 工具的行为）。
// 默认要求匹配唯一；replaceAll=true 时全部替换。
func doEdit(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	if req.OldString == "" {
		resp.Error = "oldString 不能为空"
		return resp
	}
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
		resp.Error = "这是一个目录，不能编辑"
		return resp
	}
	if st.Size() > maxEditBytes {
		resp.Error = "文件过大，拒绝编辑（上限 8MB，可用 oc_exec 处理）"
		return resp
	}
	data, err := os.ReadFile(path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	if !utf8.Valid(data) {
		resp.Error = "文件不是文本（含二进制内容），拒绝编辑"
		return resp
	}
	content := string(data)
	count := strings.Count(content, req.OldString)
	if count == 0 {
		resp.Error = "未找到匹配内容"
		return resp
	}
	if count > 1 && !req.ReplaceAll {
		resp.Error = "匹配到 " + strconv.Itoa(count) + " 处，请提供更长的上下文或设置 replaceAll"
		return resp
	}
	out := content
	n := 1
	if req.ReplaceAll {
		out = strings.ReplaceAll(content, req.OldString, req.NewString)
		n = count
	} else {
		out = strings.Replace(content, req.OldString, req.NewString, 1)
	}
	// 原子写回
	tmp := path + ".oclink.tmp"
	if err := os.WriteFile(tmp, []byte(out), 0o644); err != nil {
		resp.Error = err.Error()
		return resp
	}
	if err := os.Rename(tmp, path); err != nil {
		resp.Error = err.Error()
		return resp
	}
	resp.OK = true
	resp.Path = path
	resp.Count = n
	resp.Bytes = len(out)
	return resp
}

// doGrep 在远端目录里按正则搜索文件内容（对齐本地 grep 工具）。
func doGrep(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	if req.Pattern == "" {
		resp.Error = "pattern 不能为空"
		return resp
	}
	re, err := regexp.Compile(req.Pattern)
	if err != nil {
		resp.Error = "正则无效: " + err.Error()
		return resp
	}
	root, err := safePath(cfg, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	limit := req.MaxResults
	if limit <= 0 || limit > maxMatches {
		limit = 200
	}
	out := []string{}
	scanned := 0
	stop := errors.New("stop")
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= limit {
			return stop
		}
		scanned++
		if scanned > maxScanFiles {
			return stop
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxGrepFileBytes {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			return nil // 跳过二进制
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !re.MatchString(line) {
				continue
			}
			t := strings.TrimSpace(line)
			if len(t) > 200 {
				t = t[:200]
			}
			out = append(out, p+":"+strconv.Itoa(i+1)+": "+t)
			if len(out) >= limit {
				break
			}
		}
		return nil
	})
	resp.OK = true
	resp.Matches = out
	resp.Count = len(out)
	resp.Truncated = len(out) >= limit
	return resp
}

// doGlob 按文件名模式查找文件（支持 *、?、**，对齐本地 glob 工具）。
func doGlob(cfg Config, req proto.Request) proto.Response {
	resp := proto.Response{Op: req.Op, ID: req.ID}
	if req.Pattern == "" {
		resp.Error = "pattern 不能为空"
		return resp
	}
	root, err := safePath(cfg, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	re, err := globToRegexp(req.Pattern)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	limit := req.MaxResults
	if limit <= 0 || limit > maxMatches {
		limit = 200
	}
	withSlash := strings.Contains(req.Pattern, "/")
	out := []string{}
	stop := errors.New("stop")
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if len(out) >= limit {
			return stop
		}
		target := d.Name()
		if withSlash {
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return nil
			}
			target = filepath.ToSlash(rel)
		}
		if re.MatchString(target) {
			out = append(out, p)
		}
		return nil
	})
	resp.OK = true
	resp.Matches = out
	resp.Count = len(out)
	resp.Truncated = len(out) >= limit
	return resp
}

// globToRegexp 把 glob 转为正则：** 跨层级，* 不跨 /，? 单字符。
func globToRegexp(pat string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
