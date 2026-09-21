package hub

// 发布服务：给 agent 提供版本清单与升级包。
//
// 目录约定（hub -release-dir 指定，默认 data/releases）：
//   release.json      版本清单（用 relsign 签名）
//   release.json.sig  Ed25519 签名（base64）
//   agent-windows-amd64.exe / agent-linux-amd64 / agent-linux-arm64 / agent-macos-amd64 / agent-macos-arm64
//
// release.json 示例：
//   {"version":"0.2.0","notes":"...","files":{"windows-amd64":{"name":"agent-windows-amd64.exe","sha256":"..."}}}

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ReleaseServer 提供版本清单与文件下载（公开，无鉴权；内容本身不是秘密）。
type ReleaseServer struct {
	dir string
}

// NewReleaseServer 创建发布服务。
func NewReleaseServer(dir string) *ReleaseServer {
	return &ReleaseServer{dir: dir}
}

func (r *ReleaseServer) manifestPath() string { return filepath.Join(r.dir, "release.json") }

// ServeLatest 返回 release.json 内容。
func (r *ReleaseServer) ServeLatest(w http.ResponseWriter, req *http.Request) {
	data, err := os.ReadFile(r.manifestPath())
	if err != nil {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// ServeSig 返回 release.json.sig。
func (r *ReleaseServer) ServeSig(w http.ResponseWriter, req *http.Request) {
	data, err := os.ReadFile(r.manifestPath() + ".sig")
	if err != nil {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

// ServeFile 按文件名下载发布文件（只允许目录内的单个文件名，防目录穿越）。
func (r *ReleaseServer) ServeFile(w http.ResponseWriter, req *http.Request) {
	name := strings.TrimPrefix(req.URL.Path, "/api/agent/files/")
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		http.NotFound(w, req)
		return
	}
	path := filepath.Join(r.dir, filepath.Base(name))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.NotFound(w, req)
		return
	}
	http.ServeFile(w, req, path)
}
