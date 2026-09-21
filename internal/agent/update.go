package agent

// agent 自更新：从 hub 拉版本清单（release.json + release.json.sig），
// Ed25519 验签 + SHA-256 校验后暂存为 oclink-agent.staged；
// 下次启动时自动替换自身（Windows/Linux 都允许重命名正在运行的 exe）。

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// AgentVersion 是 agent 自身版本（与协议版本 proto.Version 独立）。
const AgentVersion = "0.2.4"

// updatePublicKeyB64 是发布签名公钥（Ed25519, base64）。由 relsign -gen 生成后填入。
const updatePublicKeyB64 = "vHX9hUuCe4LdCHr+giwpqI+lNltrcHYpILRgDZJmoCs="

type updateManifest struct {
	Version string                `json:"version"`
	Notes   string                `json:"notes"`
	Files   map[string]updateFile `json:"files"`
}

type updateFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type stagedMeta struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func httpGet(url string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var r io.Reader = resp.Body
	if maxBytes > 0 {
		r = io.LimitReader(resp.Body, maxBytes)
	}
	return io.ReadAll(r)
}

func exeDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// CheckAndStageUpdate 检查并暂存升级包。返回新版本号（无更新返回空）。
func CheckAndStageUpdate(adminBase, currentVersion string) (string, error) {
	base := strings.TrimRight(adminBase, "/")
	if base == "" {
		return "", errors.New("未配置管理地址，无法检查更新")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(updatePublicKeyB64))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return "", errors.New("内置发布公钥无效（构建时未配置）")
	}
	manBytes, err := httpGet(base+"/api/agent/latest", 1<<20)
	if err != nil {
		return "", fmt.Errorf("获取版本清单失败: %w", err)
	}
	sigB64, err := httpGet(base+"/api/agent/latest.sig", 4096)
	if err != nil {
		return "", fmt.Errorf("获取签名失败: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return "", fmt.Errorf("签名格式错误: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), manBytes, sig) {
		return "", errors.New("版本清单签名校验失败（拒绝更新）")
	}
	var man updateManifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return "", fmt.Errorf("清单解析失败: %w", err)
	}
	if man.Version == "" || man.Version == currentVersion {
		return "", nil
	}
	key := runtime.GOOS + "-" + runtime.GOARCH
	f, ok := man.Files[key]
	if !ok || f.Name == "" {
		return "", fmt.Errorf("清单里没有 %s 的升级包", key)
	}
	data, err := httpGet(base+"/api/agent/files/"+f.Name, 200<<20)
	if err != nil {
		return "", fmt.Errorf("下载升级包失败: %w", err)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, f.SHA256) {
		return "", errors.New("升级包 SHA-256 校验失败（拒绝更新）")
	}
	dir, err := exeDir()
	if err != nil {
		return "", err
	}
	staged := filepath.Join(dir, "oclink-agent.staged")
	if err := os.WriteFile(staged, data, 0o755); err != nil {
		return "", err
	}
	meta, _ := json.Marshal(stagedMeta{Version: man.Version, SHA256: got})
	if err := os.WriteFile(staged+".json", meta, 0o600); err != nil {
		return "", err
	}
	return man.Version, nil
}

// ApplyStagedUpdate 若存在暂存升级包则替换自身，返回是否执行了替换与新版本号。
// 说明：正在运行的进程仍是旧镜像，新程序在下次启动生效。
func ApplyStagedUpdate() (string, bool) {
	dir, err := exeDir()
	if err != nil {
		return "", false
	}
	exe := filepath.Join(dir, agentExeName())
	staged := filepath.Join(dir, "oclink-agent.staged")
	if _, err := os.Stat(staged); err != nil {
		return "", false
	}
	var meta stagedMeta
	if data, err := os.ReadFile(staged + ".json"); err == nil {
		_ = json.Unmarshal(data, &meta)
	}
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return "", false
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(old, exe)
		return "", false
	}
	_ = os.Remove(staged + ".json")
	return meta.Version, true
}

func agentExeName() string {
	if runtime.GOOS == "windows" {
		return "oclink-agent.exe"
	}
	return "oclink-agent"
}

// UnderServiceEnv 是否运行在服务管理器下（systemd/SCM），用于更新后自重启。
func UnderServiceEnv() bool { return underServiceEnv() }
