package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"oclink/internal/proto"
)

func withTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OCLINK_CONFIG_DIR", dir)
	return dir
}

// 配置损坏但 key 文本还在：必须从原文抢救回来，身份不能丢
func TestLoadConfigRescuesKeyFromBrokenJSON(t *testing.T) {
	dir := withTempConfig(t)
	_, keyText, err := proto.NewPairingKey()
	if err != nil {
		t.Fatal(err)
	}
	broken := "{\n \"name\": \"pc\",\n \"hub\": \"1.2.3.4:5\",\n \"key\": \"" + keyText + "\",\n \"clients\": [ {\"id\":\"abc\" "
	if err := os.WriteFile(filepath.Join(dir, "desktop.json"), []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadConfig()
	if c.Key != keyText {
		t.Fatalf("key 未恢复: %q", c.Key)
	}
	if !c.RecoveredKey {
		t.Fatal("应标记 RecoveredKey")
	}
	if c.Hub != "1.2.3.4:5" {
		t.Fatalf("hub 未恢复: %q", c.Hub)
	}
	if _, err := os.Stat(filepath.Join(dir, "desktop.json.recovered")); err != nil {
		t.Fatal("应留档 desktop.json.recovered")
	}
}

// 配置损坏且 key 救不回来：标记 BrokenIdentity 并备份，身份不会被悄悄换掉
func TestLoadConfigMarksBrokenWithoutKey(t *testing.T) {
	dir := withTempConfig(t)
	if err := os.WriteFile(filepath.Join(dir, "desktop.json"), []byte("{\"name\":\"x\""), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadConfig()
	if !c.BrokenIdentity {
		t.Fatal("应标记 BrokenIdentity")
	}
	if c.Key != "" {
		t.Fatalf("不应凭空有 key: %q", c.Key)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "desktop.json.broken-*"))
	if len(matches) == 0 {
		t.Fatal("应备份 broken 文件")
	}
}

// 正常配置照常读取，不误报
func TestLoadConfigNormal(t *testing.T) {
	dir := withTempConfig(t)
	raw, _ := json.Marshal(Config{Name: "pc", Hub: "h:1", Key: "OCL-ABC", Fingerprint: "fp"})
	if err := os.WriteFile(filepath.Join(dir, "desktop.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadConfig()
	if c.Name != "pc" || c.Key != "OCL-ABC" || c.BrokenIdentity || c.RecoveredKey {
		t.Fatalf("异常: %+v", c)
	}
}
