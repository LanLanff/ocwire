package hub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 3 天保留：启动时清理过期记录。
func TestAuditPruneKeepsThreeDays(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	old := time.Now().AddDate(0, 0, -4).Format(time.RFC3339)
	recent := time.Now().Add(-time.Hour).Format(time.RFC3339)
	content := `{"time":"` + old + `","action":"connect","device":"x"}` + "\n" +
		`{"time":"` + recent + `","action":"kick","device":"x"}` + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAuditor(p) // 构造时清理
	got := a.Tail(10)
	if len(got) != 1 || got[0].Action != "kick" {
		t.Fatalf("期望只剩 1 条 kick，实际: %+v", got)
	}
	data, _ := os.ReadFile(p)
	if strings.Contains(string(data), old) {
		t.Fatal("过期记录仍在文件里")
	}
}

// 分页：TailBefore 返回 before 之前的记录，不重复不遗漏。
func TestAuditTailBeforePaging(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	base := time.Now().Add(-time.Hour)
	var lines []string
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		lines = append(lines, `{"time":"`+ts+`","action":"a`+string(rune('0'+i))+`"}`)
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAuditor(p)
	page1 := a.TailBefore(2, time.Time{})
	if len(page1) != 2 || page1[0].Action != "a4" || page1[1].Action != "a3" {
		t.Fatalf("第一页错误: %+v", page1)
	}
	before, _ := time.Parse(time.RFC3339, page1[1].Time)
	page2 := a.TailBefore(2, before)
	if len(page2) != 2 || page2[0].Action != "a2" || page2[1].Action != "a1" {
		t.Fatalf("第二页错误: %+v", page2)
	}
	page3 := a.TailBefore(2, func() time.Time { t0, _ := time.Parse(time.RFC3339, page2[1].Time); return t0 }())
	if len(page3) != 1 || page3[0].Action != "a0" {
		t.Fatalf("第三页错误: %+v", page3)
	}
}
