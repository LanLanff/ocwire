// oc-link agent（B 端）。
//
// 用法：
//
//	oclink-agent                     前台运行（读 exe 同目录 agent.json）
//	oclink-agent install             安装为系统服务（开机自启、崩溃自拉起）
//	oclink-agent uninstall           卸载服务
//	oclink-agent status              查看服务状态
//	oclink-agent version             打印版本
//	oclink-agent -register -hub 124.93.28.120:21122 -fingerprint <证书指纹>   自助配对（打印连接码）
//	oclink-agent -service            （内部）以服务方式运行
//
// agent.json 示例：
//
//	{
//	  "hub": "124.93.28.120:21122",
//	  "key": "OCL-....",
//	  "fingerprint": "AA:BB:CC:...",
//	  "readonly": false,
//	  "root": "",
//	  "name": "我的电脑",
//	  "admin": "http://192.168.1.40:10000"   // 可选：自动更新/激活用
//	}
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"oclink/internal/agent"
	"oclink/internal/client"
	"oclink/internal/proto"
)

type fileConfig struct {
	Hub         string `json:"hub"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
	ReadOnly    bool   `json:"readonly"`
	Root        string `json:"root"`
	Name        string `json:"name"`
	Insecure    bool   `json:"insecure"`
	Admin       string `json:"admin"` // 管理页地址（自动更新用）
	Clients     []struct {
		ID    string `json:"id"`
		Label string `json:"label,omitempty"`
	} `json:"clients,omitempty"`
}

func exePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "oclink-agent"
	}
	return exe
}

func main() {
	// 子命令（install / uninstall / status / version）
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		switch os.Args[1] {
		case "install":
			if err := agent.InstallService(exePath()); err != nil {
				log.Fatalf("安装服务失败: %v", err)
			}
			fmt.Println("✅ 服务已安装并启动（oclink-agent）。")
			fmt.Println("   配置：请把 agent.json 放在程序同目录，或用 -enroll 激活。")
			return
		case "uninstall":
			if err := agent.UninstallService(); err != nil {
				log.Fatalf("卸载服务失败: %v", err)
			}
			fmt.Println("✅ 服务已卸载。")
			return
		case "status":
			s, err := agent.ServiceStatusText()
			if err != nil {
				fmt.Println("服务状态：未安装")
				return
			}
			fmt.Println("服务状态：" + s)
			return
		case "version":
			fmt.Printf("oclink-agent %s（协议 %s，%s/%s）\n", agent.AgentVersion, proto.Version, runtime.GOOS, runtime.GOARCH)
			return
		}
	}

	cfgPath := flag.String("config", "", "配置文件路径（默认：exe 同目录的 agent.json）")
	hub := flag.String("hub", "", "中继地址 host:port")
	keyStr := flag.String("key", "", "配对密钥")
	fp := flag.String("fingerprint", "", "服务器证书 SHA-256 指纹")
	name := flag.String("name", "", "设备名（日志用）")
	root := flag.String("root", "", "文件操作限定目录")
	readonly := flag.Bool("readonly", false, "只读模式（禁 exec/write）")
	insecure := flag.Bool("insecure", false, "跳过证书指纹校验（仅本地测试）")
	adminBase := flag.String("admin", "", "管理页地址（自动更新/设备流激活用，如 http://192.168.1.40:10000）")
	serviceMode := flag.Bool("service", false, "以系统服务方式运行（由服务管理器调用）")
	registerMode := flag.Bool("register", false, "自助配对：本机生成密钥并登记到中继，打印连接码（免管理台）")
	noUpdate := flag.Bool("no-update", false, "关闭自动更新检查")
	flag.Parse()

	// 先应用暂存更新（把新版本 exe 换到位，下次启动生效）
	if v, ok := agent.ApplyStagedUpdate(); ok {
		log.Printf("已应用后台更新（目标版本 %s），重启后生效", v)
	}

	configFile := *cfgPath
	if configFile == "" {
		if exe, err := os.Executable(); err == nil {
			configFile = filepath.Join(filepath.Dir(exe), "agent.json")
		} else {
			configFile = "agent.json"
		}
	}
	fc := fileConfig{}
	if data, err := os.ReadFile(configFile); err == nil {
		_ = json.Unmarshal(data, &fc)
	} else {
		log.Printf("未读到配置文件（将只使用命令行参数）: %s", configFile)
	}
	pick := func(flagVal, fileVal string) string {
		if flagVal != "" {
			return flagVal
		}
		return fileVal
	}

	admin := pick(*adminBase, fc.Admin)

	// 双击（无参数、无配置）时给出中文引导
	noArgs := *hub == "" && *keyStr == "" && fc.Hub == "" && fc.Key == "" && !*serviceMode && !*registerMode
	if noArgs {
		interactiveGuide()
		return
	}

	// 自助配对（全盲，免管理台）：本机生成密钥 → 登记到中继 → 写 agent.json → 打印连接码
	if *registerMode {
		hubAddr := pick(*hub, fc.Hub)
		if hubAddr == "" {
			hubAddr = agent.DefaultHub
		}
		fp := pick(*fp, fc.Fingerprint)
		if fp == "" && hubAddr == agent.DefaultHub {
			fp = agent.DefaultFingerprint
		}
		if hubAddr == "" {
			log.Fatalf("缺少中继地址：用 -hub 指定")
		}
		if fp == "" && !*insecure && !fc.Insecure {
			log.Fatalf("缺少证书指纹：用 -fingerprint 指定，或 -insecure（仅本地测试）")
		}
		regName := pick(*name, fc.Name)
		if regName == "" {
			regName, _ = os.Hostname()
		}
		var key []byte
		keyText := pick(*keyStr, fc.Key)
		if keyText == "" {
			k, _, err := proto.NewPairingKey()
			if err != nil {
				log.Fatalf("生成密钥失败: %v", err)
			}
			key = k
			keyText = proto.FormatPairingKey(k)
		} else {
			k, err := proto.ParsePairingKey(keyText)
			if err != nil {
				log.Fatalf("配对密钥无效: %v", err)
			}
			key = k
		}
		clientID, err := proto.NewClientID()
		if err != nil {
			log.Fatalf("生成凭证失败: %v", err)
		}
		clientKey := proto.ClientKey(key, clientID)
		authKeyB64 := base64.StdEncoding.EncodeToString(proto.AuthKey(clientKey))
		if err := agent.RegisterSelf(hubAddr, fp, *insecure || fc.Insecure, key, regName); err != nil {
			log.Fatalf("自助登记失败: %v", err)
		}
		if err := agent.ProvisionClient(hubAddr, fp, *insecure || fc.Insecure, key, clientID, authKeyB64, "默认"); err != nil {
			log.Fatalf("登记控制端凭证失败: %v", err)
		}
		obj := map[string]any{
			"hub": hubAddr, "key": keyText, "fingerprint": fp, "name": regName,
			"readonly": false, "root": "",
			"clients": []map[string]string{{"id": clientID, "label": "默认"}},
		}
		data, _ := json.MarshalIndent(obj, "", "  ")
		if err := os.WriteFile(configFile, data, 0o600); err != nil {
			log.Fatalf("写入配置失败: %v", err)
		}
		fmt.Println("✅ 已登记到中继（中继只保存校验子键，无法解密）")
		fmt.Printf("配置文件: %s\n\n", configFile)
		fmt.Println("把下面这串「邀请码」发给 A 端输入（或扫码）：")
		fmt.Println(client.EncodeInvite(hubAddr, proto.FormatPairingKey(clientKey), fp, regName, proto.DeviceID(key), clientID, "默认"))
		return
	}

	keyText := pick(*keyStr, fc.Key)
	cfg := agent.Config{
		Hub:         pick(*hub, fc.Hub),
		Fingerprint: pick(*fp, fc.Fingerprint),
		Name:        pick(*name, fc.Name),
		Root:        pick(*root, fc.Root),
		ReadOnly:    *readonly || fc.ReadOnly,
		Insecure:    *insecure || fc.Insecure,
	}
	if cfg.Hub == "" || keyText == "" {
		fmt.Fprintf(os.Stderr, "缺少 hub 或 key。两种接入方式：\n"+
			"  1) 自助配对：oclink-agent -register（本机生成密钥、登记并写配置）\n"+
			"  2) 命令行参数：-hub ... -key ... -fingerprint ...\n"+
			"  配置文件路径：%s\n", configFile)
		os.Exit(2)
	}
	key, err := proto.ParsePairingKey(keyText)
	if err != nil {
		log.Fatalf("配对密钥无效: %v", err)
	}
	cfg.Key = key
	if len(fc.Clients) > 0 {
		clients := fc.Clients
		cfg.ClientEncKey = func(clientID string) ([]byte, bool) {
			for _, c := range clients {
				if c.ID == clientID {
					return proto.EncKey(proto.ClientKey(key, clientID)), true
				}
			}
			return nil, false
		}
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	if cfg.Name == "" {
		cfg.Name = "device-" + proto.DeviceID(key)
	}
	if cfg.Root != "" {
		abs, err := filepath.Abs(cfg.Root)
		if err != nil {
			log.Fatalf("root 路径无效: %v", err)
		}
		cfg.Root = abs
	}

	// 自动更新检查（后台）
	if admin != "" && !*noUpdate {
		go updateLoop(admin, *serviceMode)
	}

	log.Printf("oc-link-agent %s | 设备 %s | 中继 %s | 只读=%v | root=%q", agent.AgentVersion, cfg.Name, cfg.Hub, cfg.ReadOnly, cfg.Root)

	run := func(stop <-chan struct{}) {
		a := agent.New(cfg)
		go a.Run()
		<-stop
	}
	if *serviceMode {
		if err := agent.RunServiceMode(run); err != nil {
			log.Fatalf("服务模式启动失败: %v", err)
		}
		return
	}
	run(nil)
}

// interactiveGuide 是双击运行（无配置）时的中文引导。
func interactiveGuide() {
	in := bufio.NewReader(os.Stdin)
	fmt.Println("======================================")
	fmt.Println("           oc-link 被控端")
	fmt.Println("======================================")
	fmt.Println()
	fmt.Println("没有找到配置（agent.json）。选择接入方式：")
	fmt.Println("  1) 生成连接码（推荐，免管理台）：本机生成密钥并登记到中继")
	fmt.Println("  2) 安装为系统服务（需管理员权限；建议先完成配对）")
	fmt.Println("  3) 查看手动方式 / 退出")
	fmt.Print("\n请选择 [1/2/3]: ")
	line, _ := in.ReadString('\n')
	switch strings.TrimSpace(line) {
	case "1":
		guideSelfRegister(in)
		return
	case "2":
		if err := agent.InstallService(exePath()); err != nil {
			fmt.Printf("安装服务失败: %v\n（提示：请用「以管理员身份运行」再试）\n", err)
		} else {
			fmt.Println("✅ 已安装为系统服务（请确保已先完成配对）。")
		}
	default:
		fmt.Println()
		fmt.Println("手动方式：")
		fmt.Println("  · 自助配对：oclink-agent -register -hub 124.93.28.120:21122 -fingerprint <证书指纹>")
		fmt.Println("  · 或把 agent.json 放到本程序同目录，然后双击运行")
		fmt.Println("  · 安装服务：oclink-agent install（管理员）")
		fmt.Println("  · 查看状态：oclink-agent status")
	}
	pause(in)
}

// guideSelfRegister 双击引导：本机生成密钥并登记到中继，打印连接码。
func guideSelfRegister(in *bufio.Reader) {
	name, _ := os.Hostname()
	hubAddr, fp := agent.DefaultHub, agent.DefaultFingerprint
	if hubAddr == "" {
		fmt.Print("中继地址（如 124.93.28.120:21122）: ")
		l, _ := in.ReadString('\n')
		hubAddr = strings.TrimSpace(l)
		if hubAddr == "" {
			fmt.Println("未填写地址，已退出。")
			pause(in)
			return
		}
		fmt.Print("证书指纹: ")
		l, _ = in.ReadString('\n')
		fp = strings.TrimSpace(l)
		if fp == "" {
			fmt.Println("未填写指纹，已退出。")
			pause(in)
			return
		}
	}
	key, _, err := proto.NewPairingKey()
	if err != nil {
		fmt.Printf("生成密钥失败: %v\n", err)
		pause(in)
		return
	}
	clientID, err := proto.NewClientID()
	if err != nil {
		fmt.Printf("生成凭证失败: %v\n", err)
		pause(in)
		return
	}
	clientKey := proto.ClientKey(key, clientID)
	authKeyB64 := base64.StdEncoding.EncodeToString(proto.AuthKey(clientKey))
	if err := agent.RegisterSelf(hubAddr, fp, false, key, name); err != nil {
		fmt.Printf("\n登记失败: %v\n", err)
		pause(in)
		return
	}
	if err := agent.ProvisionClient(hubAddr, fp, false, key, clientID, authKeyB64, "默认"); err != nil {
		fmt.Printf("\n登记控制端凭证失败: %v\n", err)
		pause(in)
		return
	}
	keyText := proto.FormatPairingKey(key)
	if exe, err := os.Executable(); err == nil {
		cfgPath := filepath.Join(filepath.Dir(exe), "agent.json")
		obj := map[string]any{
			"hub": hubAddr, "key": keyText, "fingerprint": fp, "name": name, "readonly": false, "root": "",
			"clients": []map[string]string{{"id": clientID, "label": "默认"}},
		}
		data, _ := json.MarshalIndent(obj, "", "  ")
		if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
			fmt.Printf("写入配置失败: %v\n", err)
		} else {
			fmt.Printf("已写入配置: %s\n", cfgPath)
		}
	}
	fmt.Println("\n把下面这串「邀请码」发给 A 端输入（或扫码）：")
	fmt.Println(client.EncodeInvite(hubAddr, proto.FormatPairingKey(clientKey), fp, name, proto.DeviceID(key), clientID, "默认"))
	fmt.Print("\n要把本程序安装为系统服务吗？（开机自启/崩溃自拉起，需管理员）[y/N]: ")
	ans, _ := in.ReadString('\n')
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
		if err := agent.InstallService(exePath()); err != nil {
			fmt.Printf("安装服务失败: %v\n（提示：请用「以管理员身份运行」再试）\n", err)
		} else {
			fmt.Println("✅ 已安装为系统服务。")
		}
	}
	pause(in)
}

func pause(in *bufio.Reader) {
	fmt.Print("\n按回车键退出...")
	_, _ = in.ReadString('\n')
}

// updateLoop 周期检查新版本；在服务环境下自动重启以应用。
func updateLoop(adminBase string, serviceMode bool) {
	first := true
	for {
		if !first {
			time.Sleep(6 * time.Hour)
		}
		first = false
		v, err := agent.CheckAndStageUpdate(adminBase, agent.AgentVersion)
		if err != nil {
			log.Printf("更新检查失败: %v", err)
			continue
		}
		if v == "" {
			continue
		}
		log.Printf("发现新版本 %s，已下载并通过签名/SHA-256 校验", v)
		if serviceMode || agent.UnderServiceEnv() {
			log.Printf("正在重启以应用更新...")
			time.Sleep(300 * time.Millisecond)
			os.Exit(1) // SCM recovery / systemd Restart=always 会拉起新版本
		}
		log.Printf("当前为手动运行：新版本将在下次启动时生效（文件已替换）")
	}
}
