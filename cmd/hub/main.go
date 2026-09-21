// oc-link 中继服务（hub）——全盲模式。
//
// 只做三件事：设备自助登记（存 deviceId + 校验子键）、鉴权与配对、转发密文。
// 没有密钥保管、没有账号体系、没有托管设备：服务器永远无法解密或恢复任何密钥。
package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"log"
	"net/http"
	"path/filepath"

	"oclink/internal/hub"
	"oclink/internal/proto"
	"oclink/internal/tlscert"
)

func main() {
	tunnelAddr := flag.String("tunnel", ":21122", "隧道监听地址（TLS）")
	adminAddr := flag.String("admin", ":21123", "管理页监听地址（TLS）")
	dataPath := flag.String("data", "data/devices.json", "设备数据文件")
	certPath := flag.String("cert", "data/cert.pem", "TLS 证书路径")
	keyPath := flag.String("key", "data/key.pem", "TLS 私钥路径")
	adminPassword := flag.String("admin-password", "", "管理页密码（留空则随机生成并打印）")
	adminTLS := flag.Bool("admin-tls", true, "管理页启用 HTTPS（false 为明文 HTTP，建议只在局域网/VPN 内用）")
	releaseDir := flag.String("release-dir", "", "agent 发布目录（含 release.json/release.json.sig/升级包；默认 data/releases）")
	selfRegister := flag.Bool("self-register", true, "自助登记：B 端用自身密钥登记到中继（全盲，无需管理台）")
	publicAddr := flag.String("public-addr", "", "（兼容保留，当前版本不使用）")
	flag.Parse()
	_ = publicAddr

	pw := *adminPassword
	if pw == "" {
		raw := make([]byte, 12)
		_, _ = rand.Read(raw)
		pw = base64.RawURLEncoding.EncodeToString(raw)
		log.Printf("管理页随机密码: %s", pw)
	}

	store, err := hub.OpenStore(*dataPath)
	if err != nil {
		log.Fatalf("打开数据文件失败: %v", err)
	}

	cert, fingerprint, err := tlscert.LoadOrCreate(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("加载/生成证书失败: %v", err)
	}
	log.Printf("oc-link-hub %s 启动", proto.Version)
	log.Printf("TLS 指纹: %s", fingerprint)

	tunnel := hub.NewTunnel(store, proto.Version)
	tunnel.SetSelfRegister(*selfRegister)

	dataDir := filepath.Dir(*dataPath)
	auditor := hub.NewAuditor(filepath.Join(dataDir, "audit.jsonl"))
	tunnel.SetAudit(auditor)

	relDir := *releaseDir
	if relDir == "" {
		relDir = filepath.Join(dataDir, "releases")
	}
	releases := hub.NewReleaseServer(relDir)

	admin := hub.NewAdminHandler(store, tunnel, pw)
	admin.SetOps(auditor, releases)
	log.Printf("全盲模式：无密钥保管、无账号；自助登记=%v；发布目录 %s", *selfRegister, relDir)

	ln, err := tls.Listen("tcp", *tunnelAddr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatalf("监听隧道失败: %v", err)
	}
	log.Printf("隧道监听 %s（TLS 1.3，只转发密文）", *tunnelAddr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}
			go tunnel.Serve(conn)
		}
	}()

	go func() {
		srv := &http.Server{Addr: *adminAddr, Handler: admin}
		if *adminTLS {
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			log.Printf("管理页 https://%s/", *adminAddr)
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				log.Printf("管理页退出: %v", err)
			}
		} else {
			log.Printf("管理页 http://%s/（明文 HTTP）", *adminAddr)
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("管理页退出: %v", err)
			}
		}
	}()

	select {}
}
