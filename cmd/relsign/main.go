// relsign：发布签名工具（Ed25519）。
//
//	relsign -gen -key deploy\release.key          生成私钥并打印公钥（base64，填进 agent）
//	relsign -key deploy\release.key release.json  对文件签名，输出 release.json.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	gen := flag.Bool("gen", false, "生成密钥对")
	keyPath := flag.String("key", "release.key", "私钥文件路径")
	flag.Parse()
	if *gen {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(*keyPath, priv, 0o600); err != nil {
			panic(err)
		}
		fmt.Println("public:", base64.StdEncoding.EncodeToString(pub))
		fmt.Println("private saved:", *keyPath)
		return
	}
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: relsign -key key file.json")
		os.Exit(2)
	}
	priv, err := os.ReadFile(*keyPath)
	if err != nil {
		panic(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		panic("私钥长度不对")
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	out := flag.Arg(0) + ".sig"
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("signed:", out)
}
