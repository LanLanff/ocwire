// oc-link 桌面客户端：被控端（B）+ 控制端（A）轻管理，一体窗口。
//
// 密钥只存本机（~/.config/oc-link/desktop.json）；中继零知识、端到端加密。
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:            "oc-link 客户端",
		Width:            1080,
		Height:           740,
		MinWidth:         900,
		MinHeight:        600,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 244, G: 246, B: 251, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "oc-link-desktop",
		},
		// 关闭 WebView2 硬件加速：部分机器（老显卡/双显卡/驱动不兼容）会因此整机卡死
		Windows: &windows.Options{
			WebviewGpuIsDisabled: true,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
