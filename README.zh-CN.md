# ocwire

[![CI](https://github.com/LanLanff/ocwire/actions/workflows/ci.yml/badge.svg)](https://github.com/LanLanff/ocwire/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/LanLanff/ocwire)](https://github.com/LanLanff/ocwire/releases/latest)

[English](README.md) | **简体中文**

**用聊天控制你的其他电脑** —— 通过全盲中继 + 端到端加密，为 [opencode](https://opencode.ai) / OpenChamber 而生。

在 opencode 聊天里直接对别的电脑执行命令、读写文件、搜索、传文件。**不开端口、不用 VPN、不用 SSH**；中继从头到尾看不到明文，也拿不到任何密钥。

> 项目内部代号仍是 `oc-link`；`ocwire` 是对外名称。

```
 A 侧（你的聊天）                   全盲中继                  B 侧（被控机器）
┌──────────────────────┐        ┌──────────────┐        ┌──────────────────────┐
│ opencode / OpenChamber│        │  ocwire-hub  │        │ ocwire-desktop（图形）│
│  └─ 插件（引擎）      │◄──────►│  TLS 1.3     │◄──────►│  或 oclink-agent（命令行）│
│      oc_exec / oc_read│  E2EE  │  零密钥      │  E2EE  │  127.0.0.1 → 工具     │
└──────────────────────┘        └──────────────┘        └──────────────────────┘
```

## 功能

- **聊天原生**：A 端引擎是 opencode 插件，`oc_exec`、`oc_read`、`oc_write`、`oc_grep`、`oc_glob`、`oc_list`、`oc_edit` 在聊天里直接可用
- **全盲中继**：只保存 `deviceId`（哈希）和每控制端的校验子键；HKDF 用途隔离 + X25519 + AES-256-GCM + 严格序号防重放，中继解不开、伪造不了、也无法重排
- **零暴露**：两端都是**出站**连中继，无需任何入站端口；全链路证书指纹钉死
- **自助登记**：B 端首次启动自动登记，用 `OCL2:` 邀请码（二维码/文本）配对；**每个控制端一把独立凭证**
- **控制端管理**：踢下线 / 禁用 / 启用 / 冷却 / 审计；卸载的离线设备可从管理台清理
- **待命心跳**：A 引擎在线状态真实——`在线待命` / `控制中` / `等待被控端`，界面不闪
- **签名自动更新**：agent 校验 Ed25519 签名的发布清单后才升级
- **三形态**：桌面客户端（Wails）/ 命令行 agent / OpenChamber 面板，支持 Windows / Linux / macOS

## 截图

管理台（中继）——设备列表、逐控制端管理、离线清理：

![relay devices](assets/console-devices.png)

每个控制端凭证的实时状态与吊销：

![relay controllers](assets/console-clients.png)

> 截图为演示数据。桌面端与面板截图后续补充。

## 快速开始

### 1. 中继（一台小 VPS，或局域网机器）

```bash
go build -o oclink-hub ./cmd/hub
./oclink-hub -tunnel :21122 -admin :10000 -data /opt/ocwire/data
# 首次启动会打印随机管理密码；打开 http://<主机>:10000
```

### 2. B 侧（要被控制的机器）

- 图形版：下载 `ocwire-desktop.zip`，运行 `oc-link.exe`，首次启动自动登记。点 **生成邀请码**，把码发给 A 侧。
- 命令行版：`oclink-agent -register -hub <中继> -fingerprint <证书指纹>`，会打印邀请码。

### 3. A 侧（opencode）

```bash
# 把插件两个文件放进 opencode，然后重启壳子
cp plugin/client.mjs plugin/oc-link.ts ~/.config/opencode/plugins/
```

然后在聊天里把邀请码发过去，说"用这个邀请码添加设备"（或直接调 `oc_add`）。
之后就可以说：*"连接 MS8323-1"*、*"在 MS8323-1 上执行 df -h"*、*"读一下 MS8323-1 的 /etc/hosts"*。

## 安全模型（简版）

| 威胁 | 对策 |
|---|---|
| 中继运营方 | 永远拿不到密钥，只存校验子键（`HKDF(key,"auth")`） |
| 网络中间人 | TLS 1.3 + 两端钉死 SHA-256 指纹 |
| 邀请码泄露 | 单设备、可吊销的独立凭证；可逐控制端禁用/踢下线 |
| 重放 / 重排 | 单调 `seq` 作为 AES-GCM 的 AAD；接收端严格递增校验 |
| 伪造中继 | E2EE 握手把 X25519 与共享 `encKey` 混合，中间人无法完成握手 |

详见 [SECURITY.md](SECURITY.md)。

## 仓库结构

```
cmd/hub          中继 + 管理台
cmd/agent        命令行被控端（B 侧，无界面）
internal/hub     中继：隧道、存储、审计、管理 API
internal/agent   agent 运行时（服务模式、自动更新）
internal/client  测试/工具用的协议客户端
internal/proto   信封、HKDF 密钥体系、E2EE 会话
internal/wire    帧协议（4 字节长度前缀，上限 32MB）
plugin/          opencode 插件：A 引擎 + 工具            → A 侧
extension/       OpenChamber 面板（设备/添加/日志）       → A 侧界面
desktop/         Wails 图形客户端（B 全功能 + A 页）
docs/            架构说明
```

## 致谢与声明

- [opencode](https://github.com/sst/opencode)（SST 出品）——本项目作为它的插件运行；代码相互独立，未内联其源码
- [OpenChamber](https://github.com/openchamber/openchamber)——宿主壳子与扩展面板；面板使用其已发布的 `@openchamber/sdk`
- 运行依赖：`@opencode-ai/plugin`、`@openchamber/sdk`（均为 MIT）

**ocwire 是独立社区项目**，不隶属于 opencode 或 OpenChamber，也未被其背书；相关商标归各自所有者。

## 状态

v0.1 —— 全链路开发与测试完成（中继 / 桌面端 / agent / 插件 / 面板），中继有 Go 单测、桌面端有 E2E 测试。文档与 CI 正在为公开发布收尾，欢迎 Issue 和 PR。

## 开发

```bash
go build ./cmd/hub ./cmd/agent        # 中继 + agent
go test ./internal/...                # 单元测试
cd desktop && go vet . && wails build # 图形端（需要 wails CLI）
node --check plugin/client.mjs        # 插件语法检查
```

## 许可

MIT —— 见 [LICENSE](LICENSE)。
