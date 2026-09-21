# oc-link-plugin

AI 驱动的加密远程控制 —— opencode 插件。

- 端到端加密（X25519 + AES-256-GCM），中继只转发密文
- 账号登录后自动同步有权限的设备（`oc_login`）
- 远程执行命令 / 读写文件 / 编辑 / 搜索 / 列目录（`oc_exec`、`oc_read`、`oc_write`、`oc_edit`、`oc_grep`、`oc_glob`、`oc_list`）
- 设备流激活、角色权限（viewer/operator/admin）、审计日志

## 安装

1. 安装依赖（opencode 侧需要）：

```bash
npm i @opencode-ai/plugin
```

2. 在 `~/.config/opencode/opencode.json`（或项目 `.opencode/opencode.json`）里声明插件：

```json
{
  "plugin": ["oc-link-plugin"]
}
```

3. 重启 opencode，然后在对话里：

```
用 oc_login 登录 http://你的管理页:10000，用户名 xxx
```

登录后设备会写进 `~/.config/oc-link/config.json`，之后直接说"在 办公室电脑 上执行 xxx"即可。

## 说明

- 密钥只保存在本机配置文件，不进聊天、不进模型上下文。
- `oc_login` 的令牌保存在本机配置里，可在管理页"禁用用户/改密"一键吊销。
