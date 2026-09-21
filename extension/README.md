# oc-link 面板（OpenChamber 扩展）

给 [oc-link](https://github.com/) 做的 OpenChamber 扩展：

- 右侧栏"oc-link 设备面板"：输入设备名，一键检查状态 / 执行命令 / 列目录（自动发消息给 AI 调用 oc_* 工具）
- 聊天工具美化：`oc_login`、`oc_status`、`oc_exec` 等工具显示为带图标和标题的卡片

## 安装

设置 → 扩展 → 粘贴本文件夹绝对路径 → 添加 → 批准"发送消息"权限。

需要 OpenChamber >= 1.24.0（Web / 桌面版；手机与 VS Code 暂不支持扩展）。

## 开发

```bash
npm install
npx esbuild panel/main.ts --bundle --format=iife --outfile=panel/main.js
```

`package.json` 的 `openchamber` 块是清单（面板、权限、工具样式）。
