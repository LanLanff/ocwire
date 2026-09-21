// oc-link opencode 插件：把远端设备能力注册成工具，供模型调用。
//
// 安装：把本文件和 client.mjs 一起复制到 ~/.config/opencode/plugins/，重启 opencode。
// 配置：~/.config/oc-link/config.json 里写目标设备（密钥不进聊天、不进模型上下文）。
//
//	{
//	  "profiles": {
//	    "default": { "hub": "124.93.28.120:21122", "key": "OCL-....", "fingerprint": "AA:BB:..." }
//	  }
//	}
import { type Plugin, tool } from "@opencode-ai/plugin"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { connectAndRequest, loadConfig, listProfiles, configPath, ensureManager } from "./client.mjs"

function resolve(profileName) {
  const cfg = loadConfig()
  const profiles = cfg.profiles || {}
  const name = profileName || "default"
  const p = profiles[name]
  if (!p) {
    throw new Error(
      "没有找到目标 [" + name + "]。请在 ~/.config/oc-link/config.json 配置；现有目标: " +
        (Object.keys(profiles).join(", ") || "无")
    )
  }
  return { name, clientName: cfg.clientName || os.hostname(), ...p, insecure: cfg.insecure || p.insecure || false }
}

function render(resp) {
  if (!resp) return "(空响应)"
  if (resp.ok === false && resp.error) {
    return "错误: " + resp.error + (resp.stderr ? "\n" + resp.stderr : "")
  }
  switch (resp.op) {
    case "ping":
      return "在线"
    case "exec": {
      let s = "exit=" + (resp.exitCode ?? 0) + (resp.truncated ? "  (输出已截断)" : "") + "\n"
      if (resp.stdout) s += resp.stdout
      if (resp.stderr) s += "\n[stderr]\n" + resp.stderr
      return s.trim() || "(无输出)"
    }
    case "read":
      if (resp.encoding === "base64") return "[二进制文件 " + resp.size + " 字节，base64]\n" + resp.content
      return resp.content
    case "write":
      return "已写入 " + resp.bytes + " 字节 → " + resp.path
    case "list":
      if (!resp.entries || !resp.entries.length) return "(空目录)"
      return resp.entries
        .map((e) => (e.dir ? "[D] " : "    ") + e.name + (e.dir ? "" : "  (" + e.size + ")"))
        .join("\n")
    case "edit":
      return "已替换 " + (resp.count ?? 1) + " 处 → " + resp.path
    case "grep":
      if (!resp.matches || !resp.matches.length) return "(无匹配)"
      return resp.matches.join("\n")
    case "glob":
      if (!resp.matches || !resp.matches.length) return "(无匹配文件)"
      return resp.matches.join("\n")
    default:
      return JSON.stringify(resp)
  }
}

async function call(target, request, timeoutMs) {
  const p = resolve(target)
  const resp = await connectAndRequest(p, request, { timeoutMs: timeoutMs || 30000 })
  return render(resp)
}

export const OcLink: Plugin = async () => {
  // 启动本机连接管理器（长连接 + 自动重连）；已有实例则复用
  ensureManager().catch(() => {})
  return {
    tool: {
    oc_add: tool({
      description:
        "用被控端生成的邀请码（OCL2:…）添加一个控制目标到本机配置；也可以手动给 hub+key。添加后可直接用目标名操作",
      args: {
        code: tool.schema.string().optional().describe("邀请码 OCL2:...（被控端界面复制）"),
        name: tool.schema.string().optional().describe("可选：目标名（默认用连接码里的名字）"),
        hub: tool.schema.string().optional().describe("手动模式：中继地址 host:port"),
        key: tool.schema.string().optional().describe("手动模式：配对密钥 OCL-..."),
        fingerprint: tool.schema.string().optional().describe("手动模式：证书指纹"),
      },
      async execute(args): Promise<string> {
        let hub = String(args.hub || "").trim()
        let key = String(args.key || "").trim()
        let fp = String(args.fingerprint || "").trim()
        let name = String(args.name || "").trim()
        let deviceId = String(args.deviceId || "").trim()
        let clientId = String(args.clientId || "").trim()
        const code = String(args.code || "").trim()
        if (code) {
          if (code.startsWith("OCL1:")) return "旧连接码已停用：请在 B 端「控制端」页重新生成邀请码"
          if (!code.startsWith("OCL2:")) return "邀请码格式不对（应以 OCL2: 开头）"
          try {
            const raw = Buffer.from(code.slice(5), "base64url").toString("utf8")
            const j = JSON.parse(raw)
            hub = hub || String(j.h || "")
            key = key || String(j.k || "")
            fp = fp || String(j.f || "")
            name = name || String(j.n || j.l || "")
            deviceId = deviceId || String(j.d || "")
            clientId = clientId || String(j.c || "")
          } catch {
            return "邀请码内容损坏，请重新复制"
          }
        }
        if (!hub || !key || !deviceId || !clientId) return "邀请码缺少必要信息（hub/key/deviceId/clientId）"
        name = name || "设备"
        const p = configPath()
        let cfg: any = {}
        try {
          cfg = JSON.parse(fs.readFileSync(p, "utf8"))
        } catch {}
        if (!cfg || typeof cfg !== "object") cfg = {}
        cfg.profiles = cfg.profiles || {}
        const base = name
        for (let i = 2; cfg.profiles[name]; i++) name = base + "-" + i
        cfg.profiles[name] = { hub, key, fingerprint: fp, deviceId, clientId }
        fs.mkdirSync(path.dirname(p), { recursive: true })
        fs.writeFileSync(p, JSON.stringify(cfg, null, 2), { mode: 0o600 })
        return "已添加目标 [" + name + "]（中继 " + hub + "）\n现有目标: " + Object.keys(cfg.profiles).join(", ")
      },
    }),
    oc_remove: tool({
      description: "从本机删除一个控制目标（只删本机配置，不影响被控端）；删除后该目标的邀请码立即失效，长连接断开",
      args: {
        name: tool.schema.string().describe("目标名（用 oc_devices 查看）"),
      },
      async execute(args): Promise<string> {
        const name = String(args.name || "").trim()
        if (!name) return "请给出目标名（用 oc_devices 查看）"
        const p = configPath()
        let cfg: any = {}
        try {
          cfg = JSON.parse(fs.readFileSync(p, "utf8"))
        } catch {}
        cfg.profiles = cfg.profiles || {}
        if (!cfg.profiles[name]) {
          const names = Object.keys(cfg.profiles)
          return "没有找到目标 [" + name + "]" + (names.length ? "；现有: " + names.join(", ") : "")
        }
        delete cfg.profiles[name]
        fs.mkdirSync(path.dirname(p), { recursive: true })
        fs.writeFileSync(p, JSON.stringify(cfg, null, 2), { mode: 0o600 })
        let engine = ""
        try {
          const m: any = await ensureManager()
          if (m && m.removeTarget) {
            await m.removeTarget(name)
            engine = "，已断开并移出常驻引擎"
          }
        } catch {}
        return "已删除目标 [" + name + "]" + engine + "\n现有目标: " + (Object.keys(cfg.profiles).join(", ") || "无")
      },
    }),
    oc_name: tool({
      description: "查看或设置控制端（本机）名字；B 端会显示这个名字，改完重连生效",
      args: { name: tool.schema.string().optional().describe("留空=查看当前名字") },
      async execute(args): Promise<string> {
        const p = configPath()
        let cfg: any = {}
        try {
          cfg = JSON.parse(fs.readFileSync(p, "utf8"))
        } catch {}
        if (!cfg || typeof cfg !== "object") cfg = {}
        const cur = (typeof cfg.clientName === "string" && cfg.clientName) || os.hostname()
        const next = String(args.name || "").trim()
        if (!next) return "当前控制端名字: " + cur + "（要改就说：oc_name 名字）"
        if (next.length > 24) return "名字最多 24 个字符"
        cfg.clientName = next
        fs.mkdirSync(path.dirname(p), { recursive: true })
        fs.writeFileSync(p, JSON.stringify(cfg, null, 2), { mode: 0o600 })
        return "已改名为「" + next + "」，断开重连后 B 端即可看到。"
      },
    }),
    oc_devices: tool({
      description: "列出 oc-link 目标设备与长连接状态（未连接/连接中/等待被控端/已连接/重连中/出错）",
      args: {},
      async execute(): Promise<string> {
        try {
          const m: any = await ensureManager()
          const st: any = await m.getState(0)
          const list = (st.targets || []) as any[]
          if (!list.length) return "还没有配置目标。用 oc_add 粘贴被控端生成的连接码。"
          const label: Record<string, string> = {
            off: "未连接",
            connecting: "连接中",
            waiting: "等待被控端",
            online: "已连接",
            reconnecting: "重连中",
            error: "出错",
          }
          return list
            .map((t) => {
              let s = t.name + ": " + (label[t.state] || t.state)
              if (t.peer) s += " · 对端 " + t.peer
              if (t.autoConnect) s += " · 自动连接"
              if (t.error) s += " · " + t.error
              return s
            })
            .join("\n")
        } catch (e) {
          return "读取连接状态失败: " + String(e)
        }
      },
    }),
    oc_connect: tool({
      description: "对目标开启长连接（稳定时保持，断线自动重连）",
      args: { target: tool.schema.string().describe("目标名") },
      async execute(args): Promise<string> {
        try {
          const m: any = await ensureManager()
          await m.connect(String(args.target))
          return "已开始连接 [" + args.target + "]，断线会自动重连。"
        } catch (e) {
          return "失败: " + String(e)
        }
      },
    }),
    oc_disconnect: tool({
      description: "断开目标的长连接",
      args: { target: tool.schema.string().describe("目标名") },
      async execute(args): Promise<string> {
        try {
          const m: any = await ensureManager()
          await m.disconnect(String(args.target))
          return "已断开 [" + args.target + "]。"
        } catch (e) {
          return "失败: " + String(e)
        }
      },
    }),
    oc_status: tool({
      description: "检查 oc-link 到某个远端设备的连通性（是否在线、能否建立加密会话）",
      args: { target: tool.schema.string().optional().describe("目标名，默认 default") },
      async execute(args) {
        const profiles = listProfiles()
        if (!profiles.length) {
          return "还没有配置目标。请在 ~/.config/oc-link/config.json 写入 profiles。"
        }
        const t = args.target || "default"
        try {
          await call(t, { op: "ping", id: "1" }, 15000)
          return "目标 [" + t + "] 在线，加密会话正常。已配置目标: " + profiles.join(", ")
        } catch (e) {
          return "目标 [" + t + "] 不可用: " + (e && e.message) + "\n已配置目标: " + profiles.join(", ")
        }
      },
    }),
    oc_exec: tool({
      description:
        "在远端设备上执行命令（Windows 走 PowerShell，Linux 走 sh）。长任务（下载/编译）请把 timeoutMs 调大（如 1800000=30 分钟），或用后台方式：Start-Process/start /b 起任务并把输出重定向到日志，然后轮询日志与产物，避免超时被杀",
      args: {
        cmd: tool.schema.string().describe("要执行的命令"),
        target: tool.schema.string().optional().describe("目标名，默认 default"),
        cwd: tool.schema.string().optional().describe("工作目录"),
        timeoutMs: tool.schema.number().optional().describe("超时毫秒，默认 120000；长任务可设大（如 1800000）"),
      },
      async execute(args) {
        return call(
          args.target,
          { op: "exec", id: "1", cmd: args.cmd, cwd: args.cwd, timeoutMs: args.timeoutMs },
          args.timeoutMs ? args.timeoutMs + 10000 : 60000
        )
      },
    }),
    oc_read: tool({
      description: "读取远端设备上的文件（文本返回内容，二进制返回 base64）",
      args: {
        path: tool.schema.string().describe("文件绝对路径"),
        target: tool.schema.string().optional(),
        maxBytes: tool.schema.number().optional(),
      },
      async execute(args) {
        return call(args.target, { op: "read", id: "1", path: args.path, maxBytes: args.maxBytes })
      },
    }),
    oc_write: tool({
      description: "把文本内容写入远端设备的文件（UTF-8，自动建目录，原子替换）",
      args: {
        path: tool.schema.string().describe("文件绝对路径"),
        content: tool.schema.string().describe("文件内容（文本）"),
        target: tool.schema.string().optional(),
        createDirs: tool.schema.boolean().optional(),
      },
      async execute(args) {
        const b64 = Buffer.from(args.content, "utf8").toString("base64")
        return call(args.target, {
          op: "write",
          id: "1",
          path: args.path,
          dataB64: b64,
          createDirs: args.createDirs !== false,
        })
      },
    }),
    oc_list: tool({
      description: "列出远端设备上的目录内容",
      args: {
        path: tool.schema.string().describe("目录绝对路径"),
        target: tool.schema.string().optional(),
      },
      async execute(args) {
        return call(args.target, { op: "list", id: "1", path: args.path })
      },
    }),
    oc_edit: tool({
      description: "在远端设备的已有文件里做精确字符串替换（默认要求匹配唯一，可 replaceAll）",
      args: {
        path: tool.schema.string().describe("文件绝对路径"),
        oldString: tool.schema.string().describe("要查找的原内容"),
        newString: tool.schema.string().describe("替换成的新内容"),
        replaceAll: tool.schema.boolean().optional().describe("true=全部替换；默认仅在唯一匹配时替换"),
        target: tool.schema.string().optional(),
      },
      async execute(args) {
        return call(args.target, {
          op: "edit",
          id: "1",
          path: args.path,
          oldString: args.oldString,
          newString: args.newString,
          replaceAll: args.replaceAll,
        })
      },
    }),
    oc_grep: tool({
      description: "在远端设备按正则搜索文件内容，返回 路径:行号:内容",
      args: {
        pattern: tool.schema.string().describe("正则表达式"),
        path: tool.schema.string().describe("搜索起始目录（绝对路径）"),
        maxResults: tool.schema.number().optional(),
        target: tool.schema.string().optional(),
      },
      async execute(args) {
        return call(
          args.target,
          { op: "grep", id: "1", pattern: args.pattern, path: args.path, maxResults: args.maxResults },
          60000
        )
      },
    }),
    oc_glob: tool({
      description: "在远端设备按文件名模式查找文件（支持 * ? 和 **）",
      args: {
        pattern: tool.schema.string().describe("例如 **/*.log 或 *.go"),
        path: tool.schema.string().describe("搜索起始目录（绝对路径）"),
        maxResults: tool.schema.number().optional(),
        target: tool.schema.string().optional(),
      },
      async execute(args) {
        return call(
          args.target,
          { op: "glob", id: "1", pattern: args.pattern, path: args.path, maxResults: args.maxResults },
          60000
        )
      },
    }),
  },
  }
}
