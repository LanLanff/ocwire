// oc-link 本地服务：把面板的请求代理到 opencode 插件进程里的「连接管理器」。
//
// 面板运行在沙箱 iframe 里，碰不到 localhost；OpenChamber 通过 serviceRequest
// 把请求转发到这个进程，这里再转发到 127.0.0.1:<manager 端口>（token 鉴权）。
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const PORT = Number(process.env.OPENCHAMBER_SERVICE_PORT || 0);
const TOKEN = process.env.OPENCHAMBER_SERVICE_TOKEN || "";
const MANAGER_FILE = path.join(os.homedir(), ".config", "oc-link", "manager.json");

function readManager() {
  try {
    const info = JSON.parse(fs.readFileSync(MANAGER_FILE, "utf8"));
    if (info && info.port && info.token) return info;
  } catch {
    /* ignore */
  }
  return null;
}

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function proxy(mgr, method, pathAndQuery, contentType, bodyBuf) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: mgr.port,
        path: pathAndQuery,
        method,
        headers: {
          "Content-Type": contentType || "application/json",
          Authorization: "Bearer " + mgr.token,
          ...(bodyBuf && bodyBuf.length ? { "Content-Length": bodyBuf.length } : {}),
        },
        timeout: 60000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      }
    );
    req.on("timeout", () => req.destroy(new Error("连接管理器响应超时")));
    req.on("error", reject);
    if (bodyBuf && bodyBuf.length) req.write(bodyBuf);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  try {
    if ((req.headers.authorization || "") !== "Bearer " + TOKEN) {
      return send(res, 401, { error: "unauthorized" });
    }
    const url = new URL(req.url || "/", "http://127.0.0.1");
    if (url.pathname === "/health") return send(res, 200, { ok: true, pid: process.pid });

    const mgr = readManager();
    if (!mgr) {
      return send(res, 503, {
        error: "连接管理器未运行：请确认本机已安装 oc-link 插件，并重启 OpenChamber（插件启动时会拉起管理器）",
      });
    }

    const chunks = [];
    for await (const c of req) chunks.push(c);
    const r = await proxy(mgr, req.method, url.pathname + url.search, req.headers["content-type"], Buffer.concat(chunks));
    res.writeHead(r.status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": r.body.length });
    res.end(r.body);
  } catch (e) {
    send(res, 502, { error: "连接管理器不可达: " + String((e && e.message) || e) });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log("[oc-link] service listening on 127.0.0.1:" + PORT);
});
