// 连接管理器自测：长连接、请求复用、B 端重启后自动恢复、目标管理。
// 依赖：本地 hub（127.0.0.1:21223 / 管理页 10003，密码 testpass123）。
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HUB = "127.0.0.1:21223";
const ADMIN = "http://127.0.0.1:10003";
const PASS = "testpass123";

// 用临时 home，避免污染真实配置
const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "ocl-mgr-"));
process.env.USERPROFILE = tmpHome;
process.env.HOME = tmpHome;
fs.mkdirSync(path.join(tmpHome, ".config", "oc-link"), { recursive: true });

const { ensureManager } = await import("./client.mjs");

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL: " + msg);
    process.exit(1);
  }
  console.log("ok - " + msg);
}

// 1. 管理员登录 + 建设备（本地 Node 16 没有全局 fetch，用 node:http）
function httpReq(method, url, { body, headers } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const r = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        headers: { ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}), ...(headers || {}) },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
      }
    );
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

let cookie = "";
async function admin(method, p, body) {
  const r = await httpReq(method, ADMIN + p, { body, headers: cookie ? { Cookie: cookie } : {} });
  const sc = r.headers["set-cookie"];
  if (sc && sc[0]) cookie = sc[0].split(";")[0];
  let d = null;
  try {
    d = r.text ? JSON.parse(r.text) : null;
  } catch {}
  if (r.status !== 200) throw new Error(p + " HTTP " + r.status + ": " + r.text);
  return d;
}
await admin("POST", "/api/login", { username: "admin", password: PASS });
const dev = await admin("POST", "/api/devices", { name: "管理器测试" });
assert(dev.key && dev.id, "中继设备已创建 " + dev.id);

const agentExe = fileURLToPath(new URL("../dist/oclink-agent-windows-amd64.exe", import.meta.url));
const agentArgs = ["-hub", dev.hub, "-key", dev.key, "-fingerprint", dev.fingerprint, "-name", "管理器测试B", "-no-update"];

async function startAgent() {
  const c = spawn(agentExe, agentArgs, { stdio: "ignore" });
  await sleep(700);
  return c;
}

const agent1 = await startAgent();

try {
  const m = await ensureManager();

  // 2. 添加目标
  const name = await m.addTarget({ hub: dev.hub, key: dev.key, fingerprint: dev.fingerprint, name: "管理器测试" });
  assert(name, "目标已添加: " + name);

  // 3. 开启长连接，等待 online
  await m.connect(name);
  let st = null;
  let online = false;
  for (let i = 0; i < 40; i++) {
    st = await m.getState(0);
    const t = st.targets.find((x) => x.name === name);
    if (t && t.state === "online") {
      online = true;
      break;
    }
    await sleep(300);
  }
  assert(online, "长连接已建立（online）");
  let t = st.targets.find((x) => x.name === name);
  assert((t.peer || "").includes("管理器测试B"), "看到 B 端设备名: " + t.peer);

  // 4. 复用同一长连接多次请求
  for (let i = 0; i < 3; i++) {
    const resp = await m.request(name, { op: "ping", id: "p" + i }, 10000);
    assert(resp && resp.ok, "第 " + (i + 1) + " 次 ping 成功");
  }
  st = await m.getState(0);
  t = st.targets.find((x) => x.name === name);
  assert(t.requests >= 3, "请求计数 = " + t.requests);
  assert(t.state === "online", "多次请求后连接保持 online（长连接）");

  // 5. B 端重启 → 自动恢复
  agent1.kill();
  await sleep(1500);
  st = await m.getState(0);
  t = st.targets.find((x) => x.name === name);
  assert(t.state !== "error", "B 端下线后状态不是 error（" + t.state + "）");
  const agent2 = await startAgent();
  online = false;
  for (let i = 0; i < 40; i++) {
    st = await m.getState(0);
    t = st.targets.find((x) => x.name === name);
    if (t && t.state === "online") {
      online = true;
      break;
    }
    await sleep(300);
  }
  assert(online, "B 端重启后自动恢复 online");
  const resp2 = await m.request(name, { op: "ping", id: "again" }, 10000);
  assert(resp2 && resp2.ok, "恢复后 ping 成功");
  agent2.kill();

  // 6. 断开
  await m.disconnect(name);
  await sleep(200);
  st = await m.getState(0);
  t = st.targets.find((x) => x.name === name);
  assert(t.state === "off", "断开后状态 off");

  // 7. 删除目标
  await m.removeTarget(name);
  const cfg = JSON.parse(fs.readFileSync(path.join(tmpHome, ".config", "oc-link", "config.json"), "utf8"));
  assert(!cfg.profiles || !cfg.profiles[name], "目标已从配置删除");

  // 8. manager.json 已写入
  assert(fs.existsSync(path.join(tmpHome, ".config", "oc-link", "manager.json")), "manager.json 已写入");

  console.log("ALL PASS");
} finally {
  try {
    agent1.kill();
  } catch {}
  try {
    await httpReq("DELETE", ADMIN + "/api/devices/" + dev.id, { headers: { Cookie: cookie } });
  } catch {}
  process.exit(0);
}
