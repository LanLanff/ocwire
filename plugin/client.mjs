// oc-link A 端客户端核心（Node/Bun 通用）。
//
// 职责：TLS 连接中继 → 挑战应答鉴权 → 与 B 端做 X25519+AES-256-GCM 端到端加密 → 收发请求。
// 连接模型：内置「持久连接管理器」——每个目标一条长连接，断线自动重连；
// 工具调用、设备面板、桌面端都复用它，避免多入口各自建连互相顶掉（独占位）。
// 管理器只在 127.0.0.1 上监听，端口和 token 写在 ~/.config/oc-link/manager.json。
// 安全要点：
//   1. 默认强制校验服务器证书指纹（除非显式 insecure）；
//   2. 同一设备的调用自动串行排队，避免并发连接互相顶掉；
//   3. 密钥只从本地配置读取，不经聊天/模型。
// 这个文件同时导出一个空的插件函数，即使被 opencode 当插件扫描到也无害。
import tls from "node:tls";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const VERSION = "0.1.0";
const TAG_HANDSHAKE = 1;
const TAG_DATA = 2;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// 配置默认放在 ~/.config/oc-link/config.json
export function configPath() {
  return path.join(os.homedir(), ".config", "oc-link", "config.json");
}

export function loadConfig() {
  const dir = path.join(os.homedir(), ".config", "oc-link");
  const read = (f) => {
    try {
      const p = path.join(dir, f);
      if (!fs.existsSync(p)) return null;
      return JSON.parse(fs.readFileSync(p, "utf8"));
    } catch (e) {
      return null;
    }
  };
  // 依次找 config.json / agent.json（两者都认）
  const raw = read("config.json") || read("agent.json");
  if (!raw) return { profiles: {}, insecure: false };
  // 格式1：A 端标准（嵌套 profiles，可放多台）
  if (raw.profiles && typeof raw.profiles === "object") return raw;
  // 格式2：B 端 agent.json（平铺）→ 自动当作 default 这台
  if (raw.hub || raw.key) {
    const prof = { hub: raw.hub, key: raw.key, fingerprint: raw.fingerprint };
    if (raw.insecure === true) prof.insecure = true;
    return { profiles: { default: prof }, insecure: raw.insecure === true };
  }
  return { profiles: {}, insecure: false };
}

export function listProfiles() {
  const cfg = loadConfig();
  return Object.keys(cfg.profiles || {});
}

// ---- 密钥派生（与 Go 端完全一致）----

function b32decode(s) {
  s = String(s).toUpperCase().replace(/^OCL-?/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("配对密钥格式不对");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hkdf(ikm, info, len) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), Buffer.from(info), len));
}

function derive(key) {
  const deviceID = crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from("ocl-link:device:"), key]))
    .digest("hex")
    .slice(0, 16);
  return {
    deviceID,
    authKey: hkdf(key, "ocl-link:auth", 32),
    encKey: hkdf(key, "ocl-link:e2ee", 32),
  };
}

function proof(authKey, nonce, role, deviceID, clientID) {
  const parts = [nonce, Buffer.from("|" + role + "|" + deviceID)];
  if (clientID) parts.push(Buffer.from("|" + clientID));
  return crypto.createHmac("sha256", authKey).update(Buffer.concat(parts)).digest();
}

function seqAAD(seq) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(seq));
  return b;
}

function seal(aeadKey, seq, plain) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aeadKey, nonce);
  c.setAAD(seqAAD(seq));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { seq, nonce, body: Buffer.concat([ct, c.getAuthTag()]) };
}

function open(aeadKey, seq, nonce, body) {
  const ct = body.subarray(0, body.length - 16);
  const tag = body.subarray(body.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", aeadKey, nonce);
  d.setAAD(seqAAD(seq));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// ---- 帧收发（4 字节大端长度 + JSON）----

class Conn {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    socket.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.pump();
    });
    socket.on("close", () => this.fail(new Error("连接已关闭")));
    socket.on("error", (e) => this.fail(e));
  }
  pump() {
    while (this.waiters.length) {
      if (this.buf.length < 4) return;
      const n = this.buf.readUInt32BE(0);
      if (this.buf.length < 4 + n) return;
      const payload = this.buf.subarray(4, 4 + n);
      this.buf = this.buf.subarray(4 + n);
      this.waiters.shift().resolve(payload);
    }
  }
  fail(err) {
    while (this.waiters.length) this.waiters.shift().reject(err);
  }
  readFrame(timeoutMs) {
    return new Promise((resolve, reject) => {
      const w = { resolve, reject };
      let timer = null;
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error("等待超时"));
        }, timeoutMs);
      }
      w.resolve = (v) => {
        if (timer) clearTimeout(timer);
        resolve(v);
      };
      w.reject = (e) => {
        if (timer) clearTimeout(timer);
        reject(e);
      };
      this.waiters.push(w);
      this.pump();
    });
  }
  async readEnv(timeoutMs) {
    const f = await this.readFrame(timeoutMs);
    return JSON.parse(f.toString("utf8"));
  }
  writeEnv(env) {
    const payload = Buffer.from(JSON.stringify(env));
    const hdr = Buffer.alloc(4);
    hdr.writeUInt32BE(payload.length);
    return new Promise((res, rej) => {
      this.socket.write(Buffer.concat([hdr, payload]), (e) => (e ? rej(e) : res()));
    });
  }
  close() {
    try {
      this.socket.destroy();
    } catch (e) {
      /* ignore */
    }
  }
}

function dial(profile, timeoutMs) {
  return new Promise((resolve, reject) => {
    const i = profile.hub.lastIndexOf(":");
    const host = profile.hub.slice(0, i);
    const port = Number(profile.hub.slice(i + 1));
    const socket = tls.connect(
      { host, port, rejectUnauthorized: false, minVersion: "TLSv1.3", timeout: timeoutMs },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          if (!profile.insecure) {
            if (!profile.fingerprint) {
              socket.destroy();
              reject(new Error("未配置证书指纹（请在配置里填 fingerprint，或显式 insecure:true 跳过校验）"));
              return;
            }
            if (!cert || !cert.fingerprint256) {
              socket.destroy();
              reject(new Error("拿不到服务器证书，无法校验指纹"));
              return;
            }
            const got = String(cert.fingerprint256).toUpperCase();
            if (got !== String(profile.fingerprint).toUpperCase()) {
              socket.destroy();
              reject(new Error("证书指纹不匹配（拿到 " + got + "）"));
              return;
            }
          }
          resolve(new Conn(socket));
        } catch (e) {
          reject(e);
        }
      }
    );
    socket.on("error", reject);
  });
}

// 控制端（A 端）显示名：优先 target 级 displayName，其次 clientName；都没有用调用处给的全局名字兜底。
// 注意：不能回退成 profile.name——那是「目标（被控端）」的名字，会让 B 端看到“自己控制自己”。
function clientDisplayName(profile, fallback) {
  return profile.displayName || profile.clientName || fallback || "";
}

async function sendHandshake(conn, pubRaw, displayName, clientId) {
  const hs = Buffer.concat([
    Buffer.from([TAG_HANDSHAKE]),
    Buffer.from(JSON.stringify({ pub: pubRaw.toString("base64"), name: displayName || "", cid: clientId || "" })),
  ]);
  await conn.writeEnv({ type: "msg", data: hs.toString("base64") });
}

// 一次请求的完整流程：每次调用建立一条短连接，完成一次请求后关闭。
async function connectAndRequestDirect(profile, request, opts = {}) {
  const timeoutMs = opts.timeoutMs || 30000;
  const deadline = Date.now() + timeoutMs;
  const key = b32decode(profile.key);
  const d = derive(key);
  const deviceId = profile.deviceId || d.deviceID;
  const conn = await dial(profile, Math.min(timeoutMs, 10000));
  try {
    await conn.writeEnv({ type: "hello", role: "client", deviceId, clientId: profile.clientId || "", version: VERSION, name: clientDisplayName(profile), ...(profile.token ? { token: profile.token } : {}) });
    let env = await conn.readEnv(10000);
    if (env.type !== "challenge") throw new Error("握手失败: " + (env.error || env.type));
    const nonce = Buffer.from(env.nonce, "base64");
    await conn.writeEnv({ type: "auth", proof: proof(d.authKey, nonce, "client", deviceId, profile.clientId).toString("base64") });
    env = await conn.readEnv(10000);
    if (env.type !== "ready") throw new Error("鉴权失败: " + (env.error || env.type));

    const kp = crypto.generateKeyPairSync("x25519");
    const pubRaw = Buffer.from(kp.publicKey.export({ format: "jwk" }).x, "base64url");
    let sessionKey = null;
    let sentHs = false;
    let sentReq = false;

    while (Date.now() < deadline) {
      env = await conn.readEnv(deadline - Date.now());
      if (env.type === "peer") {
        if (env.peer === "up" && !sentHs) {
          await sendHandshake(conn, pubRaw, clientDisplayName(profile), profile.clientId);
          sentHs = true;
        } else if (env.peer === "down") {
          sessionKey = null;
          sentHs = false;
          sentReq = false;
        }
        continue;
      }
      if (env.type === "error") {
        throw new Error("中继返回错误: " + (env.error || "unknown"));
      }
      if (env.type !== "msg") continue;
      const payload = Buffer.from(env.data, "base64");
      if (!payload.length) continue;
      if (payload[0] === TAG_HANDSHAKE) {
        const hs = JSON.parse(payload.subarray(1).toString("utf8"));
        const peerPub = Buffer.from(hs.pub, "base64");
        const peer = crypto.createPublicKey({
          key: { kty: "OKP", crv: "X25519", x: peerPub.toString("base64url") },
          format: "jwk",
        });
        const shared = crypto.diffieHellman({ privateKey: kp.privateKey, publicKey: peer });
        sessionKey = hkdf(Buffer.concat([shared, d.encKey]), "ocl-link:session", 32);
        if (!sentHs) {
          await sendHandshake(conn, pubRaw, clientDisplayName(profile), profile.clientId);
          sentHs = true;
        }
        if (!sentReq) {
          sentReq = true;
          const sealed = seal(sessionKey, 1, Buffer.from(JSON.stringify(request)));
          const out = Buffer.concat([Buffer.from([TAG_DATA]), sealed.body]);
          await conn.writeEnv({
            type: "msg",
            seq: sealed.seq,
            nonce: sealed.nonce.toString("base64"),
            data: out.toString("base64"),
          });
        }
      } else if (payload[0] === TAG_DATA && sessionKey) {
        const plain = open(sessionKey, env.seq, Buffer.from(env.nonce, "base64"), payload.subarray(1));
        return JSON.parse(plain.toString("utf8"));
      }
    }
    throw new Error("超时未收到响应");
  } finally {
    conn.close();
  }
}

// 直连模式：按“中继+设备”串行排队，避免同一设备并发连接互相顶掉（独占位的副作用）。
const queues = new Map();
function directQueued(profile, request, opts = {}) {
  const qk = String(profile.hub || "") + "|" + String(profile.key || "").slice(0, 24);
  const prev = queues.get(qk) || Promise.resolve();
  const run = prev.then(
    () => connectAndRequestDirect(profile, request, opts),
    () => connectAndRequestDirect(profile, request, opts)
  );
  queues.set(
    qk,
    run.then(
      () => undefined,
      () => undefined
    )
  );
  return run;
}

// ============================================================================
// 持久连接管理器：长连接 + 断线自动重连
//
// 为什么需要它：同一台设备同一时刻只允许一个 A 端连接（新连接会顶掉旧连接）。
// 面板/工具/桌面端如果各自建连，就会互相踢线。管理器在本机只维护一张连接表，
// 每台设备最多一条长连接；工具调用与面板操作都复用它，断了按退避自动重连。
//
// 位置：运行在 opencode 插件进程里（oc壳子/CLI 都能用）；
// 对外接口：只监听 127.0.0.1 的 HTTP，端口和 token 写在
//   ~/.config/oc-link/manager.json（0600），供扩展面板的服务代理和桌面端使用。
// ============================================================================

const VERSION_MGR = VERSION;
const MANAGER_PORTS = Array.from({ length: 10 }, (_, i) => 17890 + i);
const MANAGER_FILE = path.join(os.homedir(), ".config", "oc-link", "manager.json");
const CONFIG_FILE = path.join(os.homedir(), ".config", "oc-link", "config.json");
const FATAL_RE = /设备不存在|没有该设备的操作权限|需要登录令牌|身份校验失败|版本不一致|指纹不匹配|密钥格式|密钥长度/;
const STATE_LABEL = { off: "未连接", connecting: "连接中", waiting: "等待被控端", online: "已连接", reconnecting: "重连中", error: "出错" };
const SLOW_RE = /已被中继禁用|已被吊销/; // 权限类失败：放慢重试，管理员启用后自动恢复

export function managerInfoPath() {
  return MANAGER_FILE;
}

function readManagerInfo() {
  try {
    return JSON.parse(fs.readFileSync(MANAGER_FILE, "utf8"));
  } catch {
    return null;
  }
}

function writeManagerInfo(info) {
  fs.mkdirSync(path.dirname(MANAGER_FILE), { recursive: true });
  fs.writeFileSync(MANAGER_FILE, JSON.stringify(info, null, 2), { mode: 0o600 });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => {
      b += c;
      if (b.length > 1 << 20) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(b ? JSON.parse(b) : {});
      } catch {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

// 不依赖全局 fetch：用 node:http 发 JSON 请求（兼容较老的 Node 运行时）。
function httpJson(method, urlStr, body, headers = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const data = body === undefined ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname + u.search,
        method,
        headers: { ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}), ...headers },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
      }
    );
    req.on("timeout", () => req.destroy(new Error("请求超时")));
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function managerFetch(info, p, method = "GET", body, timeoutMs = 65000) {
  const r = await httpJson(method, "http://127.0.0.1:" + info.port + p, body, { Authorization: "Bearer " + info.token }, timeoutMs);
  let data = null;
  try {
    data = r.text ? JSON.parse(r.text) : null;
  } catch {
    /* ignore */
  }
  if (r.status < 200 || r.status >= 300) throw new Error((data && data.error) || "连接管理器 HTTP " + r.status);
  return data;
}

async function managerAlive(info) {
  try {
    const r = await httpJson("GET", "http://127.0.0.1:" + info.port + "/health", undefined, { Authorization: "Bearer " + info.token }, 800);
    return r.status === 200;
  } catch {
    return false;
  }
}

function makeSession(shared, encKey) {
  return { key: hkdf(Buffer.concat([shared, encKey]), "ocl-link:session", 32), sendSeq: 0, lastRecvSeq: 0 };
}

function deriveSessionKey(kp, peerPubB64, encKey) {
  const peer = crypto.createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: Buffer.from(peerPubB64, "base64").toString("base64url") },
    format: "jwk",
  });
  const shared = crypto.diffieHellman({ privateKey: kp.privateKey, publicKey: peer });
  return makeSession(shared, encKey);
}

function sessionSeal(sess, plain) {
  const seq = sess.sendSeq + 1;
  const sealed = seal(sess.key, seq, plain);
  sess.sendSeq = seq;
  return sealed;
}

function sessionOpen(sess, seq, nonce, body) {
  if (seq <= sess.lastRecvSeq) throw new Error("序号异常（重放或乱序）");
  const plain = open(sess.key, seq, nonce, body);
  sess.lastRecvSeq = seq;
  return plain;
}

class Target {
  constructor(name, profile, manager) {
    this.name = name;
    this.manager = manager;
    this.stopped = true;
    this.manualOff = false; // 用户手动断开后保持断开，直到再次手动连接或重启
    this.state = "off";
    this.peer = "";
    this.lastError = "";
    this.connectedAt = 0;
    this.lastActive = 0;
    this.requests = 0;
    this.conn = null;
    this.session = null;
    this.kp = null;
    this.pubRaw = null;
    this.sentHs = false;
    this.inflight = null;
    this.queue = [];
    this.timer = null;
    this.backoff = 1000;
    this.keepalive = null;
    this.presenceOn = false; // 待命心跳：不控制时也保持「A 在线」
    this.pconn = null;
    this.slowLogged = false; // 权限类失败只提示一次，之后慢速重试
    this.updateProfile(profile);
  }

  updateProfile(profile) {
    this.profile = profile;
    this.d = derive(b32decode(profile.key));
  }

  setState(s) {
    if (this.state === s) return;
    this.state = s;
    this.manager.pushEvent("state", this.name, STATE_LABEL[s] + (s === "error" && this.lastError ? "：" + this.lastError : ""));
  }

  start() {
    if (!this.stopped) return;
    this.stopPresence(); // 开始控制时不需要待命心跳
    this.stopped = false;
    this.manualOff = false;
    this.lastError = "";
    this.backoff = 1000;
    this.manager.pushEvent("connect", this.name, "开始连接");
    this.loop();
  }

  stop() {
    this.manualOff = true; // 手动断开：autoConnect 也不再自动拉起，直到下次启动/手动连接
    if (this.stopped && this.state === "off") return;
    this.stopped = true;
    clearTimeout(this.timer);
    this.timer = null;
    this.stopKeepalive();
    if (this.conn) {
      try {
        this.conn.close();
      } catch {
        /* ignore */
      }
      this.conn = null;
    }
    this.session = null;
    this.setState("off");
    this.manager.pushEvent("connect", this.name, "已断开");
    this.failAll(new Error("连接已断开"));
    this.startPresence(); // 断开控制后保持「A 在线待命」
  }

  // —— 待命心跳：只向中继表明「A 引擎在线」，不占用控制通道、不打扰 B ——
  startPresence() {
    if (this.presenceOn) return;
    this.presenceOn = true;
    this.manager.pushEvent("info", this.name, "控制端在线待命");
    this.presenceLoop();
  }

  stopPresence() {
    this.presenceOn = false;
    if (this.pconn) {
      try {
        this.pconn.close();
      } catch {
        /* ignore */
      }
      this.pconn = null;
    }
  }

  async presenceLoop() {
    while (this.presenceOn) {
      try {
        await this.presenceOnce();
      } catch (e) {
        const msg = String((e && e.message) || e);
        if (FATAL_RE.test(msg)) {
          // 配置/密钥级错误：待命停止（需要用户处理）
          this.presenceOn = false;
          this.manager.pushEvent("error", this.name, "待命停止：" + msg);
          return;
        }
        // 被禁用/吊销/网络问题：30 秒后自动重试（管理员启用后即可恢复）
      }
      if (!this.presenceOn) return;
      await sleep(12000);
    }
  }

  async presenceOnce() {
    const conn = await dial(this.profile, 10000);
    this.pconn = conn;
    try {
      const deviceId = this.profile.deviceId || this.d.deviceID;
      await conn.writeEnv({
        type: "hello",
        role: "client",
        deviceId,
        clientId: this.profile.clientId || "",
        version: VERSION_MGR,
        presence: true,
        name: clientDisplayName(this.profile, this.manager.getClientName()),
      });
      let env = await conn.readEnv(10000);
      if (env.type !== "challenge") throw new Error("握手失败: " + (env.error || env.type));
      const nonce = Buffer.from(env.nonce, "base64");
      await conn.writeEnv({ type: "auth", proof: proof(this.d.authKey, nonce, "client", deviceId, this.profile.clientId).toString("base64") });
      env = await conn.readEnv(10000);
      if (env.type !== "ready") throw new Error("鉴权失败: " + (env.error || env.type));
      for (;;) {
        await sleep(30000);
        if (!this.presenceOn) return;
        await conn.writeEnv({ type: "ping" });
        const pong = await conn.readEnv(15000).catch(() => null);
        if (!pong) throw new Error("待命连接断开");
      }
    } finally {
      if (this.pconn === conn) this.pconn = null;
      try {
        conn.close();
      } catch {
        /* ignore */
      }
    }
  }

  failAll(err) {
    if (this.inflight) {
      clearTimeout(this.inflight.timer);
      const inf = this.inflight;
      this.inflight = null;
      inf.reject(err);
    }
    while (this.queue.length) this.queue.shift().reject(err);
  }

  async loop() {
    let first = true;
    while (!this.stopped) {
      this.setState(first ? "connecting" : "reconnecting");
      first = false;
      try {
        await this.connectOnce();
        if (!this.stopped) this.setState("reconnecting");
        this.slowLogged = false;
      } catch (e) {
        this.lastError = String((e && e.message) || e);
        if (FATAL_RE.test(this.lastError)) {
          this.stopped = true;
          this.setState("error");
          this.manager.pushEvent("error", this.name, this.lastError);
          this.failAll(new Error(this.lastError));
          this.startPresence(); // 即使控制失败，也让中继看到「A 在线」
          return;
        }
        if (SLOW_RE.test(this.lastError)) {
          // 被禁用/吊销等权限状态：进入出错态并放慢重试，管理员启用后自动恢复
          this.setState("error");
          if (!this.slowLogged) {
            this.manager.pushEvent("error", this.name, this.lastError);
            this.slowLogged = true;
          }
        }
      }
      if (this.stopped) return;
      const slow = SLOW_RE.test(this.lastError);
      const wait = slow ? 12000 : this.backoff;
      if (!slow) this.backoff = Math.min(this.backoff * 2, 15000);
      await sleep(wait);
    }
  }

  async connectOnce() {
    this.manager.pushEvent("info", this.name, "正在连接 " + this.profile.hub);
    const conn = await dial(this.profile, 10000);
    this.conn = conn;
    try {
      const deviceId = this.profile.deviceId || this.d.deviceID;
      await conn.writeEnv({ type: "hello", role: "client", deviceId, clientId: this.profile.clientId || "", version: VERSION_MGR, name: clientDisplayName(this.profile, this.manager.getClientName()), ...(this.profile.token ? { token: this.profile.token } : {}) });
      let env = await conn.readEnv(10000);
      if (env.type !== "challenge") throw new Error("握手失败: " + (env.error || env.type));
      const nonce = Buffer.from(env.nonce, "base64");
      await conn.writeEnv({ type: "auth", proof: proof(this.d.authKey, nonce, "client", deviceId, this.profile.clientId).toString("base64") });
      env = await conn.readEnv(10000);
      if (env.type !== "ready") throw new Error("鉴权失败: " + (env.error || env.type));

      this.backoff = 1000;
      this.connectedAt = Date.now();
      this.lastActive = Date.now();
      this.lastError = "";
      this.setState("waiting");
      this.manager.pushEvent("connected", this.name, "已接入中继");
      this.startKeepalive();
      await this.readLoop(conn);
    } finally {
      this.stopKeepalive();
      if (this.conn === conn) this.conn = null;
      try {
        conn.close();
      } catch {
        /* ignore */
      }
      this.session = null;
      this.peer = "";
      this.connectedAt = 0;
      if (!this.stopped && this.state !== "error") this.setState("reconnecting");
    }
  }

  async readLoop(conn) {
    for (;;) {
      const env = await conn.readEnv();
      this.lastActive = Date.now();
      if (env.type === "peer") {
        if (env.peer === "up") {
          this.newHandshake();
          await sendHandshake(conn, this.pubRaw, clientDisplayName(this.profile, this.manager.getClientName()), this.profile.clientId);
        } else {
          this.session = null;
          this.peer = "";
          this.setState("waiting");
          this.manager.pushEvent("peer", this.name, "对端离线");
        }
        continue;
      }
      if (env.type === "ping") {
        await conn.writeEnv({ type: "pong" }).catch(() => {});
        continue;
      }
      if (env.type === "pong") continue;
      if (env.type === "error") {
        this.lastError = env.error || "中继返回错误";
        this.manager.pushEvent("error", this.name, this.lastError);
        if (FATAL_RE.test(this.lastError)) throw new Error(this.lastError);
        continue;
      }
      if (env.type !== "msg") continue;
      const payload = Buffer.from(env.data || "", "base64");
      if (!payload.length) continue;
      if (payload[0] === TAG_HANDSHAKE) {
        let hs = {};
        try {
          hs = JSON.parse(payload.subarray(1).toString("utf8"));
        } catch {
          continue;
        }
        if (!hs.pub) continue;
        this.session = deriveSessionKey(this.kp, hs.pub, this.d.encKey);
        this.peer = String(hs.name || "");
        if (!this.sentHs) {
          await sendHandshake(conn, this.pubRaw, clientDisplayName(this.profile, this.manager.getClientName()), this.profile.clientId);
          this.sentHs = true;
        }
        this.setState("online");
        this.manager.pushEvent("peer", this.name, "端到端会话已建立" + (this.peer ? "（" + this.peer + "）" : ""));
        this.pump();
      } else if (payload[0] === TAG_DATA && this.session) {
        let resp;
        try {
          resp = JSON.parse(sessionOpen(this.session, env.seq, Buffer.from(env.nonce, "base64"), payload.subarray(1)).toString("utf8"));
        } catch {
          this.manager.pushEvent("error", this.name, "收到无法解密的响应");
          continue;
        }
        const inf = this.inflight;
        if (inf && resp && resp.id === inf.id) {
          this.inflight = null;
          clearTimeout(inf.timer);
          this.requests++;
          this.manager.pushEvent(resp.ok ? "request" : "error", this.name, (resp.op || "?") + (resp.ok ? " 成功" : " 失败" + (resp.error ? "：" + resp.error : "")));
          inf.resolve(resp);
          this.pump();
        }
      }
    }
  }

  newHandshake() {
    this.kp = crypto.generateKeyPairSync("x25519");
    this.pubRaw = Buffer.from(this.kp.publicKey.export({ format: "jwk" }).x, "base64url");
    this.sentHs = false;
    this.session = null;
  }

  startKeepalive() {
    this.stopKeepalive();
    this.keepalive = setInterval(() => {
      if (!this.conn) return;
      if (Date.now() - this.lastActive > 90000) {
        this.manager.pushEvent("error", this.name, "连接无响应，重连中");
        try {
          this.conn.close();
        } catch {
          /* ignore */
        }
        return;
      }
      this.conn.writeEnv({ type: "ping" }).catch(() => {});
    }, 30000);
  }

  stopKeepalive() {
    if (this.keepalive) {
      clearInterval(this.keepalive);
      this.keepalive = null;
    }
  }

  // 发一条请求：复用长连接；对端还没上线就排队等待（有总超时）。
  request(request, timeoutMs) {
    const id = "r" + crypto.randomBytes(6).toString("hex");
    return new Promise((resolve, reject) => {
      this.queue.push({ id, req: { ...request, id }, resolve, reject, deadline: Date.now() + (timeoutMs || 30000) });
      this.pump();
    });
  }

  pump() {
    if (this.inflight || !this.queue.length) return;
    const job = this.queue[0];
    const remain = job.deadline - Date.now();
    if (remain <= 0) {
      this.queue.shift();
      job.reject(new Error("请求超时"));
      return this.pump();
    }
    if (!this.session || !this.conn) {
      if (this.stopped) {
        this.queue.shift();
        job.reject(new Error(this.lastError || "连接未建立"));
        return this.pump();
      }
      setTimeout(() => this.pump(), Math.min(500, remain));
      return;
    }
    this.queue.shift();
    const sealed = sessionSeal(this.session, Buffer.from(JSON.stringify(job.req)));
    const out = Buffer.concat([Buffer.from([TAG_DATA]), sealed.body]);
    const inf = { id: job.id, resolve: job.resolve, reject: job.reject, timer: null };
    inf.timer = setTimeout(() => {
      if (this.inflight === inf) {
        this.inflight = null;
        inf.reject(new Error("等待响应超时"));
        this.pump();
      }
    }, remain);
    this.inflight = inf;
    this.conn
      .writeEnv({ type: "msg", seq: sealed.seq, nonce: sealed.nonce.toString("base64"), data: out.toString("base64") })
      .catch((e) => {
        if (this.inflight === inf) {
          this.inflight = null;
          clearTimeout(inf.timer);
          inf.reject(e);
          this.pump();
        }
      });
  }
}

class Manager {
  constructor() {
    this.targets = new Map();
    this.events = [];
    this.seq = 0;
    this.port = 0;
    this.token = crypto.randomBytes(24).toString("hex");
    this.remote = false;
    this.server = null;
  }

  pushEvent(kind, target, message) {
    this.seq++;
    this.events.push({ seq: this.seq, t: Date.now(), kind, target, message });
    if (this.events.length > 300) this.events.splice(0, this.events.length - 300);
  }

  profileFor(name) {
    const cfg = loadConfig();
    const p = (cfg.profiles || {})[name];
    if (!p) return null;
    return { name, clientName: cfg.clientName || os.hostname(), ...p, insecure: cfg.insecure || p.insecure === true };
  }

  // 跟随 config.json 变化：新设备建目标、改密钥刷新、autoConnect 自动连。
  syncTargets() {
    const cfg = loadConfig();
    const profiles = cfg.profiles || {};
    for (const [name, p] of Object.entries(profiles)) {
      const merged = { name, ...p, insecure: cfg.insecure || p.insecure === true };
      let t = this.targets.get(name);
      if (!t) {
        t = new Target(name, merged, this);
        this.targets.set(name, t);
      } else {
        t.updateProfile(merged);
      }
      if (p.autoConnect === true && t.stopped && !t.manualOff) t.start();
      else if (t.stopped) t.startPresence();
    }
    for (const [name, t] of this.targets) {
      if (!profiles[name] && t.stopped) {
        t.stopPresence();
        this.targets.delete(name);
      }
    }
  }

  target(name) {
    const t = this.targets.get(name);
    if (!t) throw new Error("未找到目标: " + name);
    return t;
  }

  connect(name) {
    this.syncTargets();
    this.target(name).start();
  }

  disconnect(name) {
    this.target(name).stop();
  }

  connectAll() {
    this.syncTargets();
    for (const t of this.targets.values()) t.start();
  }

  disconnectAll() {
    for (const t of this.targets.values()) t.stop();
  }

  async request(name, request, timeoutMs) {
    if (!this.targets.has(name) || !this.profileFor(name)) this.syncTargets();
    const prof = this.profileFor(name);
    if (!prof) throw new Error("未找到目标: " + name);
    const t = this.targets.get(name);
    if (t && !t.stopped) return t.request(request, timeoutMs);
    // 没有开启长连接：直连一次（仍然单飞，不与其他请求互踢）
    return directQueued(prof, request, { timeoutMs });
  }

  getState(since = 0) {
    this.syncTargets();
    const targets = [];
    for (const [name, t] of this.targets) {
      targets.push({
        name,
        hub: t.profile.hub,
        state: t.state,
        peer: t.peer || "",
        error: t.lastError || "",
        connectedAt: t.connectedAt || 0,
        lastActive: t.lastActive || 0,
        requests: t.requests || 0,
        autoConnect: t.profile.autoConnect === true,
        present: !!t.pconn,
        token: !!t.profile.token,
      });
    }
    return {
      ok: true,
      now: Date.now(),
      targets,
      events: this.events.filter((e) => e.seq > since),
      clientName: this.getClientName(),
      manager: { port: this.port, pid: process.pid, version: VERSION_MGR },
    };
  }

  getClientName() {
    const cfg = loadConfig();
    return (typeof cfg.clientName === "string" && cfg.clientName.trim()) || os.hostname();
  }

  // setClientName 写入 config.json 的 clientName；已连接的目标立即重连，让 B 端看到新名字。
  setClientName(name) {
    name = String(name || "").trim();
    if (name.length > 24) throw new Error("名字最多 24 个字符");
    const cfg = loadConfig();
    const before = this.getClientName();
    if (name === "") delete cfg.clientName;
    else cfg.clientName = name;
    fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    const after = this.getClientName();
    for (const t of this.targets.values()) t.profile = { ...t.profile, clientName: after };
    if (after !== before) {
      for (const t of this.targets.values()) {
        if (!t.stopped) {
          t.stop();
          t.start();
        }
      }
    }
    this.pushEvent("info", "", "控制端名字已改为 " + after);
    return after;
  }

  decodeTargetBody(body) {
    let hub = String((body && body.hub) || "").trim();
    let key = String((body && body.key) || "").trim();
    let fp = String((body && body.fingerprint) || "").trim();
    let name = String((body && body.name) || "").trim();
    let deviceId = String((body && body.deviceId) || "").trim();
    let clientId = String((body && body.clientId) || "").trim();
    const code = String((body && body.code) || "").trim();
    if (code) {
      if (code.startsWith("OCL1:")) throw new Error("旧连接码已停用：请在 B 端重新生成邀请码");
      if (!code.startsWith("OCL2:")) throw new Error("邀请码格式不对（应以 OCL2: 开头）");
      let j;
      try {
        j = JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8"));
      } catch {
        throw new Error("邀请码内容损坏");
      }
      hub = hub || String(j.h || "");
      key = key || String(j.k || "");
      fp = fp || String(j.f || "");
      name = name || String(j.n || j.l || "");
      deviceId = deviceId || String(j.d || "");
      clientId = clientId || String(j.c || "");
    }
    if (!hub || !key || !deviceId || !clientId) throw new Error("邀请码缺少必要信息（hub/key/deviceId/clientId）");
    return { hub, key, fingerprint: fp, name: name || "设备", deviceId, clientId };
  }

  addTarget(body) {
    const t = this.decodeTargetBody(body);
    const cfg = loadConfig();
    cfg.profiles = cfg.profiles || {};
    let name = t.name;
    for (let i = 2; cfg.profiles[name]; i++) name = t.name + "-" + i;
    cfg.profiles[name] = { hub: t.hub, key: t.key, fingerprint: t.fingerprint, deviceId: t.deviceId, clientId: t.clientId };
    fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    this.pushEvent("info", name, "已添加目标");
    this.syncTargets();
    return name;
  }

  removeTarget(name) {
    const cfg = loadConfig();
    if (cfg.profiles && cfg.profiles[name]) {
      delete cfg.profiles[name];
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    }
    const t = this.targets.get(name);
    if (t) {
      t.stop();
      this.targets.delete(name);
    }
    this.pushEvent("info", name, "已删除目标（只删本机配置）");
  }

  setAuto(name, on) {
    const cfg = loadConfig();
    if (!cfg.profiles || !cfg.profiles[name]) throw new Error("未找到目标: " + name);
    cfg.profiles[name].autoConnect = !!on;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    if (on) this.target(name).start();
  }


  listen() {
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => this.handleHttp(req, res));
      let i = 0;
      const tryNext = () => {
        if (i >= MANAGER_PORTS.length) {
          reject(new Error("没有可用端口"));
          return;
        }
        const port = MANAGER_PORTS[i++];
        const onError = (e) => {
          if (e && e.code === "EADDRINUSE") {
            server.removeListener("error", onError);
            tryNext();
          } else {
            reject(e);
          }
        };
        server.once("error", onError);
        server.listen(port, "127.0.0.1", () => {
          server.removeListener("error", onError);
          server.on("error", () => {});
          this.port = port;
          this.server = server;
          resolve(port);
        });
      };
      tryNext();
    });
  }

  async handleHttp(req, res) {
    const send = (code, obj) => {
      res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(obj));
    };
    try {
      if ((req.headers.authorization || "") !== "Bearer " + this.token) return send(401, { error: "unauthorized" });
      const url = new URL(req.url || "/", "http://127.0.0.1");
      if (url.pathname === "/health") return send(200, { ok: true, pid: process.pid, version: VERSION_MGR });
      if (url.pathname === "/state") return send(200, this.getState(Number(url.searchParams.get("since") || 0)));
      if (url.pathname === "/client-name" && req.method === "GET") return send(200, { name: this.getClientName() });
      if (req.method === "POST") {
        const body = await readJsonBody(req);
        switch (url.pathname) {
          case "/connect":
            this.connect(body.name);
            return send(200, this.getState(0));
          case "/disconnect":
            this.disconnect(body.name);
            return send(200, this.getState(0));
          case "/connect-all":
            this.connectAll();
            return send(200, this.getState(0));
          case "/disconnect-all":
            this.disconnectAll();
            return send(200, this.getState(0));
          case "/request":
            return send(200, await this.request(body.name, body.request, body.timeoutMs));
          case "/targets/add":
            return send(200, { ok: true, name: this.addTarget(body) });
          case "/targets/remove":
            this.removeTarget(body.name);
            return send(200, { ok: true });
          case "/targets/auto":
            this.setAuto(body.name, !!body.on);
            return send(200, { ok: true });
          case "/client-name":
            return send(200, { ok: true, name: this.setClientName(body.name) });
        }
      }
      send(404, { error: "not found" });
    } catch (e) {
      send(500, { error: String((e && e.message) || e) });
    }
  }
}

class RemoteManager {
  constructor(info) {
    this.info = info;
    this.remote = true;
  }
  async getState(since = 0) {
    return managerFetch(this.info, "/state?since=" + since);
  }
  async connect(name) {
    return managerFetch(this.info, "/connect", "POST", { name });
  }
  async disconnect(name) {
    return managerFetch(this.info, "/disconnect", "POST", { name });
  }
  async connectAll() {
    return managerFetch(this.info, "/connect-all", "POST", {});
  }
  async disconnectAll() {
    return managerFetch(this.info, "/disconnect-all", "POST", {});
  }
  async request(name, request, timeoutMs) {
    return managerFetch(this.info, "/request", "POST", { name, request, timeoutMs }, (timeoutMs || 30000) + 5000);
  }
  async addTarget(body) {
    const r = await managerFetch(this.info, "/targets/add", "POST", body);
    return r.name;
  }
  async removeTarget(name) {
    return managerFetch(this.info, "/targets/remove", "POST", { name });
  }
  async setAuto(name, on) {
    return managerFetch(this.info, "/targets/auto", "POST", { name, on });
  }
  async getClientName() {
    const r = await managerFetch(this.info, "/client-name");
    return r.name || "";
  }
  async setClientName(name) {
    const r = await managerFetch(this.info, "/client-name", "POST", { name });
    return r.name || "";
  }
}

let _manager = null;
let _managerPromise = null;

// ensureManager 保证本机只有一个连接管理器：
// 已有存活实例（可能是另一个 opencode 进程）就复用它的 HTTP 接口，否则自己起。
export function ensureManager() {
  if (_manager) return Promise.resolve(_manager);
  if (_managerPromise) return _managerPromise;
  _managerPromise = (async () => {
    const info = readManagerInfo();
    if (info && info.port && info.token && (await managerAlive(info))) {
      _manager = new RemoteManager(info);
      return _manager;
    }
    const m = new Manager();
    await m.listen();
    writeManagerInfo({ port: m.port, token: m.token, pid: process.pid, version: VERSION_MGR, startedAt: Date.now() });
    try {
      process.on("exit", () => {
        const cur = readManagerInfo();
        if (cur && cur.pid === process.pid) {
          try {
            fs.unlinkSync(MANAGER_FILE);
          } catch {
            /* ignore */
          }
        }
      });
    } catch {
      /* ignore */
    }
    m.syncTargets();
    _manager = m;
    return m;
  })().catch((e) => {
    _managerPromise = null;
    throw e;
  });
  return _managerPromise;
}

// 统一入口：目标有名字且管理器可用时走长连接管理器；
// 管理器起不来（极端情况）才退回旧的“每次一条短连接”。
export async function connectAndRequest(profile, request, opts = {}) {
  if (profile && profile.name && !opts.direct) {
    let m = null;
    try {
      m = await ensureManager();
    } catch {
      m = null;
    }
    if (m) return m.request(profile.name, request, opts.timeoutMs || 30000);
  }
  return directQueued(profile, request, opts);
}

// 被 opencode 当插件扫到时的空插件（无副作用）
export const ClientCore = async () => ({});
export default ClientCore;
