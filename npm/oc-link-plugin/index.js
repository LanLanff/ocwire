// ../../plugin/oc-link.ts
import { tool } from "@opencode-ai/plugin";
import fs2 from "node:fs";
import path2 from "node:path";

// ../../plugin/client.mjs
import tls from "node:tls";
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
var VERSION = "0.1.0";
var TAG_HANDSHAKE = 1;
var TAG_DATA = 2;
var B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function configPath() {
  return path.join(os.homedir(), ".config", "oc-link", "config.json");
}
function loadConfig() {
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
  const raw = read("config.json") || read("agent.json");
  if (!raw) return { profiles: {}, insecure: false };
  if (raw.profiles && typeof raw.profiles === "object") return raw;
  if (raw.hub || raw.key) {
    const prof = { hub: raw.hub, key: raw.key, fingerprint: raw.fingerprint };
    if (raw.insecure === true) prof.insecure = true;
    return { profiles: { default: prof }, insecure: raw.insecure === true };
  }
  return { profiles: {}, insecure: false };
}
function listProfiles() {
  const cfg = loadConfig();
  return Object.keys(cfg.profiles || {});
}
function b32decode(s) {
  s = String(s).toUpperCase().replace(/^OCL-?/, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("\u914D\u5BF9\u5BC6\u94A5\u683C\u5F0F\u4E0D\u5BF9");
    value = value << 5 | idx;
    bits += 5;
    if (bits >= 8) {
      out.push(value >>> bits - 8 & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
function hkdf(ikm, info, len) {
  return Buffer.from(crypto.hkdfSync("sha256", ikm, Buffer.alloc(0), Buffer.from(info), len));
}
function derive(key) {
  const deviceID = crypto.createHash("sha256").update(Buffer.concat([Buffer.from("ocl-link:device:"), key])).digest("hex").slice(0, 16);
  return {
    deviceID,
    authKey: hkdf(key, "ocl-link:auth", 32),
    encKey: hkdf(key, "ocl-link:e2ee", 32)
  };
}
function proof(authKey, nonce, role, deviceID) {
  return crypto.createHmac("sha256", authKey).update(Buffer.concat([nonce, Buffer.from("|" + role + "|" + deviceID)])).digest();
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
var Conn = class {
  constructor(socket) {
    this.socket = socket;
    this.buf = Buffer.alloc(0);
    this.waiters = [];
    socket.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this.pump();
    });
    socket.on("close", () => this.fail(new Error("\u8FDE\u63A5\u5DF2\u5173\u95ED")));
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
    return new Promise((resolve2, reject) => {
      const w = { resolve: resolve2, reject };
      let timer = null;
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) this.waiters.splice(i, 1);
          reject(new Error("\u7B49\u5F85\u8D85\u65F6"));
        }, timeoutMs);
      }
      w.resolve = (v) => {
        if (timer) clearTimeout(timer);
        resolve2(v);
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
      this.socket.write(Buffer.concat([hdr, payload]), (e) => e ? rej(e) : res());
    });
  }
  close() {
    try {
      this.socket.destroy();
    } catch (e) {
    }
  }
};
function dial(profile, timeoutMs) {
  return new Promise((resolve2, reject) => {
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
              reject(new Error("\u672A\u914D\u7F6E\u8BC1\u4E66\u6307\u7EB9\uFF08\u8BF7\u5728\u914D\u7F6E\u91CC\u586B fingerprint\uFF0C\u6216\u663E\u5F0F insecure:true \u8DF3\u8FC7\u6821\u9A8C\uFF09"));
              return;
            }
            if (!cert || !cert.fingerprint256) {
              socket.destroy();
              reject(new Error("\u62FF\u4E0D\u5230\u670D\u52A1\u5668\u8BC1\u4E66\uFF0C\u65E0\u6CD5\u6821\u9A8C\u6307\u7EB9"));
              return;
            }
            const got = String(cert.fingerprint256).toUpperCase();
            if (got !== String(profile.fingerprint).toUpperCase()) {
              socket.destroy();
              reject(new Error("\u8BC1\u4E66\u6307\u7EB9\u4E0D\u5339\u914D\uFF08\u62FF\u5230 " + got + "\uFF09"));
              return;
            }
          }
          resolve2(new Conn(socket));
        } catch (e) {
          reject(e);
        }
      }
    );
    socket.on("error", reject);
  });
}
async function sendHandshake(conn, pubRaw, displayName) {
  const hs = Buffer.concat([
    Buffer.from([TAG_HANDSHAKE]),
    Buffer.from(JSON.stringify({ pub: pubRaw.toString("base64"), name: displayName || "" }))
  ]);
  await conn.writeEnv({ type: "msg", data: hs.toString("base64") });
}
async function connectAndRequestDirect(profile, request, opts = {}) {
  const timeoutMs = opts.timeoutMs || 3e4;
  const deadline = Date.now() + timeoutMs;
  const key = b32decode(profile.key);
  const d = derive(key);
  const conn = await dial(profile, Math.min(timeoutMs, 1e4));
  try {
    await conn.writeEnv({ type: "hello", role: "client", deviceId: d.deviceID, version: VERSION, ...profile.token ? { token: profile.token } : {} });
    let env = await conn.readEnv(1e4);
    if (env.type !== "challenge") throw new Error("\u63E1\u624B\u5931\u8D25: " + (env.error || env.type));
    const nonce = Buffer.from(env.nonce, "base64");
    await conn.writeEnv({ type: "auth", proof: proof(d.authKey, nonce, "client", d.deviceID).toString("base64") });
    env = await conn.readEnv(1e4);
    if (env.type !== "ready") throw new Error("\u9274\u6743\u5931\u8D25: " + (env.error || env.type));
    const kp = crypto.generateKeyPairSync("x25519");
    const pubRaw = Buffer.from(kp.publicKey.export({ format: "jwk" }).x, "base64url");
    let sessionKey = null;
    let sentHs = false;
    let sentReq = false;
    while (Date.now() < deadline) {
      env = await conn.readEnv(deadline - Date.now());
      if (env.type === "peer") {
        if (env.peer === "up" && !sentHs) {
          await sendHandshake(conn, pubRaw, profile.displayName || profile.name || "");
          sentHs = true;
        } else if (env.peer === "down") {
          sessionKey = null;
          sentHs = false;
          sentReq = false;
        }
        continue;
      }
      if (env.type === "error") {
        throw new Error("\u4E2D\u7EE7\u8FD4\u56DE\u9519\u8BEF: " + (env.error || "unknown"));
      }
      if (env.type !== "msg") continue;
      const payload = Buffer.from(env.data, "base64");
      if (!payload.length) continue;
      if (payload[0] === TAG_HANDSHAKE) {
        const hs = JSON.parse(payload.subarray(1).toString("utf8"));
        const peerPub = Buffer.from(hs.pub, "base64");
        const peer = crypto.createPublicKey({
          key: { kty: "OKP", crv: "X25519", x: peerPub.toString("base64url") },
          format: "jwk"
        });
        const shared = crypto.diffieHellman({ privateKey: kp.privateKey, publicKey: peer });
        sessionKey = hkdf(Buffer.concat([shared, d.encKey]), "ocl-link:session", 32);
        if (!sentHs) {
          await sendHandshake(conn, pubRaw, profile.displayName || profile.name || "");
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
            data: out.toString("base64")
          });
        }
      } else if (payload[0] === TAG_DATA && sessionKey) {
        const plain = open(sessionKey, env.seq, Buffer.from(env.nonce, "base64"), payload.subarray(1));
        return JSON.parse(plain.toString("utf8"));
      }
    }
    throw new Error("\u8D85\u65F6\u672A\u6536\u5230\u54CD\u5E94");
  } finally {
    conn.close();
  }
}
var queues = /* @__PURE__ */ new Map();
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
      () => void 0,
      () => void 0
    )
  );
  return run;
}
var VERSION_MGR = VERSION;
var MANAGER_PORTS = Array.from({ length: 10 }, (_, i) => 17890 + i);
var MANAGER_FILE = path.join(os.homedir(), ".config", "oc-link", "manager.json");
var CONFIG_FILE = path.join(os.homedir(), ".config", "oc-link", "config.json");
var FATAL_RE = /设备不存在|没有该设备的操作权限|需要登录令牌|身份校验失败|版本不一致|指纹不匹配|密钥格式|密钥长度/;
var STATE_LABEL = { off: "\u672A\u8FDE\u63A5", connecting: "\u8FDE\u63A5\u4E2D", waiting: "\u7B49\u5F85\u88AB\u63A7\u7AEF", online: "\u5DF2\u8FDE\u63A5", reconnecting: "\u91CD\u8FDE\u4E2D", error: "\u51FA\u9519" };
function readManagerInfo() {
  try {
    return JSON.parse(fs.readFileSync(MANAGER_FILE, "utf8"));
  } catch {
    return null;
  }
}
function writeManagerInfo(info) {
  fs.mkdirSync(path.dirname(MANAGER_FILE), { recursive: true });
  fs.writeFileSync(MANAGER_FILE, JSON.stringify(info, null, 2), { mode: 384 });
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function readJsonBody(req) {
  return new Promise((resolve2) => {
    let b = "";
    req.on("data", (c) => {
      b += c;
      if (b.length > 1 << 20) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve2(b ? JSON.parse(b) : {});
      } catch {
        resolve2({});
      }
    });
    req.on("error", () => resolve2({}));
  });
}
function httpJson(method, urlStr, body, headers = {}, timeoutMs = 15e3) {
  return new Promise((resolve2, reject) => {
    const u = new URL(urlStr);
    const data = body === void 0 ? null : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname + u.search,
        method,
        headers: { ...data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}, ...headers },
        timeout: timeoutMs
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve2({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
      }
    );
    req.on("timeout", () => req.destroy(new Error("\u8BF7\u6C42\u8D85\u65F6")));
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}
async function managerFetch(info, p, method = "GET", body, timeoutMs = 65e3) {
  const r = await httpJson(method, "http://127.0.0.1:" + info.port + p, body, { Authorization: "Bearer " + info.token }, timeoutMs);
  let data = null;
  try {
    data = r.text ? JSON.parse(r.text) : null;
  } catch {
  }
  if (r.status < 200 || r.status >= 300) throw new Error(data && data.error || "\u8FDE\u63A5\u7BA1\u7406\u5668 HTTP " + r.status);
  return data;
}
async function managerAlive(info) {
  try {
    const r = await httpJson("GET", "http://127.0.0.1:" + info.port + "/health", void 0, { Authorization: "Bearer " + info.token }, 800);
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
    format: "jwk"
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
  if (seq <= sess.lastRecvSeq) throw new Error("\u5E8F\u53F7\u5F02\u5E38\uFF08\u91CD\u653E\u6216\u4E71\u5E8F\uFF09");
  const plain = open(sess.key, seq, nonce, body);
  sess.lastRecvSeq = seq;
  return plain;
}
var Target = class {
  constructor(name, profile, manager) {
    this.name = name;
    this.manager = manager;
    this.stopped = true;
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
    this.backoff = 1e3;
    this.keepalive = null;
    this.updateProfile(profile);
  }
  updateProfile(profile) {
    this.profile = profile;
    this.d = derive(b32decode(profile.key));
  }
  setState(s) {
    if (this.state === s) return;
    this.state = s;
    this.manager.pushEvent("state", this.name, STATE_LABEL[s] + (s === "error" && this.lastError ? "\uFF1A" + this.lastError : ""));
  }
  start() {
    if (!this.stopped) return;
    this.stopped = false;
    this.lastError = "";
    this.backoff = 1e3;
    this.manager.pushEvent("connect", this.name, "\u5F00\u59CB\u8FDE\u63A5");
    this.loop();
  }
  stop() {
    if (this.stopped && this.state === "off") return;
    this.stopped = true;
    clearTimeout(this.timer);
    this.timer = null;
    this.stopKeepalive();
    if (this.conn) {
      try {
        this.conn.close();
      } catch {
      }
      this.conn = null;
    }
    this.session = null;
    this.setState("off");
    this.manager.pushEvent("connect", this.name, "\u5DF2\u65AD\u5F00");
    this.failAll(new Error("\u8FDE\u63A5\u5DF2\u65AD\u5F00"));
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
      } catch (e) {
        this.lastError = String(e && e.message || e);
        if (FATAL_RE.test(this.lastError)) {
          this.stopped = true;
          this.setState("error");
          this.manager.pushEvent("error", this.name, this.lastError);
          this.failAll(new Error(this.lastError));
          return;
        }
      }
      if (this.stopped) return;
      const wait = this.backoff;
      this.backoff = Math.min(this.backoff * 2, 15e3);
      await sleep(wait);
    }
  }
  async connectOnce() {
    this.manager.pushEvent("info", this.name, "\u6B63\u5728\u8FDE\u63A5 " + this.profile.hub);
    const conn = await dial(this.profile, 1e4);
    this.conn = conn;
    try {
      await conn.writeEnv({ type: "hello", role: "client", deviceId: this.d.deviceID, version: VERSION_MGR, ...this.profile.token ? { token: this.profile.token } : {} });
      let env = await conn.readEnv(1e4);
      if (env.type !== "challenge") throw new Error("\u63E1\u624B\u5931\u8D25: " + (env.error || env.type));
      const nonce = Buffer.from(env.nonce, "base64");
      await conn.writeEnv({ type: "auth", proof: proof(this.d.authKey, nonce, "client", this.d.deviceID).toString("base64") });
      env = await conn.readEnv(1e4);
      if (env.type !== "ready") throw new Error("\u9274\u6743\u5931\u8D25: " + (env.error || env.type));
      this.backoff = 1e3;
      this.connectedAt = Date.now();
      this.lastActive = Date.now();
      this.lastError = "";
      this.setState("waiting");
      this.manager.pushEvent("connected", this.name, "\u5DF2\u63A5\u5165\u4E2D\u7EE7");
      this.startKeepalive();
      await this.readLoop(conn);
    } finally {
      this.stopKeepalive();
      if (this.conn === conn) this.conn = null;
      try {
        conn.close();
      } catch {
      }
      this.session = null;
      this.peer = "";
      this.connectedAt = 0;
      if (!this.stopped && this.state !== "error") this.setState("reconnecting");
    }
  }
  async readLoop(conn) {
    for (; ; ) {
      const env = await conn.readEnv();
      this.lastActive = Date.now();
      if (env.type === "peer") {
        if (env.peer === "up") {
          this.newHandshake();
          await sendHandshake(conn, this.pubRaw, this.profile.displayName || this.profile.name || "");
        } else {
          this.session = null;
          this.peer = "";
          this.setState("waiting");
          this.manager.pushEvent("peer", this.name, "\u5BF9\u7AEF\u79BB\u7EBF");
        }
        continue;
      }
      if (env.type === "pong" || env.type === "ping") continue;
      if (env.type === "error") {
        this.lastError = env.error || "\u4E2D\u7EE7\u8FD4\u56DE\u9519\u8BEF";
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
          await sendHandshake(conn, this.pubRaw, this.profile.displayName || this.profile.name || "");
          this.sentHs = true;
        }
        this.setState("online");
        this.manager.pushEvent("peer", this.name, "\u7AEF\u5230\u7AEF\u4F1A\u8BDD\u5DF2\u5EFA\u7ACB" + (this.peer ? "\uFF08" + this.peer + "\uFF09" : ""));
        this.pump();
      } else if (payload[0] === TAG_DATA && this.session) {
        let resp;
        try {
          resp = JSON.parse(sessionOpen(this.session, env.seq, Buffer.from(env.nonce, "base64"), payload.subarray(1)).toString("utf8"));
        } catch {
          this.manager.pushEvent("error", this.name, "\u6536\u5230\u65E0\u6CD5\u89E3\u5BC6\u7684\u54CD\u5E94");
          continue;
        }
        const inf = this.inflight;
        if (inf && resp && resp.id === inf.id) {
          this.inflight = null;
          clearTimeout(inf.timer);
          this.requests++;
          this.manager.pushEvent(resp.ok ? "request" : "error", this.name, (resp.op || "?") + (resp.ok ? " \u6210\u529F" : " \u5931\u8D25" + (resp.error ? "\uFF1A" + resp.error : "")));
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
      if (Date.now() - this.lastActive > 9e4) {
        this.manager.pushEvent("error", this.name, "\u8FDE\u63A5\u65E0\u54CD\u5E94\uFF0C\u91CD\u8FDE\u4E2D");
        try {
          this.conn.close();
        } catch {
        }
        return;
      }
      this.conn.writeEnv({ type: "ping" }).catch(() => {
      });
    }, 3e4);
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
    return new Promise((resolve2, reject) => {
      this.queue.push({ id, req: { ...request, id }, resolve: resolve2, reject, deadline: Date.now() + (timeoutMs || 3e4) });
      this.pump();
    });
  }
  pump() {
    if (this.inflight || !this.queue.length) return;
    const job = this.queue[0];
    const remain = job.deadline - Date.now();
    if (remain <= 0) {
      this.queue.shift();
      job.reject(new Error("\u8BF7\u6C42\u8D85\u65F6"));
      return this.pump();
    }
    if (!this.session || !this.conn) {
      if (this.stopped) {
        this.queue.shift();
        job.reject(new Error(this.lastError || "\u8FDE\u63A5\u672A\u5EFA\u7ACB"));
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
        inf.reject(new Error("\u7B49\u5F85\u54CD\u5E94\u8D85\u65F6"));
        this.pump();
      }
    }, remain);
    this.inflight = inf;
    this.conn.writeEnv({ type: "msg", seq: sealed.seq, nonce: sealed.nonce.toString("base64"), data: out.toString("base64") }).catch((e) => {
      if (this.inflight === inf) {
        this.inflight = null;
        clearTimeout(inf.timer);
        inf.reject(e);
        this.pump();
      }
    });
  }
};
var Manager = class {
  constructor() {
    this.targets = /* @__PURE__ */ new Map();
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
    if (this.events.length > 500) this.events.splice(0, this.events.length - 500);
  }
  profileFor(name) {
    const cfg = loadConfig();
    const p = (cfg.profiles || {})[name];
    if (!p) return null;
    return { name, ...p, insecure: cfg.insecure || p.insecure === true };
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
      if (p.autoConnect === true && t.stopped) t.start();
    }
    for (const [name, t] of this.targets) {
      if (!profiles[name] && t.stopped) this.targets.delete(name);
    }
  }
  target(name) {
    const t = this.targets.get(name);
    if (!t) throw new Error("\u672A\u627E\u5230\u76EE\u6807: " + name);
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
    if (!prof) throw new Error("\u672A\u627E\u5230\u76EE\u6807: " + name);
    const t = this.targets.get(name);
    if (t && !t.stopped) return t.request(request, timeoutMs);
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
        token: !!t.profile.token
      });
    }
    return {
      ok: true,
      now: Date.now(),
      targets,
      events: this.events.filter((e) => e.seq > since),
      manager: { port: this.port, pid: process.pid, version: VERSION_MGR }
    };
  }
  decodeTargetBody(body) {
    let hub = String(body && body.hub || "").trim();
    let key = String(body && body.key || "").trim();
    let fp = String(body && body.fingerprint || "").trim();
    let name = String(body && body.name || "").trim();
    const code = String(body && body.code || "").trim();
    if (code) {
      if (!code.startsWith("OCL1:")) throw new Error("\u8FDE\u63A5\u7801\u683C\u5F0F\u4E0D\u5BF9\uFF08\u5E94\u4EE5 OCL1: \u5F00\u5934\uFF09");
      let j;
      try {
        j = JSON.parse(Buffer.from(code.slice(5), "base64url").toString("utf8"));
      } catch {
        throw new Error("\u8FDE\u63A5\u7801\u5185\u5BB9\u635F\u574F");
      }
      hub = hub || String(j.h || "");
      key = key || String(j.k || "");
      fp = fp || String(j.f || "");
      name = name || String(j.n || "");
    }
    if (!hub || !key) throw new Error("\u7F3A\u5C11 hub \u6216 key");
    return { hub, key, fingerprint: fp, name: name || "\u8BBE\u5907" };
  }
  addTarget(body) {
    const t = this.decodeTargetBody(body);
    const cfg = loadConfig();
    cfg.profiles = cfg.profiles || {};
    let name = t.name;
    for (let i = 2; cfg.profiles[name]; i++) name = t.name + "-" + i;
    cfg.profiles[name] = { hub: t.hub, key: t.key, fingerprint: t.fingerprint };
    fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    this.pushEvent("info", name, "\u5DF2\u6DFB\u52A0\u76EE\u6807");
    this.syncTargets();
    return name;
  }
  removeTarget(name) {
    const cfg = loadConfig();
    if (cfg.profiles && cfg.profiles[name]) {
      delete cfg.profiles[name];
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    }
    const t = this.targets.get(name);
    if (t) {
      t.stop();
      this.targets.delete(name);
    }
    this.pushEvent("info", name, "\u5DF2\u5220\u9664\u76EE\u6807\uFF08\u53EA\u5220\u672C\u673A\u914D\u7F6E\uFF09");
  }
  setAuto(name, on) {
    const cfg = loadConfig();
    if (!cfg.profiles || !cfg.profiles[name]) throw new Error("\u672A\u627E\u5230\u76EE\u6807: " + name);
    cfg.profiles[name].autoConnect = !!on;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    if (on) this.target(name).start();
  }
  async login(body) {
    const base = String(body && body.hub || "").replace(/\/+$/, "");
    if (!base) throw new Error("\u8BF7\u63D0\u4F9B\u7BA1\u7406\u9875\u5730\u5740");
    const lr = await httpJson("POST", base + "/api/user/login", { username: body.username, password: body.password }, {}, 15e3);
    let login = {};
    try {
      login = lr.text ? JSON.parse(lr.text) : {};
    } catch {
    }
    if (lr.status !== 200 || !login.ok) throw new Error("\u767B\u5F55\u5931\u8D25: " + (login.error || lr.status));
    const dr = await httpJson("GET", base + "/api/user/devices", void 0, { Authorization: "Bearer " + login.token }, 15e3);
    let data = {};
    try {
      data = dr.text ? JSON.parse(dr.text) : {};
    } catch {
    }
    if (dr.status !== 200) throw new Error("\u62C9\u53D6\u8BBE\u5907\u5931\u8D25: " + (data.error || dr.status));
    const cfg = loadConfig();
    cfg.profiles = cfg.profiles || {};
    const names = [];
    for (const d of data.devices || []) {
      cfg.profiles[d.name] = { hub: data.hub, key: d.key, fingerprint: data.fingerprint, token: login.token, canOperate: d.canOperate !== false };
      names.push(d.name);
    }
    fs.mkdirSync(path.dirname(CONFIG_FILE), { recursive: true });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    this.pushEvent("info", "", "\u8D26\u53F7\u767B\u5F55\u6210\u529F\uFF0C\u540C\u6B65 " + names.length + " \u53F0\u8BBE\u5907");
    this.syncTargets();
    return { ok: true, count: names.length, names, user: login.user };
  }
  listen() {
    return new Promise((resolve2, reject) => {
      const server = http.createServer((req, res) => this.handleHttp(req, res));
      let i = 0;
      const tryNext = () => {
        if (i >= MANAGER_PORTS.length) {
          reject(new Error("\u6CA1\u6709\u53EF\u7528\u7AEF\u53E3"));
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
          server.on("error", () => {
          });
          this.port = port;
          this.server = server;
          resolve2(port);
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
          case "/login":
            return send(200, await this.login(body));
        }
      }
      send(404, { error: "not found" });
    } catch (e) {
      send(500, { error: String(e && e.message || e) });
    }
  }
};
var RemoteManager = class {
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
    return managerFetch(this.info, "/request", "POST", { name, request, timeoutMs }, (timeoutMs || 3e4) + 5e3);
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
  async login(body) {
    return managerFetch(this.info, "/login", "POST", body);
  }
};
var _manager = null;
var _managerPromise = null;
function ensureManager() {
  if (_manager) return Promise.resolve(_manager);
  if (_managerPromise) return _managerPromise;
  _managerPromise = (async () => {
    const info = readManagerInfo();
    if (info && info.port && info.token && await managerAlive(info)) {
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
          }
        }
      });
    } catch {
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
async function connectAndRequest(profile, request, opts = {}) {
  if (profile && profile.name && !opts.direct) {
    let m = null;
    try {
      m = await ensureManager();
    } catch {
      m = null;
    }
    if (m) return m.request(profile.name, request, opts.timeoutMs || 3e4);
  }
  return directQueued(profile, request, opts);
}

// ../../plugin/oc-link.ts
function resolve(profileName) {
  const cfg = loadConfig();
  const profiles = cfg.profiles || {};
  const name = profileName || "default";
  const p = profiles[name];
  if (!p) {
    throw new Error(
      "\u6CA1\u6709\u627E\u5230\u76EE\u6807 [" + name + "]\u3002\u8BF7\u5728 ~/.config/oc-link/config.json \u914D\u7F6E\uFF1B\u73B0\u6709\u76EE\u6807: " + (Object.keys(profiles).join(", ") || "\u65E0")
    );
  }
  return { name, ...p, insecure: cfg.insecure || p.insecure || false };
}
function render(resp) {
  if (!resp) return "(\u7A7A\u54CD\u5E94)";
  if (resp.ok === false && resp.error) {
    return "\u9519\u8BEF: " + resp.error + (resp.stderr ? "\n" + resp.stderr : "");
  }
  switch (resp.op) {
    case "ping":
      return "\u5728\u7EBF";
    case "exec": {
      let s = "exit=" + (resp.exitCode ?? 0) + (resp.truncated ? "  (\u8F93\u51FA\u5DF2\u622A\u65AD)" : "") + "\n";
      if (resp.stdout) s += resp.stdout;
      if (resp.stderr) s += "\n[stderr]\n" + resp.stderr;
      return s.trim() || "(\u65E0\u8F93\u51FA)";
    }
    case "read":
      if (resp.encoding === "base64") return "[\u4E8C\u8FDB\u5236\u6587\u4EF6 " + resp.size + " \u5B57\u8282\uFF0Cbase64]\n" + resp.content;
      return resp.content;
    case "write":
      return "\u5DF2\u5199\u5165 " + resp.bytes + " \u5B57\u8282 \u2192 " + resp.path;
    case "list":
      if (!resp.entries || !resp.entries.length) return "(\u7A7A\u76EE\u5F55)";
      return resp.entries.map((e) => (e.dir ? "[D] " : "    ") + e.name + (e.dir ? "" : "  (" + e.size + ")")).join("\n");
    case "edit":
      return "\u5DF2\u66FF\u6362 " + (resp.count ?? 1) + " \u5904 \u2192 " + resp.path;
    case "grep":
      if (!resp.matches || !resp.matches.length) return "(\u65E0\u5339\u914D)";
      return resp.matches.join("\n");
    case "glob":
      if (!resp.matches || !resp.matches.length) return "(\u65E0\u5339\u914D\u6587\u4EF6)";
      return resp.matches.join("\n");
    default:
      return JSON.stringify(resp);
  }
}
async function call(target, request, timeoutMs) {
  const p = resolve(target);
  const resp = await connectAndRequest(p, request, { timeoutMs: timeoutMs || 3e4 });
  return render(resp);
}
var OcLink = async () => {
  ensureManager().catch(() => {
  });
  return {
    tool: {
      oc_login: tool({
        description: "\u7528\u8D26\u53F7\u767B\u5F55 oc-link \u7BA1\u7406\u670D\u52A1\uFF08\u7BA1\u7406\u9875\u5730\u5740 + \u7528\u6237\u540D + \u5BC6\u7801\uFF09\uFF0C\u81EA\u52A8\u628A\u8BE5\u8D26\u53F7\u6709\u6743\u9650\u7684\u8BBE\u5907\u540C\u6B65\u5230\u672C\u673A\u914D\u7F6E\uFF1B\u4E4B\u540E\u53EF\u76F4\u63A5\u7528\u8BBE\u5907\u540D\u64CD\u4F5C",
        args: {
          hub: tool.schema.string().describe("\u7BA1\u7406\u9875\u5730\u5740\uFF0C\u4F8B\u5982 http://192.168.1.40:10000"),
          username: tool.schema.string(),
          password: tool.schema.string()
        },
        async execute(args) {
          const base = String(args.hub || "").replace(/\/+$/, "");
          if (!base) return "\u8BF7\u63D0\u4F9B\u7BA1\u7406\u9875\u5730\u5740\uFF08\u4F8B\u5982 http://192.168.1.40:10000\uFF09";
          try {
            const m = await ensureManager();
            const r = await m.login({ hub: base, username: args.username, password: args.password });
            const names = (r.names || []).join(", ");
            return "\u767B\u5F55\u6210\u529F\uFF08" + (r.user && r.user.name) + " / " + (r.user && r.user.role) + "\uFF09\uFF0C\u5DF2\u540C\u6B65 " + r.count + " \u53F0\u8BBE\u5907: " + (names || "\u65E0") + "\n\u914D\u7F6E\u6587\u4EF6: " + configPath();
          } catch (e) {
            return "\u767B\u5F55\u5931\u8D25: " + String(e);
          }
        }
      }),
      oc_add: tool({
        description: "\u7528\u88AB\u63A7\u7AEF\u751F\u6210\u7684\u8FDE\u63A5\u7801\uFF08OCL1:\u2026\uFF09\u6DFB\u52A0\u4E00\u4E2A\u63A7\u5236\u76EE\u6807\u5230\u672C\u673A\u914D\u7F6E\uFF1B\u4E5F\u53EF\u4EE5\u624B\u52A8\u7ED9 hub+key\u3002\u6DFB\u52A0\u540E\u53EF\u76F4\u63A5\u7528\u76EE\u6807\u540D\u64CD\u4F5C",
        args: {
          code: tool.schema.string().optional().describe("\u8FDE\u63A5\u7801 OCL1:...\uFF08\u88AB\u63A7\u7AEF\u754C\u9762\u590D\u5236\uFF09"),
          name: tool.schema.string().optional().describe("\u53EF\u9009\uFF1A\u76EE\u6807\u540D\uFF08\u9ED8\u8BA4\u7528\u8FDE\u63A5\u7801\u91CC\u7684\u540D\u5B57\uFF09"),
          hub: tool.schema.string().optional().describe("\u624B\u52A8\u6A21\u5F0F\uFF1A\u4E2D\u7EE7\u5730\u5740 host:port"),
          key: tool.schema.string().optional().describe("\u624B\u52A8\u6A21\u5F0F\uFF1A\u914D\u5BF9\u5BC6\u94A5 OCL-..."),
          fingerprint: tool.schema.string().optional().describe("\u624B\u52A8\u6A21\u5F0F\uFF1A\u8BC1\u4E66\u6307\u7EB9")
        },
        async execute(args) {
          let hub = String(args.hub || "").trim();
          let key = String(args.key || "").trim();
          let fp = String(args.fingerprint || "").trim();
          let name = String(args.name || "").trim();
          const code = String(args.code || "").trim();
          if (code) {
            if (!code.startsWith("OCL1:")) return "\u8FDE\u63A5\u7801\u683C\u5F0F\u4E0D\u5BF9\uFF08\u5E94\u4EE5 OCL1: \u5F00\u5934\uFF09";
            try {
              const raw = Buffer.from(code.slice(5), "base64url").toString("utf8");
              const j = JSON.parse(raw);
              hub = hub || String(j.h || "");
              key = key || String(j.k || "");
              fp = fp || String(j.f || "");
              name = name || String(j.n || "");
            } catch {
              return "\u8FDE\u63A5\u7801\u5185\u5BB9\u635F\u574F\uFF0C\u8BF7\u91CD\u65B0\u590D\u5236";
            }
          }
          if (!hub || !key) return "\u7F3A\u5C11 hub \u6216 key\uFF08\u7C98\u8D34\u8FDE\u63A5\u7801\uFF0C\u6216\u540C\u65F6\u63D0\u4F9B hub+key\uFF09";
          name = name || "\u8BBE\u5907";
          const p = configPath();
          let cfg = {};
          try {
            cfg = JSON.parse(fs2.readFileSync(p, "utf8"));
          } catch {
          }
          if (!cfg || typeof cfg !== "object") cfg = {};
          cfg.profiles = cfg.profiles || {};
          const base = name;
          for (let i = 2; cfg.profiles[name]; i++) name = base + "-" + i;
          cfg.profiles[name] = { hub, key, fingerprint: fp };
          fs2.mkdirSync(path2.dirname(p), { recursive: true });
          fs2.writeFileSync(p, JSON.stringify(cfg, null, 2));
          return "\u5DF2\u6DFB\u52A0\u76EE\u6807 [" + name + "]\uFF08\u4E2D\u7EE7 " + hub + "\uFF09\n\u73B0\u6709\u76EE\u6807: " + Object.keys(cfg.profiles).join(", ");
        }
      }),
      oc_devices: tool({
        description: "\u5217\u51FA oc-link \u76EE\u6807\u8BBE\u5907\u4E0E\u957F\u8FDE\u63A5\u72B6\u6001\uFF08\u672A\u8FDE\u63A5/\u8FDE\u63A5\u4E2D/\u7B49\u5F85\u88AB\u63A7\u7AEF/\u5DF2\u8FDE\u63A5/\u91CD\u8FDE\u4E2D/\u51FA\u9519\uFF09",
        args: {},
        async execute() {
          try {
            const m = await ensureManager();
            const st = await m.getState(0);
            const list = st.targets || [];
            if (!list.length) return "\u8FD8\u6CA1\u6709\u914D\u7F6E\u76EE\u6807\u3002\u7528 oc_add \u7C98\u8D34\u8FDE\u63A5\u7801\uFF0C\u6216 oc_login \u767B\u5F55\u540C\u6B65\u8BBE\u5907\u3002";
            const label = {
              off: "\u672A\u8FDE\u63A5",
              connecting: "\u8FDE\u63A5\u4E2D",
              waiting: "\u7B49\u5F85\u88AB\u63A7\u7AEF",
              online: "\u5DF2\u8FDE\u63A5",
              reconnecting: "\u91CD\u8FDE\u4E2D",
              error: "\u51FA\u9519"
            };
            return list.map((t) => {
              let s = t.name + ": " + (label[t.state] || t.state);
              if (t.peer) s += " \xB7 \u5BF9\u7AEF " + t.peer;
              if (t.autoConnect) s += " \xB7 \u81EA\u52A8\u8FDE\u63A5";
              if (t.error) s += " \xB7 " + t.error;
              return s;
            }).join("\n");
          } catch (e) {
            return "\u8BFB\u53D6\u8FDE\u63A5\u72B6\u6001\u5931\u8D25: " + String(e);
          }
        }
      }),
      oc_connect: tool({
        description: "\u5BF9\u76EE\u6807\u5F00\u542F\u957F\u8FDE\u63A5\uFF08\u7A33\u5B9A\u65F6\u4FDD\u6301\uFF0C\u65AD\u7EBF\u81EA\u52A8\u91CD\u8FDE\uFF09",
        args: { target: tool.schema.string().describe("\u76EE\u6807\u540D") },
        async execute(args) {
          try {
            const m = await ensureManager();
            await m.connect(String(args.target));
            return "\u5DF2\u5F00\u59CB\u8FDE\u63A5 [" + args.target + "]\uFF0C\u65AD\u7EBF\u4F1A\u81EA\u52A8\u91CD\u8FDE\u3002";
          } catch (e) {
            return "\u5931\u8D25: " + String(e);
          }
        }
      }),
      oc_disconnect: tool({
        description: "\u65AD\u5F00\u76EE\u6807\u7684\u957F\u8FDE\u63A5",
        args: { target: tool.schema.string().describe("\u76EE\u6807\u540D") },
        async execute(args) {
          try {
            const m = await ensureManager();
            await m.disconnect(String(args.target));
            return "\u5DF2\u65AD\u5F00 [" + args.target + "]\u3002";
          } catch (e) {
            return "\u5931\u8D25: " + String(e);
          }
        }
      }),
      oc_status: tool({
        description: "\u68C0\u67E5 oc-link \u5230\u67D0\u4E2A\u8FDC\u7AEF\u8BBE\u5907\u7684\u8FDE\u901A\u6027\uFF08\u662F\u5426\u5728\u7EBF\u3001\u80FD\u5426\u5EFA\u7ACB\u52A0\u5BC6\u4F1A\u8BDD\uFF09",
        args: { target: tool.schema.string().optional().describe("\u76EE\u6807\u540D\uFF0C\u9ED8\u8BA4 default") },
        async execute(args) {
          const profiles = listProfiles();
          if (!profiles.length) {
            return "\u8FD8\u6CA1\u6709\u914D\u7F6E\u76EE\u6807\u3002\u8BF7\u5728 ~/.config/oc-link/config.json \u5199\u5165 profiles\u3002";
          }
          const t = args.target || "default";
          try {
            await call(t, { op: "ping", id: "1" }, 15e3);
            return "\u76EE\u6807 [" + t + "] \u5728\u7EBF\uFF0C\u52A0\u5BC6\u4F1A\u8BDD\u6B63\u5E38\u3002\u5DF2\u914D\u7F6E\u76EE\u6807: " + profiles.join(", ");
          } catch (e) {
            return "\u76EE\u6807 [" + t + "] \u4E0D\u53EF\u7528: " + (e && e.message) + "\n\u5DF2\u914D\u7F6E\u76EE\u6807: " + profiles.join(", ");
          }
        }
      }),
      oc_exec: tool({
        description: "\u5728\u8FDC\u7AEF\u8BBE\u5907\u4E0A\u6267\u884C\u547D\u4EE4\uFF08Windows \u8D70 PowerShell\uFF0CLinux \u8D70 sh\uFF09\u3002\u957F\u4EFB\u52A1\uFF08\u4E0B\u8F7D/\u7F16\u8BD1\uFF09\u8BF7\u628A timeoutMs \u8C03\u5927\uFF08\u5982 1800000=30 \u5206\u949F\uFF09\uFF0C\u6216\u7528\u540E\u53F0\u65B9\u5F0F\uFF1AStart-Process/start /b \u8D77\u4EFB\u52A1\u5E76\u628A\u8F93\u51FA\u91CD\u5B9A\u5411\u5230\u65E5\u5FD7\uFF0C\u7136\u540E\u8F6E\u8BE2\u65E5\u5FD7\u4E0E\u4EA7\u7269\uFF0C\u907F\u514D\u8D85\u65F6\u88AB\u6740",
        args: {
          cmd: tool.schema.string().describe("\u8981\u6267\u884C\u7684\u547D\u4EE4"),
          target: tool.schema.string().optional().describe("\u76EE\u6807\u540D\uFF0C\u9ED8\u8BA4 default"),
          cwd: tool.schema.string().optional().describe("\u5DE5\u4F5C\u76EE\u5F55"),
          timeoutMs: tool.schema.number().optional().describe("\u8D85\u65F6\u6BEB\u79D2\uFF0C\u9ED8\u8BA4 120000\uFF1B\u957F\u4EFB\u52A1\u53EF\u8BBE\u5927\uFF08\u5982 1800000\uFF09")
        },
        async execute(args) {
          return call(
            args.target,
            { op: "exec", id: "1", cmd: args.cmd, cwd: args.cwd, timeoutMs: args.timeoutMs },
            args.timeoutMs ? args.timeoutMs + 1e4 : 6e4
          );
        }
      }),
      oc_read: tool({
        description: "\u8BFB\u53D6\u8FDC\u7AEF\u8BBE\u5907\u4E0A\u7684\u6587\u4EF6\uFF08\u6587\u672C\u8FD4\u56DE\u5185\u5BB9\uFF0C\u4E8C\u8FDB\u5236\u8FD4\u56DE base64\uFF09",
        args: {
          path: tool.schema.string().describe("\u6587\u4EF6\u7EDD\u5BF9\u8DEF\u5F84"),
          target: tool.schema.string().optional(),
          maxBytes: tool.schema.number().optional()
        },
        async execute(args) {
          return call(args.target, { op: "read", id: "1", path: args.path, maxBytes: args.maxBytes });
        }
      }),
      oc_write: tool({
        description: "\u628A\u6587\u672C\u5185\u5BB9\u5199\u5165\u8FDC\u7AEF\u8BBE\u5907\u7684\u6587\u4EF6\uFF08UTF-8\uFF0C\u81EA\u52A8\u5EFA\u76EE\u5F55\uFF0C\u539F\u5B50\u66FF\u6362\uFF09",
        args: {
          path: tool.schema.string().describe("\u6587\u4EF6\u7EDD\u5BF9\u8DEF\u5F84"),
          content: tool.schema.string().describe("\u6587\u4EF6\u5185\u5BB9\uFF08\u6587\u672C\uFF09"),
          target: tool.schema.string().optional(),
          createDirs: tool.schema.boolean().optional()
        },
        async execute(args) {
          const b64 = Buffer.from(args.content, "utf8").toString("base64");
          return call(args.target, {
            op: "write",
            id: "1",
            path: args.path,
            dataB64: b64,
            createDirs: args.createDirs !== false
          });
        }
      }),
      oc_list: tool({
        description: "\u5217\u51FA\u8FDC\u7AEF\u8BBE\u5907\u4E0A\u7684\u76EE\u5F55\u5185\u5BB9",
        args: {
          path: tool.schema.string().describe("\u76EE\u5F55\u7EDD\u5BF9\u8DEF\u5F84"),
          target: tool.schema.string().optional()
        },
        async execute(args) {
          return call(args.target, { op: "list", id: "1", path: args.path });
        }
      }),
      oc_edit: tool({
        description: "\u5728\u8FDC\u7AEF\u8BBE\u5907\u7684\u5DF2\u6709\u6587\u4EF6\u91CC\u505A\u7CBE\u786E\u5B57\u7B26\u4E32\u66FF\u6362\uFF08\u9ED8\u8BA4\u8981\u6C42\u5339\u914D\u552F\u4E00\uFF0C\u53EF replaceAll\uFF09",
        args: {
          path: tool.schema.string().describe("\u6587\u4EF6\u7EDD\u5BF9\u8DEF\u5F84"),
          oldString: tool.schema.string().describe("\u8981\u67E5\u627E\u7684\u539F\u5185\u5BB9"),
          newString: tool.schema.string().describe("\u66FF\u6362\u6210\u7684\u65B0\u5185\u5BB9"),
          replaceAll: tool.schema.boolean().optional().describe("true=\u5168\u90E8\u66FF\u6362\uFF1B\u9ED8\u8BA4\u4EC5\u5728\u552F\u4E00\u5339\u914D\u65F6\u66FF\u6362"),
          target: tool.schema.string().optional()
        },
        async execute(args) {
          return call(args.target, {
            op: "edit",
            id: "1",
            path: args.path,
            oldString: args.oldString,
            newString: args.newString,
            replaceAll: args.replaceAll
          });
        }
      }),
      oc_grep: tool({
        description: "\u5728\u8FDC\u7AEF\u8BBE\u5907\u6309\u6B63\u5219\u641C\u7D22\u6587\u4EF6\u5185\u5BB9\uFF0C\u8FD4\u56DE \u8DEF\u5F84:\u884C\u53F7:\u5185\u5BB9",
        args: {
          pattern: tool.schema.string().describe("\u6B63\u5219\u8868\u8FBE\u5F0F"),
          path: tool.schema.string().describe("\u641C\u7D22\u8D77\u59CB\u76EE\u5F55\uFF08\u7EDD\u5BF9\u8DEF\u5F84\uFF09"),
          maxResults: tool.schema.number().optional(),
          target: tool.schema.string().optional()
        },
        async execute(args) {
          return call(
            args.target,
            { op: "grep", id: "1", pattern: args.pattern, path: args.path, maxResults: args.maxResults },
            6e4
          );
        }
      }),
      oc_glob: tool({
        description: "\u5728\u8FDC\u7AEF\u8BBE\u5907\u6309\u6587\u4EF6\u540D\u6A21\u5F0F\u67E5\u627E\u6587\u4EF6\uFF08\u652F\u6301 * ? \u548C **\uFF09",
        args: {
          pattern: tool.schema.string().describe("\u4F8B\u5982 **/*.log \u6216 *.go"),
          path: tool.schema.string().describe("\u641C\u7D22\u8D77\u59CB\u76EE\u5F55\uFF08\u7EDD\u5BF9\u8DEF\u5F84\uFF09"),
          maxResults: tool.schema.number().optional(),
          target: tool.schema.string().optional()
        },
        async execute(args) {
          return call(
            args.target,
            { op: "glob", id: "1", pattern: args.pattern, path: args.path, maxResults: args.maxResults },
            6e4
          );
        }
      })
    }
  };
};
export {
  OcLink
};
