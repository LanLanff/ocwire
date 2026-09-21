"use strict";

/* oc-link 桌面客户端前端：纯静态，无框架。
   通过 window.go.main.App.* 调用 Go 绑定，window.runtime.EventsOn 订阅事件。 */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

let state = null;
let activity = [];
let profiles = [];
let clients = [];
let clientsSig = null;
let inviteLink = "";
let inviteClientId = "";
let managerState = { running: false, targets: [] };
let logFilter = "";
let logKind = "";

const KIND_LABEL = {
  connected: "中继上线",
  disconnected: "中继离线",
  "peer-up": "控制端接入",
  "peer-down": "控制端断开",
  request: "命令",
  kick: "断开",
  revoke: "吊销",
  enroll: "激活",
  import: "导入",
  info: "信息",
  error: "错误",
  enabled: "已启用",
  disabled: "已禁用",
};

function api() {
  return window.go && window.go.main && window.go.main.App;
}

async function call(name, ...args) {
  const app = api();
  if (!app) throw new Error("Wails 运行时未就绪");
  return await app[name](...args);
}

function esc(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmtBytes(n) {
  if (!n) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// 自绘确认弹窗（不用原生 confirm，太丑）
function confirmDialog(opts) {
  return new Promise((resolve) => {
    const root = $("#modalRoot");
    $("#modalTitle").textContent = opts.title || "确认";
    $("#modalText").textContent = opts.message || "";
    $("#modalOk").textContent = opts.okText || "确定";
    root.classList.toggle("danger", !!opts.danger);
    root.classList.remove("hidden");
    const done = (v) => {
      root.classList.add("hidden");
      $("#modalOk").onclick = null;
      $("#modalCancel").onclick = null;
      root.onclick = null;
      document.onkeydown = null;
      resolve(v);
    };
    $("#modalOk").onclick = () => done(true);
    $("#modalCancel").onclick = () => done(false);
    root.onclick = (ev) => {
      if (ev.target === root) done(false);
    };
    document.onkeydown = (ev) => {
      if (ev.key === "Escape") done(false);
      if (ev.key === "Enter") done(true);
    };
  });
}

/* ---- 状态渲染 ---- */

function renderState(s) {
  state = s;
  const running = s.running;
  const connected = s.connected;

  $("#topStatusText").textContent = s.disabled
    ? "已禁用"
    : !s.activated
      ? "未激活"
      : connected
        ? "已连接"
        : running
          ? "运行中"
          : "已停止";
  $("#topStatus").className = "status-pill" + (s.disabled ? " err" : connected ? " live" : running ? " on" : "");
  $("#bigDot").className = "big-dot" + (s.disabled ? " err" : connected ? " live" : running ? " on" : "");

  $("#devName").textContent = s.name || "-";
  $("#devMeta").textContent = s.disabled
    ? "已被中继管理员禁用（等待启用）"
    : s.activated
      ? "设备 ID " + (s.deviceId || "").slice(0, 16) + "…  ·  中继 " + s.hub
      : "尚未激活";
  const dban = $("#disabledBanner");
  if (dban) dban.classList.toggle("hidden", !s.disabled);

  $("#btnToggle").textContent = running ? "停止" : "启动";
  $("#btnToggle").disabled = !s.activated;

  updateStats(s);
  renderClients();

  $("#btnShowLink").disabled = !inviteLink;
  $("#btnCopyLink").disabled = !inviteLink;
  if (!s.activated) $("#qrBox").classList.add("hidden");

  $("#autoStart").checked = !!s.autostart;
  if (document.activeElement !== $("#inputName")) $("#inputName").value = s.name || "";

  $("#aboutVersion").textContent = s.version || "-";
  $("#aboutHub").textContent = s.hub || s.defaultHub || "-";
  $("#aboutDevice").textContent = s.deviceId || "-";

  const relayStatus = $("#relayStatus");
  if (relayStatus) {
    relayStatus.textContent = s.disabled
      ? "已禁用（等待管理员在中继上启用）"
      : s.activated
        ? s.running
          ? s.connected
            ? "已连接控制端"
            : "运行中"
          : "已停止"
        : "未接入";
    $("#relayName").textContent = s.name || "-";
    $("#relayHub").textContent = s.hub || s.defaultHub || "-";
    $("#btnToggle2").textContent = s.running ? "断开中继" : "接入中继";
    $("#btnToggle2").disabled = !s.activated;
  }
}

function entryHtml(e) {
  const when = e.t ? new Date(e.t) : null;
  const t = when ? when.toLocaleTimeString("zh-CN", { hour12: false }) : "";
  const full = when ? when.toLocaleString("zh-CN", { hour12: false }) : "";
  const label = KIND_LABEL[e.kind] || e.kind;
  const bad = e.kind === "error" || (e.kind === "request" && e.ok === false);
  let d = "";
  if (e.kind === "request") {
    d = (e.peer ? "「" + esc(e.peer) + "」 " : "") + esc(e.op || "") + (e.detail ? " · " + esc(e.detail) : "");
  } else if (e.kind === "peer-up") {
    d = "控制端「" + esc(e.peer || "未命名") + "」已连接";
  } else if (e.kind === "peer-down") {
    d = "控制端「" + esc(e.peer || "未命名") + "」已断开";
  } else {
    d = esc(e.detail || e.error || "");
  }
  let extra = "";
  if (e.kind === "request") {
    extra = e.ok ? (e.ms ? e.ms + " ms" : "成功") : "失败" + (e.error ? " · " + esc(e.error) : "");
    if (e.bytes) extra += " · " + fmtBytes(e.bytes);
  } else if (e.error) {
    extra = esc(e.error);
  }
  return (
    '<div class="entry' + (bad ? " bad" : "") + '"><span class="t" title="' + esc(full) + '">' + esc(t) +
    '</span><span class="k ' + esc(e.kind) + '">' + esc(label) + "</span>" +
    '<span class="d">' + d + (extra ? ' <span class="extra">' + extra + "</span>" : "") + "</span></div>"
  );
}

function renderActivity() {
  const devBox = $("#logFilter");
  const peers = peerStats();
  const want = logFilter;
  const opts = ['<option value="">全部设备</option>'].concat(
    peers.map((p) => '<option value="' + esc(p.name) + '">' + esc(p.name) + "（" + p.requests + "）</option>")
  );
  devBox.innerHTML = opts.join("");
  devBox.value = peers.some((p) => p.name === want) ? want : "";
  if (devBox.value !== want) logFilter = devBox.value;

  const kindBox = $("#logKind");
  if (kindBox && kindBox.value !== logKind) kindBox.value = logKind;

  let list = activity.filter((e) => !logFilter || peerKey(e) === logFilter);
  if (logKind) list = list.filter((e) => kindGroup(e.kind) === logKind);

  const count = $("#logCount");
  if (count) count.textContent = list.length ? "共 " + list.length + " 条" : "";

  const el = $("#logList");
  if (!list.length) {
    el.innerHTML =
      '<div class="empty">' + (activity.length ? "没有符合筛选条件的记录" : "暂无记录，发生连接或命令后会出现在这里") + "</div>";
    return;
  }
  let html = "";
  let lastDay = "";
  for (let i = list.length - 1; i >= 0; i--) {
    const e = list[i];
    const day = dayKey(e.t);
    if (day && day !== lastDay) {
      html += '<div class="day">' + esc(day) + "</div>";
      lastDay = day;
    }
    html += entryHtml(e);
  }
  el.innerHTML = html;
}

function kindGroup(kind) {
  if (kind === "request") return "cmd";
  if (kind === "peer-up" || kind === "peer-down") return "peer";
  if (kind === "connected" || kind === "disconnected" || kind === "disabled" || kind === "enabled") return "relay";
  return "other";
}

function dayKey(t) {
  if (!t) return "";
  const d = new Date(t);
  if (isNaN(d)) return "";
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return "今天";
  const y = new Date(today.getTime() - 86400000);
  if (d.toDateString() === y.toDateString()) return "昨天";
  return d.toLocaleDateString("zh-CN", { month: "long", day: "numeric" });
}

// 解析 OCL2 邀请码（不导入密钥，仅用于本机预览与校验）
function parseInvite(text) {
  const code = String(text || "").replace(/\s+/g, "");
  if (!code) return { ok: false, msg: "" };
  if (code.startsWith("OCL1:")) return { ok: false, msg: "这是旧版连接码（OCL1），已停用；请让被控端重新生成邀请码" };
  if (!code.startsWith("OCL2:")) return { ok: false, msg: "看起来不是邀请码（应以 OCL2: 开头）" };
  try {
    let s = code.slice(5).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const j = JSON.parse(new TextDecoder("utf-8").decode(bytes));
    return { ok: true, name: j.n || j.l || "设备", hub: j.h || "" };
  } catch (e) {
    return { ok: false, msg: "邀请码内容损坏，请让被控端重新生成" };
  }
}

function validateInviteInput() {
  const ta = $("#codeInput");
  const st = $("#addStatus");
  const btn = $("#btnAddProfile");
  if (!ta || !st || !btn) return { ok: false };
  const r = parseInvite(ta.value);
  ta.classList.remove("invalid", "valid");
  if (r.ok) {
    ta.classList.add("valid");
    st.className = "addstatus ok";
    st.textContent = "✓ 识别成功：设备「" + r.name + "」" + (r.hub ? " · 中继 " + r.hub : "");
    btn.disabled = false;
  } else {
    if (ta.value.trim()) ta.classList.add("invalid");
    st.className = "addstatus err";
    st.textContent = r.msg || "";
    btn.disabled = true;
  }
  return r;
}

async function pasteInviteFromClipboard() {
  let text = "";
  try {
    const rt = window.runtime;
    if (rt && rt.ClipboardGetText) text = await rt.ClipboardGetText();
    else if (navigator.clipboard && navigator.clipboard.readText) text = await navigator.clipboard.readText();
  } catch (e) {
    /* ignore */
  }
  if (!text) {
    toast("读不到剪贴板，请手动 Ctrl+V 粘贴", "err");
    return;
  }
  $("#codeInput").value = String(text).trim();
  validateInviteInput();
}

function peerKey(e) {
  return e.peer || "未命名控制端";
}

function peerStats() {
  const map = new Map();
  for (const e of activity) {
    if (e.kind !== "request" && e.kind !== "peer-up") continue;
    const k = peerKey(e);
    const cur = map.get(k) || { name: k, requests: 0, last: 0 };
    if (e.kind === "request") cur.requests++;
    const ts = e.t ? Date.parse(e.t) : 0;
    if (ts > cur.last) cur.last = ts;
    map.set(k, cur);
  }
  return Array.from(map.values()).sort((a, b) => b.last - a.last);
}

function updateStats(s) {
  $("#statPeer").textContent = s.connected ? s.peerName || "未命名" : "无";
  $("#statPeers").textContent = String(clients.length);
  let reqs = 0;
  for (const e of activity) if (e.kind === "request") reqs++;
  $("#statReq").textContent = String(reqs);
}

function fmtWhen(ts) {
  if (!ts) return "";
  const diff = Date.now() - ts;
  if (diff < 60000) return "刚刚";
  if (diff < 3600000) return Math.floor(diff / 60000) + " 分钟前";
  if (diff < 86400000) return Math.floor(diff / 3600000) + " 小时前";
  return new Date(ts).toLocaleDateString("zh-CN");
}

function renderClients() {
  const el = $("#clientList");
  // 控制端被删掉后，邀请码卡片同步清空
  if (inviteClientId && !clients.some((c) => c.id === inviteClientId)) {
    clearInvite();
  }
  const sig = clients.map((c) => c.id + ":" + (c.label || "") + ":" + (c.used ? 1 : 0) + ":" + (c.disabled ? 1 : 0) + ":" + (c.online ? 1 : 0)).join("|");
  if (sig === clientsSig) return; // 内容没变就不重绘，避免点击被重建吞掉
  clientsSig = sig;
  if (!clients.length) {
    el.innerHTML = '<div class="peer-empty">还没有授权任何控制端。点右上角「＋ 生成邀请码」，把邀请码发给 A 端输入。</div>';
    return;
  }
  el.innerHTML = clients
    .map((c) => {
      const label = c.label || "待连接 · " + c.id.slice(0, 8);
      const status = c.disabled ? "已禁用" : c.online ? "在线" : c.used ? "离线" : "未使用";
      const dot = c.disabled ? "err" : c.online ? "ok" : "";
      return (
        '<div class="peer-row" data-id="' +
        esc(c.id) +
        '"><span class="dot-mini ' +
        dot +
        '"></span><div class="pi"><div class="pn">' +
        esc(label) +
        '</div><div class="pd">' +
        status +
        " · ID " +
        esc(c.id.slice(0, 8)) +
        (c.createdAt ? " · " + esc(fmtWhen(Date.parse(c.createdAt))) : "") +
        "</div></div>" +
        '<button class="ghost sm" data-act="link">邀请码</button>' +
        '<button class="ghost sm" data-act="toggle">' +
        (c.disabled ? "启用" : "禁用") +
        "</button>" +
        '<button class="danger-ghost sm" data-act="del">删除</button></div>'
      );
    })
    .join("");
}

function renderProfiles() {
  const el = $("#profileList");
  const total = $("#aTotal");
  if (total) total.textContent = String(profiles.length);
  if (!profiles.length) {
    el.innerHTML = '<div class="empty">还没有控制目标</div>';
    return;
  }
  el.innerHTML = profiles
    .map(
      (p) => {
        const tg = managerState.running ? managerState.targets.find((t) => t.name === p.name) : null;
        const label =
          { off: "未连接", connecting: "连接中", waiting: "等待被控端", online: "已连接", reconnecting: "重连中", error: "出错" }[tg && tg.state] ||
          (tg ? tg.state : managerState.running ? "未连接" : "—");
        const stCls = tg && tg.state === "online" ? "st-ok" : tg && tg.state === "error" ? "st-err" : tg && tg.state !== "off" ? "st-warn" : "";
        const connected = !!tg && tg.state !== "off" && tg.state !== "error";
        const peer = tg && tg.peer ? " · 对端 " + esc(tg.peer) : "";
        const ops = managerState.running
          ? connected
            ? '<button class="ghost sm" data-act="disc">断开</button>'
            : '<button class="ghost sm" data-act="conn">连接</button>'
          : "";
        return (
          '<div class="profile" data-name="' +
          esc(p.name) +
          '"><div class="pi"><div class="pn">' +
          esc(p.name) +
          (p.canOperate ? "" : ' <span class="badge gray">只读</span>') +
          (p.token ? ' <span class="badge">令牌</span>' : "") +
          '</div><div class="pd">' +
          esc(p.hub) +
          (p.deviceId ? " · " + esc(p.deviceId) : "") +
          ' · <span class="' +
          stCls +
          '">' +
          esc(label) +
          "</span>" +
          peer +
          "</div></div>" +
          '<span class="badge gray test-result hidden"></span>' +
          ops +
          '<button class="ghost sm" data-act="test">测试</button>' +
          '<button class="danger-ghost sm" data-act="del">删除</button></div>'
        );
      }
    )
    .join("");
  if (!managerState.running) {
    el.innerHTML =
      '<div class="peer-empty">常驻引擎未运行（启动 oc 壳子后，这里会显示每个目标的连接状态，并可连接 / 断开）</div>' + el.innerHTML;
  }

  el.querySelectorAll("button[data-act]").forEach((b) => {
    b.addEventListener("click", async () => {
      const name = b.closest(".profile").dataset.name;
      if (b.dataset.act === "test") {
        await testProfile(b, name);
        return;
      }
      if (b.dataset.act === "conn" || b.dataset.act === "disc") {
        try {
          if (b.dataset.act === "conn") await call("ManagerConnect", name);
          else await call("ManagerDisconnect", name);
          toast(b.dataset.act === "conn" ? "已开始连接" : "已断开", "ok");
          await refreshManagerState();
        } catch (e) {
          toast(String(e), "err");
        }
        return;
      }
      const sure = await confirmDialog({
        title: "删除目标",
        message: "删除「" + name + "」的目标配置？\n只删本机配置，不影响被控端。",
        danger: true,
        okText: "删除",
      });
      if (!sure) return;
      try {
        await call("DeleteProfile", name);
        toast("已删除", "ok");
        await refreshProfiles();
      } catch (e) {
        toast(String(e), "err");
      }
    });
  });
}

async function testProfile(btn, name) {
  const badge = btn.closest(".profile").querySelector(".test-result");
  badge.classList.remove("hidden", "ok", "err");
  badge.classList.add("gray");
  badge.textContent = "测试中…";
  try {
    const msg = await call("TestProfile", name);
    badge.className = "badge test-result ok";
    badge.textContent = msg;
  } catch (e) {
    badge.className = "badge test-result err";
    badge.textContent = "失败";
    toast(name + ": " + String(e), "err");
  }
}

/* ---- 刷新 ---- */

async function refreshState() {
  const s = await call("GetState");
  renderState(s);
}

async function refreshProfiles() {
  profiles = (await call("ListProfiles")) || [];
  renderProfiles();
}

async function refreshActivity() {
  activity = (await call("GetActivity", 100)) || [];
  renderActivity();
}

async function refreshClientName() {
  const el = $("#clientName");
  if (!el) return;
  const v = await call("GetClientName");
  if (document.activeElement !== el) el.value = v || "";
}

async function refreshClients() {
  clients = (await call("ListClients")) || [];
  renderClients();
}

async function refreshManagerState() {
  try {
    managerState = (await call("ManagerState")) || { running: false, targets: [] };
  } catch (_) {
    managerState = { running: false, targets: [] };
  }
  renderProfiles();
}

async function refreshAll() {
  await Promise.all([refreshState(), refreshProfiles(), refreshActivity(), refreshClientName(), refreshClients()]);
  await refreshManagerState();
}

/* ---- 交互绑定 ---- */

function switchTab(name) {
  $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + name));
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {}
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch (_) {}
  ta.remove();
  return ok;
}

async function showLink(force) {
  if (!inviteLink) return;
  const box = $("#qrBox");
  if (!force && !box.classList.contains("hidden")) {
    box.classList.add("hidden");
    return;
  }
  const img = $("#qrImg");
  if (img.dataset.for !== inviteLink) {
    const data = await call("QRImage", inviteLink);
    if (!data) {
      toast("二维码生成失败", "err");
      return;
    }
    img.src = data;
    img.dataset.for = inviteLink;
  }
  $("#linkText").value = inviteLink;
  box.classList.remove("hidden");
}

// 从邀请码里取出 clientId（不涉及密钥解析，只是读公开字段）
function inviteIdOf(link) {
  try {
    let b64 = link.slice(5).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    return JSON.parse(atob(b64)).c || "";
  } catch (_) {
    return "";
  }
}

// 清空邀请码显示（删除控制端时同步清理）
function clearInvite() {
  inviteLink = "";
  inviteClientId = "";
  $("#qrBox").classList.add("hidden");
  $("#linkText").value = "";
  $("#btnShowLink").disabled = true;
  $("#btnCopyLink").disabled = true;
}

function wire() {
  $$(".tab").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

  const toggleRelay = async () => {
    if (!state) return;
    try {
      if (state.running) {
        await call("Stop");
        toast("已断开中继");
      } else {
        await call("Start");
        toast("已接入中继", "ok");
      }
      await refreshState();
    } catch (e) {
      toast(String(e), "err");
    }
  };
  $("#btnToggle").addEventListener("click", toggleRelay);
  $("#btnToggle2").addEventListener("click", toggleRelay);

  $("#btnRename").addEventListener("click", () => {
    switchTab("set");
    $("#inputName").focus();
    $("#inputName").select();
  });

  $("#logFilter").addEventListener("change", (ev) => {
    logFilter = ev.target.value;
    renderActivity();
  });

  $("#logKind").addEventListener("change", (ev) => {
    logKind = ev.target.value;
    renderActivity();
  });

  $("#btnShowLink").addEventListener("click", () => void showLink(false));

  // 控制端列表：事件委托（重绘也不会丢点击）
  $("#clientList").addEventListener("click", async (ev) => {
    const b = ev.target.closest("button[data-act]");
    if (!b) return;
    const row = b.closest(".peer-row");
    const id = row && row.dataset.id;
    if (!id) return;
    if (b.dataset.act === "link") {
      try {
        inviteLink = await call("InviteLink", id);
        inviteClientId = id;
        $("#btnShowLink").disabled = false;
        $("#btnCopyLink").disabled = false;
        await showLink(true);
        toast("已显示邀请码", "ok");
      } catch (e) {
        toast(String(e), "err");
      }
      return;
    }
    const cur = clients.find((c) => c.id === id);
    if (b.dataset.act === "toggle") {
      const disable = !(cur && cur.disabled);
      const sure2 = await confirmDialog({
        title: disable ? "禁用控制端" : "启用控制端",
        message: disable
          ? "禁用后该控制端无法连接本机（在线连接会被断开），随时可以再启用。"
          : "启用后该控制端可以重新连接本机。",
        danger: disable,
        okText: disable ? "禁用" : "启用",
      });
      if (!sure2) return;
      try {
        await call("SetClientDisabled", id, disable);
        toast(disable ? "已禁用" : "已启用", "ok");
        await refreshAll();
      } catch (e) {
        toast(String(e), "err");
      }
      return;
    }
    const sure = await confirmDialog({
      title: "删除控制端",
      message: "删除后它的邀请码立即失效，在线连接会被断开。",
      danger: true,
      okText: "删除",
    });
    if (!sure) return;
    try {
      await call("RemoveClient", id);
      if (inviteClientId === id) clearInvite();
      toast("已删除", "ok");
      await refreshAll();
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#btnCreateInvite").addEventListener("click", async () => {
    try {
      inviteLink = await call("CreateInvite", "");
      inviteClientId = inviteIdOf(inviteLink);
      await refreshAll();
      toast("已生成邀请码，A 端连上后名字会自动显示", "ok");
      switchTab("b");
      await showLink(true);
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#btnCopyLink").addEventListener("click", async () => {
    if (!inviteLink) return;
    const ok = await copyText(inviteLink);
    toast(ok ? "邀请码已复制" : "复制失败，请手动复制二维码下方文本", ok ? "ok" : "err");
  });

  $("#btnClearLog").addEventListener("click", async () => {
    const sure = await confirmDialog({
      title: "清空记录",
      message: "全部命令记录将被清除，无法恢复。",
      danger: true,
      okText: "清空",
    });
    if (!sure) return;
    try {
      await call("ClearActivity");
      activity = [];
      renderActivity();
      updateStats(state || {});
      toast("已清空", "ok");
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#btnMoreLog").addEventListener("click", async () => {
    if (!activity.length) return toast("没有更早的记录了");
    const oldest = Date.parse(activity[0].t || "");
    if (!oldest) return toast("没有更早的记录了");
    try {
      const older = (await call("GetActivityBefore", oldest, 100)) || [];
      if (!older.length) return toast("没有更早的记录了");
      activity = older.concat(activity);
      renderActivity();
      toast("已加载 " + older.length + " 条", "ok");
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#btnSaveClientName").addEventListener("click", async () => {
    try {
      await call("SetClientName", $("#clientName").value.trim());
      toast("已保存，重连后 B 端显示新名字", "ok");
      await refreshClientName();
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#codeInput").addEventListener("input", () => {
    $("#btnGoConnect").classList.add("hidden");
    validateInviteInput();
  });
  $("#codeInput").addEventListener("change", validateInviteInput);

  $("#btnPasteCode").addEventListener("click", async () => {
    await pasteInviteFromClipboard();
    $("#codeInput").focus();
  });

  $("#btnGoConnect").addEventListener("click", async () => {
    const name = $("#btnGoConnect").dataset.name || "";
    if (!name) return;
    try {
      await call("ManagerConnect", name);
      toast("已开始连接 " + name, "ok");
      const tab = document.querySelector('.tab[data-tab="a"]');
      if (tab) tab.click();
      await refreshManagerState();
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#btnAddProfile").addEventListener("click", async () => {
    const ta = $("#codeInput");
    const st = $("#addStatus");
    const btn = $("#btnAddProfile");
    const r = parseInvite(ta.value);
    if (!r.ok) {
      st.className = "addstatus err";
      st.textContent = r.msg || "请先粘贴邀请码";
      return;
    }
    btn.disabled = true;
    btn.textContent = "添加中…";
    try {
      const name = await call("AddProfile", ta.value.trim());
      ta.value = "";
      ta.classList.remove("valid", "invalid");
      const go = $("#btnGoConnect");
      go.classList.remove("hidden");
      go.dataset.name = name;
      st.className = "addstatus ok";
      st.textContent = "✓ 已添加目标「" + name + "」，点「去连接」开始控制";
      toast("已添加: " + name, "ok");
      await refreshProfiles();
      await refreshManagerState();
    } catch (e) {
      st.className = "addstatus err";
      st.textContent = String(e);
      btn.disabled = false;
    } finally {
      btn.textContent = "添加设备";
    }
  });

  $("#btnSaveName").addEventListener("click", async () => {
    try {
      await call("SetName", $("#inputName").value.trim());
      toast("已保存", "ok");
      await refreshState();
    } catch (e) {
      toast(String(e), "err");
    }
  });

  $("#autoStart").addEventListener("change", async (ev) => {
    try {
      await call("SetAutostart", ev.target.checked);
      toast(ev.target.checked ? "已开启开机自启" : "已关闭开机自启", "ok");
    } catch (e) {
      toast(String(e), "err");
      ev.target.checked = !ev.target.checked;
    }
  });

  // 高级输入已常驻显示，无需切换
}

function bindRuntimeEvents() {
  const rt = window.runtime;
  if (!rt || !rt.EventsOn) return;
  let renderQueued = false;
  const queueRender = () => {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      renderActivity();
      updateStats(state || {});
    });
  };
  rt.EventsOn("state", (s) => renderState(s));
  rt.EventsOn("activity", (e) => {
    activity.push(e);
    if (activity.length > 300) activity.shift();
    queueRender();
    if ((e.kind === "peer-up" || e.kind === "request") && e.clientId && e.clientId === inviteClientId) {
      clearInvite(); // 邀请码已被使用：二维码自动隐藏
    }
    if (e.kind === "peer-up" || e.kind === "peer-down") refreshClients().catch(() => {});
  });
}

async function waitFor(fn, ms) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    const v = fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 80));
  }
  return null;
}

async function boot() {
  const ok = await waitFor(() => api(), 5000);
  if (!ok) {
    toast("未检测到 Wails 运行时（请用 oc-link.exe 打开）", "err");
    return;
  }
  bindRuntimeEvents();
  wire();
  try {
    await refreshAll();
  } catch (e) {
    toast(String(e), "err");
  }
  setInterval(() => {
    if (!document.hidden) {
      refreshState().catch(() => {});
      refreshManagerState().catch(() => {});
    }
  }, 5000);
}

window.addEventListener("load", boot);
