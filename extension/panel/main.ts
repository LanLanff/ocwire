// oc-link 设备面板：设备列表 + 状态 + 连接/断开 + 添加设备 + 活动记录。
// 面板在沙箱 iframe 里，通过 OpenChamber 的 serviceRequest 调本地 service，
// service 再转发到插件进程里的连接管理器（长连接 + 自动重连）。
import { connectHost, HostRequestError } from "@openchamber/sdk";
import { applyHostReady } from "@openchamber/sdk/ui";

const host = connectHost();

type TargetState = "off" | "connecting" | "waiting" | "online" | "reconnecting" | "error";
interface Target {
  name: string;
  hub: string;
  state: TargetState;
  peer: string;
  error: string;
  connectedAt: number;
  lastActive: number;
  requests: number;
  autoConnect: boolean;
  token: boolean;
}
interface Ev {
  seq: number;
  t: number;
  kind: string;
  target: string;
  message: string;
}
interface StateResp {
  ok: boolean;
  now: number;
  targets: Target[];
  events: Ev[];
  clientName?: string;
}

const $ = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector(sel) as T;

let lastSeq = 0;
let events: Ev[] = [];
let busy = false;
let devicesEl: HTMLElement;
let logDev = "";
let logKind = "";
let shownLog = 50; // 日志每次最多渲染 50 条，更多由「显示更早」展开

async function api(path: string, method: "GET" | "POST" = "GET", body?: unknown): Promise<any> {
  const r = await host.serviceRequest({ method, path, body: body === undefined ? undefined : JSON.stringify(body) });
  let data: any = null;
  try {
    data = r.body ? JSON.parse(r.body) : null;
  } catch {
    /* ignore */
  }
  if (r.status >= 400) throw new Error((data && data.error) || "HTTP " + r.status);
  return data;
}

function friendly(e: unknown): string {
  if (e instanceof HostRequestError) {
    switch (e.code) {
      case "NO_SERVICE":
        return "本地服务未授权：打开 设置 → 扩展 → oc-link，允许「本地服务」，然后重新打开这个面板。";
      case "SERVICE_FAILED":
        return "本地服务启动失败：在扩展设置里禁用后再启用，或重启 OpenChamber。";
      case "DISABLED":
        return "扩展已被停用：请在 设置 → 扩展 里重新启用。";
      case "HOST_TIMEOUT":
        return "请求超时：连接管理器可能正忙，会自动重试。";
      default:
        return e.code + ": " + e.message;
    }
  }
  return String(e);
}

function setBanner(msg: string, isErr = false) {
  const b = $("#banner");
  if (!msg) {
    b.style.display = "none";
    return;
  }
  b.textContent = msg;
  b.className = "banner" + (isErr ? " err" : "");
  b.style.display = "";
}

function metaText(t: Target): { text: string; cls: string } {
  if (t.state === "online") {
    return {
      text: "已连接 · " + (t.peer ? "对端 " + t.peer + " · " : "") + (t.requests ? t.requests + " 次请求" : "空闲"),
      cls: "st-ok",
    };
  }
  if (t.state === "waiting") return { text: "已接入中继，等待被控端上线", cls: "st-warn" };
  if (t.state === "connecting") return { text: "正在连接 " + t.hub, cls: "st-warn" };
  if (t.state === "reconnecting") return { text: "连接断开，自动重连中" + (t.error ? " · " + t.error : ""), cls: "st-warn" };
  if (t.state === "error") return { text: t.error || "出错", cls: "st-err" };
  return { text: t.hub, cls: "" };
}

let targetsByName = new Map<string, Target>();
const cards = new Map<
  string,
  {
    root: HTMLElement;
    name: HTMLElement;
    autoTag: HTMLElement;
    meta: HTMLElement;
    toggle: HTMLButtonElement;
    auto: HTMLButtonElement;
    del: HTMLButtonElement;
    armed: boolean;
    armTimer: number;
  }
>();
let emptyEl: HTMLElement | null = null;

function ensureEmpty() {
  if (!emptyEl) {
    emptyEl = document.createElement("div");
    emptyEl.className = "empty";
    emptyEl.textContent = "还没有设备。展开下面「添加设备」，粘贴被控端的连接码。";
  }
  return emptyEl;
}

function createCard(name: string) {
  const root = document.createElement("div");
  root.className = "dev";
  root.dataset.name = name;

  const dot = document.createElement("span");
  dot.className = "dot";
  root.appendChild(dot);

  const info = document.createElement("div");
  info.className = "info";
  const nameRow = document.createElement("div");
  nameRow.className = "name-row";
  const nameEl = document.createElement("span");
  nameEl.className = "name";
  nameEl.textContent = name;
  nameRow.appendChild(nameEl);
  const autoTag = document.createElement("span");
  autoTag.className = "tag";
  autoTag.textContent = "自动";
  autoTag.style.display = "none";
  nameRow.appendChild(autoTag);
  info.appendChild(nameRow);
  const meta = document.createElement("div");
  meta.className = "meta";
  info.appendChild(meta);
  root.appendChild(info);

  const ops = document.createElement("div");
  ops.className = "ops";

  const toggle = document.createElement("button");
  toggle.className = "mini";
  toggle.onclick = () => {
    const cur = targetsByName.get(name);
    const wasConnected = !!cur && cur.state !== "off" && cur.state !== "error";
    void act(
      () => api(wasConnected ? "/disconnect" : "/connect", "POST", { name }),
      () => (wasConnected ? "已断开 " : "已开始连接 ") + name
    );
  };
  ops.appendChild(toggle);

  const auto = document.createElement("button");
  auto.className = "mini icon";
  auto.textContent = "⚡";
  auto.onclick = () => {
    const cur = targetsByName.get(name);
    const on = !(cur && cur.autoConnect);
    void act(
      () => api("/targets/auto", "POST", { name, on }),
      () => (on ? "已开启自动连接 " : "已关闭自动连接 ") + name
    );
  };
  ops.appendChild(auto);

  const card = {
    root,
    name: nameEl,
    autoTag,
    meta,
    toggle,
    auto,
    del: document.createElement("button"),
    armed: false,
    armTimer: 0,
  };
  const del = card.del;
  del.className = "mini icon danger";
  del.title = "从本机配置删除";
  del.textContent = "✕";
  del.onclick = () => {
    if (!card.armed) {
      card.armed = true;
      del.textContent = "确定?";
      del.style.width = "auto";
      del.style.padding = "0 6px";
      card.armTimer = window.setTimeout(() => {
        card.armed = false;
        del.textContent = "✕";
        del.style.width = "24px";
        del.style.padding = "0";
      }, 3000);
      return;
    }
    window.clearTimeout(card.armTimer);
    card.armed = false;
    del.textContent = "✕";
    del.style.width = "24px";
    del.style.padding = "0";
    void act(() => api("/targets/remove", "POST", { name }), "已删除 " + name);
  };
  ops.appendChild(del);

  root.appendChild(ops);
  return card;
}

// 原地更新设备卡片：只改文字/状态，不重建 DOM。
// （每 1.5 秒整块重建会把「按下-松开」落在两个按钮实例上，导致点击被吞）
function renderDevices(targets: Target[]) {
  targetsByName = new Map(targets.map((t) => [t.name, t]));
  const seen = new Set<string>();
  for (const t of targets) {
    seen.add(t.name);
    let card = cards.get(t.name);
    if (!card) {
      card = createCard(t.name);
      cards.set(t.name, card);
      devicesEl.appendChild(card.root);
    }
    card.root.dataset.state = t.state;
    card.name.textContent = t.name;
    card.autoTag.style.display = t.autoConnect ? "" : "none";
    card.auto.className = "mini icon" + (t.autoConnect ? " on" : "");
    card.auto.title = t.autoConnect ? "关闭自动连接" : "开启自动连接";
    const connected = t.state !== "off" && t.state !== "error";
    const label = connected ? "断开" : "连接";
    if (card.toggle.textContent !== label) card.toggle.textContent = label;

    const m = metaText(t);
    if (card.meta.dataset.cls !== m.cls || card.meta.dataset.text !== m.text) {
      card.meta.dataset.cls = m.cls;
      card.meta.dataset.text = m.text;
      card.meta.textContent = "";
      if (m.cls) {
        const sp = document.createElement("span");
        sp.className = m.cls;
        sp.textContent = m.text;
        card.meta.appendChild(sp);
      } else {
        card.meta.textContent = m.text;
      }
    }
  }
  for (const [name, card] of cards) {
    if (!seen.has(name)) {
      card.root.remove();
      cards.delete(name);
    }
  }
  if (!targets.length) {
    if (!emptyEl || !emptyEl.isConnected) devicesEl.appendChild(ensureEmpty());
  } else if (emptyEl && emptyEl.isConnected) {
    emptyEl.remove();
  }
}

// 解析 OCL2 邀请码（只在本机校验/预览，不上传）
function parseInvite(text: string): { ok: boolean; name?: string; hub?: string; msg?: string } {
  const code = String(text || "").replace(/\s+/g, "");
  if (!code) return { ok: false };
  if (code.startsWith("OCL1:")) return { ok: false, msg: "这是旧版连接码（OCL1），已停用；请让被控端重新生成邀请码" };
  if (!code.startsWith("OCL2:")) return { ok: false, msg: "看起来不是邀请码（应以 OCL2: 开头）" };
  try {
    let s = code.slice(5).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const j = JSON.parse(new TextDecoder("utf-8").decode(bytes));
    return { ok: true, name: j.n || j.l || "设备", hub: j.h || "" };
  } catch {
    return { ok: false, msg: "邀请码内容损坏，请让被控端重新生成" };
  }
}

function validateAdd() {
  const ta = $("#code") as HTMLTextAreaElement | null;
  const st = $("#add-status");
  const btn = $("#btn-add") as HTMLButtonElement | null;
  if (!ta || !st || !btn) return;
  const r = parseInvite(ta.value);
  ta.classList.remove("valid", "invalid");
  if (r.ok) {
    ta.classList.add("valid");
    st.className = "status ok";
    st.textContent = "✓ 识别成功：设备「" + r.name + "」" + (r.hub ? " · 中继 " + r.hub : "");
    btn.disabled = false;
  } else {
    if (ta.value.trim()) ta.classList.add("invalid");
    st.className = "status err";
    st.textContent = r.msg || "";
    btn.disabled = true;
  }
}

function kindGroup(kind: string): string {
  if (kind === "request") return "cmd";
  if (kind === "peer-up" || kind === "peer-down" || kind === "peer") return "peer";
  if (kind === "connected" || kind === "disconnected" || kind === "disabled" || kind === "enabled" || kind === "connect" || kind === "state") return "relay";
  return "other";
}

function dayKey(t: number): string {
  if (!t) return "";
  const d = new Date(t);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return "今天";
  const y = new Date(today.getTime() - 86400000);
  if (d.toDateString() === y.toDateString()) return "昨天";
  return d.toLocaleDateString("zh-CN", { month: "long", day: "numeric" });
}

function renderEvents() {
  const box = $("#loglist");
  const devSel = $("#log-dev") as HTMLSelectElement | null;
  const cnt = $("#log-count");

  if (devSel) {
    const names = Array.from(new Set(events.map((e) => e.target).filter(Boolean)));
    const want = logDev;
    devSel.innerHTML = "";
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "全部设备";
    devSel.appendChild(all);
    for (const n of names) {
      const o = document.createElement("option");
      o.value = n;
      o.textContent = n;
      devSel.appendChild(o);
    }
    devSel.value = names.includes(want) ? want : "";
    logDev = devSel.value;
  }

  let list = events.filter((e) => !logDev || e.target === logDev);
  if (logKind) list = list.filter((e) => kindGroup(e.kind) === logKind);
  if (cnt) cnt.textContent = list.length ? list.length + " 条" : "";
  const total = list.length;
  if (list.length > shownLog) list = list.slice(list.length - shownLog);

  box.textContent = "";
  if (!list.length) {
    const d = document.createElement("div");
    d.className = "loading";
    d.textContent = events.length ? "没有符合筛选条件的记录" : "暂无记录";
    box.appendChild(d);
    const mb0 = $("#btn-more-log") as HTMLButtonElement | null;
    if (mb0) mb0.style.display = "none";
    return;
  }
  const frag = document.createDocumentFragment();
  let lastDay = "";
  for (const ev of [...list].reverse()) {
    const day = dayKey(ev.t);
    if (day && day !== lastDay) {
      const dd = document.createElement("div");
      dd.className = "day";
      dd.textContent = day;
      frag.appendChild(dd);
      lastDay = day;
    }
    const row = document.createElement("div");
    row.className = "ev";
    const time = document.createElement("span");
    time.className = "t";
    time.title = new Date(ev.t).toLocaleString("zh-CN", { hour12: false });
    time.textContent = new Date(ev.t).toLocaleTimeString("zh-CN", { hour12: false });
    row.appendChild(time);
    const kind = document.createElement("span");
    kind.className =
      "k " +
      (ev.kind === "error"
        ? "k-err"
        : ev.kind === "request" || ev.kind === "connected"
          ? "k-ok"
          : ev.kind === "state" || ev.kind === "connect" || ev.kind === "info"
            ? "k-info"
            : "k-warn");
    kind.textContent = ev.target || "系统";
    row.appendChild(kind);
    const msg = document.createElement("span");
    msg.className = "m";
    msg.textContent = ev.message;
    row.appendChild(msg);
    frag.appendChild(row);
  }
  box.appendChild(frag);
  const mb = $("#btn-more-log") as HTMLButtonElement | null;
  if (mb) mb.style.display = total > shownLog ? "" : "none";
}

function setSummary(targets: Target[]) {
  const online = targets.filter((t) => t.state === "online").length;
  const active = targets.filter((t) => t.state !== "off" && t.state !== "error").length;
  $("#summary").textContent = targets.length
    ? online + "/" + targets.length + " 在线" + (active !== online ? " · " + active + " 条连接" : "")
    : "未配置设备";
}

async function poll() {
  try {
    const st: StateResp = await api("/state?since=" + lastSeq);
    if (st.events && st.events.length) {
      for (const e of st.events) if (e.seq > lastSeq) lastSeq = e.seq;
      events = events.concat(st.events).slice(-200);
      // 只在日志页可见时重绘，避免在设备页时白白渲染上百行
      const logView = document.getElementById("view-log");
      if (logView && !logView.classList.contains("hidden")) renderEvents();
    }
    const nameEl = $("#myName") as HTMLInputElement | null;
    if (nameEl && document.activeElement !== nameEl && typeof st.clientName === "string" && st.clientName) {
      nameEl.value = st.clientName;
    }
    setBanner("");
    renderDevices(st.targets || []);
    setSummary(st.targets || []);
  } catch (e) {
    setBanner(friendly(e), true);
  }
}

async function act(fn: () => Promise<unknown>, okMsg?: string | (() => string)) {
  if (busy) {
    host.toast({ kind: "info", message: "正在处理上一条操作，请稍候" });
    return;
  }
  busy = true;
  try {
    await fn();
    const msg = typeof okMsg === "function" ? okMsg() : okMsg;
    if (msg) host.toast({ kind: "success", message: msg });
    await poll();
  } catch (e) {
    host.toast({ kind: "error", message: friendly(e) });
  } finally {
    busy = false;
  }
}

function switchTab(v: string) {
  document.querySelectorAll<HTMLButtonElement>("button.t2").forEach((x) => x.classList.toggle("active", x.dataset.v === v));
  for (const k of ["dev", "add", "log"]) {
    const el = document.getElementById("view-" + k);
    if (el) el.classList.toggle("hidden", k !== v);
  }
  if (v === "log") renderEvents();
}

function on(sel: string, fn: (el: HTMLElement) => void) {
  const el = $(sel);
  if (el) fn(el);
}

function bind() {
  devicesEl = $("#devices");
  on("#btn-refresh", (el) => {
    el.onclick = () => void poll();
  });
  on("#btn-save-name", (el) => {
    el.onclick = () => {
      const nameEl = $("#myName") as HTMLInputElement;
      void act(async () => {
        const r = await api("/client-name", "POST", { name: nameEl.value.trim() });
        if (r && r.name) nameEl.value = r.name;
      }, "已保存，正在用新名字重连");
    };
  });
  on("#btn-connect-all", (el) => {
    el.onclick = () => void act(async () => {
      await api("/connect-all", "POST", {});
    }, "已开始连接全部设备");
  });
  on("#btn-disconnect-all", (el) => {
    el.onclick = () => void act(async () => {
      await api("/disconnect-all", "POST", {});
    }, "已断开全部设备");
  });

  on("#code", (el) => {
    const ta = el as HTMLTextAreaElement;
    ta.addEventListener("input", validateAdd);
    ta.addEventListener("change", validateAdd);
  });
  on("#btn-paste", (el) => {
    el.onclick = async () => {
      let text = "";
      try {
        if (navigator.clipboard && navigator.clipboard.readText) text = await navigator.clipboard.readText();
      } catch {
        /* ignore */
      }
      if (!text) {
        host.toast({ kind: "error", message: "读不到剪贴板，请手动 Ctrl+V 粘贴" });
        return;
      }
      const ta = $("#code") as HTMLTextAreaElement;
      ta.value = text.trim();
      validateAdd();
      ta.focus();
    };
  });
  on("#btn-add", (el) => {
    el.onclick = () => {
      const ta = $("#code") as HTMLTextAreaElement;
      const r = parseInvite(ta.value);
      if (!r.ok) {
        const st = $("#add-status");
        st.className = "status err";
        st.textContent = r.msg || "请先粘贴邀请码";
        return;
      }
      void act(async () => {
        await api("/targets/add", "POST", { code: ta.value.trim() });
        ta.value = "";
        ta.classList.remove("valid", "invalid");
        const st = $("#add-status");
        st.className = "status ok";
        st.textContent = "✓ 已添加「" + r.name + "」";
        switchTab("dev");
      }, "已添加设备: " + r.name);
    };
  });

  on("#log-dev", (el) => {
    el.addEventListener("change", (ev) => {
      logDev = (ev.target as HTMLSelectElement).value;
      shownLog = 50;
      renderEvents();
    });
  });
  on("#log-kind", (el) => {
    el.addEventListener("change", (ev) => {
      logKind = (ev.target as HTMLSelectElement).value;
      shownLog = 50;
      renderEvents();
    });
  });
  on("#btn-more-log", (el) => {
    el.onclick = () => {
      shownLog += 50;
      renderEvents();
    };
  });

  document.querySelectorAll<HTMLButtonElement>("button.t2").forEach((b) => {
    b.addEventListener("click", () => switchTab(b.dataset.v || "dev"));
  });

  window.setInterval(() => {
    void poll();
  }, 1500);
}

host.onReady((ctx) => {
  applyHostReady(ctx, document.documentElement);
  try {
    bind();
  } catch (e) {
    setBanner("面板初始化出错：" + String(e), true);
  }
  void poll();
});
