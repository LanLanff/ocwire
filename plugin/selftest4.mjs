// 自测4：验证命令超时 + 进程树清理（跑一个 30 秒的 ping，设 2 秒超时）。
import { connectAndRequest } from "./client.mjs";

const hub = process.argv[2] || "127.0.0.1:21122";
const key = process.argv[3];
if (!key) {
  console.error("用法: node selftest4.mjs <hub> <key>");
  process.exit(2);
}

const t0 = Date.now();
const r = await connectAndRequest(
  { hub, key, insecure: true },
  { op: "exec", id: "t", cmd: "ping -n 30 127.0.0.1", timeoutMs: 2000 },
  { timeoutMs: 20000 }
);
console.log("elapsed_ms=" + (Date.now() - t0));
console.log(JSON.stringify(r).slice(0, 300));
