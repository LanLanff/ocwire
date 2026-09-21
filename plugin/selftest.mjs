// 自测：用 Node 直接跑 A 端核心，验证与 Go 端（中继+agent）的加密互通。
// 用法： node selftest.mjs 127.0.0.1:21122 "OCL-...."
import { connectAndRequest } from "./client.mjs";

const hub = process.argv[2] || "127.0.0.1:21122";
const key = process.argv[3];
if (!key) {
  console.error("用法: node selftest.mjs <hub> <key>");
  process.exit(2);
}

const profile = { hub, key, insecure: true };
const resp = await connectAndRequest(profile, { op: "exec", id: "1", cmd: "echo hi-from-node" }, { timeoutMs: 25000 });
console.log(JSON.stringify(resp, null, 2));
