// 自测2：并发两次调用，验证客户端串行队列（不应互相顶掉）。
import { connectAndRequest } from "./client.mjs";

const hub = process.argv[2] || "127.0.0.1:21122";
const key = process.argv[3];
if (!key) {
  console.error("用法: node selftest2.mjs <hub> <key>");
  process.exit(2);
}

const profile = { hub, key, insecure: true };
const rs = await Promise.all([
  connectAndRequest(profile, { op: "exec", id: "a", cmd: "echo one" }, { timeoutMs: 30000 }),
  connectAndRequest(profile, { op: "exec", id: "b", cmd: "echo two" }, { timeoutMs: 30000 }),
]);
console.log(JSON.stringify(rs.map((r) => ({ id: r.id, ok: r.ok, out: (r.stdout || "").trim() })), null, 2));
