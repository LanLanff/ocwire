// 自测3：验证 oc_edit / oc_grep / oc_glob 三个新操作。
import { connectAndRequest } from "./client.mjs";

const hub = process.argv[2] || "127.0.0.1:21122";
const key = process.argv[3];
if (!key) {
  console.error("用法: node selftest3.mjs <hub> <key>");
  process.exit(2);
}

const profile = { hub, key, insecure: true };
async function run(req) {
  try {
    const r = await connectAndRequest(profile, req, { timeoutMs: 30000 });
    console.log("OP " + req.op + " => " + JSON.stringify(r).slice(0, 400));
  } catch (e) {
    console.log("OP " + req.op + " => ERROR " + e.message);
  }
}

await run({
  op: "write",
  id: "w",
  path: "D:\\item\\oc-link\\data\\edit-test.txt",
  dataB64: Buffer.from("hello alpha\nhello beta\ngamma\n", "utf8").toString("base64"),
  createDirs: true,
});
await run({ op: "grep", id: "g", pattern: "hello", path: "D:\\item\\oc-link\\data" });
await run({ op: "glob", id: "l", pattern: "*.txt", path: "D:\\item\\oc-link\\data" });
await run({ op: "edit", id: "e", path: "D:\\item\\oc-link\\data\\edit-test.txt", oldString: "hello alpha", newString: "HELLO ALPHA" });
await run({ op: "edit", id: "e2", path: "D:\\item\\oc-link\\data\\edit-test.txt", oldString: "hello", newString: "hi" });
await run({ op: "edit", id: "e3", path: "D:\\item\\oc-link\\data\\edit-test.txt", oldString: "hello", newString: "hi", replaceAll: true });
await run({ op: "read", id: "r", path: "D:\\item\\oc-link\\data\\edit-test.txt" });
