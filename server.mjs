import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "";
const PORT = process.env.PORT ?? 3000;
const SEEN_FILE = new URL("./seen.json", import.meta.url);
const sign = (s) => crypto.createHmac("sha256", SECRET).update(s).digest("hex");

// proof_tx -> task_id pertama yang memakainya
let seen = {};
try { seen = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8")); } catch {}
const saveSeen = () => {
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify(seen)); }
  catch (e) { console.error("seen save failed:", e.message); }
};

const big = (v) => { try { return BigInt(String(v)); } catch { return null; } };
const norm = (v) => String(v ?? "").trim().toLowerCase();

function decide(i, taskId) {
  i = i ?? {};
  const bal = big(i.public_balance), min = big(i.minimum);
  const amt = big(i.amount), cap = big(i.max_transfer);
  const exp = big(i.expiry_block), cur = big(i.current_block);
  const ref = norm(i.proof_tx);

  if ([bal, min, amt, cap, exp, cur].includes(null) || !ref ||
      !i.registered_vk || !i.proof_vk || !i.recipient || !i.condition_recipient)
    return { decision: "REJECT", reason_code: "MALFORMED_INPUT" };

  const prior = seen[ref];
  let out;
  if (norm(i.proof_vk) !== norm(i.registered_vk)) out = ["REJECT", "VK_SUBSTITUTION"];
  else if (prior && prior !== taskId) out = ["REJECT", "PROOF_REUSED"];
  else if (cur > exp) out = ["REJECT", "EXPIRED_CONDITION"];
  else if (norm(i.recipient) !== norm(i.condition_recipient)) out = ["REJECT", "RECIPIENT_MISMATCH"];
  else if (amt > cap) out = ["REJECT", "AMOUNT_OVERFLOW"];
  else if (bal < min) out = ["REJECT", "THRESHOLD_MISMATCH"];
  else out = ["APPROVE", "VALID_CONDITION"];

  if (!prior) { seen[ref] = taskId; saveSeen(); }
  return { decision: out[0], reason_code: out[1], proof_tx: i.proof_tx };
}

http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/agent") { res.writeHead(404); return res.end(); }
  const chunks = []; let size = 0;
  req.on("data", (c) => { size += c.length; if (size > 1e6) req.destroy(); else chunks.push(c); });
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8");
    let task;
    try { task = JSON.parse(raw); } catch { res.writeHead(400); return res.end(); }

    // Cek signature request: hanya dicatat dulu, belum menolak
    const got = req.headers["x-agent-games-signature"];
    if (got) console.log("req-signature:", got === sign(raw) ? "match" : "MISMATCH");

    let out;
    if (task.type === "agent-games.preflight.v1") out = { ok: true, protocolVersion: "v1" };
    else if (task.type === "agent-games.proof-gatekeeper.v1") out = decide(task.input, task.task_id);
    else out = { decision: "REJECT", reason_code: "UNSUPPORTED_TASK" };

    console.log(new Date().toISOString(), task.type, task.task_id ?? "", out.decision ?? "", out.reason_code ?? "");
    const body = JSON.stringify(out);
    res.writeHead(200, { "content-type": "application/json", "x-agent-games-signature": sign(body) });
    res.end(body);
  });
}).listen(PORT, "127.0.0.1", () => console.log("listening on", PORT));
