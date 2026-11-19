// Proof Gatekeeper agent server — zkVerify Agent Games
// Node.js stdlib only (+ snarkjs for local Groth16 proving).
// No frameworks. Secrets ONLY from env vars. Never log secrets.
//
// REDIS PATCH (2026-11-17, see REDIS_PATCH_NOTES.md): the proof_tx
// seen-set is ALSO kept in Upstash Redis (REST API, no new dependency —
// plain global fetch), because seen.json on Railway's ephemeral disk is
// wiped on every redeploy (R04: seen_proof_refs 10 -> 2 after the 04:00 WIB
// Kurier redeploy). Redis is the durable source of truth; the local file +
// in-memory Set stay as cache + fallback. A Redis outage must NEVER fail a
// task: every Redis call has a 2s timeout and falls back to the local set.
//
// Protocol sources (public, 15 Nov 2026):
//   https://agentgames.zkverify.io/build
//   https://agentgames.zkverify.io/events/proof-gatekeeper
//   https://agentgames.zkverify.io/api/circuit-info
// See ../notes/GATEKEEPER_BUILD.md for the full spec + open questions.
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const snarkjs = require('snarkjs');

// ---------------------------------------------------------------- config
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM_PATH = process.env.GATEKEEPER_WASM || path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = process.env.GATEKEEPER_ZKEY || path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = process.env.GATEKEEPER_VK || path.join(__dirname, 'circuits', 'vk.json');
const SEEN_PATH = process.env.GATEKEEPER_SEEN_FILE || path.join(__dirname, 'seen.json');
const DECISIONS_PATH = process.env.GATEKEEPER_DECISIONS_FILE || path.join(__dirname, 'decisions.json');
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const KURIER_URL = process.env.KURIER_URL || 'https://api.kurier.xyz/api/v1';
const VK_HASH = process.env.GATEKEEPER_VK_HASH || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
// BN128 scalar field modulus (for encoding 256-bit hashes as field elements).
const FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const PROOF_TIMEOUT_MS = parseInt(process.env.GATEKEEPER_PROOF_TIMEOUT_MS || '45000', 10);

// ---------------------------------------------------------------- Redis
// Persistent seen-set via Upstash Redis REST (free tier). Enabled only when
// BOTH UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are set.
// Key: "seen-proof-tx" (a SET). Protocol is the Upstash REST command
// format, same as hi5's reference implementation: POST the base URL with a
// JSON body ["SISMEMBER"|"SADD"|"SCARD", "seen-proof-tx", member?]
// and `Authorization: Bearer <token>`. No new npm dependency.
// GATEKEEPER_REDIS_BACKFILL=1 enables the one-time guarded seed below;
// GATEKEEPER_SEEN_EXPORT=1 enables the guarded GET /seen snapshot endpoint.
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '');
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REDIS_ENABLED = Boolean(REDIS_URL && REDIS_TOKEN);
const REDIS_KEY = 'seen-proof-tx';
const REDIS_TIMEOUT_MS = 2000;
// Cached SCARD result (null = unknown / not yet fetched). /health reports
// this alongside the local count; it is refreshed at startup and bumped on
// each successful SADD. It is a cache, never a decision input.
let redisSeenCount = null;

if (!HMAC_SECRET) {
  console.warn('[gatekeeper] WARNING: AGENT_GAMES_HMAC_SECRET is not set. ' +
    'Inbound HMAC verification and response signing are DISABLED until it is set. ' +
    'Set it from the dashboard (Rotate Secret) and restart. Do NOT use a placeholder in production.');
}

// ---------------------------------------------------------------- state
function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJson(file, obj) {
  try { fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n'); } catch (e) { console.error('[gatekeeper] save failed', file, e.message); }
}
// proof_tx values already decided (reuse detection). Persisted across restarts.
const seenProofTx = new Set(loadJson(SEEN_PATH, []));
// task_id -> last signed response body (idempotency: same task retried returns same decision).
const decisionsByTask = loadJson(DECISIONS_PATH, {});

let vk = null;
try { vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8')); } catch (e) { console.warn('[gatekeeper] vk.json not found, local proof verification disabled:', e.message); }

// ------------------------------------------------- Redis seen-set helpers
// Every helper is non-fatal by design: on any error/timeout it logs a
// warning and the caller proceeds on the local set. Redis must never fail
// a task (the decision matters more than the reuse record).
function redisSignal() {
  // AbortSignal.timeout exists on Node >= 18; keep a manual fallback so
  // the server still works on older runtimes.
  if (typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(REDIS_TIMEOUT_MS);
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), REDIS_TIMEOUT_MS);
  return ctrl.signal;
}

async function redisCall(command, member) {
  const body = member === undefined ? [command, REDIS_KEY] : [command, REDIS_KEY, member];
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: redisSignal(),
  });
  if (!res.ok) throw new Error(`Redis HTTP ${res.status}`);
  const data = await res.json();
  if (data && data.error) throw new Error(`Redis error: ${data.error}`);
  return data ? data.result : undefined;
}

// Returns true/false when Redis answers, null when Redis is off / fails /
// times out (caller then uses the local set).
async function redisIsMember(proofTx) {
  if (!REDIS_ENABLED) return null;
  try {
    const result = await redisCall('SISMEMBER', proofTx);
    return result === 1 || result === '1';
  } catch (e) {
    console.warn('[gatekeeper] WARN: Redis SISMEMBER failed, using local seen-set:', e.message);
    return null;
  }
}

// Fire-and-forget record. Returns true on success, false otherwise; never
// throws. Callers MUST NOT await this before answering the task.
async function redisAdd(proofTx) {
  if (!REDIS_ENABLED) return false;
  try {
    await redisCall('SADD', proofTx);
    if (redisSeenCount !== null) redisSeenCount += 1;
    return true;
  } catch (e) {
    console.warn('[gatekeeper] WARN: Redis SADD failed, proof_tx recorded locally only:', e.message);
    return false;
  }
}

async function redisCount() {
  if (!REDIS_ENABLED) return null;
  try {
    const result = await redisCall('SCARD');
    const n = Number(result);
    return Number.isFinite(n) ? n : null;
  } catch (e) {
    console.warn('[gatekeeper] WARN: Redis SCARD failed:', e.message);
    return null;
  }
}

// Dummy-test-data guard. The repo's seen.json holds only placeholder values
// (0xad1aaa..., 0x1aaa..., 0xede1aaa... — long runs of 'a'). Real
// proof_tx values are (pseudo-)random hex; 10+ consecutive 'a's in one
// is effectively impossible. Never seed Redis with placeholders.
function isDummyProofTx(v) {
  if (typeof v !== 'string') return true;
  const hex = v.replace(/^0x/, '');
  if (!/^0x[0-9a-fA-F]+$/.test(v)) return true;
  if (/a{10,}/i.test(hex)) return true;
  const aCount = (hex.match(/a/gi) || []).length;
  return hex.length > 0 && aCount / hex.length > 0.5;
}

// One-time guarded backfill. Runs ONLY when GATEKEEPER_REDIS_BACKFILL=1.
// - If Redis already has members (SCARD > 0): do nothing. Redis wins.
// - If Redis is empty: SADD each non-dummy entry of the LOCAL file.
//   On Railway the file baked into the image comes from git, and seen.json
//   is gitignored, so this normally seeds NOTHING there — that is the safe
//   behaviour. It only seeds something when an operator has deliberately
//   placed a real snapshot file next to the server before starting it.
// - Proof_tx values lost in earlier redeploys (all of R04) CANNOT be
//   recovered by this function. See REDIS_PATCH_NOTES.md.
async function maybeBackfillRedisFromLocal() {
  if (!REDIS_ENABLED || process.env.GATEKEEPER_REDIS_BACKFILL !== '1') return;
  try {
    const count = await redisCount();
    if (count === null) { console.warn('[gatekeeper] backfill skipped: Redis SCARD unreadable'); return; }
    if (count > 0) { console.log(`[gatekeeper] backfill skipped: Redis already has ${count} members`); return; }
    const local = loadJson(SEEN_PATH, []);
    const valid = (Array.isArray(local) ? local : []).filter((x) => !isDummyProofTx(x));
    const skipped = (Array.isArray(local) ? local.length : 0) - valid.length;
    if (valid.length === 0) { console.log(`[gatekeeper] backfill skipped: no valid local entries (skipped ${skipped} dummy)`); return; }
    let added = 0;
    for (const member of valid) { if (await redisAdd(member)) added += 1; }
    console.log(`[gatekeeper] backfill done: seeded ${added}/${valid.length} local entries to Redis (skipped ${skipped} dummy)`);
    redisSeenCount = await redisCount();
  } catch (e) {
    console.warn('[gatekeeper] backfill failed (non-fatal):', e.message);
  }
}

// Startup refresh: fetch SCARD once (fire-and-forget) + optional backfill.
// Neither blocks listen().
if (REDIS_ENABLED) {
  redisCount().then((n) => { if (n !== null) redisSeenCount = n; });
  maybeBackfillRedisFromLocal();
}

// ---------------------------------------------------------------- HMAC
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
// Header format is not spelled out in the public docs; accept raw hex and
// an optional "sha256=" prefix, in hex or base64. Comparison is timing-safe.
function verifySignature(rawBody, header) {
  if (!HMAC_SECRET) return false;
  if (!header) return false;
  let sig = String(header).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const digest = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest();
  const expectedHex = digest.toString('hex');
  const expectedB64 = digest.toString('base64');
  const a = Buffer.from(sig, 'utf8');
  for (const expected of [expectedHex, expectedB64]) {
    const b = Buffer.from(expected, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
function signBody(rawBody) {
  if (!HMAC_SECRET) return '';
  return hmacHex(HMAC_SECRET, rawBody);
}

// ---------------------------------------------------------------- helpers
function normAddr(s) {
  return String(s || '').trim().toLowerCase().replace(/^0x/, '');
}
function normHash(s) {
  return String(s || '').trim().toLowerCase();
}
function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  const s = String(v).trim();
  if (/^0x/i.test(s)) return BigInt(s);
  return BigInt(s);
}
// task_id like "gk_24_9d1" is a string; the circuit takes a field element.
// Encoding (GUESS — see GATEKEEPER_BUILD.md open questions): UTF-8 bytes
// as one big-endian integer. Short ids fit in the field; long ones wrap mod p.
// DEPRECATED 19 Nov 2026: this encoding NEVER matched what the platform
// expects for public signal [12] (taskId) — every correct task scored +10
// (platform proof_failure, 0 verified, R04–R06). Kept for reference/tests;
// buildCircuitInput now uses taskIdField() below.
function taskIdToField(taskId) {
  const bytes = Buffer.from(String(taskId || ''), 'utf8');
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return (n % FIELD_MODULUS).toString();
}
function sha256Hex(str) {
  return '0x' + crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}
// 19 Nov 2026 — taskId encoding FIX (from hi5, verified against his live
// repo commit 599aeff + the reference implementation's public-signal layout
// [0]=commitment(taskId,salt) … [12]=taskId):
// The platform binds the proof to the task via public signal [12] and
// expects BigInt of the task UUID hex (dashes stripped). Platform task ids
// look like "task_R06_0b566b18-6031-b1ff-ce22-b7bf6b3494b3" — the UUID is
// embedded after the "task_R06_" prefix, so match() finds it anywhere in
// the string. A UUID is 128 bits, FIELD_P ~254 bits, so it fits exactly
// (no mod wrap). This mirrors how the Steal circuit treats matchId (bytes32).
// hi5's live proof: keccak256 and sha256 of the full task_id were BOTH
// disproven live (R06 task 2, 19:54 WIB, +10 again); after switching to
// UUID-BigInt live 21:16 WIB, his R06 tasks 4–7 all scored +12 FULL and
// verified proof went 0 -> 4. Salt is UNCHANGED (random per proof, same as
// the reference implementation's freshSalt()) — salt is a private input
// hidden inside the commitment, so only the taskId encoding matters.
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
function taskIdField(taskId) {
  const m = String(taskId).match(UUID_RE);
  if (m) return BigInt('0x' + m[0].replace(/-/g, '')).toString();
  return (BigInt(sha256Hex(taskId)) % FIELD_MODULUS).toString(); // non-UUID (practice/probe)
}
function addrToField(addr) {
  const n = BigInt('0x' + (normAddr(addr) || '0'));
  return (n % FIELD_MODULUS).toString();
}
// vk hashes are 256-bit hex and can exceed the BN128 scalar field, so reduce
// mod p. Equality is preserved (same hash -> same field element), which is
// all the circuit's vk check needs.
function vkHashToField(hex) {
  const n = BigInt('0x' + normHash(hex).replace(/^0x/, ''));
  return (n % FIELD_MODULUS).toString();
}

// ---------------------------------------------------------------- decision
// Trap-check order follows the order the traps are listed on
// /events/proof-gatekeeper (VK, THRESHOLD, REUSED, EXPIRED, RECIPIENT, AMOUNT).
// Order only matters when a task carries several traps at once; the platform
// does not document a priority, so this is an assumption.
function decide(input) {
  const registeredVk = normHash(input.registered_vk);
  const proofVk = normHash(input.proof_vk);
  const minimum = toBigInt(input.minimum);
  const balance = toBigInt(input.public_balance);
  const amount = toBigInt(input.amount);
  const maxTransfer = toBigInt(input.max_transfer);
  const expiryBlock = toBigInt(input.expiry_block);
  const currentBlock = toBigInt(input.current_block);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const proofTx = normHash(input.proof_tx || '');

  if (registeredVk && proofVk && registeredVk !== proofVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proofTx };
  }
  if (balance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proofTx };
  }
  if (proofTx && seenProofTx.has(proofTx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proofTx };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proofTx };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', proofTx };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', proofTx };
  }
  // Advisory only (logged, not a rejection): the registered key in the
  // envelope differs from the platform's published vkHash. The spec's trap
  // definition is proof_vk != registered_vk, so this alone does not reject
  // — but it is suspicious and worth seeing in logs. (Adopted from hi5's
  // gatekeeper-core.js after the 15 Nov comparison; see notes/HI5_COMPARISON.md.)
  if (registeredVk !== VK_HASH) {
    console.warn(`[gatekeeper] WARN: registered_vk differs from platform vkHash`);
  }

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proofTx };
}

// Async wrapper: identical checks, except the PROOF_REUSED trap also
// consults Redis (the durable source of truth) when the local set does
// not already contain the proof_tx.
//
// Implementation note: the sync decide() above is the single source of
// trap ORDER (VK -> THRESHOLD -> REUSED(local) -> EXPIRED -> RECIPIENT ->
// AMOUNT). decideAsync reuses it verbatim:
//  - if decide() already REJECTs (any trap, incl. local REUSED), that
//    verdict stands — no Redis call is needed, because the first failing
//    trap in order decides the reason_code;
//  - only on a local APPROVE (all circuit-visible checks pass) do we ask
//    Redis. A Redis hit flips the verdict to REJECT/PROOF_REUSED.
//  - Redis unknown (off / error / timeout) keeps the local APPROVE —
//    Redis must never fail a task.
async function decideAsync(input) {
  const local = decide(input);
  if (local.decision === 'REJECT') return local;
  const proofTx = normHash(input.proof_tx || '');
  if (!proofTx) return local;
  const inRedis = await redisIsMember(proofTx);
  if (inRedis === true) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proofTx };
  }
  return local;
}

// ---------------------------------------------------------------- proof
// Circuit inputs (recovered from gatekeeper.wasm via FNV-hash probing):
//   publicBalance, minimum, recipient, conditionRecipient, amount,
//   maxTransfer, expiryBlock, currentBlock, decision, taskId, salt,
//   registeredVkHash, proofVkHash   (13 inputs; VK nPublic = 13)
// The circuit constrains decision to the correct evaluation of the checks
// (verified locally: decision=1 with a failing check does NOT prove — see
// notes/GATEKEEPER_BUILD.md). So a proof with decision=0 is the proof of a
// correct REJECT, and decision=1 the proof of a correct APPROVE.
function buildCircuitInput(task, result) {
  const input = task.input;
  return {
    publicBalance: toBigInt(input.public_balance).toString(),
    minimum: toBigInt(input.minimum).toString(),
    recipient: addrToField(input.recipient),
    conditionRecipient: addrToField(input.condition_recipient),
    amount: toBigInt(input.amount).toString(),
    maxTransfer: toBigInt(input.max_transfer).toString(),
    expiryBlock: toBigInt(input.expiry_block).toString(),
    currentBlock: toBigInt(input.current_block).toString(),
    decision: result.decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdField(task.task_id), // 19 Nov 2026: UUID-BigInt (was taskIdToField UTF-8 — never matched platform signal [12])
    salt: BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString(),
    registeredVkHash: vkHashToField(input.registered_vk),
    proofVkHash: vkHashToField(input.proof_vk),
  };
}

async function generateProof(task, result) {
  const circuitInput = buildCircuitInput(task, result);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  if (vk) {
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!ok) throw new Error('local proof verification failed');
  }
  return { proof, public_signals: publicSignals };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out after ' + ms + 'ms')), ms);
  });
  return Promise.race([promise.finally(() => clearTimeout(timer)), timeout]);
}

// Kurier submission — REQUIRED for scored proofs to count as verified.
// The platform scores -2 "proof_failure" per task when the proof is not
// confirmed on-chain (observed R04: 0/2 verified, hi5 identical despite a
// different encoding; top agents with Kurier verify). Requires KURIER_API_KEY
// (mainnet, free). Awaited with a bounded budget inside the 60s task
// deadline: submit the proof, poll job-status until Finalized, and return
// the on-chain tx hash to use as response.proof_tx. Any failure returns
// null (non-fatal) and the caller keeps the platform's input proof_tx echo.
const KURIER_TIMEOUT_MS = parseInt(process.env.KURIER_TIMEOUT_MS || '40000', 10);
const KURIER_POLL_MS = 3000;

async function kurierSubmitOnce(proof, publicSignals, vkRegistered) {
  const body = {
    proofType: 'groth16',
    vkRegistered,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: { proof, publicSignals, vk: vkRegistered ? VK_HASH : vk },
  };
  const res = await fetch(`${KURIER_URL}/submit-proof/${KURIER_API_KEY}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error('kurier submit HTTP ' + res.status);
  const job = await res.json();
  return job.jobId || job.job_id || job.id || null;
}

async function kurierPoll(jobId, deadlineMs) {
  while (Date.now() < deadlineMs) {
    const res = await fetch(`${KURIER_URL}/job-status/${KURIER_API_KEY}/${jobId}`);
    if (res.ok) {
      const st = await res.json();
      const status = String(st.status || st.state || '').toLowerCase();
      if (status === 'finalized' || status === 'success' || status === 'verified') {
        return st.txHash || st.tx_hash || st.transactionHash || st.proofTx || null;
      }
      if (status === 'failed' || status === 'error' || status === 'rejected') {
        throw new Error('kurier job ' + status);
      }
    }
    await new Promise((r) => setTimeout(r, KURIER_POLL_MS));
  }
  throw new Error('kurier poll timed out');
}

async function submitToKurier(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadlineMs = Date.now() + Math.max(0, budgetMs);
  try {
    let jobId = null;
    try {
      jobId = await kurierSubmitOnce(proof, publicSignals, true);
    } catch (e) {
      // Fallback (redsparksz pattern): retry with the full vk inline.
      if (!vk) throw e;
      console.warn('[gatekeeper] kurier submit vkRegistered:true failed, retrying with full vk:', e.message);
      jobId = await kurierSubmitOnce(proof, publicSignals, false);
    }
    if (!jobId) throw new Error('kurier submit returned no jobId');
    const txHash = await kurierPoll(jobId, deadlineMs);
    if (txHash) console.log('[gatekeeper] kurier Finalized, txHash:', txHash);
    return txHash || null;
  } catch (e) {
    console.error('[gatekeeper] kurier failed (non-fatal, keeping echo proof_tx):', e.message);
    return null;
  }
}

// ---------------------------------------------------------------- HTTP
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => {
      chunks.push(c);
      if (Buffer.concat(chunks).length > 1024 * 1024) { req.destroy(); reject(new Error('body too large')); }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(req, res, rawBody) {
  // 1. Verify HMAC on the RAW body BEFORE parsing.
  if (!verifySignature(rawBody, req.headers['x-agent-games-signature'])) {
    console.warn('[gatekeeper] bad/missing HMAC signature');
    return sendJson(res, 401, { error: 'invalid signature' });
  }
  let task;
  try { task = JSON.parse(rawBody.toString('utf8')); }
  catch { return sendJson(res, 400, { error: 'invalid json' }); }

  // 2. Preflight handshake.
  if (task.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }
  if (task.type && task.type !== 'agent-games.proof-gatekeeper.v1') {
    return sendJson(res, 400, { error: 'unknown task type' });
  }
  if (!task.input || !task.task_id) {
    return sendJson(res, 400, { error: 'missing task_id/input' });
  }

  // 3. Idempotency: same task_id retried -> same signed response.
  if (decisionsByTask[task.task_id]) {
    const cached = decisionsByTask[task.task_id];
    const body = Buffer.from(JSON.stringify(cached));
    const headers = { 'content-type': 'application/json', 'content-length': body.length };
    if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(body);
    res.writeHead(200, headers);
    return res.end(body);
  }

  // 4. Deterministic decision (fail closed: any error -> REJECT).
  // Past-deadline tasks fail closed as EXPIRED_CONDITION before any
  // proving is attempted on a late answer. (Adopted from hi5's
  // gatekeeper-core.js after the 15 Nov comparison; see notes/HI5_COMPARISON.md.)
  let result;
  if (task.deadline_at) {
    const deadlineMs = Date.parse(task.deadline_at);
    if (!Number.isNaN(deadlineMs) && Date.now() > deadlineMs) {
      console.warn(`[gatekeeper] ${task.task_id}: past deadline_at, fail closed`);
      result = { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proofTx: normHash(task.input.proof_tx || '') };
    }
  }
  if (!result) {
    try {
      result = await decideAsync(task.input);
    } catch (e) {
      console.error('[gatekeeper] decide error (fail closed):', e.message);
      result = { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proofTx: normHash(task.input.proof_tx || '') };
    }
  }

  // 5. Proof. PROOF_REUSED tasks have no proof to submit (platform scoring
  // note) and are excluded from the reliability bonus — omit proof there.
  // Every other task gets a local Groth16 proof; if proving fails or times
  // out we still return the decision (a -2 proof penalty beats a -2 timeout
  // plus a wrong/missing decision).
  const response = { decision: result.decision, reason_code: result.reason_code };
  if (task.input.proof_tx) response.proof_tx = task.input.proof_tx;
  if (result.reason_code !== 'PROOF_REUSED') {
    try {
      const t0 = Date.now();
      const { proof, public_signals } = await withTimeout(
        generateProof(task, result), PROOF_TIMEOUT_MS, 'proof generation');
      response.proof = proof;
      response.public_signals = public_signals;
      console.log(`[gatekeeper] ${task.task_id} ${result.decision}/${result.reason_code} proof ok in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
      // Kurier: submit + wait for Finalized (bounded by the task deadline),
      // then use the on-chain tx hash as proof_tx so the platform counts
      // the proof as verified. On any failure keep the echo proof_tx.
      const deadlineMs = task.deadline_at ? Date.parse(task.deadline_at) : 0;
      let kurierBudget = KURIER_TIMEOUT_MS;
      if (deadlineMs) kurierBudget = Math.min(kurierBudget, deadlineMs - Date.now() - 5000);
      if (kurierBudget > 0) {
        const txHash = await submitToKurier(proof, public_signals, kurierBudget);
        if (txHash) response.proof_tx = txHash;
      }
    } catch (e) {
      console.error(`[gatekeeper] ${task.task_id} proof FAILED (decision still returned):`, e.message);
    }
  } else {
    console.log(`[gatekeeper] ${task.task_id} REJECT/PROOF_REUSED (no proof attached)`);
  }

  // 6. Record proof_tx as seen + cache decision by task_id (persisted).
  // Local set first (unchanged), then Redis — fire-and-forget, NEVER
  // awaited before answering. redisAdd() never throws.
  // NOTE: only the INPUT proof_tx is recorded. The Kurier txHash that may
  // replace response.proof_tx is our own submission hash, never a platform
  // input, so it must NOT enter the seen-set.
  if (result.proofTx) {
    seenProofTx.add(result.proofTx);
    saveJson(SEEN_PATH, [...seenProofTx]);
    void redisAdd(result.proofTx);
  }
  decisionsByTask[task.task_id] = response;
  saveJson(DECISIONS_PATH, decisionsByTask);

  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/agent')) {
      // GET on the registered path too: the dashboard health check may probe
      // the registered URL itself rather than /health.
      return sendJson(res, 200, {
        ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1',
        uptime_s: Math.floor(process.uptime()),
        hmac_configured: Boolean(HMAC_SECRET),
        kurier_configured: Boolean(KURIER_API_KEY),
        seen_proof_refs: seenProofTx.size,
        redis_configured: REDIS_ENABLED,
        redis_seen_count: redisSeenCount,
      });
    }
    // GET /seen — snapshot of the live seen-set, for taking a backfill
    // snapshot BEFORE a future redeploy. Disabled unless
    // GATEKEEPER_SEEN_EXPORT=1, and requires the HMAC secret in the
    // x-admin-secret header (same secret as the dashboard, never logged).
    // Keep it OFF in normal operation; enable only in the gap, snapshot,
    // then disable again. It intentionally does NOT exist on the current
    // live server, so it cannot recover the set that is already live.
    if (req.method === 'GET' && url.pathname === '/seen') {
      if (process.env.GATEKEEPER_SEEN_EXPORT !== '1' || !HMAC_SECRET ||
          req.headers['x-admin-secret'] !== HMAC_SECRET) {
        return sendJson(res, 404, { error: 'not found' });
      }
      return sendJson(res, 200, {
        ok: true, count: seenProofTx.size,
        redis_configured: REDIS_ENABLED, redis_seen_count: redisSeenCount,
        proof_tx: [...seenProofTx],
      });
    }
    if (req.method === 'POST' && (url.pathname === '/agent' || url.pathname === '/')) {
      const rawBody = await readRawBody(req);
      return handleTask(req, res, rawBody);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[gatekeeper] handler error:', e.message);
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[gatekeeper] listening on http://${HOST}:${PORT} (POST /agent, GET /health)`);
    console.log(`[gatekeeper] hmac_configured=${Boolean(HMAC_SECRET)} kurier_configured=${Boolean(KURIER_API_KEY)} redis_configured=${REDIS_ENABLED} seen_local=${seenProofTx.size} redis_seen_count=${redisSeenCount}`);
  });
}

module.exports = { server, decide, decideAsync, verifySignature, hmacHex, taskIdToField, taskIdField, sha256Hex, addrToField, vkHashToField, buildCircuitInput, redisIsMember, redisAdd, isDummyProofTx, REDIS_ENABLED, REDIS_KEY };
