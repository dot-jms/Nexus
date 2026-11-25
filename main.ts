// Nexus WebSocket relay — Deno Deploy
// Server-side auth via Deno KV. Accounts persist across restarts.
// Puck is the platform admin. Co-admins can be appointed by Puck.

// ─── Deploy version — changes on every new deploy ───────────────────────────
// Deno Deploy re-runs this file fresh on each deploy, so Date.now() at module
// load time gives a unique version per deployment automatically.
// DEPLOY_VERSION: stable across cold starts — only changes when code actually changes.
// Using a fixed string that you manually bump on real deploys, NOT Date.now() which
// changes every cold start and triggers spurious client reloads on Deno Deploy free tier.
const DEPLOY_VERSION = "v1";
console.log(`[nexus] deploy version: ${DEPLOY_VERSION}`);
// Bumped whenever the client and server must change together. The client compares this on every connect and
// warns if the server it talks to is older than it needs (a stale deploy looks fine until you refresh).
const PROTOCOL = 7;
console.log(`[nexus] server protocol v${PROTOCOL}`);

// ─── KV setup ───────────────────────────────────────────────────────────────
const kv = await Deno.openKv();

// Seed Puck admin account if not already present
const puckKey = ["accounts", "puck"];
const puckEntry = await kv.get(puckKey);
const PUCK_PW = Deno.env.get("PUCK_PASSWORD") ?? crypto.randomUUID().slice(0, 12);
if (!puckEntry.value) {
  await kv.set(puckKey, {
    name: "Puck",
    tag: "0001",
    color: "#6c63ff",
    pfp: null,
    passwordHash: await hashPw(PUCK_PW),
    systemRole: "admin",
    coAdmin: false,
    createdAt: Date.now(),
  });
  console.log(Deno.env.get("PUCK_PASSWORD") ? "Seeded Puck admin account (password from PUCK_PASSWORD)" : `Seeded Puck admin account. One-time password: ${PUCK_PW} — change it now.`);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// FIX #2: Replaced weak djb2 hash with SHA-256 via Web Crypto.
// hashPwLegacy kept to transparently migrate existing accounts on next login.
function hashPwLegacy(pw: string): string {
  let h = 5381;
  for (let i = 0; i < pw.length; i++) {
    h = (((h << 5) + h) + pw.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

async function hashPw(pw: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(pw),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function genToken(): string {
  return crypto.randomUUID().replace(/-/g, "") + Date.now().toString(36);
}

// Active sessions: token → lowercase username
const sessions = new Map<string, string>();
// clients: ws → { name, tag, color, pfp, token, systemRole, coAdmin }
const clients = new Map<WebSocket, Record<string, unknown>>();
const publicServers = new Map<string, Record<string, unknown>>();
const msgHistory = new Map<string, unknown[]>();
const offline = new Map<string, unknown[]>();
// timed bans: lowercase username → { until: number, reason: string }
// FIX #3: timedBans is now the in-memory cache; source of truth is KV ["bans", username]
const timedBans = new Map<string, { until: number; reason: string }>();
// frozen users: lowercase username → { reason: string, by: string, at: number }
// Frozen users can connect and read but cannot send messages anywhere
const frozenUsers = new Map<string, { reason: string; by: string; at: number }>();
// channel locks cache: channelId → { locked: boolean, by: string }
const channelLocks = new Map<string, { locked: boolean; by: string }>();
// per-channel slowmode: channelId → seconds between posts
const slowmodes = new Map<string, number>();
// per-user last-post timestamp for slowmode enforcement: "chId:username" → timestamp
const slowmodeLastPost = new Map<string, number>();
// active DM voice calls: callId → { participants: Set<string>, startedAt: number }
interface CallRec {
  id: string;
  participants: Set<string>;            // display names currently IN the call (also used by the admin ghost tools)
  startedAt: number;
  conv: string | null;                  // "dm:a:b" or "g:<gid>"
  gid: string | null;
  starter: string; starterLower: string;
  invited: Map<string, { name: string; state: "ringing" | "joined" | "declined" | "missed" | "left"; ringUntil: number }>;
  answeredAt: number | null;            // when a second person actually joined (call duration starts here)
  ringTimers: Map<string, ReturnType<typeof setTimeout>>;
  wsOf: Map<string, WebSocket>;         // which connection each person is calling from
  finalized: boolean;
  peerState?: Map<string, { muted: boolean; deafened: boolean }>;   // lowercase name → mic/headphone state, relayed to the others
}
const activeCalls = new Map<string, CallRec>();
// who in this call has the mic muted / headphones off, so a newcomer's dock can show it straight away
function callStates(call: CallRec): Record<string, { muted: boolean; deafened: boolean }> {
  const out: Record<string, { muted: boolean; deafened: boolean }> = {};
  const here = new Set([...call.participants].map((p) => p.toLowerCase()));
  for (const [k, s] of call.peerState ?? []) if (here.has(k) && (s.muted || s.deafened)) out[k] = s;
  return out;
}
// ghost call watchers: callId → admin username (only one ghost per call for simplicity)
const ghostCalls = new Map<string, string>();
// platform maintenance mode — only admins can connect/identify when true
let maintenanceMode = false;
// audit log ring buffer (last 500 admin actions, also persisted to KV)
const AUDIT_LIMIT = 500;

// ─── Stale call cleanup — every 60s, end calls nobody is connected to any more ─────────────
setInterval(() => {
  const onlineNames = new Set<string>();
  for (const [, ci] of clients) { if (ci.name) onlineNames.add(ci.name as string); }
  for (const [, call] of activeCalls) {
    const anyOnline = [...call.participants].some((p) => onlineNames.has(p));
    const stillRinging = [...call.invited.values()].some((i) => i.state === "ringing");
    if (!anyOnline && !stillRinging) void finalizeCall(call, call.answeredAt ? "ended" : "cancelled");
  }
}, 60_000);

// Per-key async mutex: stops concurrent read-modify-write on KV values (lost messages)
const _locks = new Map<string, Promise<unknown>>();
function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const next = (_locks.get(key) ?? Promise.resolve()).catch(() => {}).then(fn);
  _locks.set(key, next);
  next.finally(() => { if (_locks.get(key) === next) _locks.delete(key); }).catch(() => {});
  return next;
}
const SERVER_RECORD_WRITERS = new Set([
  "channel_add", "channel_update", "channel_remove", "roles_update", "role_assign", "server_update",
  "server_create", "server_delete", "join_server", "leave_server", "kick_member",
  "admin_add_channel", "admin_delete_channel", "admin_rename_server", "admin_set_server_icon",
  "admin_set_server_desc", "admin_set_server_public", "admin_transfer_ownership",
]);
// Peer-to-peer history relay: reqId → who asked, for which server/channel (expires after 60s)
const historyRequests = new Map<string, { requester: string; serverId: string; channelId: string; exp: number }>();
const historyRequestLast = new Map<string, number>(); // "user:channel" → last request time (rate limit)
setInterval(() => {
  const now = Date.now();
  for (const [id, r] of historyRequests) if (r.exp < now) historyRequests.delete(id);
  for (const [k, t] of historyRequestLast) if (now - t > 60_000) historyRequestLast.delete(k);
}, 30_000);
// Login throttle: 8 failures / 5 min per username
const loginFails = new Map<string, { n: number; t: number }>();

// ─── Utilities ──────────────────────────────────────────────────────────────
function broadcast(data: unknown, exclude: WebSocket | null = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}

// Broadcast only to clients who are members of a specific server
function broadcastToServer(serverId: string, data: unknown, exclude: WebSocket | null = null) {
  const msg = JSON.stringify(data);
  for (const [ws, info] of clients) {
    if (ws === exclude || ws.readyState !== WebSocket.OPEN) continue;
    const serverIds = info.serverIds as Set<string> | undefined;
    if (serverIds?.has(serverId)) ws.send(msg);
  }
}

function sendToUser(name: string, data: unknown, queue = true): boolean {
  // BUG 4 FIX: offline queue used mixed-case names as keys, causing misses on flush.
  // Normalize to lowercase so sendToUser("Alice") and offline.get("alice") always match.
  const nameLower = name.toLowerCase();
  let delivered = false;
  for (const [ws, info] of clients) {
    if ((info.name as string)?.toLowerCase() === nameLower && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
      delivered = true;
    }
  }
  if (!delivered && queue) {
    if (!offline.has(nameLower)) offline.set(nameLower, []);
    const q = offline.get(nameLower)!;
    q.push(data);
    if (q.length > 200) q.splice(0, q.length - 200);
  }
  return delivered;
}

function storeMessage(channelId: string, msg: unknown) {
  if (!msgHistory.has(channelId)) msgHistory.set(channelId, []);
  const hist = msgHistory.get(channelId)!;
  hist.push(msg);
  if (hist.length > 100) hist.splice(0, hist.length - 100);
}

// Write an audit log entry. Persisted to KV with a timestamp-based key so
// they're naturally ordered and queryable by range. Capped at AUDIT_LIMIT.
async function auditLog(action: string, by: string, details: Record<string, unknown> = {}) {
  const entry = { action, by, at: Date.now(), ...details };
  const key = ["audit", Date.now(), Math.random().toString(36).slice(2, 8)];
  await kv.set(key, entry);
  console.log(`[audit] ${by} → ${action}`, details);
}

// Verify token → returns lowercase username or null
async function verifyTokenKv(token: string | undefined): Promise<string | null> {
  if (!token) return null;
  const mem = sessions.get(token);
  if (mem) return mem;
  const entry = await kv.get<string>(["sessions", token]);
  if (entry.value) {
    sessions.set(token, entry.value);
    return entry.value;
  }
  // RECOVERY: session not in KV (e.g. after database wipe/swap).
  // Scan accounts to find one whose last known token matches.
  // This lets cached client tokens survive a KV reset.
  const acctIter = kv.list<Record<string, unknown>>({ prefix: ["accounts"] });
  for await (const item of acctIter) {
    if (item.value?.lastToken === token) {
      const username = item.key[1] as string;
      sessions.set(token, username);
      // FIX #7: Use expireIn here too so recovered tokens don't accumulate indefinitely
      await kv.set(["sessions", token], username, { expireIn: 30 * 24 * 60 * 60 * 1000 });
      console.log(`[token-recovery] recovered session for ${username}`);
      return username;
    }
  }
  return null;
}

// ─── Presence ───────────────────────────────────────────────────────────────
// Online-ness belongs to a USER, not to a connection. A user can have several sockets (two tabs, or the new
// page that connects a moment BEFORE the old one's close is processed on a refresh), so "went offline" must
// only be announced when their LAST socket closes. Status (online / idle / dnd / invisible) is remembered.
const VALID_STATUS = new Set(["online", "idle", "dnd", "invisible"]);
const userStatus = new Map<string, string>(); // lowercase name -> status
function socketsOf(nameLower: string): Array<[WebSocket, Record<string, unknown>]> {
  const out: Array<[WebSocket, Record<string, unknown>]> = [];
  for (const [w, ci] of clients) {
    if (w.readyState === WebSocket.OPEN && ((ci.name as string) || "").toLowerCase() === nameLower) out.push([w, ci]);
  }
  return out;
}
// How `viewerLower` should see this user. An invisible user looks offline to everyone but themselves.
function presenceOf(nameLower: string, viewerLower?: string): { online: boolean; status: string } {
  if (!socketsOf(nameLower).length) return { online: false, status: "offline" };
  const status = userStatus.get(nameLower) || "online";
  if (status === "invisible" && nameLower !== viewerLower) return { online: false, status: "offline" };
  return { online: true, status };
}
// last-seen is its own key so writing it can never clobber an account record being edited at the same time
async function getLastSeen(nameLower: string): Promise<number | null> {
  return ((await kv.get<number>(["last_seen", nameLower])).value as number | null) || null;
}
// Tell everyone who should care (people sharing a server with them, and their friends) about a change.
async function announcePresence(nameLower: string, displayName: string, fallbackServers?: Set<string>) {
  const mine = new Set<string>(fallbackServers || []);
  for (const [, ci] of socketsOf(nameLower)) for (const id of ((ci.serverIds as Set<string>) || [])) mine.add(id);
  const friendNames = new Set<string>(
    (((await kv.get<Array<Record<string, unknown>>>(["friends", nameLower])).value) || []).map((f) => String(f.name || "").toLowerCase()),
  );
  for (const m of await groupMates(nameLower)) friendNames.add(m);   // people in my group chats can see me too
  const p = presenceOf(nameLower);
  const lastSeen = p.online ? null : await getLastSeen(nameLower);
  const payload = JSON.stringify({ type: "presence", user: displayName, online: p.online, status: p.status, lastSeen });
  for (const [w, ci] of clients) {
    if (w.readyState !== WebSocket.OPEN) continue;
    const n = ((ci.name as string) || "").toLowerCase();
    if (!n || n === nameLower) continue;
    const shares = [...((ci.serverIds as Set<string>) || [])].some((id) => mine.has(id));
    if (shares || friendNames.has(n)) { try { w.send(payload); } catch { /* socket closing */ } }
  }
}
// Sockets that have been silent for too long are dead (laptop slept, wifi dropped...): close them so the
// person stops showing as online. The client sends a ping every 20s.
const envNum = (k: string, d: number) => { try { return Number(Deno.env.get(k)) || d; } catch { return d; } };
const IDLE_MS = envNum("NEXUS_IDLE_MS", 150_000);   // (overridable so the sweep can be tested in seconds)
setInterval(() => {
  const now = Date.now();
  for (const [w, ci] of clients) {
    if (w.readyState !== WebSocket.OPEN || !ci.name) continue;
    if (now - (Number(ci.lastActive) || now) > IDLE_MS) {
      console.log(`[sweep] closing silent connection for ${ci.name}`);
      try { w.close(4000, "idle"); } catch { /* already closing */ }
    }
  }
}, envNum("NEXUS_SWEEP_MS", 30_000));

// Friendship helpers --------------------------------------------------------
type Rec2 = Record<string, unknown>;
async function friendCard(acct: Rec2, viewerLower: string): Promise<Rec2> {
  const l = String(acct.name).toLowerCase();
  const p = presenceOf(l, viewerLower);
  return { name: acct.name, pfp: safePfp(acct.pfp), color: acct.color || null, online: p.online, status: p.status, lastSeen: p.online ? null : await getLastSeen(l) };
}
// Both people become friends. Used when a request is accepted (or when two requests cross).
async function makeFriends(accepter: string, requester: string): Promise<boolean> {
  const [aAcct, bAcct] = await Promise.all([kv.get<Rec2>(["accounts", accepter]), kv.get<Rec2>(["accounts", requester])]);
  if (!aAcct.value || !bAcct.value) return false;
  for (const [owner, other] of [[accepter, bAcct.value], [requester, aAcct.value]] as Array<[string, Rec2]>) {
    await withLock("friends:" + owner, async () => {
      const key = ["friends", owner];
      const list = (((await kv.get<Rec2[]>(key)).value) || []) as Rec2[];
      if (!list.some((f) => String(f.name).toLowerCase() === String(other.name).toLowerCase())) {
        list.push({ name: other.name, pfp: null, color: other.color || null });
        await kv.set(key, list);
      }
    });
  }
  for (const [x, y] of [[accepter, requester], [requester, accepter]]) {
    await kv.delete(["friend_requests", x, y]);
    await kv.delete(["friend_requests_out", x, y]);
  }
  sendToUser(aAcct.value.name as string, { type: "friend_added", by: aAcct.value.name, friend: await friendCard(bAcct.value, accepter) }, true);
  sendToUser(bAcct.value.name as string, { type: "friend_added", by: aAcct.value.name, friend: await friendCard(aAcct.value, requester) }, true);
  return true;
}

// Who is in a server, who is online. One membership listing + parallel account reads; everything one person
// can be (online/offline/invisible) is decided here, once, so every client renders the same list.
async function buildMemberList(svId: string, viewerLower: string): Promise<Rec2[]> {
  const names = new Map<string, string>(); // lower -> stored key
  for await (const item of kv.list({ prefix: ["server_member", svId] })) {
    const raw = String(item.key[2]);
    if (!names.has(raw.toLowerCase())) names.set(raw.toLowerCase(), raw);
  }
  const lowers = [...names.keys()];
  const accts = await Promise.all(lowers.map((l) => kv.get<Rec2>(["accounts", l])));
  const seen = await Promise.all(lowers.map((l) => (presenceOf(l, viewerLower).online || l === viewerLower) ? Promise.resolve(null) : getLastSeen(l)));
  const out: Rec2[] = [];
  lowers.forEach((l, i) => {
    const a = accts[i].value; if (!a) return;
    const p = l === viewerLower ? { online: true, status: userStatus.get(l) || "online" } : presenceOf(l, viewerLower);
    out.push({ ...profileOf(a), online: p.online, status: p.online ? p.status : undefined, lastSeen: p.online ? null : seen[i] });
  });
  return out;
}
// Older servers had members who chatted but were never recorded as members (join never saved). Find them in
// recent history and record them. This reads every channel's history, so it runs rarely and AFTER replying.
const lastGhostSweep = new Map<string, number>();
async function ghostSweep(svId: string): Promise<number> {
  if (Date.now() - (lastGhostSweep.get(svId) || 0) < 10 * 60_000) return 0;
  lastGhostSweep.set(svId, Date.now());
  const known = new Set<string>();
  for await (const item of kv.list({ prefix: ["server_member", svId] })) known.add(String(item.key[2]).toLowerCase());
  const sv = (await kv.get<Rec2>(["servers", svId])).value;
  let added = 0;
  for (const ch of ((sv?.channels as Array<{ id: string }>) || [])) {
    for (const m of (((await kv.get<unknown[]>(["ch_history", ch.id])).value) || []) as Rec2[]) {
      const lower = String(m.author || "").toLowerCase();
      if (!lower || known.has(lower)) continue;
      known.add(lower);
      const acct = (await kv.get<Rec2>(["accounts", lower])).value;
      if (!acct) continue;
      await kv.set(["server_member", svId, acct.name as string], { joinedAt: Date.now(), addedBy: "ghost-sweep" });
      await addServerToUser(lower, svId);
      added++;
      console.log(`[ghost-sweep] added missing member ${lower} to server ${svId}`);
    }
  }
  return added;
}

// ─── Conversations: 1:1 DMs, group chats, read receipts, per-conversation settings ───────────
type Rec3 = Record<string, unknown>;
const GROUP_PFP_MAX = 24_000;   // chars of a group picture (it rides along in every contacts list, so keep it small)
const GROUP_MAX = 10;     // people in a group chat
const CALL_MAX = 5;       // people in one call (peer-to-peer mesh)
const RING_MS = envNum("NEXUS_RING_MS", 45_000);   // how long a call rings (overridable for tests)
const dmConv = (a: string, b: string) => "dm:" + [a.toLowerCase(), b.toLowerCase()].sort().join(":");
const dmHistKey = (a: string, b: string): Deno.KvKey => ["dm_history", [a.toLowerCase(), b.toLowerCase()].sort().join(":")];
const newId = () => crypto.randomUUID().replace(/-/g, "").slice(0, 16);
const cleanId = (v: unknown): string => (typeof v === "string" && /^[A-Za-z0-9_-]{4,64}$/.test(v)) ? v : newId();
async function nameOf(lower: string): Promise<string> { return String(((await kv.get<Rec3>(["accounts", lower])).value?.name) || lower); }

async function getSettings(lower: string): Promise<{ readReceipts: boolean; typingIndicators: boolean }> {
  const v = ((await kv.get<Rec3>(["user_settings", lower])).value) || {};
  return { readReceipts: v.readReceipts !== false, typingIndicators: v.typingIndicators !== false };
}
async function getPrefs(lower: string): Promise<Record<string, Rec3>> { return ((await kv.get<Record<string, Rec3>>(["dm_prefs", lower])).value) || {}; }
async function patchPref(lower: string, conv: string, patch: Rec3): Promise<Rec3> {
  let merged: Rec3 = {};
  await withLock("dm_prefs:" + lower, async () => {
    const all = await getPrefs(lower);
    merged = { ...(all[conv] || {}), ...patch };
    all[conv] = merged;
    await kv.set(["dm_prefs", lower], all);
  });
  return merged;
}
async function getRead(conv: string, lower: string): Promise<number> { return Number(((await kv.get<{ ts: number }>(["dm_read", conv, lower])).value)?.ts) || 0; }
async function bumpRead(conv: string, lower: string, upTo: number): Promise<number> {
  let result = 0;
  await withLock("dm_read:" + conv + ":" + lower, async () => {
    const cur = await getRead(conv, lower);
    result = Math.max(cur, Math.min(upTo, Date.now() + 5000));
    if (result !== cur) await kv.set(["dm_read", conv, lower], { ts: result });
  });
  return result;
}
// A message that arrived while a chat was hidden ("closed") brings it back
async function unhide(lower: string, conv: string) {
  const prefs = await getPrefs(lower);
  if (prefs[conv]?.hidden) {
    const merged = await patchPref(lower, conv, { hidden: false });
    for (const [w] of socketsOf(lower)) w.send(JSON.stringify({ type: "dm_prefs", conv, prefs: merged }));
  }
}

// History helpers
async function appendHistory(key: Deno.KvKey, entry: Rec3): Promise<boolean> {
  let ok = true;
  await withLock("hist:" + key.join("/"), async () => {
    const cur = (((await kv.get<unknown[]>(key)).value) || []) as unknown[];
    // outbox replays / double sends carry the same id: never store a message twice
    if (entry.id && cur.some((x) => (x as Rec3)?.id === entry.id)) { ok = true; return; }
    cur.push(entry);
    ok = await safeKvSet(key, fitHistory(cur));
  });
  return ok;
}
function cleanChatMessage(raw: Rec3, author: string, color: unknown): Rec3 {
  const m: Rec3 = {
    id: cleanId(raw.id), author, from: author, authorColor: typeof color === "string" ? color : null,
    text: typeof raw.text === "string" ? raw.text.slice(0, 4000) : "", ts: Date.now(),   // the SERVER's clock orders messages and read receipts
    attachments: Array.isArray(raw.attachments) ? (raw.attachments as Rec3[]).slice(0, 10) : [], reactions: [],
  };
  const rt = raw.replyTo as Rec3 | undefined;
  if (rt && typeof rt === "object" && typeof rt.id === "string") m.replyTo = { id: rt.id, author: String(rt.author || "").slice(0, 32), text: String(rt.text || "").slice(0, 200) };
  if (raw.voiceMsg && typeof raw.voiceMsg === "object") m.voiceMsg = raw.voiceMsg;
  return m;
}
const previewOf = (m?: Rec3) => !m ? "" : (typeof m.text === "string" && m.text) ? m.text : (m.system ? "" : (Array.isArray(m.attachments) && m.attachments.length ? "[attachment]" : ""));
const isMine = (m: Rec3, lower: string) => String(m.from || m.author || "").toLowerCase() === lower;
function countsAsUnread(m: Rec3, lower: string): boolean {
  if (m.system) return m.system === "call" && (m.kind === "missed" || m.kind === "cancelled") && !isMine(m, lower);
  return !isMine(m, lower);
}
const msgTs = (m: Rec3) => Number(m.ts || m._stored || 0);

// DM peers index (who I have conversations with). Built once from existing histories, then maintained.
async function getDmPeers(lower: string): Promise<string[]> {
  const idx = (await kv.get<string[]>(["dm_peers", lower])).value;
  if (idx) return idx;
  const peers = new Set<string>();
  for await (const item of kv.list({ prefix: ["dm_history"] })) {
    const parts = String(item.key[1]).split(":");
    if (!parts.includes(lower)) continue;
    const o = parts.find((p) => p !== lower);
    if (o) peers.add(o);
  }
  const arr = [...peers];
  await safeKvSet(["dm_peers", lower], arr);
  return arr;
}
async function addDmPeer(lower: string, peer: string) {
  await getDmPeers(lower); // make sure the index exists before adding to it
  await withLock("dm_peers:" + lower, async () => {
    const list = (((await kv.get<string[]>(["dm_peers", lower])).value) || []) as string[];
    if (!list.includes(peer)) { list.push(peer); await kv.set(["dm_peers", lower], list); }
  });
}

// Groups
async function getGroup(gid: string): Promise<Rec3 | null> { return (await kv.get<Rec3>(["groups", gid])).value || null; }
async function userGroupIds(lower: string): Promise<string[]> { return (((await kv.get<string[]>(["user_groups", lower])).value) || []) as string[]; }
async function addUserGroup(lower: string, gid: string) {
  await withLock("user_groups:" + lower, async () => {
    const l = await userGroupIds(lower);
    if (!l.includes(gid)) { l.push(gid); await kv.set(["user_groups", lower], l); }
  });
}
async function removeUserGroup(lower: string, gid: string) {
  await withLock("user_groups:" + lower, async () => {
    const l = await userGroupIds(lower);
    if (l.includes(gid)) await kv.set(["user_groups", lower], l.filter((x) => x !== gid));
  });
}
function validGroupPfp(v: unknown): v is string { return validPfp(v) && v.length <= GROUP_PFP_MAX; }
async function groupView(g: Rec3, viewerLower: string): Promise<Rec3> {
  const members = await Promise.all(((g.members as string[]) || []).map(async (l) => {
    const a = (await kv.get<Rec3>(["accounts", l])).value;
    const p = l === viewerLower ? { online: true, status: userStatus.get(l) || "online" } : presenceOf(l, viewerLower);
    return a ? { name: a.name, pfp: safePfp(a.pfp), color: a.color || null, online: p.online, status: p.online ? p.status : undefined }
             : { name: l, pfp: null, color: null, online: false };
  }));
  return { id: g.id, name: g.name, color: g.color || null, pfp: validGroupPfp(g.pfp) ? g.pfp : null, owner: g.owner, createdAt: g.createdAt, members };
}
function sendToGroup(g: Rec3, data: unknown, exceptLower?: string, queue = true) {
  for (const l of ((g.members as string[]) || [])) if (l !== exceptLower) sendToUser(l, data, queue);
}
async function pushGroup(g: Rec3, type = "group_updated") {   // everyone in the group gets their own view of it
  for (const l of ((g.members as string[]) || [])) sendToUser(l, { type, group: await groupView(g, l) }, true);
}
async function groupSystemMsg(g: Rec3, kind: string, text: string, by: string, extra: Rec3 = {}) {
  const m: Rec3 = { id: newId(), system: "group", kind, by, text, ts: Date.now(), ...extra };
  await appendHistory(["group_history", g.id as string], m);
  sendToGroup(g, { type: "dm_system", gid: g.id, message: m }, undefined, false);
}
// People who share a group with this user (they can see each other's presence)
async function groupMates(lower: string): Promise<Set<string>> {
  const out = new Set<string>();
  for (const gid of await userGroupIds(lower)) {
    const g = await getGroup(gid);
    for (const l of ((g?.members as string[]) || [])) if (l !== lower) out.add(l);
  }
  return out;
}

// Calls ----------------------------------------------------------------------
const fmtDur = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000)), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h ? `${h}h ${m}m` : m ? `${m}m ${sec}s` : `${sec}s`;
};
async function callConvMembers(call: CallRec): Promise<string[]> {
  if (call.gid) return (((await getGroup(call.gid))?.members) as string[]) || [];
  return call.conv ? call.conv.slice(3).split(":") : [];
}
// Everyone in the conversation sees "a call is in progress" (and can join) while one is going
async function broadcastCallState(call: CallRec, active = true) {
  const members = await callConvMembers(call);
  const base = { type: "call_state", callId: call.id, active, participants: [...call.participants], startedAt: call.startedAt, answeredAt: call.answeredAt };
  for (const l of members) {
    if (call.gid) sendToUser(l, { ...base, gid: call.gid }, false);
    else sendToUser(l, { ...base, with: await nameOf(members.find((x) => x !== l) || l) }, false);
  }
}
async function deliverInvite(call: CallRec, lower: string, onlyWs?: WebSocket): Promise<boolean> {
  const inv = call.invited.get(lower);
  if (!inv || inv.state !== "ringing") return false;
  const left = inv.ringUntil - Date.now();
  if (left <= 0) return false;
  const sAcct = (await kv.get<Rec3>(["accounts", call.starterLower])).value;
  const g = call.gid ? await getGroup(call.gid) : null;
  const payload = { type: "vcall_invite", callId: call.id, from: call.starter, fromColor: sAcct?.color || null, fromPfp: safePfp(sAcct?.pfp), gid: call.gid || undefined, groupName: g?.name, ringLeftMs: left };
  if (onlyWs) { try { onlyWs.send(JSON.stringify(payload)); return true; } catch { return false; } }
  return sendToUser(inv.name, payload, false);
}
function startRing(call: CallRec, lower: string, name: string) {
  const old = call.ringTimers.get(lower); if (old) clearTimeout(old);
  call.invited.set(lower, { name, state: "ringing", ringUntil: Date.now() + RING_MS });
  call.ringTimers.set(lower, setTimeout(() => { void ringExpired(call.id, lower); }, RING_MS));
}
function stopRing(call: CallRec, lower: string) { const t = call.ringTimers.get(lower); if (t) { clearTimeout(t); call.ringTimers.delete(lower); } }
async function ringExpired(callId: string, lower: string) {
  const call = activeCalls.get(callId); const inv = call?.invited.get(lower);
  if (!call || !inv || inv.state !== "ringing") return;
  inv.state = "missed"; call.ringTimers.delete(lower);
  sendToUser(inv.name, { type: "vcall_missed", callId, from: call.starter }, false);        // dismiss their popup
  for (const p of call.participants) sendToUser(p, { type: "vcall_no_answer", callId, user: inv.name }, false);
  await maybeEndRinging(call);
}
// Nobody joined and nobody is still ringing → the call is over
async function maybeEndRinging(call: CallRec) {
  const ringing = [...call.invited.values()].some((i) => i.state === "ringing");
  if (call.participants.size > 1 || ringing || call.finalized) return;
  const declined = [...call.invited.values()].some((i) => i.state === "declined");
  await finalizeCall(call, call.answeredAt ? "ended" : declined ? "declined" : "missed");
}
async function finalizeCall(call: CallRec, reason: "ended" | "missed" | "declined" | "cancelled") {
  if (call.finalized) return;
  call.finalized = true;
  for (const t of call.ringTimers.values()) clearTimeout(t);
  call.ringTimers.clear();
  activeCalls.delete(call.id); ghostCalls.delete(call.id);
  const endedAt = Date.now(), duration = call.answeredAt ? endedAt - call.answeredAt : 0;
  const notify = new Set<string>([...call.participants]);
  for (const inv of call.invited.values()) if (inv.state === "ringing" || inv.state === "joined") notify.add(inv.name);
  for (const n of notify) sendToUser(n, { type: "vcall_end", callId: call.id, from: call.starter, reason, duration }, false);
  await broadcastCallState(call, false);
  // the call log that appears in the conversation
  const text = reason === "ended" ? `📞 ${call.starter} started a call · lasted ${fmtDur(duration)}`
    : reason === "declined" ? "📵 Call declined" : `📵 Missed call from ${call.starter}`;
  const joined = [...call.invited.values()].filter((i) => i.state === "joined" || i.state === "left").map((i) => i.name);
  const sys: Rec3 = { id: newId(), system: "call", kind: reason, from: call.starter, ts: endedAt, duration, participants: [call.starter, ...joined], text };
  if (call.gid) {
    const g = await getGroup(call.gid);
    if (g) { await appendHistory(["group_history", call.gid], sys); sendToGroup(g, { type: "dm_system", gid: call.gid, message: sys }, undefined, false); }
  } else {
    const [a, b] = call.conv ? call.conv.slice(3).split(":") : [call.starterLower, ""];
    if (a && b) {
      await appendHistory(dmHistKey(a, b), sys);
      await addDmPeer(a, b); await addDmPeer(b, a);
      await unhide(a, dmConv(a, b)); await unhide(b, dmConv(a, b));
      sendToUser(a, { type: "dm_system", with: await nameOf(b), message: sys }, false);
      sendToUser(b, { type: "dm_system", with: await nameOf(a), message: sys }, false);
    }
  }
}
function joinCall(call: CallRec, lower: string, name: string, ws: WebSocket) {
  stopRing(call, lower);
  const roster = [...call.participants].filter((p) => p.toLowerCase() !== lower);
  call.invited.set(lower, { name, state: "joined", ringUntil: 0 });
  call.participants.add(name); call.wsOf.set(lower, ws);
  if (!call.answeredAt && call.participants.size >= 2) call.answeredAt = Date.now();
  // The newcomer connects to everyone already in the call (full mesh); the others wait for their offers.
  ws.send(JSON.stringify({ type: "vcall_roster", callId: call.id, participants: roster, answeredAt: call.answeredAt, startedAt: call.startedAt, now: Date.now(), gid: call.gid || undefined, states: callStates(call) }));
  for (const p of roster) sendToUser(p, { type: "vcall_joined", callId: call.id, user: name, answeredAt: call.answeredAt, now: Date.now() }, false);
  for (const [w] of socketsOf(lower)) if (w !== ws) w.send(JSON.stringify({ type: "vcall_handled", callId: call.id })); // other tabs stop ringing
  void broadcastCallState(call);
}
async function leaveCall(call: CallRec, lower: string) {
  if (call.finalized) return;
  const inv = call.invited.get(lower);
  const wasRinging = inv?.state === "ringing";
  for (const p of [...call.participants]) if (p.toLowerCase() === lower) call.participants.delete(p);
  if (inv && inv.state !== "declined") inv.state = "left";
  call.wsOf.delete(lower); stopRing(call, lower);
  const remaining = [...call.participants];
  const ringing = [...call.invited.values()].some((i) => i.state === "ringing");
  if (remaining.length >= 2) {
    const nm = inv?.name || await nameOf(lower);
    for (const p of remaining) sendToUser(p, { type: "vcall_left", callId: call.id, user: nm }, false);
    await broadcastCallState(call);
    return;
  }
  if (remaining.length === 1 && ringing && !call.answeredAt) { await broadcastCallState(call); return; } // starter alone, still ringing others
  if (wasRinging) { await maybeEndRinging(call); return; }
  await finalizeCall(call, call.answeredAt ? "ended" : "cancelled");
}
// When someone connects while a call is ringing for them (or in progress in their chats), tell them
async function deliverCallsTo(ws: WebSocket, lower: string) {
  for (const call of [...activeCalls.values()]) {
    if (call.finalized) continue;
    const inv = call.invited.get(lower);
    if (inv?.state === "ringing" && await deliverInvite(call, lower, ws)) {
      for (const p of call.participants) sendToUser(p, { type: "vcall_ringing", callId: call.id, to: inv.name, online: true }, false);
      continue;
    }
    if (!call.participants.has(inv?.name || "\u0000")) {
      const members = await callConvMembers(call);
      if (members.includes(lower)) {
        const base = { type: "call_state", callId: call.id, active: true, participants: [...call.participants], startedAt: call.startedAt, answeredAt: call.answeredAt };
        ws.send(JSON.stringify(call.gid ? { ...base, gid: call.gid } : { ...base, with: await nameOf(members.find((x) => x !== lower) || lower) }));
      }
    }
  }
}

function clientInfo(ws: WebSocket): Record<string, unknown> | null {
  return clients.get(ws) || null;
}

function isBanned(username: string): boolean {
  const ban = timedBans.get(username.toLowerCase());
  if (!ban) return false;
  if (ban.until === -1) return true;
  if (Date.now() < ban.until) return true;
  timedBans.delete(username.toLowerCase());
  return false;
}

// ─── FIX: Helper to add a server to a user's membership index ───────────────
// Always uses lowercase username as the KV key to avoid case mismatches.
// Read-modify-write on a user's index must be serialized, otherwise two quick joins (or a
// join racing an identify) overwrite each other and a server silently drops off the list.
async function addServerToUser(username: string, serverId: string) {
  const lower = username.toLowerCase();
  const key = ["user_servers", lower];
  await withLock("user_servers:" + lower, async () => {
    const entry = await kv.get<string[]>(key);
    const list = entry.value || [];
    if (!list.includes(serverId)) {
      list.push(serverId);
      await kv.set(key, list);
      console.log(`[membership] added server ${serverId} to user ${lower} (now has ${list.length})`);
    }
  });
}

async function removeServerFromUser(username: string, serverId: string) {
  const lower = username.toLowerCase();
  const key = ["user_servers", lower];
  await withLock("user_servers:" + lower, async () => {
    const entry = await kv.get<string[]>(key);
    if (entry.value && entry.value.includes(serverId)) {
      await kv.set(key, entry.value.filter((id: string) => id !== serverId));
    }
  });
}

// ─── KV safety ──────────────────────────────────────────────────────────────
// Deno KV rejects any single value over 64 KiB. Several handlers used to call kv.set
// without checking, the throw was swallowed, and the write silently never happened
// (this is why messages and channels "vanished" after a refresh).
const KV_MAX_VALUE_BYTES = 60_000; // margin under the 65,536 limit
const _enc = new TextEncoder();
function byteLen(v: unknown): number { return _enc.encode(JSON.stringify(v)).length; }
async function safeKvSet(key: Deno.KvKey, value: unknown): Promise<boolean> {
  try { await kv.set(key, value); return true; }
  catch (e) { console.error(`[kv] write failed for ${JSON.stringify(key).slice(0, 80)}:`, e); return false; }
}

// Strip everything from a chat message that must never be persisted or replayed:
//  - token: the sender's session token (the client attaches it to every WS frame)
//  - authorPfp: a base64 avatar up to ~40 KB, which alone blows the 64 KiB limit
//  - inline data: URLs (large attachments) are served peer-to-peer instead
function sanitizeMsgForStore(msg: Record<string, unknown>): Record<string, unknown> {
  const m: Record<string, unknown> = { ...msg };
  delete m.token;
  delete m.authorPfp;
  if (typeof m.text === "string" && m.text.length > 4000) m.text = (m.text as string).slice(0, 4000);
  if (Array.isArray(m.attachments)) {
    m.attachments = (m.attachments as Record<string, unknown>[]).map((att) => {
      const url = (att.url as string) || "";
      if (url.startsWith("data:") || url.length > 2000) return { ...att, url: "", _stripped: true };
      return att;
    });
  }
  return m;
}
// Keep the newest messages that fit inside one KV value.
function fitHistory(hist: unknown[]): unknown[] {
  let h = hist.length > 500 ? hist.slice(-500) : hist;
  while (h.length > 1 && byteLen(h) > KV_MAX_VALUE_BYTES) h = h.slice(Math.max(1, Math.ceil(h.length * 0.1)));
  return h;
}

// ─── Deleted-server tombstones ──────────────────────────────────────────────
// Without these, anything still holding the server (a stale tab, a queued server_create
// retry, announce_servers, a server_update) simply re-created it after deletion.
async function isTombstoned(serverId: string): Promise<boolean> {
  if (!serverId) return false;
  return !!(await kv.get(["deleted_servers", serverId])).value;
}

// Delete a server and everything hanging off it, then leave a tombstone.
async function purgeServer(serverId: string, by: string) {
  const entry = await kv.get<Record<string, unknown>>(["servers", serverId]);
  await kv.set(["deleted_servers", serverId], { at: Date.now(), by });
  publicServers.delete(serverId);
  await kv.delete(["servers", serverId]);
  const chans = (entry.value?.channels as Array<{ id: string }>) || [];
  for (const ch of chans) {
    await kv.delete(["ch_history", ch.id]);
    await kv.delete(["pins", serverId, ch.id]);
    await kv.delete(["channel_lock", ch.id]);
    await kv.delete(["slowmode", ch.id]);
    msgHistory.delete(ch.id); channelLocks.delete(ch.id); slowmodes.delete(ch.id);
  }
  await kv.delete(["shorts", serverId]);
  await kv.delete(["custom_emoji_names", serverId]);
  const memIter = kv.list({ prefix: ["server_member", serverId] });
  for await (const item of memIter) {
    await kv.delete(item.key);
    await removeServerFromUser(item.key[2] as string, serverId);
  }
  // Keep every connected client's in-memory membership in sync
  for (const [, ci] of clients) (ci.serverIds as Set<string> | undefined)?.delete(serverId);
}

// ─── Profile pictures / public profile ──────────────────────────────────────
// A picture is stored in the account record (which must fit one 64 KiB KV value) and later placed straight
// into <img src="..."> on every client, so only real, size-limited images are accepted.
const PFP_MAX_CHARS = 60_000;
function validPfp(v: unknown): v is string {
  return typeof v === "string" && v.length <= PFP_MAX_CHARS && /^data:image\/(?:jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(v);
}
function safePfp(v: unknown): string | null { return validPfp(v) ? v : null; }
const SOCIAL_KEYS = ["website", "twitter", "github", "youtube", "twitch", "instagram", "bluesky"] as const;
function cleanSocials(v: unknown, fallback: unknown): Record<string, string> {
  const src = (v && typeof v === "object" ? v : (fallback && typeof fallback === "object" ? fallback : {})) as Record<string, unknown>;
  const ok = (s: unknown) => typeof s === "string" && s.length <= 100 && /^[^\s"'<>]*$/.test(s) && !/^(?:javascript|data|vbscript):/i.test(s) ? s : "";
  const out: Record<string, string> = {};
  for (const k of SOCIAL_KEYS) out[k] = ok(src[k]);
  return out;
}

// ─── Profile personalisation (protocol 7) ────────────────────────────────────
// Banner, avatar frame, name effect, card tint, pronouns, location, interests. Everything is whitelisted and
// validated: colours end up in CSS custom properties and text ends up in markup on every client.
// Stored OUTSIDE the account record (key ["profile_ext", name]) so a big picture can never push the account over the
// 64 KiB KV limit, together with the optional banner image (sent only when a profile page is opened).
const BANNER_IMG_MAX = 50_000;
function validBannerImg(v: unknown): v is string {
  return typeof v === "string" && v.length <= BANNER_IMG_MAX && /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(v);
}
function hexOr(v: unknown, fb: string | null): string | null {
  if (typeof v !== "string" || !/^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(v)) return fb;
  const h = v.toLowerCase();
  return h.length === 4 ? "#" + h[1] + h[1] + h[2] + h[2] + h[3] + h[3] : h;
}
function cleanText(v: unknown, max: number): string {
  return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max) : "";
}
const BANNER_KINDS = ["default", "color", "gradient", "image"];
const FRAME_KINDS = ["none", "ring", "gradient", "glow", "neon", "dashed"];
const NAMEFX_KINDS = ["none", "gradient", "glow", "shimmer"];
function cleanExt(v: unknown, fallback: unknown, hasBannerImg: boolean): Record<string, unknown> {
  const isObj = (x: unknown) => !!x && typeof x === "object" && !Array.isArray(x);
  const src = (isObj(v) ? v : (isObj(fallback) ? fallback : {})) as Record<string, unknown>;
  const sub = (x: unknown) => (isObj(x) ? x : {}) as Record<string, unknown>;
  const pick = (x: unknown, list: string[], fb: string) => (list.includes(x as string) ? (x as string) : fb);
  const b = sub(src.banner), fr = sub(src.frame), nf = sub(src.nameFx);
  let bkind = pick(b.kind, BANNER_KINDS, "default");
  if (bkind === "image" && !hasBannerImg) bkind = "default";
  const ang = Math.round(Number(b.angle));
  const seen = new Set<string>();
  const interests: string[] = [];
  for (const x of Array.isArray(src.interests) ? src.interests : []) {
    const t = cleanText(x, 20); if (!t || seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase()); interests.push(t); if (interests.length >= 8) break;
  }
  return {
    pronouns: cleanText(src.pronouns, 24), location: cleanText(src.location, 30), interests,
    banner: { kind: bkind, c1: hexOr(b.c1, "#5865f2"), c2: hexOr(b.c2, "#eb459e"), angle: Number.isFinite(ang) ? Math.max(0, Math.min(360, ang)) : 135 },
    frame: { kind: pick(fr.kind, FRAME_KINDS, "none"), c1: hexOr(fr.c1, "#5865f2"), c2: hexOr(fr.c2, "#eb459e") },
    nameFx: { kind: pick(nf.kind, NAMEFX_KINDS, "none"), c1: hexOr(nf.c1, "#5865f2"), c2: hexOr(nf.c2, "#eb459e") },
    cardTint: hexOr(src.cardTint, null),
  };
}
async function getProfileExt(lowerName: string): Promise<{ ext: Record<string, unknown>; banner: string | null }> {
  const v = (await kv.get<Record<string, unknown>>(["profile_ext", lowerName])).value;
  const banner = validBannerImg(v?.banner) ? (v!.banner as string) : null;
  return { ext: cleanExt(v?.ext, null, !!banner), banner };
}
// The only account fields other people may see. One shape, used everywhere, always from the saved account.
function profileOf(a: Record<string, unknown>): Record<string, unknown> {
  return {
    name: a.name, tag: a.tag, color: a.color, pfp: safePfp(a.pfp), bio: typeof a.bio === "string" ? a.bio : "",
    socials: cleanSocials(a.socials, null), createdAt: a.createdAt || null,
    systemRole: a.systemRole, coAdmin: a.coAdmin,
  };
}

// ─── Shorts ─────────────────────────────────────────────────────────────────
type Rec = Record<string, unknown>;
const SHORTS_MAX = 200;
// Only http(s) links. Anything else (javascript:, data:, ...) ends up in an href/src on the client.
function cleanShortUrl(u: unknown): string | null {
  if (typeof u !== "string") return null;
  const t = u.trim();
  return t.length <= 2000 && /^https?:\/\//i.test(t) ? t : null;
}
function cleanShort(raw: Rec, author: string): Rec | null {
  const url = cleanShortUrl(raw.url);
  if (!url || typeof raw.id !== "string" || !raw.id || raw.id.length > 64) return null;
  return {
    id: raw.id, url, caption: typeof raw.caption === "string" ? raw.caption.slice(0, 300) : "",
    author, // never trust the client-supplied author
    channelId: typeof raw.channelId === "string" ? raw.channelId : null,
    ts: Number(raw.ts) || Date.now(), likes: [], comments: [],
  };
}
async function loadShorts(svId: string): Promise<Rec[]> {
  const v = ((await kv.get<Rec[]>(["shorts", svId])).value || []) as Rec[];
  // scrub anything already stored with a non-http url
  return v.map((s) => (typeof s.url === "string" && s.url && !/^https?:\/\//i.test(s.url)) ? { ...s, url: "", _stripped: true } : s);
}
async function saveShorts(svId: string, list: Rec[]): Promise<boolean> {
  let l = list.length > SHORTS_MAX ? list.slice(-SHORTS_MAX) : list;
  while (l.length > 1 && byteLen(l) > KV_MAX_VALUE_BYTES) l = l.slice(1); // stay under the 64 KiB KV value limit
  return await safeKvSet(["shorts", svId], l);
}
async function loadServerPins(svId: string, channels: unknown): Promise<Record<string, unknown[]>> {
  const out: Record<string, unknown[]> = {};
  for (const ch of ((channels as Array<{ id: string }>) || [])) {
    const p = (await kv.get<unknown[]>(["pins", svId, ch.id])).value;
    if (p?.length) out[ch.id] = p;
  }
  return out;
}
// A server record as sent to a member: includes the shorts (with likes + comments) and pins, which
// otherwise only arrived on a full reconnect, so new joiners never saw them.
async function serverInfoFor(svId: string, sv: Rec, isMember: boolean): Promise<Rec> {
  if (!isMember) return sv;
  return { ...sv, shorts: await loadShorts(svId), pins: await loadServerPins(svId, sv.channels) };
}

// memberCount is derived from the real member records, not incremented blindly.
async function recountMembers(serverId: string): Promise<number> {
  let n = 0;
  for await (const _ of kv.list({ prefix: ["server_member", serverId] })) n++;
  const entry = await kv.get<Record<string, unknown>>(["servers", serverId]);
  if (entry.value && entry.value.memberCount !== n) {
    const updated = { ...entry.value, memberCount: Math.max(n, 1) };
    await safeKvSet(["servers", serverId], updated);
    if (publicServers.has(serverId)) publicServers.set(serverId, updated);
  }
  return n;
}

// ─── Per-channel "who can send messages" ────────────────────────────────────
// A channel may carry sendRoles: string[] (role ids). Empty/absent = everyone. The owner (and platform
// admins) can always send. Role ids: "mod", custom role ids, and "member" (anyone with no role).
function cleanSendRoles(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return [...new Set(v.filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= 64))].slice(0, 50);
}
function isServerOwner(sv: Record<string, unknown>, username: string): boolean {
  const owner = (sv.ownerIdLower as string) || ((sv.ownerId as string) || "").toLowerCase();
  return owner === username.toLowerCase();
}
function roleIdOf(sv: Record<string, unknown>, username: string): string {
  const lower = username.toLowerCase();
  const mr = (sv.memberRoles as Record<string, string>) || {};
  const assigned = mr[username] ?? Object.entries(mr).find(([k]) => k.toLowerCase() === lower)?.[1];
  if (assigned === "mod") return "mod";
  if (assigned && ((sv.roles as Array<{ id: string }>) || []).some((r) => r.id === assigned)) return assigned;
  return "member"; // same rule the client's getMyRole uses
}
function canSendInChannel(sv: Record<string, unknown>, ch: Record<string, unknown>, username: string, isPower: boolean): boolean {
  const allowed = cleanSendRoles(ch.sendRoles);
  if (!allowed.length || isPower || isServerOwner(sv, username)) return true;
  return allowed.includes(roleIdOf(sv, username));
}
// Which server does this channel belong to? msg.serverId comes from the client, so it is only a hint:
// the channel must really be in that server, otherwise we look it up ourselves (a client can't dodge a
// restriction by naming a different server).
const channelServerCache = new Map<string, string>();
const unknownChannels = new Map<string, number>();
async function resolveChannel(channelId: string, claimed?: string): Promise<{ sv: Record<string, unknown>; ch: Record<string, unknown> } | null> {
  const tryServer = async (id: string) => {
    const sv = (await kv.get<Record<string, unknown>>(["servers", id])).value;
    const ch = (sv?.channels as Array<Record<string, unknown>> | undefined)?.find((c) => c.id === channelId);
    return sv && ch ? { sv, ch } : null;
  };
  const cached = channelServerCache.get(channelId);
  if (cached) { const r = await tryServer(cached); if (r) return r; channelServerCache.delete(channelId); }
  if ((unknownChannels.get(channelId) || 0) > Date.now()) return null;
  if (claimed) { const r = await tryServer(claimed); if (r) { channelServerCache.set(channelId, claimed); return r; } }
  for await (const item of kv.list<Record<string, unknown>>({ prefix: ["servers"] })) {
    const ch = (item.value?.channels as Array<Record<string, unknown>> | undefined)?.find((c) => c.id === channelId);
    if (item.value && ch) { channelServerCache.set(channelId, item.value.id as string); return { sv: item.value, ch }; }
  }
  unknownChannels.set(channelId, Date.now() + 30_000); // don't rescan for every message to a channel that doesn't exist
  return null;
}

// Owner / platform admin, or a member whose role grants the permission (mirrors the client's hasPerm)
function canManageServer(sv: Record<string, unknown>, username: string, perm: string, isPower: boolean): boolean {
  if (isPower) return true;
  const lower = username.toLowerCase();
  const owner = (sv.ownerIdLower as string) || ((sv.ownerId as string) || "").toLowerCase();
  if (owner === lower) return true;
  const memberRoles = (sv.memberRoles as Record<string, string>) || {};
  const roleId = memberRoles[username] ?? Object.entries(memberRoles).find(([k]) => k.toLowerCase() === lower)?.[1];
  if (!roleId) return false;
  const overrides = (sv.roleOverrides as Record<string, { perms?: string[] }>) || {};
  const custom = ((sv.roles as Array<{ id: string; perms?: string[] }>) || []).find((r) => r.id === roleId);
  const builtinMod = ["manage_messages", "kick_members", "pin_messages", "invite_members"];
  const perms = overrides[roleId]?.perms ?? custom?.perms ?? (roleId === "mod" ? builtinMod : []);
  return perms.includes("*") || perms.includes(perm);
}

// ─── Backfill "member since" for accounts created before createdAt was stored ───────────────────────
{
  const earliest = new Map<string, number>();
  const note = (who: string, t: number) => { if (who && t > 0 && (!earliest.has(who) || t < earliest.get(who)!)) earliest.set(who, t); };
  for await (const item of kv.list<Record<string, unknown>>({ prefix: ["server_member"] })) note(String(item.key[2]).toLowerCase(), Number(item.value?.joinedAt) || 0);
  for await (const item of kv.list<Record<string, unknown>>({ prefix: ["servers"] })) {
    const owner = ((item.value?.ownerIdLower as string) || ((item.value?.ownerId as string) || "")).toLowerCase();
    note(owner, Number(item.value?.createdAt) || 0);
  }
  let filled = 0;
  for await (const item of kv.list<Record<string, unknown>>({ prefix: ["accounts"] })) {
    const a = item.value;
    if (!a || a.createdAt) continue;
    const est = earliest.get(String(a.name || "").toLowerCase());
    if (est && await safeKvSet(item.key, { ...a, createdAt: est, createdAtEstimated: true })) filled++;
  }
  if (filled) console.log(`[startup] backfilled createdAt for ${filled} older account(s) (earliest known activity)`);
}

// ─── Load persisted servers into memory on startup ──────────────────────────
{
  const svIter = kv.list<Record<string, unknown>>({ prefix: ["servers"] });
  for await (const item of svIter) {
    const sv = item.value;
    if (sv && sv.isPublic !== false) publicServers.set(sv.id as string, sv);
  }
  console.log(`Loaded ${publicServers.size} servers from KV`);
  // Debug: list all KV keys on startup
  const allKeys: string[] = [];
  const allIter = kv.list({ prefix: [] });
  for await (const item of allIter) allKeys.push(JSON.stringify(item.key));
  console.log(`[startup] KV keys (${allKeys.length} total): ${allKeys.slice(0, 20).join(", ")}`);

  // Load channel history. Older builds persisted each sender's session token and full avatar
  // inside every message (token leak + the reason histories hit the 64 KiB cap), so scrub on load.
  let scrubbed = 0;
  const chIter = kv.list<unknown[]>({ prefix: ["ch_history"] });
  for await (const item of chIter) {
    const chId = item.key[1] as string;
    if (!item.value?.length) continue;
    const cleaned = (item.value as Record<string, unknown>[]).map(sanitizeMsgForStore);
    if (JSON.stringify(cleaned) !== JSON.stringify(item.value)) {
      const fitted = fitHistory(cleaned);
      if (await safeKvSet(item.key, fitted)) { scrubbed++; msgHistory.set(chId, fitted); continue; }
    }
    msgHistory.set(chId, item.value);
  }
  if (scrubbed) console.log(`[startup] scrubbed tokens/avatars from ${scrubbed} channel history record(s)`);
  // same for DM history (it was also storing every sender's session token)
  let dmScrubbed = 0;
  const dmHistIter = kv.list<unknown[]>({ prefix: ["dm_history"] });
  for await (const item of dmHistIter) {
    if (!item.value?.length) continue;
    const cleaned = (item.value as Record<string, unknown>[]).map((m) => ({ ...sanitizeMsgForStore(m), ...(m._stored !== undefined ? { _stored: m._stored } : {}) }));
    if (JSON.stringify(cleaned) !== JSON.stringify(item.value) && await safeKvSet(item.key, fitHistory(cleaned))) dmScrubbed++;
  }
  if (dmScrubbed) console.log(`[startup] scrubbed tokens/avatars from ${dmScrubbed} DM history record(s)`);

  // FIX #3: Restore persisted bans. Expired ones are cleaned up here so they
  // don't accumulate in KV indefinitely.
  const banIter = kv.list<{ until: number; reason: string }>({ prefix: ["bans"] });
  for await (const item of banIter) {
    const username = item.key[1] as string;
    const ban = item.value;
    if (!ban) continue;
    if (ban.until === -1 || Date.now() < ban.until) {
      timedBans.set(username, ban);
    } else {
      // Expired — purge from KV
      await kv.delete(item.key);
    }
  }
  console.log(`[startup] Loaded ${timedBans.size} active ban(s) from KV`);

  // Load frozen users from KV
  const freezeIter = kv.list<{ reason: string; by: string; at: number }>({ prefix: ["frozen"] });
  for await (const item of freezeIter) {
    frozenUsers.set(item.key[1] as string, item.value);
  }
  console.log(`[startup] Loaded ${frozenUsers.size} frozen user(s) from KV`);

  // Load channel locks into memory
  const lockIter = kv.list<{ locked: boolean; by: string }>({ prefix: ["channel_lock"] });
  for await (const item of lockIter) {
    channelLocks.set(item.key[1] as string, item.value);
  }
  console.log(`[startup] Loaded ${channelLocks.size} channel lock(s) from KV`);

  // Load slowmodes
  const slowIter = kv.list<number>({ prefix: ["slowmode"] });
  for await (const item of slowIter) {
    slowmodes.set(item.key[1] as string, item.value);
  }
  console.log(`[startup] Loaded ${slowmodes.size} slowmode(s) from KV`);

  // Load maintenance mode
  const maintEntry = await kv.get<boolean>(["platform", "maintenance"]);
  if (maintEntry.value) {
    maintenanceMode = true;
    console.log("[startup] ⚠️  MAINTENANCE MODE is active");
  }
}

// ─── Main server ────────────────────────────────────────────────────────────
Deno.serve((req) => {
  const url = new URL(req.url);

  // ── Version endpoint — client polls this to detect new deploys ──────────
  if (url.pathname === "/_version") {
    return new Response(JSON.stringify({ version: DEPLOY_VERSION }), {
      headers: {
        "content-type": "application/json",
        // Never cache this endpoint
        "cache-control": "no-store, no-cache, must-revalidate",
        "access-control-allow-origin": "*",
      },
    });
  }

  if (req.headers.get("upgrade") !== "websocket") {
    return new Response("Nexus relay running ✓", { status: 200 });
  }

  const { socket: ws, response } = Deno.upgradeWebSocket(req);

  ws.onopen = () => console.log("WS connected");

  ws.onmessage = async (e) => {
    { const ci0 = clients.get(ws); if (ci0) ci0.lastActive = Date.now(); }
    // ── Payload size guard ────────────────────────────────────────────────────
    // A single oversized base64 image message can OOM Deno Deploy's isolate.
    // Hard limit: 1.5 MB per message (covers a compressed 800px JPEG at ~700 KB
    // encoded as base64 with ~33% overhead, plus JSON envelope).
    // Messages over this limit are dropped with an error sent back to the client.
    const MAX_MSG_BYTES = 1.5 * 1024 * 1024; // 1.5 MB
    if ((e.data as string).length > MAX_MSG_BYTES) {
      try {
        ws.send(JSON.stringify({
          type: "error",
          message: `Message too large (${((e.data as string).length / 1024 / 1024).toFixed(1)} MB). Images must be under ~700 KB after compression.`,
        }));
      } catch { /* ws might already be closing */ }
      console.warn(`[size-guard] DROPPED oversized message: ${((e.data as string).length / 1024).toFixed(0)} KB`);
      return;
    }
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(e.data as string); } catch { return; }
    try {
      // Handlers that read a whole server record, change one field and write it back must not overlap on
      // the same server, or whichever finishes last silently erases the other's change (e.g. roles_update
      // racing role_assign, or a channel edit racing a join). Run them one at a time per server.
      const lockKey = SERVER_RECORD_WRITERS.has(msg.type as string) && typeof msg.serverId === "string" && msg.serverId
        ? "server:" + msg.serverId : null;
      if (lockKey) await withLock(lockKey, () => handleMsg(ws, msg));
      else await handleMsg(ws, msg);
    } catch (err) {
      console.error(`[onmessage] unhandled error type=${msg.type}:`, err);
    }
  };

  async function handleMsg(ws: WebSocket, msg: Record<string, unknown>) {
    const info = clientInfo(ws);

    // ── AUTH — no token required ──────────────────────────────────────────
    if (msg.type === "auth_register") {
      const username = (msg.username as string || "").trim();
      const password = msg.password as string || "";
      if (!username || username.length < 2) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Username must be at least 2 characters." })); return;
      }
      if (!/^[a-zA-Z0-9_.\-]{2,24}$/.test(username)) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Username can only contain letters, numbers, underscores, dots, and hyphens." })); return;
      }
      if (!password || password.length < 4) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Password must be at least 4 characters." })); return;
      }
      const key = ["accounts", username.toLowerCase()];
      const existing = await kv.get(key);
      if (existing.value) {
        ws.send(JSON.stringify({ type: "auth_error", message: "That username is already taken. Choose another." })); return;
      }
      // Tags are decorative discriminators (like Discord's #XXXX). Since usernames
      // are already unique as KV keys, a simple random assignment is sufficient.
      const tag = String(Math.floor(Math.random() * 9999) + 1).padStart(4, "0");
      const acct = {
        name: username,
        tag,
        color: msg.color || "#6c63ff",
        pfp: safePfp(msg.pfp),
        passwordHash: await hashPw(password),
        systemRole: "user",
        coAdmin: false,
        createdAt: Date.now(),
      };
      await kv.set(key, acct);
      const token = genToken();
      sessions.set(token, username.toLowerCase());
      // FIX #7: Sessions expire after 30 days
      await kv.set(["sessions", token], username.toLowerCase(), { expireIn: 30 * 24 * 60 * 60 * 1000 });
      console.log(`Registered: ${username}`);
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: safePfp(acct.pfp), createdAt: acct.createdAt || null, systemRole: acct.systemRole, coAdmin: false } }));
      return;
    }

    if (msg.type === "auth_login") {
      const username = (msg.username as string || "").trim().toLowerCase();
      const password = msg.password as string || "";
      const key = ["accounts", username];
      const entry = await kv.get<Record<string, unknown>>(key);
      if (!entry.value) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Account not found. Did you mean to register?" })); return;
      }
      const acct = entry.value;
      const lf = loginFails.get(username);
      if (lf && Date.now() - lf.t < 300_000 && lf.n >= 8) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Too many attempts. Try again in a few minutes." })); return;
      }
      // FIX #2: Support both new SHA-256 hash and legacy djb2 hash so existing
      // users are not locked out. On successful legacy login, silently upgrade.
      const newHash = await hashPw(password);
      const legacyHash = hashPwLegacy(password);
      const validNew    = acct.passwordHash === newHash;
      const validLegacy = acct.passwordHash === legacyHash;
      if (!validNew && !validLegacy) {
        const f = loginFails.get(username); loginFails.set(username, { n: (f && Date.now() - f.t < 300_000 ? f.n : 0) + 1, t: Date.now() });
        ws.send(JSON.stringify({ type: "auth_error", message: "Incorrect password." })); return;
      }
      if (validLegacy && !validNew) {
        // Migrate to SHA-256 hash transparently
        await kv.set(key, { ...acct, passwordHash: newHash });
        acct.passwordHash = newHash;
        console.log(`[auth] migrated password hash for ${username} from legacy to SHA-256`);
      }
      if (isBanned(username)) {
        const ban = timedBans.get(username);
        const until = ban?.until === -1 ? "permanently" : `until ${new Date(ban!.until).toLocaleString()}`;
        ws.send(JSON.stringify({ type: "auth_error", message: `You are banned ${until}. Reason: ${ban?.reason || "none"}` })); return;
      }
      const token = genToken();
      sessions.set(token, username);
      // FIX #7: Sessions expire after 30 days to prevent unbounded KV growth
      await kv.set(["sessions", token], username, { expireIn: 30 * 24 * 60 * 60 * 1000 });
      console.log(`Login: ${acct.name}`);
      const firstLogin = !acct.hasLoggedIn;
      if (!acct.hasLoggedIn) await kv.set(key, { ...acct, hasLoggedIn: true, lastToken: token });
      else await kv.set(key, { ...acct, lastToken: token });
      ws.send(JSON.stringify({ type: "auth_ok", token, firstLogin: !!firstLogin, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: safePfp(acct.pfp), createdAt: acct.createdAt || null, systemRole: acct.systemRole, coAdmin: acct.coAdmin || false } }));
      return;
    }

    if (msg.type === "check_username") {
      const username = (msg.username as string || "").trim().toLowerCase();
      const entry = await kv.get(["accounts", username]);
      ws.send(JSON.stringify({ type: "username_available", username, available: !entry.value }));
      return;
    }

    if (msg.type === "auth_migrate") {
      const username = (msg.username as string || "").trim();
      const password = msg.password as string || "";
      const tag = msg.tag as string || "0000";
      const color = msg.color as string || "#6c63ff";
      const pfp = safePfp(msg.pfp);
      if (!username || !password || password.length < 4) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Username and password (min 4 chars) required." })); return;
      }
      const key = ["accounts", username.toLowerCase()];
      const existing = await kv.get(key);
      if (existing.value) {
        ws.send(JSON.stringify({ type: "auth_error", message: "That username is already registered. Try logging in, or choose a different username." })); return;
      }
      const acct = { name: username, tag, color, pfp, passwordHash: await hashPw(password), systemRole: "user", coAdmin: false, createdAt: Date.now() };
      await kv.set(key, acct);
      const token = genToken();
      sessions.set(token, username.toLowerCase());
      // FIX #7: Sessions expire after 30 days
      await kv.set(["sessions", token], username.toLowerCase(), { expireIn: 30 * 24 * 60 * 60 * 1000 });
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: safePfp(acct.pfp), createdAt: acct.createdAt || null, systemRole: "user", coAdmin: false }, migrated: true }));
      return;
    }

    // ── ALL OTHER MESSAGES require a valid token ──────────────────────────
    const tokenUser = await verifyTokenKv(msg.token as string);
    if (!tokenUser) {
      console.log(`[auth] token verification failed for type=${msg.type} token=${(msg.token as string || '').slice(0,16)}...`);
      ws.send(JSON.stringify({ type: "auth_required", message: "Please log in." }));
      return;
    }

    // The client attaches its session token to every frame. Everything below this point gets
    // broadcast and/or persisted as-is, so remove the token now (identify still needs it).
    if (msg.type !== "identify") delete msg.token;

    // ── auth_change_password — allowed before full identify ───────────────
    if (msg.type === "auth_change_password") {
      const oldPassword = msg.oldPassword as string || "";
      const newPassword = msg.newPassword as string || "";
      if (!newPassword || (newPassword as string).length < 4) {
        ws.send(JSON.stringify({ type: "error", context: "change_password", message: "New password must be at least 4 characters." })); return;
      }
      const key = ["accounts", tokenUser];
      const entry = await kv.get<Record<string, unknown>>(key);
      if (!entry.value) { ws.send(JSON.stringify({ type: "error", context: "change_password", message: "Account not found." })); return; }
      // FIX #2: Support both new SHA-256 and legacy djb2 for old-password verification
      const oldHashNew    = await hashPw(oldPassword);
      const oldHashLegacy = hashPwLegacy(oldPassword);
      if (entry.value.passwordHash !== oldHashNew && entry.value.passwordHash !== oldHashLegacy) {
        ws.send(JSON.stringify({ type: "error", context: "change_password", message: "Current password is incorrect." })); return;
      }
      await kv.set(key, { ...entry.value, passwordHash: await hashPw(newPassword) });
      ws.send(JSON.stringify({ type: "success", message: "Password changed!" }));
      return;
    }

    // ── identify ──────────────────────────────────────────────────────────
    if (msg.type === "identify") {
      const key = ["accounts", tokenUser];

      // Banned users with a still-valid token must not slip back in
      if (isBanned(tokenUser)) {
        ws.send(JSON.stringify({ type: "banned", until: timedBans.get(tokenUser)?.until, reason: timedBans.get(tokenUser)?.reason }));
        ws.close(); return;
      }
      // Maintenance mode: only admins can identify
      if (maintenanceMode) {
        const maintAcct = await kv.get<Record<string, unknown>>(key);
        if (maintAcct.value?.systemRole !== "admin") {
          ws.send(JSON.stringify({ type: "maintenance", message: "Nexus is currently undergoing maintenance. Please try again soon." }));
          ws.close(1000, "Maintenance");
          return;
        }
      }

      // Register client immediately (synchronously) so subsequent messages aren't
      // dropped by the !info guard while we await KV reads below.
      clients.set(ws, {
        name: tokenUser,
        tag: "0000",
        color: "#6c63ff",
        pfp: null,
        token: msg.token,
        systemRole: "user",
        coAdmin: false,
      });

      const entry = await kv.get<Record<string, unknown>>(key);
      const acct = entry.value;
      const name = acct?.name as string || tokenUser;

      // Update with real account data
      clients.set(ws, {
        name,
        tag: acct?.tag || "0000",
        color: acct?.color || "#6c63ff", // from the saved account; whatever the client claims is ignored
        lastActive: Date.now(),
        pfp: safePfp(acct?.pfp),
        token: msg.token,
        systemRole: acct?.systemRole || "user",
        coAdmin: acct?.coAdmin || false,
        serverIds: new Set<string>(), // filled below after userSvIds is loaded
      });

      // Re-persist the session token in case KV was wiped (e.g. new database attached)
      // This means the next message with this token will verify correctly
      sessions.set(msg.token as string, tokenUser);
      // FIX #7: Refresh expiry on every identify (keeps active sessions alive)
      await kv.set(["sessions", msg.token as string], tokenUser, { expireIn: 30 * 24 * 60 * 60 * 1000 });
      console.log(`[identify] re-persisted session token for ${name}`);

      // FIX: Look up user_servers by lowercased token user (consistent key)
      const userSvsKey = ["user_servers", tokenUser]; // tokenUser is already lowercase
      let userSvIdsEntry = await kv.get<string[]>(userSvsKey);

      // MIGRATION: if nothing found under lowercase key, check original-case name
      // (handles servers created before the lowercase-key fix was deployed)
      if (!userSvIdsEntry.value && name !== tokenUser) {
        const oldKey = ["user_servers", name];
        const oldEntry = await kv.get<string[]>(oldKey);
        if (oldEntry.value?.length) {
          console.log(`[migrate] moving user_servers from key="${name}" to "${tokenUser}"`);
          await kv.set(userSvsKey, oldEntry.value);
          await kv.delete(oldKey);
          userSvIdsEntry = await kv.get<string[]>(userSvsKey);
        }
      }

      // MIGRATION: also scan all servers in KV where ownerId matches this user
      // (handles servers created before server_create saved user_servers at all)
      {
        const knownIds = new Set(userSvIdsEntry.value || []);
        const svScanIter = kv.list<Record<string, unknown>>({ prefix: ["servers"] });
        const recovered: string[] = [];
        for await (const item of svScanIter) {
          const sv = item.value;
          if (!sv) continue;
          const owner = (sv.ownerId as string || "").toLowerCase();
          if (owner === tokenUser && !knownIds.has(sv.id as string)) {
            recovered.push(sv.id as string);
            // Also ensure server_member entry exists
            const memKey = ["server_member", sv.id as string, name];
            const memEntry = await kv.get(memKey);
            if (!memEntry.value) await kv.set(memKey, { joinedAt: Date.now() });
          }
        }
        if (recovered.length) {
          console.log(`[migrate] recovered ${recovered.length} orphaned server(s) for ${name}: ${recovered.join(", ")}`);
          for (const rid of recovered) await addServerToUser(name, rid);
          userSvIdsEntry = await kv.get<string[]>(userSvsKey);
        }
      }

      console.log(`[identify] user=${name} (key=${tokenUser}) user_servers=${JSON.stringify(userSvIdsEntry.value)}`);
      const userSvIds: string[] = [...(userSvIdsEntry.value || [])];

      // The client tells us which servers it has cached. Anything it lists that the membership index
      // lost, but that still has a member record for this user, is healed back into the index.
      const clientKnownIds: string[] = Array.isArray(msg.knownServerIds)
        ? (msg.knownServerIds as unknown[]).filter((x): x is string => typeof x === "string").slice(0, 200)
        : [];
      for (const kid of clientKnownIds) {
        if (userSvIds.includes(kid)) continue;
        const [m1, m2] = await Promise.all([kv.get(["server_member", kid, name]), kv.get(["server_member", kid, tokenUser])]);
        if ((m1.value || m2.value) && (await kv.get(["servers", kid])).value) {
          userSvIds.push(kid);
          await addServerToUser(name, kid);
          console.log(`[identify] healed missing index entry ${kid} for ${name}`);
        }
      }

      // Store server membership on client info for scoped broadcasting
      const clientInfo2 = clients.get(ws);
      if (clientInfo2) (clientInfo2 as Record<string, unknown>).serverIds = new Set(userSvIds);

      const userServers: Record<string, unknown>[] = [];
      const danglingIds: string[] = [];
      for (const svId of userSvIds) {
        const svEntry = await kv.get<Record<string, unknown>>(["servers", svId]);
        console.log(`[identify] svId=${svId} found=${!!svEntry.value}`);
        if (!svEntry.value) danglingIds.push(svId);
        if (svEntry.value) {
          const sv = svEntry.value;
          // Load pins for all channels in this server
          const svPins: Record<string, unknown[]> = {};
          for (const ch of (sv.channels as Array<{ id: string }> || [])) {
            const pinData = (await kv.get<unknown[]>(["pins", svId, ch.id])).value;
            if (pinData?.length) svPins[ch.id] = pinData;
          }
          // Load shorts metadata (no video data — just url/caption/author/likes/comments)
          const shortsData = (await kv.get<unknown[]>(["shorts", svId])).value || [];
          // Load custom emoji names list (data is p2p — too large for free tier KV)
          const emojiNames = (await kv.get<string[]>(["custom_emoji_names", svId])).value || [];
          userServers.push({
            id: sv.id, name: sv.name, desc: sv.desc || "",
            color: sv.color || "#6c63ff",
            icon: null, // sent separately via get_server_info
            channels: sv.channels || [],
            ownerId: sv.ownerId,
            memberCount: sv.memberCount || 1,
            createdAt: sv.createdAt || 0,
            isPublic: sv.isPublic !== false,
            pins: svPins,
            shorts: shortsData,
            customEmojiNames: emojiNames, // names only — data fetched p2p via emoji_request
          });
        }
      }
      console.log(`[identify] sending ${userServers.length} servers to ${name}`);

      // Self-heal: ids pointing at servers that no longer exist (deleted, or deleted before the index
      // was cleaned) used to sit in the index forever.
      for (const did of danglingIds) await removeServerFromUser(name, did);
      { const ci3 = clients.get(ws); if (ci3) ci3.serverIds = new Set(userServers.map((s) => s.id as string)); }

      // Reconcile what the client has cached against the truth, so it can drop ghosts:
      //  removedServerIds — deleted, or the account isn't a member (join never took / was kicked)
      //  missingServerIds — gone from the database but not deleted on purpose (e.g. data loss); the
      //                     client's owner can re-register these, everyone else should drop them
      const listedIds = new Set(userServers.map((s) => s.id as string));
      const removedServerIds: string[] = [];
      const missingServerIds: string[] = [];
      for (const kid of clientKnownIds) {
        if (listedIds.has(kid)) continue;
        if (await isTombstoned(kid)) removedServerIds.push(kid);
        else if ((await kv.get(["servers", kid])).value) removedServerIds.push(kid);
        else missingServerIds.push(kid);
      }

      // This user's status survives refreshes (invisible must stay invisible). Several tabs share one status.
      if (!socketsOf(tokenUser).some(([w]) => w !== ws)) {
        const savedStatus = (await kv.get<string>(["user_status", tokenUser])).value;
        userStatus.set(tokenUser, savedStatus && VALID_STATUS.has(savedStatus) ? savedStatus : "online");
      }
      const myStatus = userStatus.get(tokenUser) || "online";

      // Friends come with their presence, so the friends list is correct the instant it loads.
      const friendsRaw = ((await kv.get<unknown[]>(["friends", tokenUser])).value || []) as Record<string, unknown>[];
      const friendsList = await Promise.all(friendsRaw.map(async (f) => {
        const fl = String(f.name || "").toLowerCase();
        const fAcct = (await kv.get<Record<string, unknown>>(["accounts", fl])).value;
        const p = presenceOf(fl, tokenUser);
        return {
          name: fAcct?.name || f.name, pfp: safePfp(fAcct?.pfp) || safePfp(f.pfp), color: fAcct?.color || f.color || null,
          online: p.online, status: p.status, lastSeen: p.online ? null : await getLastSeen(fl),
        };
      }));
      // Pending requests in both directions, in the shape the client uses ({name, direction, pfp, color})
      const pendingReqs: unknown[] = [];
      for await (const item of kv.list<Record<string, unknown>>({ prefix: ["friend_requests", tokenUser] })) {
        const v = item.value || {};
        pendingReqs.push({ name: v.from, direction: "in", pfp: safePfp(v.fromPfp), color: v.fromColor || null, ts: v.ts || 0 });
      }
      for await (const item of kv.list<Record<string, unknown>>({ prefix: ["friend_requests_out", tokenUser] })) {
        const v = item.value || {};
        const tAcct = (await kv.get<Record<string, unknown>>(["accounts", String(item.key[2])])).value;
        pendingReqs.push({ name: tAcct?.name || v.to, direction: "out", pfp: safePfp(tAcct?.pfp), color: tAcct?.color || null, ts: v.ts || 0 });
      }

      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: "identified",
          user: {
            name: acct?.name || tokenUser,
            tag: acct?.tag || "0000",
            color: acct?.color || "#6c63ff",
            // pfp intentionally omitted — sent separately via user_pfp so it
            // never overwrites a valid cached pfp with null on reconnect.
            systemRole: acct?.systemRole || "user",
            coAdmin: acct?.coAdmin || false,
            bio: acct?.bio || "",
            socials: acct?.socials || {},
            createdAt: acct?.createdAt || null,
            status: myStatus,
          },
          servers: userServers,
          protocol: PROTOCOL,
          removedServerIds,
          missingServerIds,
        }));
        // Always send pfp state: send null explicitly if the user has none,
        // so the client can clear a stale cached pfp after an admin wipe.
        ws.send(JSON.stringify({ type: "user_pfp", pfp: safePfp(acct?.pfp) }));
        // Own profile style (protocol 7), incl. the banner image. Always sent, so a cleared one clears on the client too.
        { const pe = await getProfileExt(String(tokenUser).toLowerCase()); ws.send(JSON.stringify({ type: "user_ext", ext: pe.ext, banner: pe.banner })); }
        // Always sent (even when empty) and authoritative: the client replaces its copy instead of merging.
        ws.send(JSON.stringify({ type: "friends_data", full: true, friends: friendsList, friendRequests: pendingReqs }));
        // Send MOTD if set
        const motdEntry = await kv.get<{ text: string; by: string; at: number }>(["platform", "motd"]);
        if (motdEntry.value?.text) {
          ws.send(JSON.stringify({ type: "motd_update", text: motdEntry.value.text, by: motdEntry.value.by }));
        }
        // Notify user if their account is frozen
        if (frozenUsers.has(tokenUser)) {
          const fz = frozenUsers.get(tokenUser)!;
          ws.send(JSON.stringify({ type: "account_frozen", reason: fz.reason, by: fz.by }));
        }

        // Send DM contacts so the client can restore its DM sidebar even after a cache clear.
        // Scan all dm_history keys that include this user and return the other party's info.
        {
          const dmContactsMap = new Map<string, { name: string; lastTs: number; last: string; pfp: string | null }>();
          const dmScanIter = kv.list<unknown[]>({ prefix: ["dm_history"] });
          for await (const item of dmScanIter) {
            const keyStr = item.key[1] as string;
            const parts = keyStr.split(":");
            if (!parts.some(p => p === tokenUser)) continue;
            const otherLower = parts.find(p => p !== tokenUser) || "";
            if (!otherLower || dmContactsMap.has(otherLower)) continue;
            const msgs = item.value || [];
            const last = msgs[msgs.length - 1] as Record<string, unknown> | undefined;
            const otherAcct = await kv.get<Record<string, unknown>>(["accounts", otherLower]);
            const displayName = (otherAcct.value?.name as string) || otherLower;
            dmContactsMap.set(otherLower, {
              name: displayName,
              lastTs: (last?._stored as number || last?.ts as number || 0),
              last: (last?.text as string || (Array.isArray((last as Record<string,unknown>)?.attachments) ? "[attachment]" : "")),
              pfp: safePfp(otherAcct.value?.pfp),
            });
          }
          if (dmContactsMap.size > 0) {
            const contacts = [...dmContactsMap.values()].sort((a, b) => b.lastTs - a.lastTs);
            ws.send(JSON.stringify({ type: "dm_contacts", contacts }));
          }
        }
      }

      // Flush queued offline messages
      const queue = offline.get(tokenUser) || offline.get(name.toLowerCase());
      if (queue?.length) {
        for (const qmsg of queue) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(qmsg));
        }
        offline.delete(tokenUser);
        offline.delete(name.toLowerCase());
      }

      // Tell the people who should know (server co-members + friends) that this user is online. This replaces
      // the old per-server member_join broadcast, which also fired on every reconnect and could race with the
      // old connection's close.
      await announcePresence(tokenUser, (acct?.name as string) || name);
      ws.send(JSON.stringify({ type: "user_settings", settings: await getSettings(tokenUser) }));
      // If someone is calling this user right now (even if they were offline when the call started), ring them
      await deliverCallsTo(ws, tokenUser);

      return;
    }

    // Log every message type that makes it past token verification
    console.log(`[msg] type=${msg.type} sender=${info?.name || "unidentified"}`);

    // ── Guard: must be identified ─────────────────────────────────────────
    if (!info) {
      console.log(`[guard] dropping msg type=${msg.type} — client not yet identified`);
      return;
    }

    const senderName = info.name as string;
    const isAdmin = info.systemRole === "admin";
    const isCoAdmin = info.coAdmin === true;
    const isPowerUser = isAdmin || isCoAdmin;

    // ── Admin: appoint/remove co-admin ───────────────────────────────────
    if (msg.type === "appoint_coadmin") {
      if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can appoint co-admins." })); return; }
      const target = (msg.target as string || "").toLowerCase();
      const targetKey = ["accounts", target];
      const targetEntry = await kv.get<Record<string, unknown>>(targetKey);
      if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); return; }
      await kv.set(targetKey, { ...targetEntry.value, coAdmin: msg.appoint === true });
      for (const [cws, ci] of clients) {
        if ((ci.name as string).toLowerCase() === target) {
          (ci as Record<string, unknown>).coAdmin = msg.appoint === true;
          cws.send(JSON.stringify({ type: "system_role_update", coAdmin: msg.appoint === true, message: msg.appoint ? "You have been appointed as Co-Admin by Puck!" : "Your Co-Admin status has been removed." }));
        }
      }
      broadcast({ type: "coadmin_update", target: targetEntry.value.name, coAdmin: msg.appoint === true }, ws);
      ws.send(JSON.stringify({ type: "success", message: `${targetEntry.value.name} is now ${msg.appoint ? "a Co-Admin" : "a regular user"}.` }));
      return;
    }

    if (msg.type === "admin_ban") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const target = (msg.target as string || "").toLowerCase();
      const targetEntry = await kv.get<Record<string, unknown>>(["accounts", target]);
      if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); return; }
      if (!isAdmin && (targetEntry.value.coAdmin || targetEntry.value.systemRole === "admin")) {
        ws.send(JSON.stringify({ type: "error", message: "Co-admins cannot ban each other or Puck." })); return;
      }
      const dur = (msg.duration as string || "").toLowerCase();
      let until: number;
      if (dur === "permanent" || dur === "perm") {
        until = -1;
      } else {
        const match = dur.match(/^(\d+)(m|h|d|w)$/);
        if (!match) { ws.send(JSON.stringify({ type: "error", message: "Duration format: 30m, 2h, 7d, permanent" })); return; }
        const [, n, unit] = match;
        const ms = parseInt(n) * ({ m: 60000, h: 3600000, d: 86400000, w: 604800000 }[unit as string] as number);
        until = Date.now() + ms;
      }
      timedBans.set(target, { until, reason: msg.reason as string || "No reason given" });
      // FIX #3: Persist ban to KV so it survives server restarts
      await kv.set(["bans", target], { until, reason: msg.reason as string || "No reason given" });
      for (const [cws, ci] of clients) {
        if ((ci.name as string).toLowerCase() === target) {
          cws.send(JSON.stringify({ type: "banned", until, reason: msg.reason || "No reason given" }));
          cws.close();
        }
      }
      const untilStr = until === -1 ? "permanently" : `until ${new Date(until).toLocaleString()}`;
      broadcast({ type: "admin_action", action: "ban", target: targetEntry.value.name, by: senderName, reason: msg.reason || "" });
      await auditLog("ban", senderName, { target, until, reason: msg.reason || "" });
      ws.send(JSON.stringify({ type: "success", message: `${targetEntry.value.name} banned ${untilStr}.` }));
      return;
    }

    if (msg.type === "admin_unban") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const unbanTarget = (msg.target as string || "").toLowerCase();
      timedBans.delete(unbanTarget);
      // FIX #3: Remove from KV as well
      await kv.delete(["bans", unbanTarget]);
      ws.send(JSON.stringify({ type: "success", message: `${msg.target} unbanned.` }));
      return;
    }

    if (msg.type === "admin_view_dms") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const targetUser = (msg.target as string || "").trim().toLowerCase();
      if (!targetUser) { ws.send(JSON.stringify({ type: "error", message: "Specify a username." })); return; }
      const iter = kv.list<unknown[]>({ prefix: ["dm_history"] });
      const convos: { name: string; messages: unknown[] }[] = [];
      for await (const item of iter) {
        const key = item.key[1] as string;
        const parts = key.split(":");
        if (parts.some((p: string) => p.toLowerCase() === targetUser)) {
          const otherName = parts.find((p: string) => p.toLowerCase() !== targetUser) || "unknown";
          convos.push({ name: otherName, messages: item.value || [] });
        }
      }
      ws.send(JSON.stringify({ type: "admin_dm_data", target: targetUser, dms: convos }));
      return;
    }

    if (msg.type === "admin_delete_server") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const adminDelId = msg.serverId as string;
      await purgeServer(adminDelId, senderName);
      broadcast({ type: "server_delete", serverId: adminDelId, by: senderName });
      ws.send(JSON.stringify({ type: "success", message: "Server deleted." }));
      return;
    }

    if (msg.type === "profile_update") {
      const key = ["accounts", senderName.toLowerCase()];
      const entry = await kv.get<Record<string, unknown>>(key);
      if (!entry.value) return;
      // Validate color: it ends up in CSS, so only a proper hex string is stored.
      const rawColor = msg.color as string || "";
      const safeColor = /^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/.test(rawColor)
        ? rawColor
        : (entry.value.color as string || "#6c63ff");
      const safeBio = (typeof msg.bio === "string" ? msg.bio : (entry.value.bio as string) ?? "").slice(0, 160);
      const socials = cleanSocials(msg.socials, entry.value.socials);
      // The picture is only touched when the message actually carries one. null removes it; anything that
      // isn't a real, small image is refused (and the old one is kept) instead of being half-saved.
      let newPfp: string | null = safePfp(entry.value.pfp);
      if ("pfp" in msg) {
        if (msg.pfp === null) newPfp = null;
        else if (validPfp(msg.pfp)) newPfp = msg.pfp;
        else ws.send(JSON.stringify({ type: "error", message: "That picture couldn't be saved. Use a JPEG, PNG, WebP or GIF under about 45 KB." }));
      }
      const updatedAcct = { ...entry.value, color: safeColor, pfp: newPfp, bio: safeBio, socials };
      if (!(await safeKvSet(key, updatedAcct))) {
        ws.send(JSON.stringify({ type: "error", message: "Couldn't save your profile. Try a smaller picture." }));
        return;
      }
      // Every open tab of this user now reflects the saved profile
      for (const [, ci] of clients) {
        if ((ci.name as string)?.toLowerCase() === senderName.toLowerCase()) { ci.color = safeColor; ci.pfp = newPfp; ci.bio = safeBio; }
      }
      // Personalisation (protocol 7): only touched when the message carries it, so an old client or a bio-only edit
      // can never reset someone's banner or frame.
      let savedExt: Record<string, unknown> | undefined;
      if ("ext" in msg || "bannerImg" in msg) {
        const lowerMe = senderName.toLowerCase();
        const cur = await getProfileExt(lowerMe);
        let banner = cur.banner;
        if ("bannerImg" in msg) {
          if (msg.bannerImg === null) banner = null;
          else if (validBannerImg(msg.bannerImg)) banner = msg.bannerImg;
          else ws.send(JSON.stringify({ type: "error", message: "That banner couldn't be saved. Use a JPEG, PNG or WebP under about 37 KB." }));
        }
        const ext = cleanExt("ext" in msg ? msg.ext : cur.ext, cur.ext, !!banner);
        if (await safeKvSet(["profile_ext", lowerMe], { ext, banner })) savedExt = ext;
        else ws.send(JSON.stringify({ type: "error", message: "Couldn't save your profile style. Try a smaller banner." }));
      }
      // Tell everyone else. Built from what was SAVED and from the logged-in name, never from the raw message:
      // before, `user` was whatever the client typed, so anyone could overwrite another person's profile on
      // everybody's screen.
      broadcast({ type: "profile_update", user: entry.value.name, color: safeColor, pfp: newPfp, bio: safeBio, socials, ext: savedExt }, ws);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "profile_update_confirm", color: safeColor, pfp: newPfp, bio: safeBio, socials, ext: savedExt }));
      }
      return;
    }

    // Prevent impersonation
    if (msg.author !== undefined) msg.author = senderName;
    if (msg.user !== undefined && msg.type !== "admin_ban" && msg.type !== "admin_unban") msg.user = senderName;
    if (msg.from !== undefined) msg.from = senderName;

    switch (msg.type) {
      case "message": {
        // Check if channel is locked — only power users can post in locked channels
        const lockState = channelLocks.get(msg.channelId as string);
        if (lockState?.locked && !isPowerUser) {
          ws.send(JSON.stringify({ type: "error", message: "This channel is locked by an admin." }));
          break;
        }
        // Check if user is frozen — frozen users cannot send messages
        if (frozenUsers.has(senderName.toLowerCase())) {
          const freeze = frozenUsers.get(senderName.toLowerCase())!;
          ws.send(JSON.stringify({ type: "error", message: `Your account is frozen: ${freeze.reason}` }));
          break;
        }
        // Role-restricted channel: only the roles the owner picked may send here
        {
          const target = await resolveChannel(msg.channelId as string, msg.serverId as string);
          if (target && !canSendInChannel(target.sv, target.ch, senderName, isPowerUser)) {
            ws.send(JSON.stringify({ type: "message_rejected", id: msg.id, channelId: msg.channelId, message: "You don't have permission to send messages in this channel." }));
            break;
          }
        }
        // Slowmode check
        const slowSecs = slowmodes.get(msg.channelId as string) || 0;
        if (slowSecs > 0 && !isPowerUser) {
          const slowKey = `${msg.channelId}:${senderName.toLowerCase()}`;
          const lastPost = slowmodeLastPost.get(slowKey) || 0;
          const elapsed = (Date.now() - lastPost) / 1000;
          if (elapsed < slowSecs) {
            const wait = Math.ceil(slowSecs - elapsed);
            ws.send(JSON.stringify({ type: "error", message: `Slowmode: wait ${wait}s before sending again.` }));
            break;
          }
          slowmodeLastPost.set(slowKey, Date.now());
        }
        const chKey = ["ch_history", msg.channelId as string];
        // Strip the token / avatar / inline base64 before persisting (see sanitizeMsgForStore).
        // Live recipients still get the full message via broadcast; late joiners fetch large
        // attachments peer-to-peer with video_request.
        const msgToStore = sanitizeMsgForStore(msg as Record<string, unknown>);
        await withLock(chKey.join(":"), async () => {
          const chEntry = await kv.get<unknown[]>(chKey);
          const chHist = (chEntry.value || []) as unknown[];
          chHist.push(msgToStore);
          // fitHistory drops the oldest messages until the value fits under the KV limit, so the
          // write can no longer fail and take the newest message down with it.
          const fitted = fitHistory(chHist);
          if (!(await safeKvSet(chKey, fitted))) {
            ws.send(JSON.stringify({ type: "error", message: "Couldn't save your last message to history." }));
          }
        });
        storeMessage(msg.channelId as string, msgToStore);
        broadcast(msg, ws);
        break;
      }

      case "get_history": {
        const chHistKey = ["ch_history", msg.channelId as string];
        const chHistEntry = await kv.get<unknown[]>(chHistKey);
        const fullHist = chHistEntry.value || msgHistory.get(msg.channelId as string) || [];
        const since = (msg.since as number) || 0;
        const unseen = fullHist.filter((m: unknown) => (m as Record<string, number>).ts > since);
        if (unseen.length && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "history", channelId: msg.channelId, messages: unseen }));
        }
        break;
      }

      // ── Peer-to-peer history ───────────────────────────────────────────────
      // A new member (or anyone with gaps) asks the other online members of the server for the
      // messages they have cached. The server only relays: it picks a few online members, forwards
      // the request, and forwards their answer back. It never trusts the client-supplied identity.
      case "history_request": {
        const hrSvId = (msg.serverId as string || "").trim();
        const hrChId = (msg.channelId as string || "").trim();
        if (!hrSvId || !hrChId) break;
        const myIds = (info.serverIds as Set<string> | undefined);
        if (!myIds?.has(hrSvId) && !isPowerUser) break; // only members can ask
        const hrSv = (await kv.get<Record<string, unknown>>(["servers", hrSvId])).value;
        if (!hrSv || !((hrSv.channels as Array<{ id: string }>) || []).some((c) => c.id === hrChId)) break;
        const rlKey = `${senderName.toLowerCase()}:${hrChId}`;
        if (Date.now() - (historyRequestLast.get(rlKey) || 0) < 8_000) break;
        historyRequestLast.set(rlKey, Date.now());

        // every other online member of this server (any channel, any tab), one socket per person
        const peers = new Map<string, WebSocket>();
        for (const [pws, ci] of clients) {
          const pn = ((ci.name as string) || "").toLowerCase();
          if (!pn || pn === senderName.toLowerCase() || pws.readyState !== WebSocket.OPEN) continue;
          if ((ci.serverIds as Set<string> | undefined)?.has(hrSvId) && !peers.has(pn)) peers.set(pn, pws);
        }
        const chosen = [...peers.values()].sort(() => Math.random() - 0.5).slice(0, 3);
        if (!chosen.length) { ws.send(JSON.stringify({ type: "history_peers", channelId: hrChId, peers: 0 })); break; }
        const reqId = crypto.randomUUID();
        historyRequests.set(reqId, { requester: senderName.toLowerCase(), serverId: hrSvId, channelId: hrChId, exp: Date.now() + 60_000 });
        const fwd = JSON.stringify({
          type: "history_request", reqId, serverId: hrSvId, channelId: hrChId,
          since: Number(msg.since) || 0, before: Number(msg.before) || 0,
        });
        for (const pws of chosen) pws.send(fwd);
        break;
      }

      case "history_serve": {
        const req = historyRequests.get(msg.reqId as string);
        if (!req || req.exp < Date.now()) break;
        if (!(info.serverIds as Set<string> | undefined)?.has(req.serverId) && !isPowerUser) break;
        const raw = Array.isArray(msg.messages) ? (msg.messages as Record<string, unknown>[]).slice(0, 150) : [];
        if (!raw.length) break;

        // Server history is authoritative. Peers only fill in what the server doesn't have: messages
        // older than its retained window, or everything if it has none. That also means a message
        // deleted from server history can't be resurrected by a stale peer cache.
        const kvHist = ((await kv.get<unknown[]>(["ch_history", req.channelId])).value || []) as Record<string, unknown>[];
        const oldestKv = kvHist.length ? Math.min(...kvHist.map((m) => Number(m.ts) || Infinity)) : Infinity;
        const out: Record<string, unknown>[] = [];
        for (const m of raw) {
          if (!m || typeof m.id !== "string" || typeof m.author !== "string" || typeof m.ts !== "number") continue;
          if (!(Number(m.ts) < oldestKv)) continue;
          const s = sanitizeMsgForStore(m);
          // whitelist: a peer can't smuggle arbitrary fields to the requester
          out.push({
            id: s.id, channelId: req.channelId, serverId: req.serverId, author: s.author,
            authorTag: s.authorTag, authorColor: s.authorColor, text: typeof s.text === "string" ? s.text : "",
            attachments: Array.isArray(s.attachments) ? s.attachments : [], ts: s.ts,
            reactions: Array.isArray(s.reactions) ? s.reactions : [], edited: s.edited === true ? true : undefined,
            voiceMsg: s.voiceMsg, replyTo: s.replyTo,
          });
        }
        if (!out.length) break;
        sendToUser(req.requester, { type: "history", channelId: req.channelId, messages: out, via: "peer", from: senderName }, false);
        break;
      }

      case "ping":
        // Keepalive — reply immediately so client knows connection is alive
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "pong", ts: msg.ts }));
        break;

      case "typing":
        broadcast(msg, ws);
        break;

      // member_join / member_leave / status are generated by the server from real connection state. They are no
      // longer relayed from clients (anyone could fake "X came online", or set someone else's status).
      case "status_update": {
        const st = VALID_STATUS.has(String(msg.status)) ? String(msg.status) : "online";
        const me = senderName.toLowerCase();
        userStatus.set(me, st);
        for (const [, ci] of socketsOf(me)) ci.status = st;
        await safeKvSet(["user_status", me], st);
        await announcePresence(me, senderName);
        break;
      }

      // Presence of my friends, on demand (e.g. when the friends page opens or the tab regains focus)
      case "get_presence": {
        const me = senderName.toLowerCase();
        const friendSet = new Set((((await kv.get<Array<Record<string, unknown>>>(["friends", me])).value) || []).map((f) => String(f.name || "").toLowerCase()));
        for (const m of await groupMates(me)) friendSet.add(m);
        const out: Record<string, unknown> = {};
        const asked = Array.isArray(msg.names) ? (msg.names as unknown[]).filter((n): n is string => typeof n === "string").slice(0, 200) : [];
        for (const n of asked) {
          const l = n.toLowerCase(); if (!friendSet.has(l)) continue;
          const p = presenceOf(l, me);
          out[l] = { name: n, online: p.online, status: p.status, lastSeen: p.online ? null : await getLastSeen(l) };
        }
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "presence_snapshot", presence: out }));
        break;
      }

      case "kick_member": {
        // Used to be a bare broadcast: anyone could "kick" anyone, and the kick was never saved,
        // so the member came straight back on their next refresh.
        const kmSvId = (msg.serverId as string || "").trim();
        const kmTarget = (msg.target as string || "").trim();
        if (!kmSvId || !kmTarget) break;
        const kmSv = (await kv.get<Record<string, unknown>>(["servers", kmSvId])).value;
        if (!kmSv) break;
        if (!canManageServer(kmSv, senderName, "kick_members", isPowerUser)) {
          ws.send(JSON.stringify({ type: "error", message: "You don't have permission to kick members." }));
          break;
        }
        const kmOwner = ((kmSv.ownerIdLower as string) || ((kmSv.ownerId as string) || "").toLowerCase());
        if (kmTarget.toLowerCase() === kmOwner) {
          ws.send(JSON.stringify({ type: "error", message: "The server owner can't be kicked." }));
          break;
        }
        await kv.delete(["server_member", kmSvId, kmTarget]);
        await removeServerFromUser(kmTarget, kmSvId);
        for (const [, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === kmTarget.toLowerCase()) (ci.serverIds as Set<string> | undefined)?.delete(kmSvId);
        }
        await recountMembers(kmSvId);
        broadcast({ type: "kick_member", serverId: kmSvId, target: kmTarget, by: senderName }, null);
        break;
      }

      case "pin_message": {
        // Persist to KV so pins survive cache clears
        const pinSvId = msg.serverId as string;
        const pinChId = msg.channelId as string;
        if (pinSvId && pinChId) {
          const pinKey = ["pins", pinSvId, pinChId];
          const pinEntry = await kv.get<unknown[]>(pinKey);
          const pinList = (pinEntry.value || []) as Record<string, unknown>[];
          if (!pinList.find(p => p.id === msg.msgId)) {
            pinList.push({ id: msg.msgId, text: msg.text, author: msg.author, ts: msg.ts });
            await kv.set(pinKey, pinList);
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "unpin_message": {
        const unpinSvId = msg.serverId as string;
        const unpinChId = msg.channelId as string;
        if (unpinSvId && unpinChId) {
          const unpinKey = ["pins", unpinSvId, unpinChId];
          const unpinEntry = await kv.get<unknown[]>(unpinKey);
          if (unpinEntry.value) {
            await kv.set(unpinKey, (unpinEntry.value as Record<string, unknown>[]).filter(p => p.id !== msg.msgId));
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "channel_add": {
        // Regular user adds a channel to their own server — writes directly to KV
        const caSvId = (msg.serverId as string || "").trim();
        const caCh   = msg.channel as Record<string, unknown>;
        if (!caSvId || !caCh?.id || !caCh?.name) break;
        const caEntry = await kv.get<Record<string, unknown>>(["servers", caSvId]);
        if (!caEntry.value) break;
        // Owner, platform admin, or a member whose role has manage_channels. Before this only the owner
        // passed, but the client lets role-holders create channels, so theirs existed only locally and
        // vanished on refresh. A refusal now tells the client and resyncs it to the real channel list.
        if (!canManageServer(caEntry.value, senderName, "manage_channels", isPowerUser)) {
          ws.send(JSON.stringify({ type: "error", message: "You don't have permission to create channels here." }));
          ws.send(JSON.stringify({ type: "server_info", server: caEntry.value }));
          break;
        }
        if (((caEntry.value.channels as Array<{ id: string }>) || []).some((c) => c.id === caCh.id)) break; // already there
        if ("sendRoles" in caCh) {
          if (isServerOwner(caEntry.value, senderName) || isPowerUser) caCh.sendRoles = cleanSendRoles(caCh.sendRoles);
          else delete caCh.sendRoles;
        }
        const caChannels = [...((caEntry.value.channels as unknown[]) || []), caCh];
        const caUpdated  = { ...caEntry.value, channels: caChannels };
        if (!(await safeKvSet(["servers", caSvId], caUpdated))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save the new channel." }));
          ws.send(JSON.stringify({ type: "server_info", server: caEntry.value }));
          break;
        }
        if (publicServers.has(caSvId)) publicServers.set(caSvId, caUpdated);
        broadcastToServer(caSvId, { type: "server_channel_added", serverId: caSvId, channel: caCh, by: senderName }, null);
        break;
      }

      case "channel_update": {
        // Owner/manage_channels: rename a channel or update its properties (public, allowedRoles, etc.)
        const cuSvId = (msg.serverId as string || "").trim();
        const cuChId = (msg.channelId as string || "").trim();
        const cuChanges = msg.changes as Record<string, unknown>;
        if (!cuSvId || !cuChId || !cuChanges) break;
        const cuEntry = await kv.get<Record<string, unknown>>(["servers", cuSvId]);
        if (!cuEntry.value) break;
        if (!canManageServer(cuEntry.value, senderName, "manage_channels", isPowerUser)) {
          ws.send(JSON.stringify({ type: "error", message: "You don't have permission to edit channels here." }));
          ws.send(JSON.stringify({ type: "server_info", server: cuEntry.value }));
          break;
        }
        // Patch the matching channel inside the channels array
        const cuApplied: Record<string, unknown> = {};
        if (typeof cuChanges.name === "string") cuApplied.name = cuChanges.name.slice(0, 64);
        if (typeof cuChanges.desc === "string") cuApplied.desc = cuChanges.desc.slice(0, 256);
        if (typeof cuChanges.isPublic === "boolean") cuApplied.isPublic = cuChanges.isPublic;
        if (Array.isArray(cuChanges.allowedRoles)) cuApplied.allowedRoles = cuChanges.allowedRoles;
        if ("sendRoles" in cuChanges) {
          // choosing who may speak is the server creator's call (or a platform admin's), not any channel manager's
          if (isServerOwner(cuEntry.value, senderName) || isPowerUser) cuApplied.sendRoles = cleanSendRoles(cuChanges.sendRoles);
          else ws.send(JSON.stringify({ type: "error", message: "Only the server owner can choose who can send messages in a channel." }));
        }
        const cuChannels = ((cuEntry.value.channels as unknown[]) || []).map((c: unknown) => {
          const ch = c as Record<string, unknown>;
          return ch.id === cuChId ? { ...ch, ...cuApplied } : ch;
        });
        const cuUpdated = { ...cuEntry.value, channels: cuChannels };
        if (!(await safeKvSet(["servers", cuSvId], cuUpdated))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save that channel change." }));
          ws.send(JSON.stringify({ type: "server_info", server: cuEntry.value }));
          break;
        }
        if (publicServers.has(cuSvId)) publicServers.set(cuSvId, cuUpdated);
        // broadcast the sanitized patch: the raw client object used to be forwarded to every member
        broadcastToServer(cuSvId, { type: "server_channel_updated", serverId: cuSvId, channelId: cuChId, changes: cuApplied, by: senderName }, null);
        break;
      }

      case "channel_remove": {
        // Regular user removes a channel from their own server
        const crSvId = (msg.serverId as string || "").trim();
        const crChId = (msg.channelId as string || "").trim();
        if (!crSvId || !crChId) break;
        const crEntry = await kv.get<Record<string, unknown>>(["servers", crSvId]);
        if (!crEntry.value) break;
        if (!canManageServer(crEntry.value, senderName, "manage_channels", isPowerUser)) {
          ws.send(JSON.stringify({ type: "error", message: "You don't have permission to delete channels here." }));
          ws.send(JSON.stringify({ type: "server_info", server: crEntry.value }));
          break;
        }
        const crChannels = ((crEntry.value.channels as unknown[]) || []).filter((c: unknown) => (c as Record<string,unknown>).id !== crChId);
        const crUpdated  = { ...crEntry.value, channels: crChannels };
        if (!(await safeKvSet(["servers", crSvId], crUpdated))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't delete the channel." }));
          ws.send(JSON.stringify({ type: "server_info", server: crEntry.value }));
          break;
        }
        if (publicServers.has(crSvId)) publicServers.set(crSvId, crUpdated);
        await kv.delete(["ch_history", crChId]);
        await kv.delete(["pins", crSvId, crChId]);
        await kv.delete(["channel_lock", crChId]);
        await kv.delete(["slowmode", crChId]);
        msgHistory.delete(crChId); channelLocks.delete(crChId); slowmodes.delete(crChId);
        broadcastToServer(crSvId, { type: "server_channel_removed", serverId: crSvId, channelId: crChId, by: senderName }, null);
        break;
      }

      case "channel_delete": {
        // Legacy client-side deletion signal — gate it behind ownership just like channel_remove
        const cdSvId = (msg.serverId as string || "").trim();
        if (cdSvId) {
          const cdEntry = await kv.get<Record<string, unknown>>(["servers", cdSvId]);
          if (cdEntry.value) {
            const cdOwnerLower = (cdEntry.value.ownerIdLower as string || (cdEntry.value.ownerId as string || "").toLowerCase());
            if (cdOwnerLower !== senderName.toLowerCase() && !isPowerUser) break;
          }
        } else if (!isPowerUser) {
          break; // no serverId and not a power user — reject silently
        }
        broadcast(msg, ws);
        break;
      }

      case "video_request": {
        // Broadcast only to server members — anyone who has this video cached will respond
        const vrServerId = msg.serverId as string;
        if (vrServerId) {
          broadcastToServer(vrServerId, msg, ws);
        } else {
          broadcast(msg, ws); // fallback for old messages without serverId
        }
        break;
      }
      case "video_serve": {
        // BUG 3 FIX: msg.to is user-controlled. A malicious client could target any
        // username and flood their offline queue with large video payloads (DoS).
        // Validate: sender must have the video in their own message history context,
        // and the payload must be a plausible video URL (data: or https:).
        const serveTarget = msg.to as string;
        const serveUrl = msg.url as string || "";
        if (!serveTarget || typeof serveTarget !== "string" || serveTarget.length > 64) break;
        // Strip the actual video data from what we re-broadcast — only metadata needed to route.
        // The actual data URL stays in the direct send only, not in any queue.
        sendToUser(serveTarget, msg, false); // false = don't queue large video payloads
        break;
      }

      case "reaction": {
        // Persist reaction to KV history
        const rxChId = msg.channelId as string;
        const rxKey = ["ch_history", rxChId];
        const rxEntry = await kv.get<unknown[]>(rxKey);
        if (rxEntry.value) {
          const rxHist = rxEntry.value as Record<string,unknown>[];
          const rxMsg = rxHist.find((m: Record<string,unknown>) => m.id === msg.messageId);
          if (rxMsg) {
            const reacts = (rxMsg.reactions as Record<string,unknown>[] || []);
            let r = reacts.find((x: Record<string,unknown>) => x.emoji === msg.emoji) as Record<string,unknown>;
            if (r) {
              const users = (r.users as string[] || []);
              if (users.includes(msg.user as string)) {
                r.count = (r.count as number) - 1;
                r.users = users.filter(u => u !== msg.user);
                if ((r.count as number) <= 0) rxMsg.reactions = reacts.filter((x: Record<string,unknown>) => x.emoji !== msg.emoji);
              } else { r.count = (r.count as number) + 1; r.users = [...users, msg.user as string]; }
            } else {
              reacts.push({ emoji: msg.emoji, count: 1, users: [msg.user] });
              rxMsg.reactions = reacts;
            }
            await kv.set(rxKey, rxHist);
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "delete_message": {
        // Remove from KV history so it's gone after reload
        const delChId = msg.channelId as string;
        const delMsgId = msg.messageId as string;
        const delKey = ["ch_history", delChId];
        const delEntry = await kv.get<unknown[]>(delKey);
        if (delEntry.value) {
          // Only the message author or a power user may delete
          const delMsg = delEntry.value.find((m: unknown) => (m as Record<string,unknown>).id === delMsgId) as Record<string,unknown> | undefined;
          if (delMsg && delMsg.author !== senderName && !isPowerUser) {
            ws.send(JSON.stringify({ type: "error", message: "You can only delete your own messages." }));
            break;
          }
          const filtered = delEntry.value.filter((m: unknown) => (m as Record<string,unknown>).id !== delMsgId);
          await kv.set(delKey, filtered);
        }
        // Also remove from in-memory cache
        const delMem = msgHistory.get(delChId);
        if (delMem) msgHistory.set(delChId, delMem.filter((m: unknown) => (m as Record<string,unknown>).id !== delMsgId));
        broadcast(msg, ws);
        break;
      }

      case "edit_message": {
        // Persist edit to KV history
        const editChId = msg.channelId as string;
        const editMsgId = msg.messageId as string;
        const editKey = ["ch_history", editChId];
        const editEntry = await kv.get<unknown[]>(editKey);
        let editApplied = false;
        if (editEntry.value) {
          const editHist = editEntry.value as Record<string,unknown>[];
          const editMsg = editHist.find((m: Record<string,unknown>) => m.id === editMsgId);
          if (editMsg && editMsg.author === senderName) {
            editMsg.text = (msg.text as string || "").slice(0, 4000);
            editMsg.edited = true;
            await kv.set(editKey, editHist);
            editApplied = true;
          }
        }
        if (editApplied) broadcast(msg, ws);
        else ws.send(JSON.stringify({ type: "error", message: "You can only edit your own messages." }));
        break;
      }

      case "roles_update": {
        // Persist custom roles to server record
        const ruSvId = msg.serverId as string;
        const ruKey = ["servers", ruSvId];
        const ruEntry = await kv.get<Record<string,unknown>>(ruKey);
        if (ruEntry.value) {
          const stored = ruEntry.value;
          const storedOwnerLower = (stored.ownerIdLower as string || (stored.ownerId as string || "").toLowerCase());
          if (storedOwnerLower === senderName.toLowerCase() || isAdmin || isCoAdmin) {
            const ruRoles = msg.roles;
            const ruOk = Array.isArray(ruRoles) && ruRoles.length <= 50 && byteLen(ruRoles) <= 20_000 &&
              ruRoles.every((r) => r && typeof r.id === "string" && r.id && r.id.length <= 64 && typeof r.name === "string");
            if (!ruOk) { ws.send(JSON.stringify({ type: "error", message: "Those roles couldn't be saved." })); break; }
            if (await safeKvSet(ruKey, { ...stored, roles: ruRoles })) {
              if (publicServers.has(ruSvId)) publicServers.get(ruSvId)!.roles = ruRoles;
            }
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "role_assign": {
        // Persist role assignment to server record
        const raSvId = msg.serverId as string;
        const raKey = ["servers", raSvId];
        const raEntry = await kv.get<Record<string,unknown>>(raKey);
        if (raEntry.value) {
          const stored = raEntry.value;
          // Permission check: only server owner or platform admin/co-admin may assign roles
          const raOwnerLower = (stored.ownerIdLower as string || (stored.ownerId as string || "").toLowerCase());
          if (raOwnerLower !== senderName.toLowerCase() && !isPowerUser) {
            ws.send(JSON.stringify({ type: "error", message: "Only the server owner or an admin can assign roles." }));
            break;
          }
          const memberRoles = (stored.memberRoles as Record<string,string> || {});
          const raKnown = msg.role === "member" || !msg.role || msg.role === "mod" ||
            ((stored.roles as Array<{ id: string }>) || []).some((r) => r.id === msg.role);
          if (!raKnown) { ws.send(JSON.stringify({ type: "error", message: "That role doesn't exist." })); break; }
          if (msg.role === 'member' || !msg.role) {
            delete memberRoles[msg.target as string];
          } else {
            memberRoles[msg.target as string] = msg.role as string;
          }
          await kv.set(raKey, { ...stored, memberRoles });
          if (publicServers.has(raSvId)) publicServers.get(raSvId)!.memberRoles = memberRoles;
        }
        broadcast(msg, ws);
        break;
      }

      case "voice_join":
        if (info) (info as Record<string,unknown>).vcChannelId = (msg.channelId as string || null);
        broadcast(msg, ws);
        break;
      case "voice_leave":
        if (info) (info as Record<string,unknown>).vcChannelId = null;
        broadcast(msg, ws);
        break;
      case "join_channel": // client sends this on channel select — just broadcast presence
        broadcast(msg, ws);
        break;

      case "voice_ghost_join": {
        // Admin silently joins a voice channel — NOT broadcast to other members.
        // Server remembers they're in the channel for signal routing only.
        // No sound, no name shown, until they choose to unmute/reveal.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        // Ack back to admin only — includes current members in that channel
        const ghostChId = (msg.channelId as string || "").trim();
        const currentMembers: string[] = [];
        for (const [, ci] of clients) {
          // We track voice channel membership via in-memory client info
          if ((ci as Record<string,unknown>).vcChannelId === ghostChId && ci.name !== senderName) {
            currentMembers.push(ci.name as string);
          }
        }
        // Tag this client as ghost-listening to this channel
        if (info) (info as Record<string,unknown>).vcChannelId = ghostChId;
        ws.send(JSON.stringify({ type: "voice_ghost_ack", channelId: ghostChId, members: currentMembers }));
        break;
      }

      case "voice_reveal": {
        // Admin reveals themselves — broadcast as a normal voice_join from here
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const revealChId = (msg.channelId as string || "").trim();
        broadcast({ type: "voice_join", channelId: revealChId, user: senderName, serverId: msg.serverId }, null);
        break;
      }

      case "voice_signal": {
        const target = (msg.to as string || "").toLowerCase();
        for (const [tws, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === target && tws.readyState === WebSocket.OPEN) {
            tws.send(JSON.stringify(msg));
          }
        }
        break;
      }

      // ═════════ Calls ═════════
      // The server owns the call: who is ringing, who joined, when it started, when it ended. That is what lets
      // it ring someone who comes online mid-ring, end a ring when the caller gives up, keep a 3-person call going
      // when one person leaves, and write "X started a call · lasted 12m" into the chat.
      case "vcall_invite": {
        const me = senderName.toLowerCase();
        const callId = typeof msg.callId === "string" && /^[A-Za-z0-9_-]{4,64}$/.test(msg.callId) ? msg.callId : "";
        if (!callId) break;
        let targets: string[] = [], gid: string | null = null;
        if (typeof msg.gid === "string" && msg.gid) {
          const g = await getGroup(msg.gid);
          if (!g || !(g.members as string[]).includes(me)) break;
          gid = g.id as string; targets = (g.members as string[]).filter((l) => l !== me);
        } else {
          const to = String(msg.to || "").trim().toLowerCase();
          if (!to || to === me || !(await kv.get(["accounts", to])).value) break;
          targets = [to];
        }
        let call = activeCalls.get(callId);
        if (!call) {
          call = {
            id: callId, participants: new Set([senderName]), startedAt: Date.now(), gid, conv: gid ? "g:" + gid : dmConv(me, targets[0]),
            starter: senderName, starterLower: me, invited: new Map(), answeredAt: null, ringTimers: new Map(), wsOf: new Map([[me, ws]]), finalized: false,
          };
          activeCalls.set(callId, call);
        } else if (![...call.participants].some((p) => p.toLowerCase() === me)) {
          ws.send(JSON.stringify({ type: "error", message: "You're not in that call." })); break;
        }
        for (const l of targets) {
          const busy = [...call.participants].filter((p) => p.toLowerCase() !== me).length + [...call.invited.values()].filter((i) => i.state === "ringing").length;
          if (1 + busy >= CALL_MAX) { ws.send(JSON.stringify({ type: "error", message: `A call can have at most ${CALL_MAX} people.` })); break; }
          if ([...call.participants].some((p) => p.toLowerCase() === l) || call.invited.get(l)?.state === "ringing") continue;
          const nm = await nameOf(l);
          startRing(call, l, nm);
          const online = socketsOf(l).length > 0;
          await deliverInvite(call, l);
          // if they're offline right now they'll be rung as soon as they come online (see deliverCallsTo)
          ws.send(JSON.stringify({ type: "vcall_ringing", callId, to: nm, online }));
        }
        await broadcastCallState(call);
        break;
      }
      case "vcall_accept": {
        const me = senderName.toLowerCase();
        const call = activeCalls.get(String(msg.callId || ""));
        const inv = call?.invited.get(me);
        if (!call || call.finalized || !inv || inv.state !== "ringing") { ws.send(JSON.stringify({ type: "vcall_end", callId: msg.callId, reason: "gone", from: "" })); break; }
        if (call.participants.size >= CALL_MAX) { ws.send(JSON.stringify({ type: "error", message: "That call is full." })); break; }
        joinCall(call, me, senderName, ws);
        break;
      }
      case "vcall_join": {   // join a call that's in progress (the banner in the chat)
        const me = senderName.toLowerCase();
        const call = activeCalls.get(String(msg.callId || ""));
        if (!call || call.finalized) { ws.send(JSON.stringify({ type: "vcall_end", callId: msg.callId, reason: "gone", from: "" })); break; }
        const members = await callConvMembers(call);
        if (!members.includes(me) && !call.invited.has(me)) break;
        if (call.participants.size >= CALL_MAX) { ws.send(JSON.stringify({ type: "error", message: "That call is full." })); break; }
        if ([...call.participants].some((p) => p.toLowerCase() === me)) break;
        joinCall(call, me, senderName, ws);
        break;
      }
      case "vcall_decline": {
        const me = senderName.toLowerCase();
        const call = activeCalls.get(String(msg.callId || ""));
        const inv = call?.invited.get(me);
        if (!call || !inv || inv.state !== "ringing") break;
        inv.state = "declined"; stopRing(call, me);
        for (const p of call.participants) sendToUser(p, { type: "vcall_decline", callId: call.id, from: senderName }, false);
        for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify({ type: "vcall_handled", callId: call.id }));
        await maybeEndRinging(call);
        break;
      }
      case "vcall_signal": {
        // WebRTC signalling between two people in the same call. `from` is the logged-in user, never the message.
        const call = activeCalls.get(String(msg.callId || ""));
        const to = String(msg.to || "");
        if (!call || !to) break;
        const inCall = (n: string) => [...call.participants].some((p) => p.toLowerCase() === n.toLowerCase());
        if (!inCall(senderName) || !inCall(to)) break;
        sendToUser(to, { ...(msg as Rec3), from: senderName }, false);
        break;
      }
      case "vcall_state": {   // my mic / headphone state → a badge on my avatar for everyone else in the call
        const call = activeCalls.get(String(msg.callId || ""));
        const meL = senderName.toLowerCase();
        if (!call || ![...call.participants].some((p) => p.toLowerCase() === meL)) break;
        const st = { muted: msg.muted === true, deafened: msg.deafened === true };
        (call.peerState ||= new Map()).set(meL, st);
        for (const p of call.participants) if (p.toLowerCase() !== meL) sendToUser(p, { type: "vcall_peer_state", callId: call.id, user: senderName, ...st }, false);
        break;
      }
      case "vcall_leave":
      case "vcall_end": {   // hanging up now only ends the call for YOU (it ends for everyone only when nobody is left)
        const call = activeCalls.get(String(msg.callId || ""));
        if (call) await leaveCall(call, senderName.toLowerCase());
        break;
      }
      case "admin_list_calls": {
        // Return all currently tracked active calls
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const callList: Record<string, unknown>[] = [];
        for (const [callId, call] of activeCalls) {
          callList.push({ callId, participants: [...call.participants], startedAt: call.startedAt });
        }
        ws.send(JSON.stringify({ type: "admin_calls_list", calls: callList }));
        break;
      }

      case "admin_vcall_ghost_join": {
        // Admin silently injects into an existing call.
        // Strategy: the server forges a vcall_accept from the ghost to each participant,
        // then forwards all future vcall_signal messages for this callId to/from the admin.
        // The admin starts muted — they can reveal themselves later via admin_vcall_ghost_reveal.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const ghostCallId = msg.callId as string;
        if (!ghostCallId || !activeCalls.has(ghostCallId)) {
          ws.send(JSON.stringify({ type: "error", message: "Call not found or already ended." })); break;
        }
        const call = activeCalls.get(ghostCallId)!;
        call.participants.add(senderName);
        // Register admin as ghost (hidden) in this call
        ghostCalls.set(ghostCallId, senderName);
        // Ack to admin with participant list so they can initiate WebRTC with each
        ws.send(JSON.stringify({
          type: "vcall_ghost_ack",
          callId: ghostCallId,
          participants: [...call.participants].filter(p => p !== senderName),
        }));
        break;
      }

      case "admin_vcall_ghost_reveal": {
        // Admin unmutes/reveals — broadcast a vcall_accept from them to all participants
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const revealCallId = msg.callId as string;
        if (!revealCallId || !activeCalls.has(revealCallId)) break;
        ghostCalls.delete(revealCallId);
        const revealCall = activeCalls.get(revealCallId)!;
        // Tell all participants that admin joined
        for (const participant of revealCall.participants) {
          if (participant === senderName) continue;
          sendToUser(participant, {
            type: "vcall_accept",
            callId: revealCallId,
            from: senderName,
            to: participant,
            fromColor: info?.color || "#6c63ff",
            fromPfp: info?.pfp || null,
          }, false);
        }
        break;
      }

      case "server_create": {
        console.log(`[server_create] RECEIVED from ${senderName} id=${msg.serverId} name=${msg.name}`);
        {
          const scId = msg.serverId as string;
          if (!scId || typeof scId !== "string") break;
          // A deleted server must stay deleted — retries / stale tabs land here.
          if (await isTombstoned(scId)) {
            ws.send(JSON.stringify({ type: "server_gone", serverId: scId }));
            break;
          }
          // Re-sending a create for a server that already exists (lost ACK, retry, KV recovery) must not
          // clobber it, and nobody may hijack somebody else's server by reusing its id.
          const scExisting = (await kv.get<Record<string, unknown>>(["servers", scId])).value;
          if (scExisting) {
            const exOwner = ((scExisting.ownerIdLower as string) || ((scExisting.ownerId as string) || "").toLowerCase());
            if (exOwner !== senderName.toLowerCase() && !isPowerUser) {
              ws.send(JSON.stringify({ type: "error", message: "That server id is already taken." }));
              break;
            }
            await kv.set(["server_member", scId, senderName], { joinedAt: Date.now() });
            await addServerToUser(senderName, scId);
            const ci0 = clients.get(ws); if (ci0) (ci0.serverIds as Set<string>)?.add(scId);
            ws.send(JSON.stringify({ type: "server_create_ok", serverId: scId }));
            break;
          }
        }
        // FIX: store ownerId as the canonical display name from the account record,
        // but guarantee it's always findable via case-insensitive lookup.
        // senderName comes from acct.name (display name), which is fine for display.
        // The ownership check on clients uses case-insensitive compare so this is safe.
        const svData = {
          id: msg.serverId, name: msg.name, desc: msg.desc || "",
          icon: msg.icon || null, color: msg.color || "#6c63ff",
          memberCount: 1, createdAt: msg.createdAt || Date.now(),
          channels: msg.channels || [], ownerId: senderName,
          ownerIdLower: senderName.toLowerCase(), // FIX: add lowercased copy for reliable matching
          isPublic: msg.isPublic !== false,
        };
        if (!(await safeKvSet(["servers", msg.serverId as string], svData))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save the server (too large?). Try again without a custom icon." }));
          break;
        }
        if (svData.isPublic) publicServers.set(msg.serverId as string, svData);

        // Verify it actually wrote
        const verifyWrite = await kv.get(["servers", msg.serverId as string]);
        console.log(`[server_create] KV write verified=${!!verifyWrite.value} id=${msg.serverId} owner=${senderName}`);

        await kv.set(["server_member", msg.serverId as string, senderName], { joinedAt: Date.now() });
        await addServerToUser(senderName, msg.serverId as string);
        { const ci1 = clients.get(ws); if (ci1) (ci1.serverIds as Set<string>)?.add(msg.serverId as string); }

        // Verify user_servers index
        const verifyIndex = await kv.get(["user_servers", senderName.toLowerCase()]);
        console.log(`[server_create] user_servers index for ${senderName.toLowerCase()}=${JSON.stringify(verifyIndex.value)}`);

        // FIX: Broadcast authoritative svData (with correct ownerId) so other clients
        // can add the server to their discover list immediately without a get_server_list fetch.
        broadcast({ type: "server_create", serverId: svData.id, name: svData.name, desc: svData.desc,
          icon: svData.icon, color: svData.color, memberCount: svData.memberCount,
          createdAt: svData.createdAt, channels: svData.channels, ownerId: svData.ownerId,
          isPublic: svData.isPublic }, ws);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "server_create_ok", serverId: msg.serverId }));
          console.log(`[server_create] ACK sent to ${senderName}`);
        } else {
          console.log(`[server_create] WARNING: ws not open (readyState=${ws.readyState}), could not ACK`);
        }
        break;
      }

      case "server_update": {
        const sid = msg.serverId as string;
        if (await isTombstoned(sid)) { ws.send(JSON.stringify({ type: "server_gone", serverId: sid })); break; }
        // Always start from the stored record. This handler used to merge the message onto the IN-MEMORY copy
        // (per server instance, easily stale) and write that back, so a stale copy silently reverted channels,
        // roles and permissions that had been saved since. server_update edits a server; it never creates one.
        const existing = await kv.get<Record<string, unknown>>(["servers", sid]);
        if (!existing.value) break;
        const storedOwnerLower = (existing.value.ownerIdLower as string || (existing.value.ownerId as string || "").toLowerCase());
        if (storedOwnerLower !== senderName.toLowerCase() && !isAdmin && !isCoAdmin) {
          console.log(`[server_update] BLOCKED: ${senderName} tried to update server ${sid} owned by ${existing.value.ownerId}`);
          break;
        }
        // Only these fields can change here. The client also sends its whole channel list, memberCount and
        // createdAt with every settings save: applying those overwrote the real data with whatever the sender's
        // cache held (channels, who-can-send locks, deleted channels coming back...). Channels, roles and
        // counts have their own messages and are never taken from here. Owner fields come from the record.
        const upd: Record<string, unknown> = {};
        if (typeof msg.name === "string" && msg.name.trim()) upd.name = msg.name.trim().slice(0, 64);
        if (typeof msg.desc === "string") upd.desc = msg.desc.slice(0, 256);
        if (typeof msg.color === "string" && /^#[0-9a-fA-F]{3,8}$/.test(msg.color)) upd.color = msg.color;
        if (typeof msg.isPublic === "boolean") upd.isPublic = msg.isPublic;
        if (msg.icon === null) upd.icon = null;
        else if (typeof msg.icon === "string") {
          if (byteLen(msg.icon) <= 45_000) upd.icon = msg.icon;
          else ws.send(JSON.stringify({ type: "error", message: "That server icon is too large to save. Pick a smaller image." }));
        }
        const updatedSv = { ...existing.value, ...upd };
        if (!(await safeKvSet(["servers", sid], updatedSv))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save the server settings." }));
          break;
        }
        if (updatedSv.isPublic !== false) publicServers.set(sid, updatedSv); else publicServers.delete(sid);
        // Tell members only what actually changed
        broadcast({ type: "server_update", serverId: sid, ...upd, ownerId: updatedSv.ownerId }, ws);
        break;
      }

      case "server_delete": {
        const delSvId = msg.serverId as string;
        const delSvEntry = await kv.get<Record<string, unknown>>(["servers", delSvId]);
        // FIX #1: Verify the sender is the server owner or a platform admin/co-admin
        const delSvOwnerLower = (
          (delSvEntry.value?.ownerIdLower as string) ||
          (delSvEntry.value?.ownerId as string || "").toLowerCase()
        );
        if (delSvOwnerLower && delSvOwnerLower !== senderName.toLowerCase() && !isPowerUser) {
          console.log(`[server_delete] BLOCKED: ${senderName} tried to delete server ${delSvId} owned by ${delSvEntry.value?.ownerId}`);
          ws.send(JSON.stringify({ type: "error", message: "Only the server owner can delete this server." }));
          break;
        }
        // purgeServer removes the server, channel history, pins, member + index entries AND leaves a
        // tombstone so a stale client can't bring it back from the dead.
        await purgeServer(delSvId, senderName);
        // Echo to the sender too: their other tabs/devices must drop it as well.
        broadcast(msg, null);
        break;
      }

      case "leave_server": {
        // FIX #6: Prevent the owner from leaving — orphaned ownerless servers can
        // never be managed or deleted by anyone. Owner must delete the server instead.
        const leaveSvEntry = await kv.get<Record<string, unknown>>(["servers", msg.serverId as string]);
        const leaveSvOwnerLower = (
          (leaveSvEntry.value?.ownerIdLower as string) ||
          (leaveSvEntry.value?.ownerId as string || "").toLowerCase()
        );
        if (leaveSvOwnerLower && leaveSvOwnerLower === senderName.toLowerCase()) {
          ws.send(JSON.stringify({ type: "error", message: "You own this server. Transfer ownership or delete it before leaving." }));
          break;
        }
        await kv.delete(["server_member", msg.serverId as string, senderName]);
        await removeServerFromUser(senderName, msg.serverId as string);
        // every socket this user has open (other tabs) leaves too
        for (const [, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === senderName.toLowerCase()) (ci.serverIds as Set<string> | undefined)?.delete(msg.serverId as string);
        }
        await recountMembers(msg.serverId as string);
        broadcast(msg, ws);
        break;
      }

      case "join_server": {
        const jsvId = msg.serverId as string;
        // Tell the client precisely why a join failed, so it can undo its optimistic "Joined" state
        // instead of showing a server the account isn't actually in.
        const joinFail = (message: string) => ws.send(JSON.stringify({ type: "error", context: "join_server", serverId: jsvId, message }));
        if (await isTombstoned(jsvId)) { ws.send(JSON.stringify({ type: "server_gone", serverId: jsvId })); break; }
        const jsvEntry = await kv.get<Record<string,unknown>>(["servers", jsvId]);
        const jsv = jsvEntry.value;
        if (!jsv) { joinFail("Server not found."); break; }
        // Non-power-users may only join public servers
        if (jsv.isPublic === false && !isPowerUser) { joinFail("That server is private."); break; }

        // Membership is written FIRST. Previously the (unguarded) server rewrite came before it, so any
        // failure there meant the join was never recorded and the account later "wasn't in any servers".
        const jsvMemKey = ["server_member", jsvId, senderName];
        const alreadyMember = !!(await kv.get(jsvMemKey)).value;
        if (!alreadyMember) await kv.set(jsvMemKey, { joinedAt: Date.now() });
        await addServerToUser(senderName, jsvId);
        // Track in every open socket of this user so scoped broadcasts + p2p history work immediately
        for (const [, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === senderName.toLowerCase()) {
            if (!ci.serverIds) ci.serverIds = new Set<string>();
            (ci.serverIds as Set<string>).add(jsvId);
          }
        }
        if (!alreadyMember) await recountMembers(jsvId);
        const jsvFresh = (await kv.get<Record<string,unknown>>(["servers", jsvId])).value || jsv;
        // Confirm to the joiner with the authoritative server record (channels, roles, count)
        ws.send(JSON.stringify({ type: "join_ok", serverId: jsvId }));
        ws.send(JSON.stringify({ type: "server_info", server: await serverInfoFor(jsvId, jsvFresh, true) }));
        if (!alreadyMember) {
          broadcast(msg, ws);
          // so open member lists add them right away (the broadcast above only bumps the count)
          const jAcct = (await kv.get<Record<string, unknown>>(["accounts", senderName.toLowerCase()])).value;
          if (jAcct) broadcastToServer(jsvId, { type: "member_join", serverId: jsvId, member: { ...profileOf(jAcct), online: true, status: userStatus.get(senderName.toLowerCase()) || "online" } }, ws);
        }
        break;
      }

      case "announce_servers":
        // FIX #4: Only allow announcing servers the sender actually owns (or power users)
        for (const sv of (msg.servers as unknown[] || [])) {
          const s = sv as Record<string, unknown>;
          if (!s.id) continue;
          if (await isTombstoned(s.id as string)) continue;
          // FIX: Check if server already exists - if so, preserve ownerId
          const existingSv = await kv.get<Record<string, unknown>>(["servers", s.id as string]);
          const existingOwner = existingSv.value?.ownerId;
          const existingOwnerLower = existingSv.value?.ownerIdLower || (existingOwner as string || "").toLowerCase();
          // If a stored owner exists and doesn't match the sender, skip unless power user
          if (existingOwnerLower && existingOwnerLower !== senderName.toLowerCase() && !isPowerUser) {
            console.log(`[announce_servers] BLOCKED: ${senderName} tried to announce server ${s.id} owned by ${existingOwner}`);
            continue;
          }
          // This used to REPLACE the stored server with whatever the client sent: it forced isPublic to true
          // (a private server became public the next time its settings were saved), dropped roles and
          // member roles, and put back channels the owner had deleted. For a server that already exists
          // only the cosmetic fields may change here; channels/roles/visibility have their own messages.
          const annIcon = typeof s.icon === "string" && s.icon && byteLen(s.icon) <= 45_000 ? s.icon : undefined;
          const svEntry: Record<string, unknown> = existingSv.value
            ? {
                ...existingSv.value,
                name: typeof s.name === "string" && s.name ? s.name.slice(0, 64) : existingSv.value.name,
                desc: typeof s.desc === "string" ? s.desc.slice(0, 256) : existingSv.value.desc,
                color: typeof s.color === "string" && s.color ? s.color : existingSv.value.color,
                ...(annIcon ? { icon: annIcon } : {}),
              }
            : {
                id: s.id, name: s.name, desc: s.desc || "",
                icon: annIcon || null, color: s.color || "#6c63ff",
                memberCount: s.memberCount || 1, createdAt: s.createdAt || Date.now(),
                channels: s.channels || [],
                ownerId: s.ownerId || senderName,
                ownerIdLower: (s.ownerId as string || senderName).toLowerCase(),
                isPublic: s.isPublic !== false,
              };
          if (!(await safeKvSet(["servers", s.id as string], svEntry))) continue;
          if (svEntry.isPublic !== false) publicServers.set(s.id as string, svEntry);
          else publicServers.delete(s.id as string);
        }
        break;

      case "get_server_list": {
        const svListIter = kv.list<Record<string, unknown>>({ prefix: ["servers"] });
        const svList: Record<string, unknown>[] = [];
        for await (const item of svListIter) {
          const sv = item.value;
          if (sv && sv.isPublic !== false) {
            svList.push({ id: sv.id, name: sv.name, desc: sv.desc || "", color: sv.color || "#6c63ff", icon: null, memberCount: sv.memberCount || 1, createdAt: sv.createdAt || 0, channels: sv.channels || [], ownerId: sv.ownerId, isPublic: true });
          }
        }
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "server_list", servers: svList }));
        break;
      }

      case "get_server_info": {
        const svInfoEntry = await kv.get<Record<string, unknown>>(["servers", msg.serverId as string]);
        const svInfo = svInfoEntry.value || publicServers.get(msg.serverId as string);
        if (svInfo && ws.readyState === WebSocket.OPEN) {
          const gsiMember = !!(info.serverIds as Set<string> | undefined)?.has(msg.serverId as string) || isPowerUser;
          ws.send(JSON.stringify({ type: "server_info", server: await serverInfoFor(msg.serverId as string, svInfo, gsiMember) }));
        }
        break;
      }

      case "fetch_dm_history": {
        const me = senderName.toLowerCase();
        const withLower = String(msg.with || "").trim().toLowerCase();
        if (!withLower) break;
        const conv = dmConv(me, withLower);
        const [hist, prefs, myRead, theirRead, theirSet, withName] = await Promise.all([
          kv.get<unknown[]>(dmHistKey(me, withLower)), getPrefs(me), getRead(conv, me), getRead(conv, withLower), getSettings(withLower), nameOf(withLower),
        ]);
        const cleared = Number(prefs[conv]?.clearedBefore) || 0;
        const messages = ((hist.value || []) as Rec3[]).filter((m) => msgTs(m) > cleared);
        // The other person's read position is only shared if THEY allow read receipts
        const reads: Record<string, number> = {};
        if (theirSet.readReceipts && theirRead) reads[withName] = theirRead;
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "dm_history", with: withName, messages, reads, myRead }));
        break;
      }

      case "fetch_dm_contacts": {
        const me = senderName.toLowerCase();
        const prefs = await getPrefs(me);
        const peers = await getDmPeers(me);
        const contacts = await Promise.all(peers.map(async (other) => {
          const conv = dmConv(me, other);
          const [acct, hist, readTs] = await Promise.all([kv.get<Rec3>(["accounts", other]), kv.get<unknown[]>(dmHistKey(me, other)), getRead(conv, me)]);
          const pr = prefs[conv] || {};
          const msgs = ((hist.value || []) as Rec3[]).filter((m) => msgTs(m) > (Number(pr.clearedBefore) || 0));
          const last = msgs[msgs.length - 1];
          const pres = presenceOf(other, me);
          return {
            name: (acct.value?.name as string) || other, pfp: safePfp(acct.value?.pfp), color: acct.value?.color || null,
            last: previewOf(last), lastTs: last ? msgTs(last) : 0,
            unread: msgs.filter((m) => msgTs(m) > readTs && countsAsUnread(m, me)).length,
            online: pres.online, status: pres.online ? pres.status : undefined,
            prefs: { muted: pr.muted || false, pinned: !!pr.pinned, hidden: !!pr.hidden },
          };
        }));
        const groups = await Promise.all((await userGroupIds(me)).map(async (gid) => {
          const g = await getGroup(gid); if (!g) return null;
          const conv = "g:" + gid;
          const [hist, readTs] = await Promise.all([kv.get<unknown[]>(["group_history", gid]), getRead(conv, me)]);
          const pr = prefs[conv] || {};
          const msgs = ((hist.value || []) as Rec3[]).filter((m) => msgTs(m) > (Number(pr.clearedBefore) || 0));
          const last = msgs[msgs.length - 1];
          return {
            ...(await groupView(g, me)), last: previewOf(last) || (last?.text as string) || "", lastTs: last ? msgTs(last) : Number(g.createdAt) || 0,
            unread: msgs.filter((m) => msgTs(m) > readTs && countsAsUnread(m, me)).length,
            prefs: { muted: pr.muted || false, pinned: !!pr.pinned, hidden: !!pr.hidden },
          };
        }));
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "dm_contacts", contacts: contacts.sort((a, b) => b.lastTs - a.lastTs), groups: groups.filter(Boolean), settings: await getSettings(me) }));
        }
        break;
      }

      case "get_members": {
        const svId = msg.serverId as string;
        const reqId = msg.reqId;
        const viewer = senderName.toLowerCase();
        // Only members can see who else is in a server
        if (!svId || !((info.serverIds as Set<string> | undefined)?.has(svId) || isPowerUser)) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "member_list", serverId: svId, reqId, members: [] }));
          break;
        }
        // Reply right away with a fast, consistent list...
        const members = await buildMemberList(svId, viewer);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "member_list", serverId: svId, reqId, members }));
        // ...then (at most every 10 minutes per server) look for people missing from the member records, and
        // send an updated list if any were found.
        if (await ghostSweep(svId) > 0 && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "member_list", serverId: svId, reqId, members: await buildMemberList(svId, viewer) }));
        }
        break;
      }

      // Look up public profiles by name (authors of messages you can see, people who left, etc.)
      case "get_profiles": {
        const gpNames = Array.isArray(msg.names) ? (msg.names as unknown[]).filter((n): n is string => typeof n === "string" && n.length <= 32) : [];
        const gpOut: Record<string, unknown>[] = [];
        for (const n of new Set(gpNames.slice(0, 60).map((x) => x.toLowerCase()))) {
          const a = (await kv.get<Record<string, unknown>>(["accounts", n])).value;
          if (a) {
            const p = profileOf(a), pe = await getProfileExt(n);
            p.ext = pe.ext;
            // the (large) banner image only goes out when a profile page is opened, never in bulk lookups
            if (msg.full === true && gpNames.length <= 3 && pe.banner) p.bannerImg = pe.banner;
            gpOut.push(p);
          }
        }
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "profiles", profiles: gpOut }));
        break;
      }

      case "dm": {
        // Frozen users can't send DMs either
        if (frozenUsers.has(senderName.toLowerCase())) {
          const freeze = frozenUsers.get(senderName.toLowerCase())!;
          ws.send(JSON.stringify({ type: "error", message: `Your account is frozen: ${freeze.reason}` }));
          break;
        }
        // The sender is the logged-in user. (This used to trust msg.from, so anyone could write messages into
        // other people's conversations.)
        const me = senderName.toLowerCase();
        const toLower = String(msg.to || "").trim().toLowerCase();
        if (!toLower || toLower === me) break;
        const target = (await kv.get<Rec3>(["accounts", toLower])).value;
        if (!target) { ws.send(JSON.stringify({ type: "error", message: "That user doesn't exist." })); break; }
        const myAcct = (await kv.get<Rec3>(["accounts", me])).value;
        const m = cleanChatMessage(msg as Rec3, senderName, myAcct?.color);
        // stored copy drops inline base64 (too big for KV); live recipients get the full message
        if (!(await appendHistory(dmHistKey(me, toLower), { ...sanitizeMsgForStore(m), _stored: m.ts }))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save that DM to history." }));
          break;
        }
        await addDmPeer(me, toLower); await addDmPeer(toLower, me);
        const conv = dmConv(me, toLower);
        await unhide(me, conv); await unhide(toLower, conv);
        sendToUser(target.name as string, { ...m, type: "dm", to: target.name }, true);
        // tell the sender the canonical timestamp, and keep their other tabs/devices in step
        ws.send(JSON.stringify({ type: "dm_ack", with: target.name, id: m.id, ts: m.ts }));
        for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify({ type: "dm_sync", with: target.name, message: m }));
        break;
      }

      case "dm_request":
      case "dm_accept":
      case "dm_decline":
        sendToUser(msg.to as string, msg, true);
        break;

      case "friend_request": {
        const me = senderName.toLowerCase();
        const toLower = String(msg.to || "").trim().toLowerCase();
        const fail = (reason: string) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "friend_request_result", ok: false, reason, to: msg.to })); };
        if (!toLower) break;
        if (toLower === me) { fail("self"); break; }
        const target = (await kv.get<Record<string, unknown>>(["accounts", toLower])).value;
        if (!target) { fail("not_found"); break; }
        const myFriends = (((await kv.get<Array<Record<string, unknown>>>(["friends", me])).value) || []);
        if (myFriends.some((f) => String(f.name).toLowerCase() === toLower)) { fail("already_friends"); break; }
        // They had already asked me: two requests crossing means "yes"
        if ((await kv.get(["friend_requests", me, toLower])).value) { await makeFriends(me, toLower); break; }
        if ((await kv.get(["friend_requests", toLower, me])).value) { fail("already_sent"); break; }
        let outN = 0;
        for await (const _ of kv.list({ prefix: ["friend_requests_out", me] })) { if (++outN >= 50) break; }
        if (outN >= 50) { fail("too_many"); break; }
        const myAcct = (await kv.get<Record<string, unknown>>(["accounts", me])).value;
        // `from` is the logged-in name, never what the message claims (it used to be spoofable)
        await kv.set(["friend_requests", toLower, me], { from: senderName, fromPfp: safePfp(myAcct?.pfp), fromColor: myAcct?.color || null, ts: Date.now() });
        await kv.set(["friend_requests_out", me, toLower], { to: target.name, ts: Date.now() });
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "friend_request_result", ok: true, to: target.name, pfp: safePfp(target.pfp), color: target.color || null }));
        sendToUser(target.name as string, { type: "friend_request", from: senderName, fromPfp: safePfp(myAcct?.pfp), fromColor: myAcct?.color || null }, true);
        break;
      }

      case "friend_accept": {
        const me = senderName.toLowerCase();
        const to = String(msg.to || "").trim().toLowerCase();
        if (!to) break;
        // Only an actual pending request can be accepted. Before, "friend_accept" with no request at all
        // simply added the sender to anyone's friends list.
        if (!(await kv.get(["friend_requests", me, to])).value) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "friend_request_result", ok: false, reason: "no_request", to: msg.to }));
          break;
        }
        await makeFriends(me, to);
        break;
      }

      case "friend_decline": {
        const me = senderName.toLowerCase();
        const to = String(msg.to || "").trim().toLowerCase();
        if (!to) break;
        await kv.delete(["friend_requests", me, to]);
        await kv.delete(["friend_requests_out", to, me]);
        const tAcct = (await kv.get<Record<string, unknown>>(["accounts", to])).value;
        if (tAcct) sendToUser(tAcct.name as string, { type: "friend_decline", from: senderName }, true);
        break;
      }

      // Take back a request I sent
      case "friend_cancel": {
        const me = senderName.toLowerCase();
        const to = String(msg.to || "").trim().toLowerCase();
        if (!to) break;
        await kv.delete(["friend_requests", to, me]);
        await kv.delete(["friend_requests_out", me, to]);
        const tAcct = (await kv.get<Record<string, unknown>>(["accounts", to])).value;
        if (tAcct) sendToUser(tAcct.name as string, { type: "friend_request_cancelled", from: senderName }, false);
        break;
      }

      case "friend_remove": {
        const me = senderName.toLowerCase();
        const target = String(msg.target || "").trim().toLowerCase();
        if (!target) break;
        for (const [owner, other] of [[me, target], [target, me]]) {
          await withLock("friends:" + owner, async () => {
            const key = ["friends", owner];
            const list = (((await kv.get<Array<Record<string, unknown>>>(key)).value) || []);
            await kv.set(key, list.filter((f) => String(f.name).toLowerCase() !== other));
          });
        }
        const tAcct = (await kv.get<Record<string, unknown>>(["accounts", target])).value;
        // the other person, and my own other tabs
        if (tAcct) sendToUser(tAcct.name as string, { type: "friend_removed", by: senderName }, false);
        sendToUser(senderName, { type: "friend_removed", by: tAcct?.name || msg.target }, false);
        break;
      }

      case "dm_delete": {
        const me = senderName.toLowerCase();
        const toLower = String(msg.to || "").trim().toLowerCase();
        const id = String(msg.messageId || "");
        if (!toLower || !id) break;
        const key = dmHistKey(me, toLower);
        let removed = false, denied = false;
        await withLock("hist:" + key.join("/"), async () => {
          const list = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = list.find((x) => x.id === id);
          if (!m) return;
          if (!isMine(m, me) && !isPowerUser) { denied = true; return; }
          removed = await safeKvSet(key, list.filter((x) => x.id !== id));
        });
        if (denied) { ws.send(JSON.stringify({ type: "error", message: "You can only delete your own messages." })); break; }
        if (removed) {
          const otherName = await nameOf(toLower);
          const payload = JSON.stringify({ type: "dm_delete", from: senderName, to: otherName, messageId: id });
          sendToUser(otherName, JSON.parse(payload), false);
          for (const [w] of socketsOf(me)) if (w !== ws) w.send(payload);
        }
        break;
      }

      case "dm_reaction": {
        const me = senderName.toLowerCase();
        const toLower = String(msg.to || "").trim().toLowerCase();
        const id = String(msg.messageId || ""), emoji = String(msg.emoji || "").slice(0, 16);
        if (!toLower || !id || !emoji) break;
        const key = dmHistKey(me, toLower);
        let changed = false, nowOn = false;
        await withLock("hist:" + key.join("/"), async () => {
          const hist = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = hist.find((x) => x.id === id);
          if (!m || m.system) return;
          const reacts = (Array.isArray(m.reactions) ? m.reactions : []) as Rec3[];
          const rr = reacts.find((x) => x.emoji === emoji);
          const has0 = !!rr && ((rr.users as string[]) || []).includes(senderName);
          const want = typeof msg.on === "boolean" ? msg.on : !has0;   // explicit on/off is safe to replay; no `on` = the old toggle
          if (want === has0) return;
          nowOn = want;
          if (rr) {
            const users = (rr.users as string[]) || [];
            if (users.includes(senderName)) {
              rr.count = Math.max(0, (rr.count as number) - 1); rr.users = users.filter((u) => u !== senderName);
              if ((rr.count as number) <= 0) m.reactions = reacts.filter((x) => x.emoji !== emoji);
            } else { rr.count = (rr.count as number) + 1; rr.users = [...users, senderName]; }
          } else { reacts.push({ emoji, count: 1, users: [senderName] }); m.reactions = reacts; }
          changed = await safeKvSet(key, hist);
        });
        if (changed) {
          const otherName = await nameOf(toLower);
          const payload = { type: "dm_reaction", to: otherName, user: senderName, messageId: id, emoji, on: nowOn };
          sendToUser(otherName, payload, false);
          for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify(payload));
        }
        break;
      }

      // ── editing your own message (it used to stay local: the other side and a refresh never saw it) ──
      case "dm_edit": {
        const me = senderName.toLowerCase();
        const toLower = String(msg.to || "").trim().toLowerCase();
        const id = String(msg.messageId || ""), text = typeof msg.text === "string" ? msg.text.slice(0, 4000) : "";
        if (!toLower || !id || !text.trim()) break;
        const key = dmHistKey(me, toLower); let changed = false, denied = false;
        await withLock("hist:" + key.join("/"), async () => {
          const hist = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = hist.find((x) => x.id === id); if (!m || m.system || m.voiceMsg) return;
          if (!isMine(m, me)) { denied = true; return; }
          m.text = text; m.edited = true;
          changed = await safeKvSet(key, hist);
        });
        if (denied) { ws.send(JSON.stringify({ type: "error", message: "You can only edit your own messages." })); break; }
        if (changed) {
          const otherName = await nameOf(toLower);
          const payload = { type: "dm_edit", from: senderName, to: otherName, messageId: id, text };
          sendToUser(otherName, payload, false);
          for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify(payload));
        }
        break;
      }
      case "group_edit": {
        const gid = String(msg.gid || ""), id = String(msg.messageId || ""), me = senderName.toLowerCase();
        const text = typeof msg.text === "string" ? msg.text.slice(0, 4000) : "";
        const g = await getGroup(gid); if (!g || !(g.members as string[]).includes(me) || !id || !text.trim()) break;
        const key: Deno.KvKey = ["group_history", gid]; let changed = false, denied = false;
        await withLock("hist:" + key.join("/"), async () => {
          const hist = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = hist.find((x) => x.id === id); if (!m || m.system || m.voiceMsg) return;
          if (!isMine(m, me)) { denied = true; return; }
          m.text = text; m.edited = true;
          changed = await safeKvSet(key, hist);
        });
        if (denied) { ws.send(JSON.stringify({ type: "error", message: "You can only edit your own messages." })); break; }
        if (changed) sendToGroup(g, { type: "group_edit", gid, messageId: id, text, from: senderName }, undefined, false);
        break;
      }

      // ── typing indicators (DMs never had one: the server didn't know this message) ──
      case "dm_typing": {
        const to = String(msg.to || "").trim(); if (!to) break;
        if (!(await getSettings(senderName.toLowerCase())).typingIndicators) break;   // I turned mine off
        sendToUser(to, { type: "dm_typing", from: senderName }, false);
        break;
      }
      case "group_typing": {
        const g = await getGroup(String(msg.gid || "")); const me = senderName.toLowerCase();
        if (!g || !(g.members as string[]).includes(me)) break;
        if (!(await getSettings(me)).typingIndicators) break;
        sendToGroup(g, { type: "group_typing", gid: g.id, from: senderName }, me, false);
        break;
      }

      // ── read receipts ──
      case "dm_read": {
        const me = senderName.toLowerCase();
        const withLower = String(msg.with || "").trim().toLowerCase(); if (!withLower || withLower === me) break;
        const conv = dmConv(me, withLower);
        const ts = await bumpRead(conv, me, Number(msg.upTo) || 0);
        const otherName = await nameOf(withLower);
        // my other tabs/devices clear their unread badge
        for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify({ type: "dm_read_self", with: otherName, upTo: ts }));
        // the other person only learns I read it if I have read receipts on
        if ((await getSettings(me)).readReceipts) sendToUser(otherName, { type: "dm_read_update", with: senderName, by: senderName, upTo: ts }, false);
        break;
      }
      case "group_read": {
        const g = await getGroup(String(msg.gid || "")); const me = senderName.toLowerCase();
        if (!g || !(g.members as string[]).includes(me)) break;
        const ts = await bumpRead("g:" + g.id, me, Number(msg.upTo) || 0);
        for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify({ type: "dm_read_self", gid: g.id, upTo: ts }));
        if ((await getSettings(me)).readReceipts) sendToGroup(g, { type: "dm_read_update", gid: g.id, by: senderName, upTo: ts }, me, false);
        break;
      }

      // ── per-conversation settings (mute / pin / close) and "clear history for me" ──
      case "dm_prefs_set": {
        const me = senderName.toLowerCase();
        const raw = String(msg.conv || "");
        let conv = "", key = raw;
        if (raw.startsWith("g:")) { const g = await getGroup(raw.slice(2)); if (!g || !(g.members as string[]).includes(me)) break; conv = raw; }
        else { const l = raw.trim().toLowerCase(); if (!l || l === me) break; conv = dmConv(me, l); key = await nameOf(l); }
        const p = (msg.prefs || {}) as Rec3, patch: Rec3 = {};
        if (typeof p.muted === "boolean" || typeof p.muted === "number") patch.muted = p.muted;
        if (typeof p.pinned === "boolean") patch.pinned = p.pinned;
        if (typeof p.hidden === "boolean") patch.hidden = p.hidden;
        if (!Object.keys(patch).length) break;
        const merged = await patchPref(me, conv, patch);
        for (const [w] of socketsOf(me)) w.send(JSON.stringify({ type: "dm_prefs", conv: key, prefs: { muted: merged.muted || false, pinned: !!merged.pinned, hidden: !!merged.hidden } }));
        break;
      }
      case "dm_clear": {
        const me = senderName.toLowerCase();
        const raw = String(msg.conv || "");
        let conv = "", key = raw;
        if (raw.startsWith("g:")) { const g = await getGroup(raw.slice(2)); if (!g || !(g.members as string[]).includes(me)) break; conv = raw; }
        else { const l = raw.trim().toLowerCase(); if (!l || l === me) break; conv = dmConv(me, l); key = await nameOf(l); }
        const now = Date.now();
        await patchPref(me, conv, { clearedBefore: now });
        await bumpRead(conv, me, now);
        for (const [w] of socketsOf(me)) w.send(JSON.stringify({ type: "dm_cleared", conv: key, ts: now }));
        break;
      }
      case "user_settings_set": {
        const me = senderName.toLowerCase();
        const cur = await getSettings(me);
        const next = { readReceipts: typeof msg.readReceipts === "boolean" ? msg.readReceipts : cur.readReceipts, typingIndicators: typeof msg.typingIndicators === "boolean" ? msg.typingIndicators : cur.typingIndicators };
        await safeKvSet(["user_settings", me], next);
        for (const [w] of socketsOf(me)) w.send(JSON.stringify({ type: "user_settings", settings: next }));
        break;
      }

      // ═════════ Group chats ═════════
      case "group_create": {
        const me = senderName.toLowerCase();
        const asked = Array.isArray(msg.members) ? (msg.members as unknown[]).filter((x): x is string => typeof x === "string") : [];
        const others = [...new Set(asked.map((n) => n.trim().toLowerCase()).filter((l) => l && l !== me))];
        const err = (message: string) => ws.send(JSON.stringify({ type: "group_error", message, reqId: msg.reqId }));
        if (others.length < 1) { err("Pick at least one person."); break; }
        if (others.length > GROUP_MAX - 1) { err(`A group can have at most ${GROUP_MAX} people.`); break; }
        const myFriends = new Set((((await kv.get<Rec3[]>(["friends", me])).value) || []).map((f) => String(f.name || "").toLowerCase()));
        let bad = "";
        for (const l of others) {
          if (!(await kv.get(["accounts", l])).value) { bad = `No user named “${l}”.`; break; }
          if (!isPowerUser && !myFriends.has(l)) { bad = "You can only add friends to a group chat."; break; }
        }
        if (bad) { err(bad); break; }
        const names = await Promise.all(others.map(nameOf));
        const palette = ["#6c63ff", "#e91e63", "#00bcd4", "#ff9800", "#4caf50", "#9c27b0", "#f44336", "#3f51b5"];
        const g: Rec3 = {
          id: newId(), color: palette[Math.floor(Math.random() * palette.length)], owner: senderName, ownerLower: me, createdAt: Date.now(),
          name: (typeof msg.name === "string" && msg.name.trim() ? msg.name.trim() : [senderName, ...names].join(", ")).slice(0, 40),
          members: [me, ...others],
        };
        if (!(await safeKvSet(["groups", g.id as string], g))) { err("Couldn't create the group."); break; }
        for (const l of g.members as string[]) await addUserGroup(l, g.id as string);
        await pushGroup(g, "group_created");
        await groupSystemMsg(g, "created", `${senderName} created the group`, senderName);
        break;
      }
      case "group_msg": {
        if (frozenUsers.has(senderName.toLowerCase())) { ws.send(JSON.stringify({ type: "error", message: "Your account is frozen." })); break; }
        const g = await getGroup(String(msg.gid || "")); const me = senderName.toLowerCase();
        if (!g || !(g.members as string[]).includes(me)) break;
        const myAcct = (await kv.get<Rec3>(["accounts", me])).value;
        const m = cleanChatMessage(msg as Rec3, senderName, myAcct?.color);
        if (!(await appendHistory(["group_history", g.id as string], { ...sanitizeMsgForStore(m), _stored: m.ts }))) {
          ws.send(JSON.stringify({ type: "error", message: "Couldn't save that message." })); break;
        }
        for (const l of g.members as string[]) await unhide(l, "g:" + g.id);
        sendToGroup(g, { type: "group_msg", gid: g.id, message: m }, me, true);
        ws.send(JSON.stringify({ type: "dm_ack", gid: g.id, id: m.id, ts: m.ts }));
        for (const [w] of socketsOf(me)) if (w !== ws) w.send(JSON.stringify({ type: "dm_sync", gid: g.id, message: m }));
        break;
      }
      case "fetch_group_history": {
        const g = await getGroup(String(msg.gid || "")); const me = senderName.toLowerCase();
        if (!g || !(g.members as string[]).includes(me)) break;
        const conv = "g:" + g.id;
        const [hist, prefs, myRead] = await Promise.all([kv.get<unknown[]>(["group_history", g.id as string]), getPrefs(me), getRead(conv, me)]);
        const cleared = Number(prefs[conv]?.clearedBefore) || 0;
        const reads: Record<string, number> = {};
        for (const l of g.members as string[]) {
          if (l === me) continue;
          if (!(await getSettings(l)).readReceipts) continue;
          const t = await getRead(conv, l); if (t) reads[await nameOf(l)] = t;
        }
        ws.send(JSON.stringify({ type: "dm_history", gid: g.id, messages: ((hist.value || []) as Rec3[]).filter((m) => msgTs(m) > cleared), reads, myRead }));
        break;
      }
      case "group_delete": {
        const gid = String(msg.gid || ""), id = String(msg.messageId || ""), me = senderName.toLowerCase();
        const g = await getGroup(gid); if (!g || !(g.members as string[]).includes(me) || !id) break;
        const key: Deno.KvKey = ["group_history", gid]; let removed = false, denied = false;
        await withLock("hist:" + key.join("/"), async () => {
          const list = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = list.find((x) => x.id === id); if (!m) return;
          if (!isMine(m, me) && !isPowerUser && g.ownerLower !== me) { denied = true; return; }   // the group owner can also remove messages
          removed = await safeKvSet(key, list.filter((x) => x.id !== id));
        });
        if (denied) { ws.send(JSON.stringify({ type: "error", message: "You can only delete your own messages." })); break; }
        if (removed) sendToGroup(g, { type: "group_delete", gid, messageId: id, by: senderName }, undefined, false);
        break;
      }
      case "group_reaction": {
        const gid = String(msg.gid || ""), id = String(msg.messageId || ""), emoji = String(msg.emoji || "").slice(0, 16), me = senderName.toLowerCase();
        const g = await getGroup(gid); if (!g || !(g.members as string[]).includes(me) || !id || !emoji) break;
        const key: Deno.KvKey = ["group_history", gid]; let changed = false, nowOn = false;
        await withLock("hist:" + key.join("/"), async () => {
          const hist = (((await kv.get<unknown[]>(key)).value) || []) as Rec3[];
          const m = hist.find((x) => x.id === id); if (!m || m.system) return;
          const reacts = (Array.isArray(m.reactions) ? m.reactions : []) as Rec3[];
          const rr = reacts.find((x) => x.emoji === emoji);
          const has0 = !!rr && ((rr.users as string[]) || []).includes(senderName);
          const want = typeof msg.on === "boolean" ? msg.on : !has0;
          if (want === has0) return;
          nowOn = want;
          if (rr) {
            const users = (rr.users as string[]) || [];
            if (users.includes(senderName)) { rr.count = Math.max(0, (rr.count as number) - 1); rr.users = users.filter((u) => u !== senderName); if ((rr.count as number) <= 0) m.reactions = reacts.filter((x) => x.emoji !== emoji); }
            else { rr.count = (rr.count as number) + 1; rr.users = [...users, senderName]; }
          } else { reacts.push({ emoji, count: 1, users: [senderName] }); m.reactions = reacts; }
          changed = await safeKvSet(key, hist);
        });
        if (changed) sendToGroup(g, { type: "group_reaction", gid, messageId: id, emoji, user: senderName, on: nowOn }, undefined, false);
        break;
      }
      case "group_add": {
        const gid = String(msg.gid || ""), me = senderName.toLowerCase();
        const asked = Array.isArray(msg.members) ? (msg.members as unknown[]).filter((x): x is string => typeof x === "string") : [];
        await withLock("group:" + gid, async () => {
          const g = await getGroup(gid);
          const err = (message: string) => ws.send(JSON.stringify({ type: "group_error", message, gid }));
          if (!g || !(g.members as string[]).includes(me)) return;
          const myFriends = new Set((((await kv.get<Rec3[]>(["friends", me])).value) || []).map((f) => String(f.name || "").toLowerCase()));
          const add: string[] = [];
          for (const n of asked) {
            const l = n.trim().toLowerCase();
            if (!l || (g.members as string[]).includes(l) || add.includes(l)) continue;
            if (!(await kv.get(["accounts", l])).value) { err(`No user named “${n}”.`); return; }
            if (!isPowerUser && !myFriends.has(l)) { err("You can only add your own friends."); return; }
            add.push(l);
          }
          if (!add.length) return;
          if ((g.members as string[]).length + add.length > GROUP_MAX) { err(`A group can have at most ${GROUP_MAX} people.`); return; }
          g.members = [...(g.members as string[]), ...add];
          if (!(await safeKvSet(["groups", gid], g))) { err("Couldn't update the group."); return; }
          const names = await Promise.all(add.map(nameOf));
          for (const l of add) await addUserGroup(l, gid);
          for (const l of g.members as string[]) sendToUser(l, { type: add.includes(l) ? "group_created" : "group_updated", group: await groupView(g, l) }, true);
          await groupSystemMsg(g, "added", `${senderName} added ${names.join(", ")}`, senderName, { targets: names });
        });
        break;
      }
      case "group_remove": {
        const gid = String(msg.gid || ""), me = senderName.toLowerCase(), target = String(msg.target || "").trim().toLowerCase();
        await withLock("group:" + gid, async () => {
          const g = await getGroup(gid);
          if (!g || g.ownerLower !== me || !target || target === me || !(g.members as string[]).includes(target)) {
            if (g && g.ownerLower !== me) ws.send(JSON.stringify({ type: "group_error", message: "Only the group owner can remove people.", gid }));
            return;
          }
          g.members = (g.members as string[]).filter((l) => l !== target);
          if (!(await safeKvSet(["groups", gid], g))) return;
          await removeUserGroup(target, gid);
          const tName = await nameOf(target);
          sendToUser(tName, { type: "group_removed", gid, reason: "removed" }, true);
          await pushGroup(g);
          await groupSystemMsg(g, "removed", `${senderName} removed ${tName}`, senderName, { targets: [tName] });
        });
        break;
      }
      case "group_leave": {
        const gid = String(msg.gid || ""), me = senderName.toLowerCase();
        await withLock("group:" + gid, async () => {
          const g = await getGroup(gid);
          if (!g || !(g.members as string[]).includes(me)) return;
          g.members = (g.members as string[]).filter((l) => l !== me);
          await removeUserGroup(me, gid);
          sendToUser(senderName, { type: "group_removed", gid, reason: "left" }, true);
          if (!(g.members as string[]).length) { await kv.delete(["groups", gid]); await kv.delete(["group_history", gid]); return; }
          if (g.ownerLower === me) { g.ownerLower = (g.members as string[])[0]; g.owner = await nameOf(g.ownerLower as string); } // ownership passes on
          await safeKvSet(["groups", gid], g);
          await pushGroup(g);
          await groupSystemMsg(g, "left", `${senderName} left the group`, senderName);
        });
        break;
      }
      case "group_set_pfp": {   // any member can set / clear the group picture (same rule as renaming)
        const gid = String(msg.gid || ""), me = senderName.toLowerCase();
        const pfp = msg.pfp === null ? null : (validGroupPfp(msg.pfp) ? msg.pfp : undefined);
        if (pfp === undefined) { ws.send(JSON.stringify({ type: "group_error", message: "That isn't a valid picture (JPEG/PNG/WebP/GIF, small).", gid })); break; }
        await withLock("group:" + gid, async () => {
          const g = await getGroup(gid);
          if (!g || !(g.members as string[]).includes(me) || (g.pfp ?? null) === pfp) return;
          if (pfp) g.pfp = pfp; else delete g.pfp;
          if (!(await safeKvSet(["groups", gid], g))) { ws.send(JSON.stringify({ type: "group_error", message: "Couldn't save the picture.", gid })); return; }
          await pushGroup(g);
          await groupSystemMsg(g, "pfp", `${senderName} ${pfp ? "changed" : "removed"} the group picture`, senderName);
        });
        break;
      }
      case "group_rename": {
        const gid = String(msg.gid || ""), me = senderName.toLowerCase();
        const name = String(msg.name || "").trim().slice(0, 40);
        if (!name) break;
        await withLock("group:" + gid, async () => {
          const g = await getGroup(gid);
          if (!g || !(g.members as string[]).includes(me) || g.name === name) return;
          const old = g.name; g.name = name;
          if (!(await safeKvSet(["groups", gid], g))) return;
          await pushGroup(g);
          await groupSystemMsg(g, "renamed", `${senderName} renamed the group to “${name}”`, senderName, { from: old, to: name });
        });
        break;
      }

      case "short_post": {
        const spSvId = msg.serverId as string;
        // only members can post; the poster is whoever is logged in, never what the client claims
        if (!spSvId || !msg.short || !((info.serverIds as Set<string> | undefined)?.has(spSvId) || isPowerUser)) break;
        const spShort = cleanShort(msg.short as Rec, senderName);
        if (!spShort) { ws.send(JSON.stringify({ type: "error", message: "That doesn't look like a valid video link (it must start with http:// or https://)." })); break; }
        let spAdded = false;
        await withLock("shorts:" + spSvId, async () => {
          const list = await loadShorts(spSvId);
          if (list.some((x) => x.id === spShort.id)) return; // a retry / outbox replay: already saved
          list.push(spShort); spAdded = true;
          if (!(await saveShorts(spSvId, list))) ws.send(JSON.stringify({ type: "error", message: "Couldn't save that short." }));
        });
        if (spAdded) broadcast({ type: "short_post", serverId: spSvId, short: spShort }, ws);
        break;
      }

      case "short_like": {
        const slSvId = msg.serverId as string;
        const slId = msg.shortId as string;
        if (!slSvId || !slId || !((info.serverIds as Set<string> | undefined)?.has(slSvId) || isPowerUser)) break;
        const slLiked = msg.liked === true;
        let slChanged = false;
        await withLock("shorts:" + slSvId, async () => {
          const list = await loadShorts(slSvId);
          const s = list.find((x) => x.id === slId);
          if (!s) return;
          const likes = new Set((s.likes as string[]) || []);
          if (slLiked && !likes.has(senderName)) { likes.add(senderName); slChanged = true; }
          else if (!slLiked && likes.has(senderName)) { likes.delete(senderName); slChanged = true; }
          if (slChanged) { s.likes = [...likes]; await saveShorts(slSvId, list); }
        });
        if (slChanged) broadcast({ type: "short_like", serverId: slSvId, shortId: slId, user: senderName, liked: slLiked }, ws);
        break;
      }

      case "short_comment": {
        const scSvId = msg.serverId as string;
        const scId = msg.shortId as string;
        const raw = (msg.comment || {}) as Rec;
        const scText = typeof raw.text === "string" ? raw.text.trim().slice(0, 500) : "";
        if (!scSvId || !scId || !scText || typeof raw.id !== "string" || !raw.id || raw.id.length > 64) break;
        if (!((info.serverIds as Set<string> | undefined)?.has(scSvId) || isPowerUser)) break;
        const scComment = { id: raw.id, author: senderName, text: scText, ts: Number(raw.ts) || Date.now() };
        let scAdded = false;
        await withLock("shorts:" + scSvId, async () => {
          const list = await loadShorts(scSvId);
          const s = list.find((x) => x.id === scId);
          if (!s) return;
          let comments = (Array.isArray(s.comments) ? s.comments : []) as Rec[];
          if (comments.some((c) => c.id === scComment.id)) return; // replay
          comments.push(scComment);
          if (comments.length > 300) comments = comments.slice(-300);
          s.comments = comments; scAdded = true;
          await saveShorts(scSvId, list);
        });
        if (scAdded) broadcast({ type: "short_comment", serverId: scSvId, shortId: scId, comment: scComment }, ws);
        break;
      }

      case "custom_emoji_add": {
        // Store the emoji name in KV (data is too large for free-tier KV — p2p like videos)
        const ceSvId = msg.serverId as string;
        const ceName = msg.name as string;
        if (ceSvId && ceName) {
          const ceNamesKey = ["custom_emoji_names", ceSvId];
          const ceNames = ((await kv.get<string[]>(ceNamesKey)).value || []);
          if (!ceNames.includes(ceName)) {
            ceNames.push(ceName);
            await kv.set(ceNamesKey, ceNames);
          }
        }
        // Broadcast full msg including data to live clients (they cache it locally)
        broadcast(msg, ws);
        break;
      }

      case "emoji_request": {
        // P2P relay: someone needs an emoji's data — broadcast to server so a caching peer responds
        broadcastToServer(msg.serverId as string, msg, ws);
        break;
      }

      case "emoji_serve": {
        // A peer is serving emoji data directly to the requester
        sendToUser(msg.to as string, msg, false);
        break;
      }

      case "admin_dm_response": {
        // FIX #5: Only power users should be able to submit DM responses — a regular
        // user crafting a fake admin_dm_response could spam or spoof the admin panel.
        if (!isPowerUser) {
          console.log(`[admin_dm_response] BLOCKED from non-admin sender ${senderName}`);
          break;
        }
        sendToUser(msg.requestedBy as string, { type: "admin_dm_data", target: senderName, dms: msg.dms }, false);
        break;
      }

      case "admin_rename_user": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can rename users." })); break; }
        const target = (msg.target as string || "").trim();
        const newName = (msg.newName as string || "").trim();
        if (!newName || !/^[a-zA-Z0-9_.\-]{2,24}$/.test(newName)) {
          ws.send(JSON.stringify({ type: "error", message: "Invalid username format." })); break;
        }
        const targetLower = target.toLowerCase();
        const newNameLower = newName.toLowerCase();
        const targetKey = ["accounts", targetLower];
        const targetEntry = await kv.get<Record<string, unknown>>(targetKey);
        if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        const newKey = ["accounts", newNameLower];
        const existingNew = await kv.get(newKey);
        if (existingNew.value) { ws.send(JSON.stringify({ type: "error", message: "That username is already taken." })); break; }

        // 1. Move the account record
        await kv.set(newKey, { ...targetEntry.value as object, name: newName });
        await kv.delete(targetKey);

        // 2. Migrate all session tokens that resolve to the old username → new username
        const sessionIter = kv.list<string>({ prefix: ["sessions"] });
        for await (const item of sessionIter) {
          if (item.value === targetLower) {
            await kv.set(item.key, newNameLower);
            sessions.set(item.key[1] as string, newNameLower);
            console.log(`[rename] migrated session token ${(item.key[1] as string).slice(0, 8)}... → ${newNameLower}`);
          }
        }
        // Also update in-memory sessions map
        for (const [tok, uname] of sessions) {
          if (uname === targetLower) sessions.set(tok, newNameLower);
        }

        // 3. Migrate user_servers index key
        const oldSvsKey = ["user_servers", targetLower];
        const oldSvsEntry = await kv.get<string[]>(oldSvsKey);
        if (oldSvsEntry.value) {
          await kv.set(["user_servers", newNameLower], oldSvsEntry.value);
          await kv.delete(oldSvsKey);
          console.log(`[rename] migrated user_servers index for ${targetLower} → ${newNameLower}`);
        }

        // 4. Migrate server_member entries — old entries use display name, update to new display name
        // Also update ownerId on any servers this user owns
        const svMemberIter = kv.list({ prefix: ["server_member"] });
        for await (const item of svMemberIter) {
          const memberName = item.key[2] as string;
          if (memberName.toLowerCase() === targetLower) {
            const svId = item.key[1] as string;
            await kv.set(["server_member", svId, newName], item.value);
            await kv.delete(item.key);
            // Update ownerId if this user owns the server
            const svEntry = await kv.get<Record<string, unknown>>(["servers", svId]);
            if (svEntry.value && (svEntry.value.ownerId as string || "").toLowerCase() === targetLower) {
              const updatedSv = { ...svEntry.value, ownerId: newName, ownerIdLower: newNameLower };
              await kv.set(["servers", svId], updatedSv);
              if (publicServers.has(svId)) publicServers.set(svId, updatedSv);
              console.log(`[rename] updated ownerId on server ${svId} → ${newName}`);
            }
          }
        }

        // 5. Update live connected clients
        for (const [cws, ci] of clients) {
          if ((ci.name as string).toLowerCase() === targetLower) {
            (ci as Record<string, unknown>).name = newName;
            cws.send(JSON.stringify({ type: "admin_rename_ok", oldName: target, newName }));
          }
        }

        // 6. BUG 5 FIX: Migrate DM history keys — DM keys use sorted lowercase name pairs.
        // e.g. "alice:charlie" → "bob:charlie" after renaming alice→bob.
        // Without this, renamed users lose access to all their DM history.
        const dmMigrateIter = kv.list<unknown[]>({ prefix: ["dm_history"] });
        for await (const item of dmMigrateIter) {
          const keyStr = item.key[1] as string;
          if (!keyStr.includes(targetLower)) continue;
          const parts = keyStr.split(":");
          if (parts.some(p => p === targetLower)) {
            const newParts = parts.map(p => p === targetLower ? newNameLower : p).sort();
            const newKey = ["dm_history", newParts.join(":")];
            // Only migrate if new key doesn't already exist (avoid overwrite)
            const newKeyEntry = await kv.get(newKey);
            if (!newKeyEntry.value) {
              await kv.set(newKey, item.value);
            } else {
              // Merge: append old history into existing (dedup by message id)
              const existing = (newKeyEntry.value as Record<string,unknown>[]) || [];
              const existingIds = new Set(existing.map((m: Record<string,unknown>) => m.id));
              const merged = [...existing, ...(item.value || []).filter((m: unknown) => !existingIds.has((m as Record<string,unknown>).id as string))];
              merged.sort((a, b) => ((a as Record<string,unknown>)._stored as number || 0) - ((b as Record<string,unknown>)._stored as number || 0));
              await kv.set(newKey, merged);
            }
            await kv.delete(item.key);
            console.log(`[rename] migrated DM history key ${keyStr} → ${newParts.join(":")}`);
          }
        }
        // 6b. protocol 6 data: groups, group index, DM peer index, per-user prefs/settings, read pointers
        {
          const swapL = (x: unknown) => (x === targetLower ? newNameLower : x);
          for await (const item of kv.list<Rec3>({ prefix: ["groups"] })) {
            const g = item.value; if (!g || !Array.isArray(g.members) || !(g.members as string[]).includes(targetLower)) continue;
            const ng: Rec3 = { ...g, members: (g.members as string[]).map(swapL) };
            if (g.ownerLower === targetLower) { ng.ownerLower = newNameLower; ng.owner = newName; }
            await safeKvSet(item.key, ng);
          }
          for (const pre of ["user_groups", "dm_peers", "dm_prefs", "user_settings", "last_seen", "user_status"]) {
            const e = await kv.get<unknown>([pre, targetLower]);
            if (e.value !== null && e.value !== undefined) {
              let v = e.value;
              if (pre === "dm_peers" && Array.isArray(v)) v = (v as string[]).map(swapL);
              if (pre === "dm_prefs" && v && typeof v === "object") {
                const o: Record<string, unknown> = {};
                for (const [c, pv] of Object.entries(v as Record<string, unknown>)) o[c.startsWith("dm:") ? "dm:" + c.slice(3).split(":").map(swapL).sort().join(":") : c] = pv;
                v = o;
              }
              await safeKvSet([pre, newNameLower], v); await kv.delete([pre, targetLower]);
            }
          }
          // everyone else's peer index / prefs mention the old name too
          for await (const item of kv.list<string[]>({ prefix: ["dm_peers"] })) {
            if (Array.isArray(item.value) && item.value.includes(targetLower)) await safeKvSet(item.key, item.value.map(swapL));
          }
          for await (const item of kv.list<Record<string, unknown>>({ prefix: ["dm_prefs"] })) {
            const o: Record<string, unknown> = {}; let touched = false;
            for (const [c, pv] of Object.entries(item.value || {})) {
              const nc = c.startsWith("dm:") ? "dm:" + c.slice(3).split(":").map(swapL).sort().join(":") : c;
              if (nc !== c) touched = true; o[nc] = pv;
            }
            if (touched) await safeKvSet(item.key, o);
          }
          for await (const item of kv.list<{ ts: number }>({ prefix: ["dm_read"] })) {
            const conv = String(item.key[1]), who = String(item.key[2]);
            const nconv = conv.startsWith("dm:") ? "dm:" + conv.slice(3).split(":").map(swapL).sort().join(":") : conv;
            const nwho = String(swapL(who));
            if (nconv !== conv || nwho !== who) { await kv.set(["dm_read", nconv, nwho], item.value); await kv.delete(item.key); }
          }
        }
        // 6c. friends + friend requests. Our own list/inbox move to the new key; every OTHER person's list/inbox holds our
        // DISPLAY NAME, so those entries are rewritten too. Without this the renamed user loses every friend and pending
        // request, and whoever registers the freed old name inherits them (and appears in all those friends' lists).
        {
          const isMe = (n: unknown) => String(n ?? "").toLowerCase() === targetLower;
          await withLock("friends:" + targetLower, async () => {
            const cur = (await kv.get<Array<Record<string, unknown>>>(["friends", targetLower])).value;
            if (cur) { await safeKvSet(["friends", newNameLower], cur); await kv.delete(["friends", targetLower]); }
          });
          for await (const item of kv.list<Array<Record<string, unknown>>>({ prefix: ["friends"] })) {
            if (!Array.isArray(item.value) || !item.value.some((f) => isMe(f.name))) continue;
            await withLock("friends:" + String(item.key[1]), async () => {
              const cur = (((await kv.get<Array<Record<string, unknown>>>(item.key)).value) || []);
              await safeKvSet(item.key, cur.map((f) => (isMe(f.name) ? { ...f, name: newName } : f)));
            });
          }
          // inbox: ["friend_requests", recipient, sender] = { from: <sender display name>, ... }
          for await (const item of kv.list<Record<string, unknown>>({ prefix: ["friend_requests"] })) {
            const rcpt = item.key[1] as string, sndr = item.key[2] as string;
            if (rcpt !== targetLower && sndr !== targetLower) continue;
            const v: Record<string, unknown> = { ...item.value }; if (sndr === targetLower) v.from = newName;
            await safeKvSet(["friend_requests", rcpt === targetLower ? newNameLower : rcpt, sndr === targetLower ? newNameLower : sndr], v);
            await kv.delete(item.key);
          }
          // outbox: ["friend_requests_out", sender, recipient] = { to: <recipient display name>, ... }
          for await (const item of kv.list<Record<string, unknown>>({ prefix: ["friend_requests_out"] })) {
            const sndr = item.key[1] as string, rcpt = item.key[2] as string;
            if (sndr !== targetLower && rcpt !== targetLower) continue;
            const v: Record<string, unknown> = { ...item.value }; if (rcpt === targetLower) v.to = newName;
            await safeKvSet(["friend_requests_out", sndr === targetLower ? newNameLower : sndr, rcpt === targetLower ? newNameLower : rcpt], v);
            await kv.delete(item.key);
          }
          console.log(`[rename] migrated friends + friend requests ${targetLower} → ${newNameLower}`);
        }
        // 6d. profile style + banner (protocol 7) is keyed by name too
        {
          const pe = (await kv.get<Record<string, unknown>>(["profile_ext", targetLower])).value;
          if (pe) { await safeKvSet(["profile_ext", newNameLower], pe); await kv.delete(["profile_ext", targetLower]); }
        }
        broadcast({ type: "admin_rename_ok", oldName: target, newName }, null);

        // 7. Migrate in-memory offline queue so queued messages reach the renamed user
        const offlineQueue = offline.get(targetLower);
        if (offlineQueue?.length) {
          offline.set(newNameLower, [...(offline.get(newNameLower) || []), ...offlineQueue]);
          offline.delete(targetLower);
          console.log(`[rename] migrated ${offlineQueue.length} queued offline message(s) to ${newNameLower}`);
        }

        ws.send(JSON.stringify({ type: "success", message: `${target} renamed to ${newName}.` }));
        break;
      }

      case "admin_set_pfp": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can change profile pictures." })); break; }
        const pfpTarget = (msg.target as string || "").trim().toLowerCase();
        const pfpData = msg.pfp === null ? null : (validPfp(msg.pfp) ? msg.pfp : undefined);
        if (pfpData === undefined) { ws.send(JSON.stringify({ type: "error", message: "That isn't a valid picture (JPEG/PNG/WebP/GIF, under ~45 KB)." })); break; }
        const pfpKey = ["accounts", pfpTarget];
        const pfpEntry = await kv.get<Record<string, unknown>>(pfpKey);
        if (!pfpEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        await kv.set(pfpKey, { ...pfpEntry.value as object, pfp: pfpData });
        for (const [, ci] of clients) {
          if ((ci.name as string).toLowerCase() === pfpTarget) (ci as Record<string, unknown>).pfp = pfpData;
        }
        broadcast({ type: "profile_update", user: pfpEntry.value.name, pfp: pfpData, color: pfpEntry.value.color }, null);
        ws.send(JSON.stringify({ type: "success", message: `PFP updated for ${pfpEntry.value.name}.` }));
        break;
      }

      case "platform_alert": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can send platform alerts." })); break; }
        const alertTitle = (msg.title as string || "").slice(0, 80);
        const alertBody = (msg.body as string || "").slice(0, 500);
        if (!alertTitle || !alertBody) { ws.send(JSON.stringify({ type: "error", message: "Alert needs a title and body." })); break; }
        broadcast({ type: "platform_alert", title: alertTitle, body: alertBody, from: senderName }, null);
        break;
      }

      case "admin_list_accounts": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can list accounts." })); break; }
        const acctIter2 = kv.list<Record<string, unknown>>({ prefix: ["accounts"] });
        const allAccounts: Record<string, unknown>[] = [];
        for await (const item of acctIter2) {
          const a = item.value;
          if (!a) continue;
          allAccounts.push({
            name: a.name, tag: a.tag, color: a.color,
            pfp: a.pfp || null, systemRole: a.systemRole || "user",
            coAdmin: a.coAdmin || false, createdAt: a.createdAt || 0,
            bio: a.bio || "",
            frozen: frozenUsers.has((a.name as string)?.toLowerCase()),
            online: [...clients.values()].some(ci => (ci.name as string)?.toLowerCase() === (a.name as string)?.toLowerCase()),
          });
        }
        allAccounts.sort((a, b) => ((a.createdAt as number) || 0) - ((b.createdAt as number) || 0));
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "admin_accounts_list", accounts: allAccounts }));
        break;
      }

      case "admin_reset_password": {
        // Force-set any user's password. Admin only.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can reset passwords." })); break; }
        const rpTarget = (msg.target as string || "").trim().toLowerCase();
        const rpNewPw  = (msg.newPassword as string || "").trim();
        if (!rpTarget || !rpNewPw || rpNewPw.length < 4) {
          ws.send(JSON.stringify({ type: "error", message: "Target username and new password (min 4 chars) required." })); break;
        }
        const rpKey   = ["accounts", rpTarget];
        const rpEntry = await kv.get<Record<string, unknown>>(rpKey);
        if (!rpEntry.value) { ws.send(JSON.stringify({ type: "error", message: `User '${rpTarget}' not found.` })); break; }
        await kv.set(rpKey, { ...rpEntry.value, passwordHash: await hashPw(rpNewPw) });
        ws.send(JSON.stringify({ type: "success", message: `Password reset for ${rpEntry.value.name}.` }));
        console.log(`[admin] ${senderName} reset password for ${rpTarget}`);
        break;
      }

      case "admin_set_color": {
        // Change any user's display color. Admin only.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can change user colors." })); break; }
        const scTarget = (msg.target as string || "").trim().toLowerCase();
        const scColor  = (msg.color  as string || "").trim();
        if (!scTarget || !/^#[0-9a-fA-F]{6}$/.test(scColor)) {
          ws.send(JSON.stringify({ type: "error", message: "Valid target and hex color required." })); break;
        }
        const scKey   = ["accounts", scTarget];
        const scEntry = await kv.get<Record<string, unknown>>(scKey);
        if (!scEntry.value) { ws.send(JSON.stringify({ type: "error", message: `User '${scTarget}' not found.` })); break; }
        await kv.set(scKey, { ...scEntry.value, color: scColor });
        // Update live client map
        for (const [, ci] of clients) {
          if ((ci.name as string).toLowerCase() === scTarget) (ci as Record<string, unknown>).color = scColor;
        }
        broadcast({ type: "profile_update", user: scEntry.value.name, color: scColor, pfp: scEntry.value.pfp }, null);
        ws.send(JSON.stringify({ type: "success", message: `Color updated for ${scEntry.value.name}.` }));
        break;
      }

      case "admin_kick_from_server": {
        // Remove a user from any server without banning from the platform.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const kickTarget = (msg.target as string || "").trim();
        const kickSvId   = (msg.serverId as string || "").trim();
        if (!kickTarget || !kickSvId) { ws.send(JSON.stringify({ type: "error", message: "Target and serverId required." })); break; }
        await kv.delete(["server_member", kickSvId, kickTarget]);
        await removeServerFromUser(kickTarget, kickSvId);
        // Force-update in-memory client if they're online
        sendToUser(kickTarget, { type: "kicked_from_server", serverId: kickSvId, by: senderName }, false);
        broadcast({ type: "member_leave", serverId: kickSvId, user: kickTarget }, null);
        ws.send(JSON.stringify({ type: "success", message: `${kickTarget} removed from server.` }));
        console.log(`[admin] ${senderName} kicked ${kickTarget} from server ${kickSvId}`);
        break;
      }

      case "admin_purge_user_messages": {
        // Delete all messages by a specific user across all channels in a server.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const purgeTarget = (msg.target as string || "").trim();
        const purgeSvId   = (msg.serverId as string || "").trim();
        if (!purgeTarget || !purgeSvId) { ws.send(JSON.stringify({ type: "error", message: "Target and serverId required." })); break; }
        const svForPurge  = await kv.get<Record<string, unknown>>(["servers", purgeSvId]);
        const channels    = (svForPurge.value?.channels as Array<{ id: string }>) || [];
        let totalDeleted  = 0;
        for (const ch of channels) {
          const histKey  = ["ch_history", ch.id];
          const histEntry = await kv.get<unknown[]>(histKey);
          if (!histEntry.value?.length) continue;
          const filtered = histEntry.value.filter((m: unknown) =>
            (m as Record<string, unknown>).author !== purgeTarget
          );
          totalDeleted += histEntry.value.length - filtered.length;
          await kv.set(histKey, filtered);
          msgHistory.set(ch.id, filtered);
        }
        broadcast({ type: "admin_purge", target: purgeTarget, serverId: purgeSvId, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Deleted ${totalDeleted} message(s) from ${purgeTarget} in server.` }));
        console.log(`[admin] ${senderName} purged ${totalDeleted} msgs from ${purgeTarget} in server ${purgeSvId}`);
        break;
      }

      case "admin_wipe_channel": {
        // Nuke an entire channel's message history.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const wipeCh = (msg.channelId as string || "").trim();
        if (!wipeCh) { ws.send(JSON.stringify({ type: "error", message: "channelId required." })); break; }
        await kv.set(["ch_history", wipeCh], []);
        msgHistory.set(wipeCh, []);
        broadcast({ type: "channel_wiped", channelId: wipeCh, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Channel history wiped.` }));
        console.log(`[admin] ${senderName} wiped channel ${wipeCh}`);
        break;
      }

      case "admin_lock_channel": {
        // Prevent non-admins from posting to a channel.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const lockCh  = (msg.channelId as string || "").trim();
        const locked  = msg.locked !== false; // default true
        if (!lockCh) { ws.send(JSON.stringify({ type: "error", message: "channelId required." })); break; }
        const lockData = { locked, by: senderName, at: Date.now() };
        await kv.set(["channel_lock", lockCh], lockData);
        channelLocks.set(lockCh, lockData); // keep in-memory cache in sync
        broadcast({ type: "channel_lock_update", channelId: lockCh, locked, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Channel ${locked ? "locked" : "unlocked"}.` }));
        console.log(`[admin] ${senderName} ${locked ? "locked" : "unlocked"} channel ${lockCh}`);
        break;
      }

      case "admin_transfer_ownership": {
        // Transfer server ownership to another member.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can transfer server ownership." })); break; }
        const toSvId   = (msg.serverId as string || "").trim();
        const toNewOwner = (msg.newOwner as string || "").trim();
        if (!toSvId || !toNewOwner) { ws.send(JSON.stringify({ type: "error", message: "serverId and newOwner required." })); break; }
        const toEntry = await kv.get<Record<string, unknown>>(["servers", toSvId]);
        if (!toEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const toNewAcct = await kv.get<Record<string, unknown>>(["accounts", toNewOwner.toLowerCase()]);
        if (!toNewAcct.value) { ws.send(JSON.stringify({ type: "error", message: `User '${toNewOwner}' not found.` })); break; }
        const toNewDisplayName = toNewAcct.value.name as string;
        const updatedSvTo = { ...toEntry.value, ownerId: toNewDisplayName, ownerIdLower: toNewOwner.toLowerCase() };
        await kv.set(["servers", toSvId], updatedSvTo);
        if (publicServers.has(toSvId)) publicServers.set(toSvId, updatedSvTo);
        broadcast({ type: "server_ownership_transfer", serverId: toSvId, newOwner: toNewDisplayName, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Ownership of server transferred to ${toNewDisplayName}.` }));
        console.log(`[admin] ${senderName} transferred ownership of ${toSvId} to ${toNewDisplayName}`);
        break;
      }

      case "admin_list_servers": {
        // Return all servers with full metadata for the admin panel.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can list all servers." })); break; }
        const svIter2 = kv.list<Record<string, unknown>>({ prefix: ["servers"] });
        const allSvs: Record<string, unknown>[] = [];
        for await (const item of svIter2) {
          const sv = item.value;
          if (!sv) continue;
          // Count members
          let memCount = 0;
          const memIter3 = kv.list({ prefix: ["server_member", sv.id as string] });
          for await (const _m of memIter3) memCount++;
          allSvs.push({
            id: sv.id, name: sv.name, desc: sv.desc || "",
            ownerId: sv.ownerId, ownerIdLower: sv.ownerIdLower,
            memberCount: memCount, createdAt: sv.createdAt || 0,
            isPublic: sv.isPublic !== false,
            channelCount: (sv.channels as unknown[] || []).length,
          });
        }
        allSvs.sort((a, b) => ((b.memberCount as number) || 0) - ((a.memberCount as number) || 0));
        ws.send(JSON.stringify({ type: "admin_servers_list", servers: allSvs }));
        break;
      }

      case "admin_list_bans": {
        // Return all active bans.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const activeBans: Record<string, unknown>[] = [];
        for (const [username, ban] of timedBans) {
          activeBans.push({ username, until: ban.until, reason: ban.reason });
        }
        ws.send(JSON.stringify({ type: "admin_bans_list", bans: activeBans }));
        break;
      }

      case "admin_view_channel": {
        // Read any channel's message history.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const viewChId = (msg.channelId as string || "").trim();
        if (!viewChId) { ws.send(JSON.stringify({ type: "error", message: "channelId required." })); break; }
        const viewHist = await kv.get<unknown[]>(["ch_history", viewChId]);
        ws.send(JSON.stringify({ type: "admin_channel_history", channelId: viewChId, messages: viewHist.value || [] }));
        break;
      }

      case "admin_broadcast_dm": {
        // Send a DM from "System" to any user.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can send system DMs." })); break; }
        const bdmTarget  = (msg.target as string || "").trim();
        const bdmText    = (msg.text   as string || "").trim().slice(0, 2000);
        if (!bdmTarget || !bdmText) { ws.send(JSON.stringify({ type: "error", message: "Target and text required." })); break; }
        const sysDM = {
          type: "dm", id: crypto.randomUUID(), from: "System", to: bdmTarget,
          text: bdmText, ts: Date.now(), authorColor: "#6c63ff", system: true,
        };
        const bdmKey  = ["dm_history", ["system", bdmTarget.toLowerCase()].sort().join(":")];
        const bdmHist = (await kv.get<unknown[]>(bdmKey)).value || [];
        bdmHist.push(sysDM);
        if (bdmHist.length > 500) bdmHist.splice(0, bdmHist.length - 500);
        await kv.set(bdmKey, bdmHist);
        sendToUser(bdmTarget, sysDM, true);
        ws.send(JSON.stringify({ type: "success", message: `System DM sent to ${bdmTarget}.` }));
        console.log(`[admin] ${senderName} sent system DM to ${bdmTarget}`);
        break;
      }

      case "admin_freeze_user": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const fzTarget = (msg.target as string || "").trim().toLowerCase();
        const fzReason = (msg.reason as string || "No reason given").trim().slice(0, 200);
        if (!fzTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        if (!isAdmin && (fzTarget === "puck" || (await kv.get<Record<string,unknown>>(["accounts",fzTarget])).value?.systemRole === "admin")) {
          ws.send(JSON.stringify({ type: "error", message: "Cannot freeze Puck." })); break;
        }
        const fzData = { reason: fzReason, by: senderName, at: Date.now() };
        frozenUsers.set(fzTarget, fzData);
        await kv.set(["frozen", fzTarget], fzData);
        sendToUser(fzTarget, { type: "account_frozen", reason: fzReason, by: senderName }, false);
        ws.send(JSON.stringify({ type: "success", message: `${msg.target} is now frozen.` }));
        console.log(`[admin] ${senderName} froze ${fzTarget}: ${fzReason}`);
        break;
      }

      case "admin_unfreeze_user": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const ufzTarget = (msg.target as string || "").trim().toLowerCase();
        if (!ufzTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        frozenUsers.delete(ufzTarget);
        await kv.delete(["frozen", ufzTarget]);
        sendToUser(ufzTarget, { type: "account_unfrozen", by: senderName }, false);
        ws.send(JSON.stringify({ type: "success", message: `${msg.target} unfrozen.` }));
        break;
      }

      case "admin_force_logout": {
        // Kill all sessions for a user and forcibly disconnect them.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can force-logout users." })); break; }
        const flTarget = (msg.target as string || "").trim().toLowerCase();
        if (!flTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        // Delete all KV sessions for this user
        const flSessionIter = kv.list<string>({ prefix: ["sessions"] });
        let flCount = 0;
        for await (const item of flSessionIter) {
          if (item.value === flTarget) {
            await kv.delete(item.key);
            sessions.delete(item.key[1] as string);
            flCount++;
          }
        }
        // Disconnect live websockets
        for (const [cws, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === flTarget) {
            try {
              cws.send(JSON.stringify({ type: "force_logout", by: senderName }));
              cws.close(1000, "Logged out by admin");
            } catch { /* already closing */ }
          }
        }
        ws.send(JSON.stringify({ type: "success", message: `${msg.target} logged out (${flCount} session(s) invalidated).` }));
        console.log(`[admin] ${senderName} force-logged out ${flTarget}, deleted ${flCount} session(s)`);
        break;
      }

      case "admin_delete_message": {
        // Delete a specific message by ID from a specific channel.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const dmsgId  = (msg.messageId as string || "").trim();
        const dmsgCh  = (msg.channelId  as string || "").trim();
        if (!dmsgId || !dmsgCh) { ws.send(JSON.stringify({ type: "error", message: "messageId and channelId required." })); break; }
        const dmsgKey  = ["ch_history", dmsgCh];
        const dmsgHist = await kv.get<unknown[]>(dmsgKey);
        if (!dmsgHist.value) { ws.send(JSON.stringify({ type: "error", message: "Channel history not found." })); break; }
        const dmsgBefore = dmsgHist.value.length;
        const dmsgAfter  = dmsgHist.value.filter((m: unknown) => (m as Record<string,unknown>).id !== dmsgId);
        if (dmsgAfter.length === dmsgBefore) { ws.send(JSON.stringify({ type: "error", message: "Message not found." })); break; }
        await kv.set(dmsgKey, dmsgAfter);
        msgHistory.set(dmsgCh, dmsgAfter);
        broadcast({ type: "delete_message", messageId: dmsgId, channelId: dmsgCh, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: "Message deleted." }));
        break;
      }

      case "admin_edit_message": {
        // Silently edit any message — no "edited" marker shown to users.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const emsgId   = (msg.messageId as string || "").trim();
        const emsgCh   = (msg.channelId  as string || "").trim();
        const emsgText = (msg.text        as string || "").trim().slice(0, 4000);
        if (!emsgId || !emsgCh || !emsgText) { ws.send(JSON.stringify({ type: "error", message: "messageId, channelId and text required." })); break; }
        const emsgKey  = ["ch_history", emsgCh];
        const emsgHist = await kv.get<unknown[]>(emsgKey);
        if (!emsgHist.value) { ws.send(JSON.stringify({ type: "error", message: "Channel not found." })); break; }
        let emsgFound  = false;
        const emsgUpdated = emsgHist.value.map((m: unknown) => {
          const mm = m as Record<string,unknown>;
          // Strip any existing edited flag so it vanishes completely
          if (mm.id === emsgId) { emsgFound = true; const { edited: _e, editedByAdmin: _ea, ...rest } = mm; return { ...rest, text: emsgText }; }
          return mm;
        });
        if (!emsgFound) { ws.send(JSON.stringify({ type: "error", message: "Message not found." })); break; }
        await kv.set(emsgKey, emsgUpdated);
        msgHistory.set(emsgCh, emsgUpdated);
        // silent: false tells the client not to show (edited)
        broadcast({ type: "edit_message", messageId: emsgId, channelId: emsgCh, text: emsgText, edited: false, silent: true }, null);
        ws.send(JSON.stringify({ type: "success", message: "Message edited." }));
        break;
      }

      case "admin_add_channel": {
        // Add a new channel to any server.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const acSvId   = (msg.serverId as string || "").trim();
        const acName   = (msg.name     as string || "").trim().slice(0, 32).replace(/\s+/g, "-").toLowerCase();
        const acType   = (msg.chType   as string || "text");
        if (!acSvId || !acName) { ws.send(JSON.stringify({ type: "error", message: "serverId and name required." })); break; }
        const acSvEntry = await kv.get<Record<string,unknown>>(["servers", acSvId]);
        if (!acSvEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const newCh = { id: crypto.randomUUID().replace(/-/g,"").slice(0,16), name: acName, type: acType, desc: msg.desc as string || "" };
        const acChannels = [...((acSvEntry.value.channels as unknown[]) || []), newCh];
        const acUpdatedSv = { ...acSvEntry.value, channels: acChannels };
        await kv.set(["servers", acSvId], acUpdatedSv);
        if (publicServers.has(acSvId)) publicServers.set(acSvId, acUpdatedSv);
        broadcast({ type: "server_channel_added", serverId: acSvId, channel: newCh, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Channel #${acName} added.` }));
        console.log(`[admin] ${senderName} added channel ${acName} to server ${acSvId}`);
        break;
      }

      case "admin_delete_channel": {
        // Remove a channel from any server and wipe its history.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const dcSvId = (msg.serverId  as string || "").trim();
        const dcChId = (msg.channelId as string || "").trim();
        if (!dcSvId || !dcChId) { ws.send(JSON.stringify({ type: "error", message: "serverId and channelId required." })); break; }
        const dcSvEntry = await kv.get<Record<string,unknown>>(["servers", dcSvId]);
        if (!dcSvEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const dcChannels = ((dcSvEntry.value.channels as unknown[]) || []).filter((c: unknown) => (c as Record<string,unknown>).id !== dcChId);
        const dcUpdated  = { ...dcSvEntry.value, channels: dcChannels };
        await kv.set(["servers", dcSvId], dcUpdated);
        if (publicServers.has(dcSvId)) publicServers.set(dcSvId, dcUpdated);
        await kv.delete(["ch_history", dcChId]);
        msgHistory.delete(dcChId);
        broadcast({ type: "server_channel_deleted", serverId: dcSvId, channelId: dcChId, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: "Channel deleted." }));
        console.log(`[admin] ${senderName} deleted channel ${dcChId} from server ${dcSvId}`);
        break;
      }

      case "admin_rename_server": {
        // Rename any server.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const rnSvId   = (msg.serverId as string || "").trim();
        const rnSvName = (msg.name     as string || "").trim().slice(0, 64);
        if (!rnSvId || !rnSvName) { ws.send(JSON.stringify({ type: "error", message: "serverId and name required." })); break; }
        const rnEntry = await kv.get<Record<string,unknown>>(["servers", rnSvId]);
        if (!rnEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const rnUpdated = { ...rnEntry.value, name: rnSvName };
        await kv.set(["servers", rnSvId], rnUpdated);
        if (publicServers.has(rnSvId)) publicServers.set(rnSvId, rnUpdated);
        broadcast({ type: "server_renamed", serverId: rnSvId, name: rnSvName, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: `Server renamed to "${rnSvName}".` }));
        break;
      }

      case "admin_add_member": {
        // Add any user to any server directly.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const amTarget = (msg.target   as string || "").trim();
        const amSvId   = (msg.serverId as string || "").trim();
        if (!amTarget || !amSvId) { ws.send(JSON.stringify({ type: "error", message: "target and serverId required." })); break; }
        const amAcctKey = ["accounts", amTarget.toLowerCase()];
        const amAcct    = await kv.get<Record<string,unknown>>(amAcctKey);
        if (!amAcct.value) { ws.send(JSON.stringify({ type: "error", message: `User '${amTarget}' not found.` })); break; }
        const amSvEntry = await kv.get<Record<string,unknown>>(["servers", amSvId]);
        if (!amSvEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        await kv.set(["server_member", amSvId, amAcct.value.name as string], { joinedAt: Date.now(), addedBy: senderName });
        await addServerToUser(amTarget.toLowerCase(), amSvId);
        sendToUser(amAcct.value.name as string, { type: "added_to_server", server: amSvEntry.value, by: senderName }, true);
        broadcast({ type: "member_join", serverId: amSvId, user: amAcct.value.name }, null);
        ws.send(JSON.stringify({ type: "success", message: `${amAcct.value.name} added to server.` }));
        console.log(`[admin] ${senderName} added ${amTarget} to server ${amSvId}`);
        break;
      }

      case "admin_set_bio": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can set user bios." })); break; }
        const bioTarget = (msg.target as string || "").trim().toLowerCase();
        const bioText   = (msg.bio    as string || "").trim().slice(0, 300);
        if (!bioTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        const bioKey   = ["accounts", bioTarget];
        const bioEntry = await kv.get<Record<string,unknown>>(bioKey);
        if (!bioEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        await kv.set(bioKey, { ...bioEntry.value, bio: bioText });
        broadcast({ type: "profile_update", user: bioEntry.value.name, bio: bioText, color: bioEntry.value.color, pfp: bioEntry.value.pfp }, null);
        ws.send(JSON.stringify({ type: "success", message: `Bio updated for ${bioEntry.value.name}.` }));
        break;
      }

      case "admin_wipe_user_pfp": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can wipe profile pictures." })); break; }
        const wpTarget = (msg.target as string || "").trim().toLowerCase();
        if (!wpTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        const wpKey   = ["accounts", wpTarget];
        const wpEntry = await kv.get<Record<string,unknown>>(wpKey);
        if (!wpEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        await kv.set(wpKey, { ...wpEntry.value, pfp: null });
        for (const [, ci] of clients) {
          if ((ci.name as string).toLowerCase() === wpTarget) (ci as Record<string,unknown>).pfp = null;
        }
        broadcast({ type: "profile_update", user: wpEntry.value.name, pfp: null, color: wpEntry.value.color }, null);
        ws.send(JSON.stringify({ type: "success", message: `PFP wiped for ${wpEntry.value.name}.` }));
        break;
      }

      case "admin_delete_dm_history": {
        // Wipe DM history between two users.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can delete DM history." })); break; }
        const ddmA = (msg.userA as string || "").trim().toLowerCase();
        const ddmB = (msg.userB as string || "").trim().toLowerCase();
        if (!ddmA || !ddmB) { ws.send(JSON.stringify({ type: "error", message: "userA and userB required." })); break; }
        const ddmKey = ["dm_history", [ddmA, ddmB].sort().join(":")];
        await kv.delete(ddmKey);
        ws.send(JSON.stringify({ type: "success", message: `DM history between ${ddmA} and ${ddmB} deleted.` }));
        console.log(`[admin] ${senderName} wiped DMs between ${ddmA} and ${ddmB}`);
        break;
      }

      case "admin_get_stats": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        // Count online users
        const onlineCount = clients.size;
        // Count total accounts
        let totalAccounts = 0;
        const statsAcctIter = kv.list({ prefix: ["accounts"] });
        for await (const _ of statsAcctIter) totalAccounts++;
        // Count total servers
        let totalServers = 0;
        const statsSvIter = kv.list({ prefix: ["servers"] });
        for await (const _ of statsSvIter) totalServers++;
        // Count total messages across all channels
        let totalMessages = 0;
        const statsChIter = kv.list<unknown[]>({ prefix: ["ch_history"] });
        for await (const item of statsChIter) totalMessages += item.value?.length || 0;
        // Count total DM convos
        let totalDmConvos = 0;
        const statsDmIter = kv.list({ prefix: ["dm_history"] });
        for await (const _ of statsDmIter) totalDmConvos++;
        ws.send(JSON.stringify({
          type: "admin_stats",
          stats: {
            onlineNow: onlineCount,
            totalAccounts,
            totalServers,
            totalMessages,
            totalDmConvos,
            frozenUsers: frozenUsers.size,
            activeBans: timedBans.size,
            lockedChannels: channelLocks.size,
            deployVersion: DEPLOY_VERSION,
          }
        }));
        break;
      }

      case "admin_list_online": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const onlineList = [];
        for (const [, ci] of clients) {
          onlineList.push({
            name: ci.name,
            tag: ci.tag,
            color: ci.color,
            systemRole: ci.systemRole,
            coAdmin: ci.coAdmin,
            frozen: frozenUsers.has((ci.name as string)?.toLowerCase()),
          });
        }
        ws.send(JSON.stringify({ type: "admin_online_list", users: onlineList }));
        break;
      }

      case "admin_set_motd": {
        // Set / clear the platform-wide Message of the Day shown on login.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can set the MOTD." })); break; }
        const motdText = (msg.text as string || "").trim().slice(0, 500);
        if (motdText) {
          await kv.set(["platform", "motd"], { text: motdText, by: senderName, at: Date.now() });
        } else {
          await kv.delete(["platform", "motd"]);
        }
        broadcast({ type: "motd_update", text: motdText, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: motdText ? "MOTD set." : "MOTD cleared." }));
        break;
      }

      case "admin_list_frozen": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const frozenList = [];
        for (const [username, data] of frozenUsers) {
          frozenList.push({ username, ...data });
        }
        ws.send(JSON.stringify({ type: "admin_frozen_list", frozen: frozenList }));
        break;
      }

      case "admin_impersonate_send": {
        // Post a message into any channel AS any user — the message appears as if they sent it.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can impersonate users." })); break; }
        const impAs   = (msg.asUser   as string || "").trim();
        const impCh   = (msg.channelId as string || "").trim();
        const impText = (msg.text      as string || "").trim().slice(0, 4000);
        if (!impAs || !impCh || !impText) { ws.send(JSON.stringify({ type: "error", message: "asUser, channelId and text required." })); break; }
        const impAcct = await kv.get<Record<string,unknown>>(["accounts", impAs.toLowerCase()]);
        if (!impAcct.value) { ws.send(JSON.stringify({ type: "error", message: `User '${impAs}' not found.` })); break; }
        const impMsg = {
          type: "message", id: crypto.randomUUID().replace(/-/g,""),
          channelId: impCh, author: impAcct.value.name,
          authorColor: impAcct.value.color || "#6c63ff",
          text: impText, ts: Date.now(), attachments: [],
          _impersonated: true, _impersonatedBy: senderName,
        };
        const impKey  = ["ch_history", impCh];
        const impHist = (await kv.get<unknown[]>(impKey)).value || [];
        impHist.push(impMsg);
        if (impHist.length > 500) impHist.splice(0, impHist.length - 500);
        await kv.set(impKey, impHist);
        storeMessage(impCh, impMsg);
        broadcast(impMsg, null);
        await auditLog("impersonate_send", senderName, { asUser: impAs, channelId: impCh, text: impText.slice(0,80) });
        ws.send(JSON.stringify({ type: "success", message: `Message sent as ${impAcct.value.name}.` }));
        break;
      }

      case "admin_nuke_account": {
        // Permanently and completely delete an account. Wipes messages, memberships, DMs, sessions.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can nuke accounts." })); break; }
        const nukeTarget = (msg.target as string || "").trim().toLowerCase();
        if (!nukeTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        if (nukeTarget === "puck") { ws.send(JSON.stringify({ type: "error", message: "Cannot nuke Puck." })); break; }
        const nukeAcct = await kv.get<Record<string,unknown>>(["accounts", nukeTarget]);
        if (!nukeAcct.value) { ws.send(JSON.stringify({ type: "error", message: `User '${nukeTarget}' not found.` })); break; }
        const nukeDisplayName = nukeAcct.value.name as string;

        // 1. Delete account
        await kv.delete(["accounts", nukeTarget]);
        await kv.delete(["profile_ext", nukeTarget]);

        // 2. Delete all sessions
        const nukeSessIter = kv.list<string>({ prefix: ["sessions"] });
        for await (const item of nukeSessIter) {
          if (item.value === nukeTarget) { await kv.delete(item.key); sessions.delete(item.key[1] as string); }
        }

        // 3. Delete user_servers index
        await kv.delete(["user_servers", nukeTarget]);

        // 4. Remove from all server memberships
        const nukeMemIter = kv.list({ prefix: ["server_member"] });
        for await (const item of nukeMemIter) {
          if ((item.key[2] as string)?.toLowerCase() === nukeTarget) await kv.delete(item.key);
        }

        // 5. Purge all channel messages by this user
        const nukeChIter = kv.list<unknown[]>({ prefix: ["ch_history"] });
        for await (const item of nukeChIter) {
          if (!item.value?.length) continue;
          const filtered = item.value.filter((m: unknown) => (m as Record<string,unknown>).author?.toString().toLowerCase() !== nukeTarget);
          if (filtered.length !== item.value.length) {
            await kv.set(item.key, filtered);
            msgHistory.set(item.key[1] as string, filtered);
          }
        }

        // 6. Delete DM history involving this user
        const nukeDmIter = kv.list({ prefix: ["dm_history"] });
        for await (const item of nukeDmIter) {
          if ((item.key[1] as string).includes(nukeTarget)) await kv.delete(item.key);
        }

        // 7. Delete bans/freeze/notes
        await kv.delete(["bans",   nukeTarget]);
        await kv.delete(["frozen", nukeTarget]);
        await kv.delete(["admin_notes", nukeTarget]);
        frozenUsers.delete(nukeTarget);
        timedBans.delete(nukeTarget);

        // 8. Kill live connections
        for (const [cws, ci] of clients) {
          if ((ci.name as string)?.toLowerCase() === nukeTarget) {
            try { cws.send(JSON.stringify({ type: "force_logout", by: senderName })); cws.close(1000, "Account deleted"); } catch { /* ok */ }
          }
        }

        broadcast({ type: "admin_nuke", target: nukeDisplayName, by: senderName }, null);
        await auditLog("nuke_account", senderName, { target: nukeTarget });
        ws.send(JSON.stringify({ type: "success", message: `Account '${nukeDisplayName}' and all associated data permanently deleted.` }));
        console.log(`[admin] ${senderName} NUKED account ${nukeTarget}`);
        break;
      }

      case "admin_set_tag": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can change user tags." })); break; }
        const stTarget = (msg.target as string || "").trim().toLowerCase();
        const stTag    = (msg.tag    as string || "").trim();
        if (!stTarget || !/^\d{4}$/.test(stTag)) { ws.send(JSON.stringify({ type: "error", message: "Target and 4-digit tag required." })); break; }
        const stKey   = ["accounts", stTarget];
        const stEntry = await kv.get<Record<string,unknown>>(stKey);
        if (!stEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        await kv.set(stKey, { ...stEntry.value, tag: stTag });
        for (const [, ci] of clients) {
          if ((ci.name as string).toLowerCase() === stTarget) (ci as Record<string,unknown>).tag = stTag;
        }
        broadcast({ type: "profile_update", user: stEntry.value.name, tag: stTag, color: stEntry.value.color, pfp: stEntry.value.pfp }, null);
        ws.send(JSON.stringify({ type: "success", message: `Tag updated to #${stTag} for ${stEntry.value.name}.` }));
        break;
      }

      case "admin_set_slowmode": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const smCh   = (msg.channelId as string || "").trim();
        const smSecs = Math.max(0, Math.min(3600, parseInt(msg.seconds as string) || 0));
        if (!smCh) { ws.send(JSON.stringify({ type: "error", message: "channelId required." })); break; }
        if (smSecs === 0) {
          slowmodes.delete(smCh);
          await kv.delete(["slowmode", smCh]);
        } else {
          slowmodes.set(smCh, smSecs);
          await kv.set(["slowmode", smCh], smSecs);
        }
        broadcast({ type: "slowmode_update", channelId: smCh, seconds: smSecs, by: senderName }, null);
        ws.send(JSON.stringify({ type: "success", message: smSecs ? `Slowmode set to ${smSecs}s.` : "Slowmode disabled." }));
        break;
      }

      case "admin_set_maintenance": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can toggle maintenance mode." })); break; }
        maintenanceMode = msg.enabled === true;
        if (maintenanceMode) {
          await kv.set(["platform", "maintenance"], true);
        } else {
          await kv.delete(["platform", "maintenance"]);
        }
        broadcast({ type: "maintenance_update", enabled: maintenanceMode, by: senderName }, null);
        if (maintenanceMode) {
          // Kick everyone except the platform admin (systemRole === "admin")
          // Co-admins have systemRole === "user" so they are correctly kicked here
          let kicked = 0;
          for (const [cws, ci] of clients) {
            if (ci.systemRole !== "admin") {
              try {
                cws.send(JSON.stringify({ type: "maintenance", message: "Nexus is entering maintenance mode. Please reconnect later." }));
                cws.close(1000, "Maintenance");
                kicked++;
              } catch { /* ok */ }
            }
          }
          ws.send(JSON.stringify({ type: "success", message: `Maintenance mode ON. Kicked ${kicked} non-admin user(s).` }));
        } else {
          ws.send(JSON.stringify({ type: "success", message: "Maintenance mode OFF. Platform is live." }));
        }
        await auditLog("maintenance_toggle", senderName, { enabled: maintenanceMode });
        break;
      }

      case "admin_mass_dm": {
        // Send a system DM to every registered user.
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can send mass DMs." })); break; }
        const massDmText = (msg.text as string || "").trim().slice(0, 2000);
        if (!massDmText) { ws.send(JSON.stringify({ type: "error", message: "Text required." })); break; }
        const massDmIter = kv.list<Record<string,unknown>>({ prefix: ["accounts"] });
        let massDmCount = 0;
        for await (const item of massDmIter) {
          const recipient = item.value?.name as string;
          if (!recipient || recipient === senderName) continue;
          const sysMassMsg = {
            type: "dm", id: crypto.randomUUID().replace(/-/g,""),
            from: "System", to: recipient, text: massDmText,
            ts: Date.now(), authorColor: "#6c63ff", system: true,
          };
          const massKey  = ["dm_history", ["system", recipient.toLowerCase()].sort().join(":")];
          const massHist = (await kv.get<unknown[]>(massKey)).value || [];
          massHist.push(sysMassMsg);
          if (massHist.length > 500) massHist.splice(0, massHist.length - 500);
          await kv.set(massKey, massHist);
          sendToUser(recipient, sysMassMsg, true);
          massDmCount++;
        }
        await auditLog("mass_dm", senderName, { text: massDmText.slice(0,80), recipients: massDmCount });
        ws.send(JSON.stringify({ type: "success", message: `Mass DM sent to ${massDmCount} user(s).` }));
        break;
      }

      case "admin_clone_server": {
        // Duplicate a server's channels & settings into a new server (no members, no messages).
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can clone servers." })); break; }
        const cloneSrcId  = (msg.serverId as string || "").trim();
        const cloneName   = (msg.name     as string || "").trim().slice(0, 64);
        if (!cloneSrcId || !cloneName) { ws.send(JSON.stringify({ type: "error", message: "serverId and name required." })); break; }
        const cloneSrc = await kv.get<Record<string,unknown>>(["servers", cloneSrcId]);
        if (!cloneSrc.value) { ws.send(JSON.stringify({ type: "error", message: "Source server not found." })); break; }
        const cloneId  = crypto.randomUUID().replace(/-/g,"").slice(0,16);
        // Give cloned channels fresh IDs
        const srcChannels = (cloneSrc.value.channels as Array<Record<string,unknown>>) || [];
        const clonedChannels = srcChannels.map(ch => ({ ...ch, id: crypto.randomUUID().replace(/-/g,"").slice(0,16) }));
        const cloneData = {
          id: cloneId, name: cloneName, desc: cloneSrc.value.desc || "",
          icon: null, color: cloneSrc.value.color || "#6c63ff",
          memberCount: 1, createdAt: Date.now(),
          channels: clonedChannels,
          ownerId: senderName, ownerIdLower: senderName.toLowerCase(),
          isPublic: cloneSrc.value.isPublic !== false,
        };
        await kv.set(["servers", cloneId], cloneData);
        await kv.set(["server_member", cloneId, senderName], { joinedAt: Date.now() });
        await addServerToUser(senderName.toLowerCase(), cloneId);
        if (cloneData.isPublic) publicServers.set(cloneId, cloneData);
        ws.send(JSON.stringify({ type: "server_create_ok", server: cloneData }));
        ws.send(JSON.stringify({ type: "success", message: `Server '${cloneName}' cloned from '${cloneSrc.value.name}'.` }));
        break;
      }

      case "admin_set_server_icon": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const ssiSvId = (msg.serverId as string || "").trim();
        const ssiIcon = msg.icon as string | null;
        if (!ssiSvId) { ws.send(JSON.stringify({ type: "error", message: "serverId required." })); break; }
        const ssiEntry = await kv.get<Record<string,unknown>>(["servers", ssiSvId]);
        if (!ssiEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const ssiUpdated = { ...ssiEntry.value, icon: ssiIcon || null };
        await kv.set(["servers", ssiSvId], ssiUpdated);
        if (publicServers.has(ssiSvId)) publicServers.set(ssiSvId, ssiUpdated);
        broadcast({ type: "server_updated", serverId: ssiSvId, icon: ssiIcon, name: ssiEntry.value.name }, null);
        ws.send(JSON.stringify({ type: "success", message: "Server icon updated." }));
        break;
      }

      case "admin_set_server_desc": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const ssdSvId = (msg.serverId as string || "").trim();
        const ssdDesc = (msg.desc    as string || "").trim().slice(0, 300);
        if (!ssdSvId) { ws.send(JSON.stringify({ type: "error", message: "serverId required." })); break; }
        const ssdEntry = await kv.get<Record<string,unknown>>(["servers", ssdSvId]);
        if (!ssdEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const ssdUpdated = { ...ssdEntry.value, desc: ssdDesc };
        await kv.set(["servers", ssdSvId], ssdUpdated);
        if (publicServers.has(ssdSvId)) publicServers.set(ssdSvId, ssdUpdated);
        broadcast({ type: "server_updated", serverId: ssdSvId, desc: ssdDesc, name: ssdEntry.value.name }, null);
        ws.send(JSON.stringify({ type: "success", message: "Server description updated." }));
        break;
      }

      case "admin_set_server_public": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const sspSvId  = (msg.serverId as string || "").trim();
        const sspPublic = msg.isPublic !== false;
        if (!sspSvId) { ws.send(JSON.stringify({ type: "error", message: "serverId required." })); break; }
        const sspEntry = await kv.get<Record<string,unknown>>(["servers", sspSvId]);
        if (!sspEntry.value) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        const sspUpdated = { ...sspEntry.value, isPublic: sspPublic };
        await kv.set(["servers", sspSvId], sspUpdated);
        if (sspPublic) publicServers.set(sspSvId, sspUpdated); else publicServers.delete(sspSvId);
        ws.send(JSON.stringify({ type: "success", message: `Server set to ${sspPublic ? "public" : "private"}.` }));
        break;
      }

      case "admin_add_note": {
        // Attach an internal admin note to any account. Never shown to the user.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const noteTarget = (msg.target as string || "").trim().toLowerCase();
        const noteText   = (msg.note   as string || "").trim().slice(0, 1000);
        if (!noteTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        const notesKey = ["admin_notes", noteTarget];
        const existing = (await kv.get<unknown[]>(notesKey)).value || [];
        existing.push({ text: noteText, by: senderName, at: Date.now() });
        await kv.set(notesKey, existing);
        ws.send(JSON.stringify({ type: "success", message: "Note saved." }));
        ws.send(JSON.stringify({ type: "admin_notes_data", target: noteTarget, notes: existing }));
        break;
      }

      case "admin_get_notes": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const gnTarget = (msg.target as string || "").trim().toLowerCase();
        if (!gnTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        const gnNotes = (await kv.get<unknown[]>(["admin_notes", gnTarget])).value || [];
        ws.send(JSON.stringify({ type: "admin_notes_data", target: gnTarget, notes: gnNotes }));
        break;
      }

      case "admin_delete_note": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const dnTarget = (msg.target as string || "").trim().toLowerCase();
        const dnRawIndex = parseInt(msg.index as string);
        if (!dnTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        if (isNaN(dnRawIndex) || dnRawIndex < 0) { ws.send(JSON.stringify({ type: "error", message: "Valid note index required." })); break; }
        const dnIndex = dnRawIndex;
        const dnKey   = ["admin_notes", dnTarget];
        const dnNotes = (await kv.get<unknown[]>(dnKey)).value || [];
        if (dnIndex >= dnNotes.length) { ws.send(JSON.stringify({ type: "error", message: "Note index out of range." })); break; }
        dnNotes.splice(dnIndex, 1);
        await kv.set(dnKey, dnNotes);
        ws.send(JSON.stringify({ type: "admin_notes_data", target: dnTarget, notes: dnNotes }));
        ws.send(JSON.stringify({ type: "success", message: "Note deleted." }));
        break;
      }

      case "admin_get_audit_log": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const auditLimit = Math.min(200, parseInt(msg.limit as string) || 50);
        const auditEntries: unknown[] = [];
        const auditIter = kv.list({ prefix: ["audit"] }, { reverse: true, limit: auditLimit });
        for await (const item of auditIter) auditEntries.push(item.value);
        ws.send(JSON.stringify({ type: "admin_audit_log", entries: auditEntries }));
        break;
      }

      case "admin_clear_audit_log": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can clear the audit log." })); break; }
        const clearIter = kv.list({ prefix: ["audit"] });
        let clearCount = 0;
        for await (const item of clearIter) { await kv.delete(item.key); clearCount++; }
        ws.send(JSON.stringify({ type: "success", message: `Audit log cleared (${clearCount} entries).` }));
        break;
      }

      case "admin_list_user_servers": {
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const lusTarget = (msg.target as string || "").trim().toLowerCase();
        if (!lusTarget) { ws.send(JSON.stringify({ type: "error", message: "Target required." })); break; }
        const lusIds = (await kv.get<string[]>(["user_servers", lusTarget])).value || [];
        const lusList: unknown[] = [];
        for (const svId of lusIds) {
          const sv = await kv.get<Record<string,unknown>>(["servers", svId]);
          if (sv.value) lusList.push({ id: sv.value.id, name: sv.value.name, ownerId: sv.value.ownerId });
        }
        ws.send(JSON.stringify({ type: "admin_user_servers", target: lusTarget, servers: lusList }));
        break;
      }

      case "admin_export_channel": {
        // Export a channel's full history as JSON back to the requester.
        if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); break; }
        const expChId = (msg.channelId as string || "").trim();
        if (!expChId) { ws.send(JSON.stringify({ type: "error", message: "channelId required." })); break; }
        const expHist = (await kv.get<unknown[]>(["ch_history", expChId])).value || [];
        ws.send(JSON.stringify({ type: "admin_channel_export", channelId: expChId, messages: expHist, exportedAt: Date.now() }));
        break;
      }

      case "admin_send_unread_announce": {
        // Push a notification to all users (appears as a notification ping).
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can send announcements." })); break; }
        const announceText = (msg.text as string || "").trim().slice(0, 500);
        if (!announceText) { ws.send(JSON.stringify({ type: "error", message: "Text required." })); break; }
        broadcast({ type: "platform_announcement", text: announceText, by: senderName, at: Date.now() }, null);
        await auditLog("send_announcement", senderName, { text: announceText.slice(0,80) });
        ws.send(JSON.stringify({ type: "success", message: "Announcement sent to all online users." }));
        break;
      }

      default:
        console.log("Unknown:", msg.type);
    }
  } // end handleMsg

  ws.onclose = async () => {
    const info = clientInfo(ws);
    clients.delete(ws);
    if (info?.name) {
      const userName = info.name as string;
      const lower = userName.toLowerCase();
      console.log("Disconnected:", userName);
      // Only when this was their LAST connection are they actually offline. (Announcing on every close made
      // everyone show as offline right after a refresh or when one of two tabs was closed.)
      if (!socketsOf(lower).length) {
        await safeKvSet(["last_seen", lower], Date.now());
        await announcePresence(lower, userName, info.serverIds as Set<string> | undefined);
      }
      // Leave any call this connection was in. (A call belongs to the tab it was joined from; if the user still has
      // another tab open, that tab's calls are unaffected.)
      const gone = !socketsOf(lower).length;
      for (const call of [...activeCalls.values()]) {
        if (call.wsOf.get(lower) === ws || (gone && [...call.participants].some((p) => p === userName))) await leaveCall(call, lower);
      }
      // Remove any ghost call they were running
      for (const [callId, ghostUser] of ghostCalls) {
        if (ghostUser === userName) ghostCalls.delete(callId);
      }
    }
  };

  ws.onerror = (err) => console.error("WS error:", err);

  return response;
});
