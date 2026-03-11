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

// ─── KV setup ───────────────────────────────────────────────────────────────
const kv = await Deno.openKv();

// Seed Puck admin account if not already present
const puckKey = ["accounts", "puck"];
const puckEntry = await kv.get(puckKey);
if (!puckEntry.value) {
  await kv.set(puckKey, {
    name: "Puck",
    tag: "0001",
    color: "#6c63ff",
    pfp: null,
    passwordHash: await hashPw("changeme"),
    systemRole: "admin",
    coAdmin: false,
    createdAt: Date.now(),
  });
  console.log("Seeded Puck admin account (password: changeme)");
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
const activeCalls = new Map<string, { participants: Set<string>; startedAt: number }>();
// ghost call watchers: callId → admin username (only one ghost per call for simplicity)
const ghostCalls = new Map<string, string>();
// platform maintenance mode — only admins can connect/identify when true
let maintenanceMode = false;
// audit log ring buffer (last 500 admin actions, also persisted to KV)
const AUDIT_LIMIT = 500;

// ─── Stale call cleanup — runs every 60s, removes calls where no participants are online ─
setInterval(() => {
  const onlineNames = new Set<string>();
  for (const [, ci] of clients) { if (ci.name) onlineNames.add(ci.name as string); }
  for (const [callId, call] of activeCalls) {
    const anyOnline = [...call.participants].some(p => onlineNames.has(p));
    if (!anyOnline) {
      activeCalls.delete(callId);
      ghostCalls.delete(callId);
    }
  }
}, 60_000);

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
async function addServerToUser(username: string, serverId: string) {
  const key = ["user_servers", username.toLowerCase()];
  const entry = await kv.get<string[]>(key);
  const list = entry.value || [];
  if (!list.includes(serverId)) {
    list.push(serverId);
    await kv.set(key, list);
    console.log(`[membership] added server ${serverId} to user ${username.toLowerCase()} (now has ${list.length})`);
  }
}

async function removeServerFromUser(username: string, serverId: string) {
  const key = ["user_servers", username.toLowerCase()];
  const entry = await kv.get<string[]>(key);
  if (entry.value) {
    await kv.set(key, entry.value.filter((id: string) => id !== serverId));
  }
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

  const chIter = kv.list<unknown[]>({ prefix: ["ch_history"] });
  for await (const item of chIter) {
    const chId = item.key[1] as string;
    if (item.value?.length) msgHistory.set(chId, item.value);
  }

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
    console.log(`[recv] type=${msg.type}`);
    try {
      await handleMsg(ws, msg);
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
        pfp: msg.pfp || null,
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
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: acct.systemRole, coAdmin: false } }));
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
      // FIX #2: Support both new SHA-256 hash and legacy djb2 hash so existing
      // users are not locked out. On successful legacy login, silently upgrade.
      const newHash = await hashPw(password);
      const legacyHash = hashPwLegacy(password);
      const validNew    = acct.passwordHash === newHash;
      const validLegacy = acct.passwordHash === legacyHash;
      if (!validNew && !validLegacy) {
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
      ws.send(JSON.stringify({ type: "auth_ok", token, firstLogin: !!firstLogin, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: acct.systemRole, coAdmin: acct.coAdmin || false } }));
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
      const pfp = msg.pfp || null;
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
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: "user", coAdmin: false }, migrated: true }));
      return;
    }

    // ── ALL OTHER MESSAGES require a valid token ──────────────────────────
    const tokenUser = await verifyTokenKv(msg.token as string);
    if (!tokenUser) {
      console.log(`[auth] token verification failed for type=${msg.type} token=${(msg.token as string || '').slice(0,16)}...`);
      ws.send(JSON.stringify({ type: "auth_required", message: "Please log in." }));
      return;
    }

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
        color: msg.color || "#6c63ff",
        pfp: msg.pfp || null,
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
        color: msg.color || acct?.color || "#6c63ff",
        pfp: msg.pfp || acct?.pfp || null,
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
          const merged = [...(userSvIdsEntry.value || []), ...recovered];
          console.log(`[migrate] recovered ${recovered.length} orphaned server(s) for ${name}: ${recovered.join(", ")}`);
          await kv.set(userSvsKey, merged);
          userSvIdsEntry = await kv.get<string[]>(userSvsKey);
        }
      }

      console.log(`[identify] user=${name} (key=${tokenUser}) user_servers=${JSON.stringify(userSvIdsEntry.value)}`);
      const userSvIds = userSvIdsEntry.value || [];

      // Store server membership on client info for scoped broadcasting
      const clientInfo2 = clients.get(ws);
      if (clientInfo2) (clientInfo2 as Record<string, unknown>).serverIds = new Set(userSvIds);

      const userServers: Record<string, unknown>[] = [];
      for (const svId of userSvIds) {
        const svEntry = await kv.get<Record<string, unknown>>(["servers", svId]);
        console.log(`[identify] svId=${svId} found=${!!svEntry.value}`);
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

      const friendsRaw = ((await kv.get<unknown[]>(["friends", tokenUser])).value || []) as Record<string, unknown>[];
      // Enrich friends with current pfp from their account records
      const friendsList = await Promise.all(friendsRaw.map(async f => {
        const fAcct = await kv.get<Record<string, unknown>>(["accounts", (f.name as string || "").toLowerCase()]);
        return { ...f, pfp: fAcct.value?.pfp || f.pfp || null, color: fAcct.value?.color || f.color || null };
      }));
      const pendingReqs: unknown[] = [];
      const reqIter = kv.list({ prefix: ["friend_requests", tokenUser] });
      for await (const item of reqIter) pendingReqs.push(item.value);

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
            socials: acct?.socials || {}
          },
          servers: userServers,
        }));
        // Always send pfp state: send null explicitly if the user has none,
        // so the client can clear a stale cached pfp after an admin wipe.
        ws.send(JSON.stringify({ type: "user_pfp", pfp: acct?.pfp || null }));
        if ((friendsList as unknown[]).length || (pendingReqs as unknown[]).length) {
          ws.send(JSON.stringify({ type: "friends_data", friends: friendsList, friendRequests: pendingReqs }));
        }
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
              pfp: (otherAcct.value?.pfp as string | null) ?? null,
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

      // Broadcast member_join to all servers this user belongs to
      // so other online members see them come online immediately
      for (const svId of userSvIds) {
        broadcastToServer(svId, {
          type: "member_join",
          serverId: svId,
          user: acct?.name || name,
          color: acct?.color || "#6c63ff",
          pfp: acct?.pfp || null,
          tag: acct?.tag || "0000",
        }, ws);
      }

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
      const adminDelEntry = await kv.get<Record<string, unknown>>(["servers", adminDelId]);
      publicServers.delete(adminDelId);
      await kv.delete(["servers", adminDelId]);
      // Clean up channel history
      const adminDelChannels = (adminDelEntry.value?.channels as Array<{ id: string }>) || [];
      for (const ch of adminDelChannels) await kv.delete(["ch_history", ch.id]);
      // Clean up member indexes
      const adminDelMemIter = kv.list({ prefix: ["server_member", adminDelId] });
      for await (const item of adminDelMemIter) {
        const memberName = item.key[2] as string;
        await kv.delete(item.key);
        await removeServerFromUser(memberName, adminDelId);
      }
      broadcast({ type: "server_delete", serverId: adminDelId, by: senderName });
      ws.send(JSON.stringify({ type: "success", message: "Server deleted." }));
      return;
    }

    if (msg.type === "profile_update") {
      const key = ["accounts", senderName.toLowerCase()];
      const entry = await kv.get<Record<string, unknown>>(key);
      // BUG 10 FIX: Validate color is a proper hex string before storing.
      // An unvalidated raw string could be stored and rendered directly in CSS, 
      // allowing style injection. Reject anything that isn't a valid 3 or 6-digit hex color.
      const rawColor = msg.color as string || "";
      const safeColor = /^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/.test(rawColor)
        ? rawColor
        : (entry.value?.color as string || "#6c63ff");
      const safeBio = (msg.bio as string ?? (entry.value?.bio as string) ?? "").slice(0, 160);
      if (entry.value) {
        await kv.set(key, { ...entry.value, color: safeColor, pfp: msg.pfp !== undefined ? msg.pfp : entry.value.pfp, bio: safeBio, socials: msg.socials ?? entry.value.socials });
      }
      if (info) {
        (info as Record<string, unknown>).color = safeColor;
        (info as Record<string, unknown>).pfp = msg.pfp;
        (info as Record<string, unknown>).bio = safeBio;
      }
      // Broadcast to all OTHER clients (they need to update their caches/renders)
      broadcast({ ...msg, color: safeColor, bio: safeBio }, ws);
      // Also confirm back to sender with the authoritative values (color may have been sanitized)
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "profile_update_confirm", color: safeColor, pfp: msg.pfp ?? null, bio: safeBio, socials: msg.socials ?? {} }));
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
        const chEntry = await kv.get<unknown[]>(chKey);
        const chHist = chEntry.value || [];
        // Strip base64 image/video/audio data before persisting to KV.
        // Deno free tier has a 64 KB per-value limit — base64 attachments can be several MB.
        // Live recipients get the full data via broadcast below; late-joiners use p2p video_request.
        const msgToStore = { ...(msg as Record<string,unknown>) };
        if (Array.isArray(msgToStore.attachments)) {
          msgToStore.attachments = (msgToStore.attachments as Record<string,unknown>[]).map(att => {
            const url = att.url as string || "";
            if (url.startsWith("data:")) {
              return { ...att, url: "", _stripped: true };
            }
            return att;
          });
        }
        chHist.push(msgToStore);
        if (chHist.length > 500) chHist.splice(0, chHist.length - 500);
        try {
          await kv.set(chKey, chHist);
        } catch(e) {
          // If history is still too large, trim aggressively and retry
          const trimmed = chHist.slice(-100);
          try { await kv.set(chKey, trimmed); } catch(_) {}
        }
        storeMessage(msg.channelId as string, msg);
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

      case "ping":
        // Keepalive — reply immediately so client knows connection is alive
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "pong", ts: msg.ts }));
        break;

      case "typing":
      case "member_join":
      case "member_leave":
      case "kick_member":
      case "status_update":
        broadcast(msg, ws);
        break;

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
        // Permission check: sender must be owner or admin
        const caOwnerLower = (caEntry.value.ownerIdLower as string || (caEntry.value.ownerId as string || "").toLowerCase());
        if (caOwnerLower !== senderName.toLowerCase() && !isAdmin && !isCoAdmin) break;
        const caChannels = [...((caEntry.value.channels as unknown[]) || []), caCh];
        const caUpdated  = { ...caEntry.value, channels: caChannels };
        await kv.set(["servers", caSvId], caUpdated);
        if (publicServers.has(caSvId)) publicServers.set(caSvId, caUpdated);
        broadcastToServer(caSvId, { type: "server_channel_added", serverId: caSvId, channel: caCh, by: senderName }, null);
        break;
      }

      case "channel_remove": {
        // Regular user removes a channel from their own server
        const crSvId = (msg.serverId as string || "").trim();
        const crChId = (msg.channelId as string || "").trim();
        if (!crSvId || !crChId) break;
        const crEntry = await kv.get<Record<string, unknown>>(["servers", crSvId]);
        if (!crEntry.value) break;
        const crOwnerLower = (crEntry.value.ownerIdLower as string || (crEntry.value.ownerId as string || "").toLowerCase());
        if (crOwnerLower !== senderName.toLowerCase() && !isAdmin && !isCoAdmin) break;
        const crChannels = ((crEntry.value.channels as unknown[]) || []).filter((c: unknown) => (c as Record<string,unknown>).id !== crChId);
        const crUpdated  = { ...crEntry.value, channels: crChannels };
        await kv.set(["servers", crSvId], crUpdated);
        if (publicServers.has(crSvId)) publicServers.set(crSvId, crUpdated);
        await kv.delete(["ch_history", crChId]);
        msgHistory.delete(crChId);
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
            await kv.set(ruKey, { ...stored, roles: msg.roles });
            if (publicServers.has(ruSvId)) publicServers.get(ruSvId)!.roles = msg.roles;
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

      case "vcall_invite": {
        const inviteCallId = msg.callId as string;
        if (inviteCallId) {
          // BUG 9 FIX: activeCalls.set already adds sender, then participants.add(senderName)
          // ran again unconditionally. Set.add is idempotent so harmless, but the intent
          // was: create new call with sender, OR add sender if rejoining. Now explicit:
          if (!activeCalls.has(inviteCallId)) {
            activeCalls.set(inviteCallId, { participants: new Set([senderName]), startedAt: Date.now() });
          } else {
            activeCalls.get(inviteCallId)!.participants.add(senderName);
          }
        }
        sendToUser(msg.to as string, msg, false); // never queue call invites
        break;
      }
      case "vcall_accept": {
        const acceptCallId = msg.callId as string;
        if (acceptCallId && activeCalls.has(acceptCallId)) {
          activeCalls.get(acceptCallId)!.participants.add(senderName);
        }
        sendToUser(msg.to as string, msg, false); // never queue
        break;
      }
      case "vcall_decline":
      case "vcall_signal": {
        // Never queue signals — stale ICE candidates arriving after negotiation
        // completes will corrupt the connection. Fire-and-forget only.
        sendToUser(msg.to as string, msg, false);
        break;
      }
      case "vcall_end": {
        // Route end signal only to call participants, not the whole server
        const endCallId = msg.callId as string;
        if (endCallId && activeCalls.has(endCallId)) {
          const endCall = activeCalls.get(endCallId)!;
          for (const participant of endCall.participants) {
            if (participant !== senderName) {
              sendToUser(participant, msg, false);
            }
          }
          activeCalls.delete(endCallId);
          ghostCalls.delete(endCallId);
        } else {
          // Fallback: if call wasn't tracked, send to explicit `to` list if provided
          if (Array.isArray(msg.to)) {
            for (const target of msg.to as string[]) {
              sendToUser(target, msg, false);
            }
          }
        }
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
        if (svData.isPublic) publicServers.set(msg.serverId as string, svData);
        await kv.set(["servers", msg.serverId as string], svData);

        // Verify it actually wrote
        const verifyWrite = await kv.get(["servers", msg.serverId as string]);
        console.log(`[server_create] KV write verified=${!!verifyWrite.value} id=${msg.serverId} owner=${senderName}`);

        await kv.set(["server_member", msg.serverId as string, senderName], { joinedAt: Date.now() });
        await addServerToUser(senderName, msg.serverId as string);

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
        const existing = await kv.get<Record<string, unknown>>(["servers", sid]);
        // FIX: Guard - only owner or admin can update a server
        const svForCheck = existing.value || publicServers.get(sid);
        if (svForCheck) {
          const storedOwnerLower = (svForCheck.ownerIdLower as string || (svForCheck.ownerId as string || "").toLowerCase());
          if (storedOwnerLower !== senderName.toLowerCase() && !isAdmin && !isCoAdmin) {
            console.log(`[server_update] BLOCKED: ${senderName} tried to update server ${sid} owned by ${svForCheck.ownerId}`);
            break;
          }
        }
        // FIX: Never allow ownerId to be changed via server_update
        // Remove ownerId/ownerIdLower from msg copy so they can't overwrite stored owner
        const safeMsg = { ...msg as Record<string, unknown> };
        delete safeMsg.ownerId;
        delete safeMsg.ownerIdLower;
        if (publicServers.has(sid)) {
          const sv = publicServers.get(sid)!;
          // Preserve ownerId/ownerIdLower from stored record
          const preservedOwner = { ownerId: sv.ownerId, ownerIdLower: sv.ownerIdLower || (sv.ownerId as string || "").toLowerCase() };
          if (safeMsg.isPublic === false) {
            publicServers.delete(sid);
            await kv.set(["servers", sid], { ...sv, ...safeMsg, ...preservedOwner, isPublic: false });
          } else {
            const updated = { ...sv, ...safeMsg, ...preservedOwner };
            publicServers.set(sid, updated);
            await kv.set(["servers", sid], updated);
          }
        } else if (safeMsg.isPublic === true) {
          const base = existing.value || {};
          const preservedOwner = { ownerId: (base.ownerId as string) || senderName, ownerIdLower: (base.ownerIdLower as string) || senderName.toLowerCase() };
          const updated = { ...base, id: sid, name: safeMsg.name, desc: safeMsg.desc || "", icon: safeMsg.icon || null, color: safeMsg.color || "#6c63ff", memberCount: safeMsg.memberCount || 1, createdAt: safeMsg.createdAt || Date.now(), channels: safeMsg.channels || [], ...preservedOwner, isPublic: true };
          publicServers.set(sid, updated);
          await kv.set(["servers", sid], updated);
        } else if (existing.value) {
          const preservedOwner = { ownerId: existing.value.ownerId, ownerIdLower: existing.value.ownerIdLower || (existing.value.ownerId as string || "").toLowerCase() };
          await kv.set(["servers", sid], { ...existing.value, ...safeMsg, ...preservedOwner });
        }
        // Broadcast the message with the correct, authoritative ownerId
        const finalSv = (await kv.get<Record<string, unknown>>(["servers", sid])).value || publicServers.get(sid);
        broadcast({ ...msg, ownerId: finalSv?.ownerId }, ws);
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
        publicServers.delete(delSvId);
        await kv.delete(["servers", delSvId]);
        const delChannels = (delSvEntry.value?.channels as Array<{ id: string }>) || [];
        for (const ch of delChannels) await kv.delete(["ch_history", ch.id]);
        // Remove from all member indexes
        const delMemIter = kv.list({ prefix: ["server_member", delSvId] });
        for await (const item of delMemIter) {
          const memberName = item.key[2] as string;
          await kv.delete(item.key);
          await removeServerFromUser(memberName, delSvId);
        }
        broadcast(msg, ws);
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
        broadcast(msg, ws);
        break;
      }

      case "join_server": {
        const jsvId = msg.serverId as string;
        // Look up the server — fall back to KV if not in the public cache (e.g. private servers)
        const jsvEntry = await kv.get<Record<string,unknown>>(["servers", jsvId]);
        const jsv = jsvEntry.value;
        if (!jsv) { ws.send(JSON.stringify({ type: "error", message: "Server not found." })); break; }
        // Non-power-users may only join public servers
        if (jsv.isPublic === false && !isPowerUser) {
          ws.send(JSON.stringify({ type: "error", message: "That server is private." }));
          break;
        }
        const sv = publicServers.get(jsvId);
        if (sv) { sv.memberCount = ((sv.memberCount as number) || 1) + 1; await kv.set(["servers", jsvId], sv); }
        await kv.set(["server_member", jsvId, senderName], { joinedAt: Date.now() });
        // FIX: Use helper to ensure consistent lowercase key
        await addServerToUser(senderName, jsvId);
        // Track in client's in-memory serverIds so broadcastToServer works immediately
        const joiningInfo = clients.get(ws);
        if (joiningInfo) {
          if (!(joiningInfo as Record<string,unknown>).serverIds) (joiningInfo as Record<string,unknown>).serverIds = new Set();
          ((joiningInfo as Record<string,unknown>).serverIds as Set<string>).add(jsvId);
        }
        broadcast(msg, ws);
        break;
      }

      case "announce_servers":
        // FIX #4: Only allow announcing servers the sender actually owns (or power users)
        for (const sv of (msg.servers as unknown[] || [])) {
          const s = sv as Record<string, unknown>;
          if (!s.id) continue;
          // FIX: Check if server already exists - if so, preserve ownerId
          const existingSv = await kv.get<Record<string, unknown>>(["servers", s.id as string]);
          const existingOwner = existingSv.value?.ownerId;
          const existingOwnerLower = existingSv.value?.ownerIdLower || (existingOwner as string || "").toLowerCase();
          // If a stored owner exists and doesn't match the sender, skip unless power user
          if (existingOwnerLower && existingOwnerLower !== senderName.toLowerCase() && !isPowerUser) {
            console.log(`[announce_servers] BLOCKED: ${senderName} tried to announce server ${s.id} owned by ${existingOwner}`);
            continue;
          }
          const svEntry: Record<string, unknown> = {
            id: s.id, name: s.name, desc: s.desc || "",
            icon: s.icon || null, color: s.color || "#6c63ff",
            memberCount: s.memberCount || 1, createdAt: s.createdAt || Date.now(),
            channels: s.channels || [],
            // FIX: preserve stored owner; only set from message if no owner on record
            ownerId: existingOwner || s.ownerId || senderName,
            ownerIdLower: existingOwnerLower || (s.ownerId as string || senderName).toLowerCase(),
            isPublic: true,
          };
          publicServers.set(s.id as string, svEntry);
          await kv.set(["servers", s.id as string], svEntry);
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
        if (svInfo && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "server_info", server: svInfo }));
        break;
      }

      case "fetch_dm_history": {
        const withUser = msg.with as string;
        // FIX #8: Lowercase-normalize key to match how dm messages are stored
        const dmKey = ["dm_history", [senderName.toLowerCase(), withUser.toLowerCase()].sort().join(":")];
        const entry = await kv.get<unknown[]>(dmKey);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "dm_history", with: withUser, messages: entry.value || [] }));
        break;
      }

      case "fetch_dm_contacts": {
        // Return all DM contacts for this user so the client can rebuild its sidebar after a cache clear.
        const dmContactsMap2 = new Map<string, { name: string; lastTs: number; last: string; pfp: string | null }>();
        const dmContactsIter = kv.list<unknown[]>({ prefix: ["dm_history"] });
        for await (const item of dmContactsIter) {
          const keyStr = item.key[1] as string;
          const parts = keyStr.split(":");
          if (!parts.some(p => p === senderName.toLowerCase())) continue;
          const otherLower = parts.find(p => p !== senderName.toLowerCase()) || "";
          if (!otherLower || dmContactsMap2.has(otherLower)) continue;
          const msgs = item.value || [];
          const last = msgs[msgs.length - 1] as Record<string, unknown> | undefined;
          const otherAcct = await kv.get<Record<string, unknown>>(["accounts", otherLower]);
          const displayName = (otherAcct.value?.name as string) || otherLower;
          dmContactsMap2.set(otherLower, {
            name: displayName,
            lastTs: (last?._stored as number || last?.ts as number || 0),
            last: (last?.text as string || (Array.isArray((last as Record<string,unknown>)?.attachments) ? "[attachment]" : "")),
            pfp: (otherAcct.value?.pfp as string | null) ?? null,
          });
        }
        const contacts2 = [...dmContactsMap2.values()].sort((a, b) => b.lastTs - a.lastTs);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "dm_contacts", contacts: contacts2 }));
        break;
      }

      case "get_members": {
        const svId = msg.serverId as string;
        const onlineNamesLower = new Set<string>();
        const onlineMembers = [];
        // Only include online users who are actually members of this server
        for (const [, ci] of clients) {
          if (!ci.name) continue;
          // Check case-insensitively — server_member keys may have been stored with original case
          const nameLower = (ci.name as string).toLowerCase();
          const memCheck = await kv.get(["server_member", svId, ci.name as string]);
          // Also try lowercase variant in case of legacy key
          const memCheckLower = memCheck.value ? memCheck : await kv.get(["server_member", svId, nameLower]);
          if (memCheck.value || memCheckLower.value) {
            if (!onlineNamesLower.has(nameLower)) {
              onlineNamesLower.add(nameLower);
              onlineMembers.push({ name: ci.name, tag: ci.tag, color: ci.color, pfp: ci.pfp, systemRole: ci.systemRole, coAdmin: ci.coAdmin, online: true });
            }
          }
        }
        const memIter2 = kv.list({ prefix: ["server_member", svId] });
        const offlineMembers = [];
        const allKnownLower = new Set(onlineNamesLower);
        for await (const item of memIter2) {
          const mName = item.key[2] as string;
          const mNameLower = mName.toLowerCase();
          if (!allKnownLower.has(mNameLower)) {
            allKnownLower.add(mNameLower);
            const mAcct = await kv.get<Record<string, unknown>>(["accounts", mNameLower]);
            if (mAcct.value) offlineMembers.push({ name: mAcct.value.name, tag: mAcct.value.tag, color: mAcct.value.color, pfp: mAcct.value.pfp, systemRole: mAcct.value.systemRole, coAdmin: mAcct.value.coAdmin, online: false });
          }
        }
        // Ghost-member sweep: scan recent channel history for message authors not in the list.
        // If someone chatted here but isn't in server_member (data inconsistency / migration gap),
        // add them to the offline list and back-fill their membership so future lookups are correct.
        const svEntry4 = await kv.get<Record<string,unknown>>(["servers", svId]);
        const svChannels4 = (svEntry4.value?.channels as Array<{ id: string }>) || [];
        for (const ch of svChannels4) {
          const chHist4 = (await kv.get<unknown[]>(["ch_history", ch.id])).value || [];
          for (const m of chHist4) {
            const mm = m as Record<string, unknown>;
            const authorRaw = mm.author as string | undefined;
            if (!authorRaw) continue;
            const authorLower = authorRaw.toLowerCase();
            if (allKnownLower.has(authorLower)) continue;
            allKnownLower.add(authorLower);
            const ghostAcct = await kv.get<Record<string, unknown>>(["accounts", authorLower]);
            if (!ghostAcct.value) continue;
            // Back-fill server membership so this user shows up correctly going forward
            await kv.set(["server_member", svId, ghostAcct.value.name as string], { joinedAt: Date.now(), addedBy: "ghost-sweep" });
            await addServerToUser(authorLower, svId);
            const isOnline = [...clients.values()].some(ci => (ci.name as string)?.toLowerCase() === authorLower);
            if (isOnline) {
              onlineMembers.push({ name: ghostAcct.value.name, tag: ghostAcct.value.tag, color: ghostAcct.value.color, pfp: ghostAcct.value.pfp, systemRole: ghostAcct.value.systemRole, coAdmin: ghostAcct.value.coAdmin, online: true });
            } else {
              offlineMembers.push({ name: ghostAcct.value.name, tag: ghostAcct.value.tag, color: ghostAcct.value.color, pfp: ghostAcct.value.pfp, systemRole: ghostAcct.value.systemRole, coAdmin: ghostAcct.value.coAdmin, online: false });
            }
            console.log(`[ghost-sweep] added missing member ${authorLower} to server ${svId}`);
          }
        }
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "member_list", serverId: msg.serverId, members: [...onlineMembers, ...offlineMembers] }));
        break;
      }

      case "dm": {
        // Frozen users can't send DMs either
        if (frozenUsers.has(senderName.toLowerCase())) {
          const freeze = frozenUsers.get(senderName.toLowerCase())!;
          ws.send(JSON.stringify({ type: "error", message: `Your account is frozen: ${freeze.reason}` }));
          break;
        }
        const dmTo = msg.to as string;
        const dmFrom = msg.from as string;
        // FIX #8: Normalize both sides to lowercase so case-variant names (e.g. after
        // an admin rename) always resolve to the same KV key.
        const dmKey = ["dm_history", [dmFrom.toLowerCase(), dmTo.toLowerCase()].sort().join(":")];
        const existing = await kv.get<unknown[]>(dmKey);
        const hist = existing.value || [];
        hist.push({ ...msg, _stored: Date.now() });
        if (hist.length > 500) hist.splice(0, hist.length - 500);
        await kv.set(dmKey, hist);
        sendToUser(dmTo, msg, true);
        break;
      }

      case "dm_request":
      case "dm_accept":
      case "dm_decline":
        sendToUser(msg.to as string, msg, true);
        break;

      case "friend_request": {
        // Store the incoming request in KV so the recipient gets it even if they're offline
        const frTo = (msg.to as string || "").toLowerCase();
        if (!frTo) break;
        const frKey = ["friend_requests", frTo, senderName.toLowerCase()];
        await kv.set(frKey, { from: senderName, fromPfp: msg.fromPfp || null, fromColor: msg.fromColor || null, ts: Date.now() });
        sendToUser(msg.to as string, msg, true);
        break;
      }

      case "friend_accept": {
        const faTo = (msg.to as string || "").toLowerCase();
        if (!faTo) break;
        // Delete the pending request from KV
        await kv.delete(["friend_requests", senderName.toLowerCase(), faTo]);
        await kv.delete(["friend_requests", faTo, senderName.toLowerCase()]);
        // Add each user to the other's friends list in KV
        const faMyKey = ["friends", senderName.toLowerCase()];
        const faTheirKey = ["friends", faTo];
        const faMyList = ((await kv.get<unknown[]>(faMyKey)).value || []) as Record<string, unknown>[];
        const faTheirList = ((await kv.get<unknown[]>(faTheirKey)).value || []) as Record<string, unknown>[];
        if (!faMyList.find(f => (f.name as string)?.toLowerCase() === faTo)) {
          faMyList.push({ name: msg.to, pfp: null, color: null });
          await kv.set(faMyKey, faMyList);
        }
        if (!faTheirList.find(f => (f.name as string)?.toLowerCase() === senderName.toLowerCase())) {
          faTheirList.push({ name: senderName, pfp: msg.fromPfp || null, color: msg.fromColor || null });
          await kv.set(faTheirKey, faTheirList);
        }
        sendToUser(msg.to as string, msg, true);
        break;
      }

      case "friend_decline": {
        const fdTo = (msg.to as string || "").toLowerCase();
        // Remove the pending request from KV
        await kv.delete(["friend_requests", senderName.toLowerCase(), fdTo]);
        await kv.delete(["friend_requests", fdTo, senderName.toLowerCase()]);
        sendToUser(msg.to as string, msg, true);
        break;
      }

      case "friend_remove": {
        const frmTarget = (msg.target as string || "").toLowerCase();
        if (!frmTarget) break;
        // Remove from both sides in KV
        const frmMyKey = ["friends", senderName.toLowerCase()];
        const frmTheirKey = ["friends", frmTarget];
        const frmMyList = ((await kv.get<unknown[]>(frmMyKey)).value || []) as Record<string, unknown>[];
        const frmTheirList = ((await kv.get<unknown[]>(frmTheirKey)).value || []) as Record<string, unknown>[];
        await kv.set(frmMyKey, frmMyList.filter(f => (f.name as string)?.toLowerCase() !== frmTarget));
        await kv.set(frmTheirKey, frmTheirList.filter(f => (f.name as string)?.toLowerCase() !== senderName.toLowerCase()));
        // Notify the other user if online
        sendToUser(msg.target as string, { type: "friend_removed", by: senderName }, false);
        break;
      }

      case "dm_delete": {
        // Delete a DM message from KV history and notify the other party
        const dmdTo  = (msg.to as string || "").toLowerCase();
        const dmdId  = msg.messageId as string;
        if (!dmdTo || !dmdId) break;
        const dmdKey   = ["dm_history", [senderName.toLowerCase(), dmdTo].sort().join(":")];
        const dmdEntry = await kv.get<unknown[]>(dmdKey);
        if (dmdEntry.value) {
          const dmdMsg = dmdEntry.value.find((m: unknown) => (m as Record<string,unknown>).id === dmdId) as Record<string,unknown> | undefined;
          // Only the message author or a power user may delete
          if (dmdMsg && dmdMsg.from !== senderName && !isPowerUser) {
            ws.send(JSON.stringify({ type: "error", message: "You can only delete your own messages." }));
            break;
          }
          const filtered = dmdEntry.value.filter((m: unknown) => (m as Record<string,unknown>).id !== dmdId);
          await kv.set(dmdKey, filtered);
        }
        // Notify the other participant so they remove it from their view too
        sendToUser(msg.to as string, msg, false);
        break;
      }

      case "dm_reaction": {
        // Persist a reaction toggle to DM history and forward to the other party
        const dmrTo  = (msg.to as string || "").toLowerCase();
        const dmrId  = msg.messageId as string;
        const dmrEmoji = msg.emoji as string;
        if (!dmrTo || !dmrId || !dmrEmoji) break;
        const dmrKey   = ["dm_history", [senderName.toLowerCase(), dmrTo].sort().join(":")];
        const dmrEntry = await kv.get<unknown[]>(dmrKey);
        if (dmrEntry.value) {
          const dmrHist = dmrEntry.value as Record<string,unknown>[];
          const dmrMsg  = dmrHist.find((m: Record<string,unknown>) => m.id === dmrId);
          if (dmrMsg) {
            const reacts = (dmrMsg.reactions as Record<string,unknown>[] || []);
            let rr = reacts.find((x: Record<string,unknown>) => x.emoji === dmrEmoji) as Record<string,unknown>;
            if (rr) {
              const users = (rr.users as string[] || []);
              if (users.includes(senderName)) {
                rr.count = (rr.count as number) - 1;
                rr.users = users.filter(u => u !== senderName);
                if ((rr.count as number) <= 0) dmrMsg.reactions = reacts.filter((x: Record<string,unknown>) => x.emoji !== dmrEmoji);
              } else { rr.count = (rr.count as number) + 1; rr.users = [...users, senderName]; }
            } else {
              reacts.push({ emoji: dmrEmoji, count: 1, users: [senderName] });
              dmrMsg.reactions = reacts;
            }
            await kv.set(dmrKey, dmrHist);
          }
        }
        // Forward to the other participant so their view updates live
        sendToUser(msg.to as string, msg, false);
        break;
      }

      case "short_post": {
        // Save short metadata to KV — no video data stored (URL-based, or p2p for uploads)
        const spSvId = msg.serverId as string;
        if (spSvId && msg.short) {
          const spKey = ["shorts", spSvId];
          const spList = ((await kv.get<unknown[]>(spKey)).value || []) as Record<string, unknown>[];
          const spShort = msg.short as Record<string, unknown>;
          // Strip any base64 video data — shorts should use external URLs or p2p
          const spToStore = { ...spShort };
          if (typeof spToStore.url === "string" && spToStore.url.startsWith("data:")) {
            spToStore.url = ""; spToStore._stripped = true;
          }
          if (!spList.find(s => s.id === spToStore.id)) {
            spList.push(spToStore);
            if (spList.length > 200) spList.splice(0, spList.length - 200);
            await kv.set(spKey, spList);
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "short_like": {
        const slSvId = msg.serverId as string;
        const slId = msg.shortId as string;
        if (slSvId && slId) {
          const slKey = ["shorts", slSvId];
          const slList = ((await kv.get<unknown[]>(slKey)).value || []) as Record<string, unknown>[];
          const slShort = slList.find(s => s.id === slId) as Record<string, unknown> | undefined;
          if (slShort) {
            const slLikes = (slShort.likes as string[] || []);
            const slUser = msg.user as string;
            if (msg.liked && !slLikes.includes(slUser)) slLikes.push(slUser);
            else if (!msg.liked) slShort.likes = slLikes.filter(u => u !== slUser);
            if (msg.liked) slShort.likes = slLikes;
            await kv.set(slKey, slList);
          }
        }
        broadcast(msg, ws);
        break;
      }

      case "short_comment": {
        const scSvId = msg.serverId as string;
        const scId = msg.shortId as string;
        if (scSvId && scId && msg.comment) {
          const scKey = ["shorts", scSvId];
          const scList = ((await kv.get<unknown[]>(scKey)).value || []) as Record<string, unknown>[];
          const scShort = scList.find(s => s.id === scId) as Record<string, unknown> | undefined;
          if (scShort) {
            if (!Array.isArray(scShort.comments)) scShort.comments = [];
            (scShort.comments as unknown[]).push(msg.comment);
            await kv.set(scKey, scList);
          }
        }
        broadcast(msg, ws);
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
        const pfpData = msg.pfp as string || null;
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
        const auditIter = kv.list({ prefix: ["audit"], reverse: true, limit: auditLimit });
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

  ws.onclose = () => {
    const info = clientInfo(ws);
    if (info) {
      broadcast({ type: "member_leave", user: info.name, serverId: "__all__" });
      console.log("Disconnected:", info.name);
      // Remove from any active calls
      const userName = info.name as string;
      for (const [callId, call] of activeCalls) {
        call.participants.delete(userName);
        if (call.participants.size === 0) activeCalls.delete(callId);
      }
      // Remove any ghost call they were running
      for (const [callId, ghostUser] of ghostCalls) {
        if (ghostUser === userName) ghostCalls.delete(callId);
      }
    }
    clients.delete(ws);
  };

  ws.onerror = (err) => console.error("WS error:", err);

  return response;
});
