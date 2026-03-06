// Nexus WebSocket relay — Deno Deploy
// Server-side auth via Deno KV. Accounts persist across restarts.
// Puck is the platform admin. Co-admins can be appointed by Puck.

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
    passwordHash: hashPw("changeme"),
    systemRole: "admin",
    coAdmin: false,
    createdAt: Date.now(),
  });
  console.log("Seeded Puck admin account (password: changeme)");
}

// ─── Helpers ────────────────────────────────────────────────────────────────
function hashPw(pw: string): string {
  let h = 5381;
  for (let i = 0; i < pw.length; i++) {
    h = (((h << 5) + h) + pw.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
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
const timedBans = new Map<string, { until: number; reason: string }>();

// ─── Utilities ──────────────────────────────────────────────────────────────
function broadcast(data: unknown, exclude: WebSocket | null = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) ws.send(msg);
  }
}

function sendToUser(name: string, data: unknown, queue = true): boolean {
  let delivered = false;
  for (const [ws, info] of clients) {
    if (info.name === name && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
      delivered = true;
    }
  }
  if (!delivered && queue) {
    if (!offline.has(name)) offline.set(name, []);
    const q = offline.get(name)!;
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
}

// ─── Main server ────────────────────────────────────────────────────────────
Deno.serve((req) => {
  if (req.headers.get("upgrade") !== "websocket") {
    return new Response("Nexus relay running ✓", { status: 200 });
  }

  const { socket: ws, response } = Deno.upgradeWebSocket(req);

  ws.onopen = () => console.log("WS connected");

  ws.onmessage = async (e) => {
    let msg: Record<string, unknown>;
    try { msg = JSON.parse(e.data as string); } catch { return; }
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
      const tag = String(Math.floor(Math.random() * 9999)).padStart(4, "0");
      const acct = {
        name: username,
        tag,
        color: msg.color || "#6c63ff",
        pfp: msg.pfp || null,
        passwordHash: hashPw(password),
        systemRole: "user",
        coAdmin: false,
        createdAt: Date.now(),
      };
      await kv.set(key, acct);
      const token = genToken();
      sessions.set(token, username.toLowerCase());
      await kv.set(["sessions", token], username.toLowerCase());
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
      if (acct.passwordHash !== hashPw(password)) {
        ws.send(JSON.stringify({ type: "auth_error", message: "Incorrect password." })); return;
      }
      if (isBanned(username)) {
        const ban = timedBans.get(username);
        const until = ban?.until === -1 ? "permanently" : `until ${new Date(ban!.until).toLocaleString()}`;
        ws.send(JSON.stringify({ type: "auth_error", message: `You are banned ${until}. Reason: ${ban?.reason || "none"}` })); return;
      }
      const token = genToken();
      sessions.set(token, username);
      await kv.set(["sessions", token], username);
      console.log(`Login: ${acct.name}`);
      const firstLogin = !acct.hasLoggedIn;
      if (!acct.hasLoggedIn) await kv.set(key, { ...acct, hasLoggedIn: true });
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
      const acct = { name: username, tag, color, pfp, passwordHash: hashPw(password), systemRole: "user", coAdmin: false, createdAt: Date.now() };
      await kv.set(key, acct);
      const token = genToken();
      sessions.set(token, username.toLowerCase());
      await kv.set(["sessions", token], username.toLowerCase());
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: "user", coAdmin: false }, migrated: true }));
      return;
    }

    // ── ALL OTHER MESSAGES require a valid token ──────────────────────────
    const tokenUser = await verifyTokenKv(msg.token as string);
    if (!tokenUser) {
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
      if (entry.value.passwordHash !== hashPw(oldPassword)) {
        ws.send(JSON.stringify({ type: "error", context: "change_password", message: "Current password is incorrect." })); return;
      }
      await kv.set(key, { ...entry.value, passwordHash: hashPw(newPassword) });
      ws.send(JSON.stringify({ type: "success", message: "Password changed!" }));
      return;
    }

    // ── identify ──────────────────────────────────────────────────────────
    if (msg.type === "identify") {
      const key = ["accounts", tokenUser];
      // Register client immediately (synchronously) so subsequent messages aren't
      // dropped by the !info guard while we await KV reads below.
      // FIX: use tokenUser (lowercase) as a stable early name; will be updated below.
      clients.set(ws, {
        name: tokenUser, // temporary — overwritten after KV lookup
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
      });

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

      const userServers: Record<string, unknown>[] = [];
      for (const svId of userSvIds) {
        const svEntry = await kv.get<Record<string, unknown>>(["servers", svId]);
        console.log(`[identify] svId=${svId} found=${!!svEntry.value}`);
        if (svEntry.value) {
          const sv = svEntry.value;
          userServers.push({
            id: sv.id, name: sv.name, desc: sv.desc || "",
            color: sv.color || "#6c63ff",
            icon: null, // sent separately via get_server_info
            channels: sv.channels || [],
            ownerId: sv.ownerId,
            memberCount: sv.memberCount || 1,
            createdAt: sv.createdAt || 0,
            isPublic: sv.isPublic !== false,
          });
        }
      }
      console.log(`[identify] sending ${userServers.length} servers to ${name}`);

      const friendsList = (await kv.get(["friends", tokenUser])).value || [];
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
            pfp: null,
            systemRole: acct?.systemRole || "user",
            coAdmin: acct?.coAdmin || false,
            bio: acct?.bio || "",
            socials: acct?.socials || {}
          },
          servers: userServers,
        }));
        if (acct?.pfp) {
          ws.send(JSON.stringify({ type: "user_pfp", pfp: acct.pfp }));
        }
        if ((friendsList as unknown[]).length || (pendingReqs as unknown[]).length) {
          ws.send(JSON.stringify({ type: "friends_data", friends: friendsList, friendRequests: pendingReqs }));
        }
      }

      // Flush queued offline messages
      const queue = offline.get(name);
      if (queue?.length) {
        for (const qmsg of queue) {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(qmsg));
        }
        offline.delete(name);
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
      for (const [cws, ci] of clients) {
        if ((ci.name as string).toLowerCase() === target) {
          cws.send(JSON.stringify({ type: "banned", until, reason: msg.reason || "No reason given" }));
          cws.close();
        }
      }
      const untilStr = until === -1 ? "permanently" : `until ${new Date(until).toLocaleString()}`;
      broadcast({ type: "admin_action", action: "ban", target: targetEntry.value.name, by: senderName, reason: msg.reason || "" });
      ws.send(JSON.stringify({ type: "success", message: `${targetEntry.value.name} banned ${untilStr}.` }));
      return;
    }

    if (msg.type === "admin_unban") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      timedBans.delete((msg.target as string || "").toLowerCase());
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
      publicServers.delete(msg.serverId as string);
      await kv.delete(["servers", msg.serverId as string]);
      broadcast({ type: "server_delete", serverId: msg.serverId, by: senderName });
      ws.send(JSON.stringify({ type: "success", message: "Server deleted." }));
      return;
    }

    if (msg.type === "profile_update") {
      const key = ["accounts", senderName.toLowerCase()];
      const entry = await kv.get<Record<string, unknown>>(key);
      if (entry.value) {
        await kv.set(key, { ...entry.value, color: msg.color || entry.value.color, pfp: msg.pfp !== undefined ? msg.pfp : entry.value.pfp, bio: msg.bio ?? entry.value.bio, socials: msg.socials ?? entry.value.socials });
      }
      if (info) { (info as Record<string, unknown>).color = msg.color; (info as Record<string, unknown>).pfp = msg.pfp; }
      broadcast(msg, ws);
      return;
    }

    // Prevent impersonation
    if (msg.author !== undefined) msg.author = senderName;
    if (msg.user !== undefined && msg.type !== "admin_ban" && msg.type !== "admin_unban") msg.user = senderName;
    if (msg.from !== undefined) msg.from = senderName;

    switch (msg.type) {
      case "message": {
        const chKey = ["ch_history", msg.channelId as string];
        const chEntry = await kv.get<unknown[]>(chKey);
        const chHist = chEntry.value || [];
        chHist.push(msg);
        if (chHist.length > 500) chHist.splice(0, chHist.length - 500);
        await kv.set(chKey, chHist);
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

      case "typing":
      case "delete_message":
      case "edit_message":
      case "reaction":
      case "member_join":
      case "member_leave":
      case "kick_member":
      case "role_assign":
      case "status_update":
      case "pin_message":
      case "roles_update":
      case "channel_delete":
      case "voice_join":
      case "voice_leave":
      case "join_channel": // client sends this on channel select — just broadcast presence
        broadcast(msg, ws);
        break;

      case "voice_signal": {
        const target = msg.to as string;
        for (const [tws, ci] of clients) {
          if (ci.name === target && tws.readyState === WebSocket.OPEN) {
            tws.send(JSON.stringify(msg));
          }
        }
        break;
      }

      case "vcall_invite":
      case "vcall_accept":
      case "vcall_decline":
      case "vcall_signal": {
        sendToUser(msg.to as string, msg, true);
        break;
      }
      case "vcall_end": {
        broadcast(msg, ws);
        break;
      }

      case "server_create": {
        console.log(`[server_create] RECEIVED from ${senderName} id=${msg.serverId} name=${msg.name}`);
        const svData = {
          id: msg.serverId, name: msg.name, desc: msg.desc || "",
          icon: msg.icon || null, color: msg.color || "#6c63ff",
          memberCount: 1, createdAt: msg.createdAt || Date.now(),
          channels: msg.channels || [], ownerId: senderName,
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

        broadcast(msg, ws);
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
        if (publicServers.has(sid)) {
          const sv = publicServers.get(sid)!;
          if (msg.isPublic === false) {
            publicServers.delete(sid);
            await kv.set(["servers", sid], { ...sv, ...msg, isPublic: false });
          } else {
            const updated = { ...sv, ...msg };
            publicServers.set(sid, updated);
            await kv.set(["servers", sid], updated);
          }
        } else if (msg.isPublic === true) {
          const base = existing.value || {};
          const updated = { ...base, id: sid, name: msg.name, desc: msg.desc || "", icon: msg.icon || null, color: msg.color || "#6c63ff", memberCount: msg.memberCount || 1, createdAt: msg.createdAt || Date.now(), channels: msg.channels || [], ownerId: msg.ownerId || senderName, isPublic: true };
          publicServers.set(sid, updated);
          await kv.set(["servers", sid], updated);
        } else if (existing.value) {
          await kv.set(["servers", sid], { ...existing.value, ...msg });
        }
        broadcast(msg, ws);
        break;
      }

      case "server_delete": {
        const delSvId = msg.serverId as string;
        const delSvEntry = await kv.get<Record<string, unknown>>(["servers", delSvId]);
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
        await kv.delete(["server_member", msg.serverId as string, senderName]);
        await removeServerFromUser(senderName, msg.serverId as string);
        broadcast(msg, ws);
        break;
      }

      case "join_server": {
        const sv = publicServers.get(msg.serverId as string);
        if (sv) { sv.memberCount = ((sv.memberCount as number) || 1) + 1; await kv.set(["servers", msg.serverId as string], sv); }
        await kv.set(["server_member", msg.serverId as string, senderName], { joinedAt: Date.now() });
        // FIX: Use helper to ensure consistent lowercase key
        await addServerToUser(senderName, msg.serverId as string);
        broadcast(msg, ws);
        break;
      }

      case "announce_servers":
        for (const sv of (msg.servers as unknown[] || [])) {
          const s = sv as Record<string, unknown>;
          if (!s.id) continue;
          const svEntry: Record<string, unknown> = {
            id: s.id, name: s.name, desc: s.desc || "",
            icon: s.icon || null, color: s.color || "#6c63ff",
            memberCount: s.memberCount || 1, createdAt: s.createdAt || Date.now(),
            channels: s.channels || [], ownerId: s.ownerId || senderName, isPublic: true,
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
        const dmKey = ["dm_history", [senderName, withUser].sort().join(":")];
        const entry = await kv.get<unknown[]>(dmKey);
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "dm_history", with: withUser, messages: entry.value || [] }));
        break;
      }

      case "get_members": {
        const onlineNames = new Set<string>();
        const onlineMembers = [];
        for (const [, ci] of clients) {
          if (ci.name) {
            onlineNames.add(ci.name as string);
            onlineMembers.push({ name: ci.name, tag: ci.tag, color: ci.color, pfp: ci.pfp, systemRole: ci.systemRole, coAdmin: ci.coAdmin, online: true });
          }
        }
        const svId = msg.serverId as string;
        const memIter2 = kv.list({ prefix: ["server_member", svId] });
        const offlineMembers = [];
        for await (const item of memIter2) {
          const mName = item.key[2] as string;
          if (!onlineNames.has(mName)) {
            const mAcct = await kv.get<Record<string, unknown>>(["accounts", mName.toLowerCase()]);
            if (mAcct.value) offlineMembers.push({ name: mAcct.value.name, tag: mAcct.value.tag, color: mAcct.value.color, pfp: mAcct.value.pfp, systemRole: mAcct.value.systemRole, coAdmin: mAcct.value.coAdmin, online: false });
          }
        }
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "member_list", serverId: msg.serverId, members: [...onlineMembers, ...offlineMembers] }));
        break;
      }

      case "dm": {
        const dmTo = msg.to as string;
        const dmFrom = msg.from as string;
        const dmKey = ["dm_history", [dmFrom, dmTo].sort().join(":")];
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
      case "friend_request":
      case "friend_accept":
      case "friend_decline":
        sendToUser(msg.to as string, msg, true);
        break;

      case "short_post":
      case "short_like":
      case "short_comment":
      case "custom_emoji_add":
        broadcast(msg, ws);
        break;

      case "admin_dm_response": {
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
        const targetKey = ["accounts", target.toLowerCase()];
        const targetEntry = await kv.get<Record<string, unknown>>(targetKey);
        if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        const newKey = ["accounts", newName.toLowerCase()];
        const existingNew = await kv.get(newKey);
        if (existingNew.value) { ws.send(JSON.stringify({ type: "error", message: "That username is already taken." })); break; }
        await kv.set(newKey, { ...targetEntry.value as object, name: newName });
        await kv.delete(targetKey);
        for (const [cws, ci] of clients) {
          if ((ci.name as string).toLowerCase() === target.toLowerCase()) {
            (ci as Record<string, unknown>).name = newName;
            cws.send(JSON.stringify({ type: "admin_rename_ok", oldName: target, newName }));
          }
        }
        broadcast({ type: "admin_rename_ok", oldName: target, newName }, null);
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

      default:
        console.log("Unknown:", msg.type);
    }
  };

  ws.onclose = () => {
    const info = clientInfo(ws);
    if (info) {
      broadcast({ type: "member_leave", user: info.name, serverId: "__all__" });
      console.log("Disconnected:", info.name);
    }
    clients.delete(ws);
  };

  ws.onerror = (err) => console.error("WS error:", err);

  return response;
});
