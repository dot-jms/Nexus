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
    passwordHash: hashPw("changeme"), // Puck should change this on first login
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

// Active sessions: token → username
const sessions = new Map<string, string>();
// clients: ws → { name, tag, color, pfp, token, systemRole, coAdmin }
const clients = new Map<WebSocket, Record<string, unknown>>();
const publicServers = new Map<string, Record<string, unknown>>();
const msgHistory = new Map<string, unknown[]>();
const offline = new Map<string, unknown[]>();
// timed bans: username → { until: number, reason: string }
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

// Verify token → returns username or null
// Checks in-memory sessions first (fast), then falls back to KV sessions
async function verifyTokenKv(token: string | undefined): Promise<string | null> {
  if (!token) return null;
  const mem = sessions.get(token);
  if (mem) return mem;
  // KV fallback (survives restarts)
  const entry = await kv.get<string>(["sessions", token]);
  if (entry.value) {
    sessions.set(token, entry.value); // warm the memory cache
    return entry.value;
  }
  return null;
}
function verifyToken(token: string | undefined): string | null {
  if (!token) return null;
  return sessions.get(token) || null;
}

// Get client info from ws
function clientInfo(ws: WebSocket): Record<string, unknown> | null {
  return clients.get(ws) || null;
}

// Check if a username is banned right now
function isBanned(username: string): boolean {
  const ban = timedBans.get(username.toLowerCase());
  if (!ban) return false;
  if (ban.until === -1) return true; // permanent
  if (Date.now() < ban.until) return true;
  timedBans.delete(username.toLowerCase()); // expired
  return false;
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
      await kv.set(["sessions", token], username.toLowerCase()); // persist across restarts
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
      // Check ban
      if (isBanned(username)) {
        const ban = timedBans.get(username);
        const until = ban?.until === -1 ? "permanently" : `until ${new Date(ban!.until).toLocaleString()}`;
        ws.send(JSON.stringify({ type: "auth_error", message: `You are banned ${until}. Reason: ${ban?.reason || "none"}` })); return;
      }
      const token = genToken();
      sessions.set(token, username);
      await kv.set(["sessions", token], username); // persist across restarts
      console.log(`Login: ${acct.name}`);
      const firstLogin = !acct.hasLoggedIn;
      if (!acct.hasLoggedIn) await kv.set(key, { ...acct, hasLoggedIn: true });
      ws.send(JSON.stringify({ type: "auth_ok", token, firstLogin: !!firstLogin, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: acct.systemRole, coAdmin: acct.coAdmin || false } }));
      return;
    }


    // ── check_username — before registering ──────────────────────────────
    if (msg.type === "check_username") {
      const username = (msg.username as string || "").trim().toLowerCase();
      const entry = await kv.get(["accounts", username]);
      ws.send(JSON.stringify({ type: "username_available", username, available: !entry.value }));
      return;
    }

    // ── MIGRATION — claim existing localStorage account on the server ─────
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
        // Username taken — offer to login instead
        ws.send(JSON.stringify({ type: "auth_error", message: "That username is already registered. Try logging in, or choose a different username." })); return;
      }
      const acct = {
        name: username, tag, color, pfp,
        passwordHash: hashPw(password),
        systemRole: "user", coAdmin: false,
        createdAt: Date.now(),
      };
      await kv.set(key, acct);
      const token = genToken();
      sessions.set(token, username.toLowerCase());
      ws.send(JSON.stringify({ type: "auth_ok", token, user: { name: acct.name, tag: acct.tag, color: acct.color, pfp: acct.pfp, systemRole: "user", coAdmin: false }, migrated: true }));
      return;
    }

    // ── ALL OTHER MESSAGES require a valid token ──────────────────────────
    const tokenUser = await verifyTokenKv(msg.token as string);
    if (!tokenUser) {
      ws.send(JSON.stringify({ type: "auth_required", message: "Please log in." }));
      return;
    }

    // ── identify — register this WS with the verified username ───────────
    if (msg.type === "identify") {
      const key = ["accounts", tokenUser];
      const entry = await kv.get<Record<string, unknown>>(key);
      const acct = entry.value;
      const name = acct?.name as string || tokenUser;
      clients.set(ws, {
        name,
        tag: acct?.tag || "0000",
        color: msg.color || acct?.color || "#6c63ff",
        pfp: msg.pfp || acct?.pfp || null,
        token: msg.token,
        systemRole: acct?.systemRole || "user",
        coAdmin: acct?.coAdmin || false,
      });
      // Send back fresh account data so client always has correct role
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: "identified",
          user: {
            name: acct?.name || tokenUser,
            tag: acct?.tag || "0000",
            color: acct?.color || "#6c63ff",
            pfp: acct?.pfp || null,
            systemRole: acct?.systemRole || "user",
            coAdmin: acct?.coAdmin || false,
            bio: acct?.bio || "",
            socials: acct?.socials || {}
          }
        }));
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

    // ── Guard: must be identified ─────────────────────────────────────────
    // auth_change_password is allowed before full identify (token is enough)
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

    if (!info) {
      // Client has a valid token but hasn't sent identify yet — ignore
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
      const appoint = msg.appoint === true;
      const targetKey = ["accounts", target];
      const targetEntry = await kv.get<Record<string, unknown>>(targetKey);
      if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); return; }
      await kv.set(targetKey, { ...targetEntry.value, coAdmin: appoint });
      // Update live client if connected
      for (const [cws, ci] of clients) {
        if ((ci.name as string).toLowerCase() === target) {
          (ci as Record<string, unknown>).coAdmin = appoint;
          cws.send(JSON.stringify({ type: "system_role_update", coAdmin: appoint, message: appoint ? "You have been appointed as Co-Admin by Puck!" : "Your Co-Admin status has been removed." }));
        }
      }
      broadcast({ type: "coadmin_update", target: targetEntry.value.name, coAdmin: appoint }, ws);
      ws.send(JSON.stringify({ type: "success", message: `${targetEntry.value.name} is now ${appoint ? "a Co-Admin" : "a regular user"}.` }));
      return;
    }

    // ── Admin/CoAdmin: timed ban ──────────────────────────────────────────
    if (msg.type === "admin_ban") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const target = (msg.target as string || "").toLowerCase();
      const targetEntry = await kv.get<Record<string, unknown>>(["accounts", target]);
      if (!targetEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); return; }
      // Co-admins can't ban each other
      if (!isAdmin && (targetEntry.value.coAdmin || targetEntry.value.systemRole === "admin")) {
        ws.send(JSON.stringify({ type: "error", message: "Co-admins cannot ban each other or Puck." })); return;
      }
      // Parse duration: "1h", "2d", "permanent"
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
      // Kick them off if connected
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
      const target = (msg.target as string || "").toLowerCase();
      timedBans.delete(target);
      ws.send(JSON.stringify({ type: "success", message: `${msg.target} unbanned.` }));
      return;
    }

    // ── Admin: view DMs ───────────────────────────────────────────────────
    if (msg.type === "admin_view_dms") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      const targetUser = msg.target as string;
      // Return any DM messages we have in memory (we only have live/recent ones)
      // The relay doesn't store DMs persistently (they live in localStorage)
      // We can request the target user to send their DM history
      sendToUser(targetUser, { type: "admin_dm_request", requestedBy: senderName }, false);
      ws.send(JSON.stringify({ type: "info", message: `Requested DM history from ${targetUser}. They must be online.` }));
      return;
    }

    // ── Admin: delete any server ──────────────────────────────────────────
    if (msg.type === "admin_delete_server") {
      if (!isPowerUser) { ws.send(JSON.stringify({ type: "error", message: "No permission." })); return; }
      publicServers.delete(msg.serverId as string);
      broadcast({ type: "server_delete", serverId: msg.serverId, by: senderName });
      ws.send(JSON.stringify({ type: "success", message: "Server deleted." }));
      return;
    }

    // ── Profile update — also update KV ──────────────────────────────────
    if (msg.type === "profile_update") {
      const key = ["accounts", senderName.toLowerCase()];
      const entry = await kv.get<Record<string, unknown>>(key);
      if (entry.value) {
        await kv.set(key, { ...entry.value, color: msg.color || entry.value.color, pfp: msg.pfp !== undefined ? msg.pfp : entry.value.pfp });
      }
      // Update in-memory client info
      if (info) { (info as Record<string, unknown>).color = msg.color; (info as Record<string, unknown>).pfp = msg.pfp; }
      broadcast(msg, ws);
      return;
    }

    // ── All other messages — verify sender matches token ─────────────────
    // Prevent impersonation: override msg.author with verified name
    if (msg.author !== undefined) msg.author = senderName;
    if (msg.user !== undefined && msg.type !== "admin_ban" && msg.type !== "admin_unban") msg.user = senderName;
    if (msg.from !== undefined) msg.from = senderName;

    switch (msg.type) {
      case "message": {
        storeMessage(msg.channelId as string, msg);
        broadcast(msg, ws);
        break;
      }

      case "get_history": {
        const hist = msgHistory.get(msg.channelId as string) || [];
        const since = (msg.since as number) || 0;
        const unseen = hist.filter((m: unknown) => (m as Record<string, number>).ts > since);
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

      // ── Voice calls (P2P, routed to specific user) ──
      case "vcall_invite":
      case "vcall_accept":
      case "vcall_decline":
      case "vcall_signal": {
        const target = msg.to as string;
        sendToUser(target, msg, true);
        break;
      }
      case "vcall_end": {
        // Broadcast end to all participants
        broadcast(msg, ws);
        break;
      }

      case "server_create": {
        if (msg.isPublic !== false) {
          publicServers.set(msg.serverId as string, {
            id: msg.serverId, name: msg.name, desc: msg.desc || "",
            icon: msg.icon || null, color: msg.color || "#6c63ff",
            memberCount: 1, createdAt: msg.createdAt || Date.now(),
            channels: msg.channels || [], ownerId: senderName,
          });
        }
        broadcast(msg, ws);
        break;
      }

      case "server_update": {
        const sid = msg.serverId as string;
        if (publicServers.has(sid)) {
          const sv = publicServers.get(sid)!;
          if (msg.isPublic === false) publicServers.delete(sid);
          else publicServers.set(sid, { ...sv, ...msg });
        } else if (msg.isPublic === true) {
          publicServers.set(sid, {
            id: sid, name: msg.name, desc: msg.desc || "",
            icon: msg.icon || null, color: msg.color || "#6c63ff",
            memberCount: msg.memberCount || 1, createdAt: msg.createdAt || Date.now(),
            channels: msg.channels || [], ownerId: msg.ownerId || senderName,
          });
        }
        broadcast(msg, ws);
        break;
      }

      case "server_delete":
      case "leave_server":
        publicServers.delete(msg.serverId as string);
        broadcast(msg, ws);
        break;

      case "join_server": {
        const sv = publicServers.get(msg.serverId as string);
        if (sv) sv.memberCount = ((sv.memberCount as number) || 1) + 1;
        broadcast(msg, ws);
        break;
      }

      case "announce_servers":
        (msg.servers as unknown[] || []).forEach((sv: unknown) => {
          const s = sv as Record<string, unknown>;
          if (!publicServers.has(s.id as string)) {
            publicServers.set(s.id as string, {
              id: s.id, name: s.name, desc: s.desc || "",
              icon: s.icon || null, color: s.color || "#6c63ff",
              memberCount: s.memberCount || 1, createdAt: s.createdAt || Date.now(),
              channels: s.channels || [], ownerId: s.ownerId || null,
            });
          }
        });
        break;

      case "get_server_list":
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "server_list", servers: [...publicServers.values()] }));
        }
        break;

      case "get_server_info": {
        const sv = publicServers.get(msg.serverId as string);
        if (sv && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "server_info", server: sv }));
        }
        break;
      }

      case "fetch_dm_history": {
        const withUser = msg.with as string;
        const dmKey = ["dm_history", [senderName, withUser].sort().join(":")];
        const entry = await kv.get<unknown[]>(dmKey);
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "dm_history", with: withUser, messages: entry.value || [] }));
        }
        break;
      }

      case "get_members": {
        const members = [];
        for (const [, ci] of clients) { if (ci.name) members.push({ name: ci.name, tag: ci.tag, color: ci.color, pfp: ci.pfp, systemRole: ci.systemRole, coAdmin: ci.coAdmin }); }
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "member_list", serverId: msg.serverId, members }));
        }
        break;
      }

      case "dm": {
        const dmTo = msg.to as string;
        const dmFrom = msg.from as string;
        // Persist to KV so messages survive relay restarts
        const dmKey = ["dm_history", [dmFrom, dmTo].sort().join(":")];
        const existing = await kv.get<unknown[]>(dmKey);
        const hist = existing.value || [];
        hist.push({ ...msg, _stored: Date.now() });
        if (hist.length > 500) hist.splice(0, hist.length - 500); // keep last 500
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

      // Admin: receive DM data from target user
      case "admin_dm_response": {
        const requester = msg.requestedBy as string;
        sendToUser(requester, { type: "admin_dm_data", target: senderName, dms: msg.dms }, false);
        break;
      }

      // Admin-only: rename any user
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
        const existing = await kv.get(newKey);
        if (existing.value) { ws.send(JSON.stringify({ type: "error", message: "That username is already taken." })); break; }
        // Copy account to new key, delete old
        await kv.set(newKey, { ...targetEntry.value as object, name: newName });
        await kv.delete(targetKey);
        // Update live client if connected
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

      // Admin-only: set any user's profile picture
      case "admin_set_pfp": {
        if (!isAdmin) { ws.send(JSON.stringify({ type: "error", message: "Only Puck can change profile pictures." })); break; }
        const pfpTarget = (msg.target as string || "").trim().toLowerCase();
        const pfpData = msg.pfp as string || null;
        const pfpKey = ["accounts", pfpTarget];
        const pfpEntry = await kv.get<Record<string, unknown>>(pfpKey);
        if (!pfpEntry.value) { ws.send(JSON.stringify({ type: "error", message: "User not found." })); break; }
        await kv.set(pfpKey, { ...pfpEntry.value as object, pfp: pfpData });
        // Update live client
        for (const [cws, ci] of clients) {
          if ((ci.name as string).toLowerCase() === pfpTarget) {
            (ci as Record<string, unknown>).pfp = pfpData;
          }
        }
        // Broadcast profile update so everyone sees the new pfp
        broadcast({ type: "profile_update", user: pfpEntry.value.name, pfp: pfpData, color: pfpEntry.value.color }, null);
        ws.send(JSON.stringify({ type: "success", message: `PFP updated for ${pfpEntry.value.name}.` }));
        break;
      }

      // Admin-only: broadcast platform alert to all connected users
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
