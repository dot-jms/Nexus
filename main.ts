// Nexus WebSocket relay server — Deno Deploy
// NOTE: Accounts are stored in each user's browser localStorage — NOT on this server.
// Restarting/redeploying this relay NEVER deletes accounts.
// Servers and message history are re-announced by clients on reconnect.
const clients = new Map();      // ws -> { name, tag, color, pfp }
const publicServers = new Map(); // serverId -> server info (rebuilt from client announces)
const msgHistory = new Map();    // channelId -> last 100 messages (for catch-up)
const offline = new Map();       // username -> [queued messages] (DMs + dm_request etc)

function broadcast(data, exclude = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
}

// Send to a specific user by name — queue if offline
function sendToUser(name, data, queue = true) {
  let delivered = false;
  for (const [ws, info] of clients) {
    if (info.name === name && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
      delivered = true;
    }
  }
  if (!delivered && queue) {
    if (!offline.has(name)) offline.set(name, []);
    const q = offline.get(name);
    q.push(data);
    // Cap queue at 200 messages per user
    if (q.length > 200) q.splice(0, q.length - 200);
  }
  return delivered;
}

// Store message in channel history (for catch-up on reconnect)
function storeMessage(channelId, msg) {
  if (!msgHistory.has(channelId)) msgHistory.set(channelId, []);
  const hist = msgHistory.get(channelId);
  hist.push(msg);
  if (hist.length > 100) hist.splice(0, hist.length - 100);
}

Deno.serve((req) => {
  if (req.headers.get("upgrade") !== "websocket") {
    return new Response("Nexus WS server running", { status: 200 });
  }

  const { socket: ws, response } = Deno.upgradeWebSocket(req);

  ws.onopen = () => console.log("Client connected");

  ws.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    switch (msg.type) {

      case "identify": {
        clients.set(ws, {
          name: msg.user,
          tag: msg.tag,
          color: msg.color,
          pfp: msg.pfp || null,
        });
        // Flush any queued messages for this user
        const queue = offline.get(msg.user);
        if (queue && queue.length) {
          for (const qmsg of queue) {
            if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(qmsg));
          }
          offline.delete(msg.user);
          console.log(`Flushed ${queue.length} queued messages to ${msg.user}`);
        }
        break;
      }

      case "message": {
        // Store in history for catch-up
        storeMessage(msg.channelId, msg);
        broadcast(msg, ws);
        break;
      }

      case "get_history": {
        // Client asks for recent messages in a channel (on join/reconnect)
        const hist = msgHistory.get(msg.channelId) || [];
        const since = msg.since || 0;
        const unseen = hist.filter(m => m.ts > since);
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
      case "profile_update":
      case "status_update":
      case "pin_message":
      case "roles_update":
      case "channel_delete":
      case "voice_join":
      case "voice_leave":
        broadcast(msg, ws);
        break;
      // Voice signals — route to specific target
      case "voice_signal": {
        const target = msg.to;
        let routed = false;
        for (const [tws, info] of clients) {
          if (info.name === target && tws.readyState === WebSocket.OPEN) {
            tws.send(JSON.stringify(msg));
            routed = true;
          }
        }
        break;
      }

      // ── Server lifecycle ──
      case "server_create":
        if (msg.isPublic !== false) {
          publicServers.set(msg.serverId, {
            id: msg.serverId, name: msg.name, desc: msg.desc || "",
            icon: msg.icon || null, color: msg.color || "#6c63ff",
            memberCount: 1, createdAt: msg.createdAt || Date.now(),
            channels: msg.channels || [], ownerId: msg.ownerId || null,
          });
        }
        broadcast(msg, ws);
        break;

      case "server_update":
        if (publicServers.has(msg.serverId)) {
          const sv = publicServers.get(msg.serverId);
          if (msg.isPublic === false) publicServers.delete(msg.serverId);
          else publicServers.set(msg.serverId, { ...sv, ...msg });
        } else if (msg.isPublic === true) {
          publicServers.set(msg.serverId, {
            id: msg.serverId, name: msg.name, desc: msg.desc || "",
            icon: msg.icon || null, color: msg.color || "#6c63ff",
            memberCount: msg.memberCount || 1, createdAt: msg.createdAt || Date.now(),
            channels: msg.channels || [], ownerId: msg.ownerId || null,
          });
        }
        broadcast(msg, ws);
        break;

      case "server_delete":
      case "leave_server":
        publicServers.delete(msg.serverId);
        broadcast(msg, ws);
        break;

      case "join_server":
        if (publicServers.has(msg.serverId)) {
          const sv = publicServers.get(msg.serverId);
          sv.memberCount = (sv.memberCount || 1) + 1;
        }
        broadcast(msg, ws);
        break;

      case "announce_servers":
        (msg.servers || []).forEach((sv) => {
          if (!publicServers.has(sv.id)) {
            publicServers.set(sv.id, {
              id: sv.id, name: sv.name, desc: sv.desc || "",
              icon: sv.icon || null, color: sv.color || "#6c63ff",
              memberCount: sv.memberCount || 1, createdAt: sv.createdAt || Date.now(),
              channels: sv.channels || [], ownerId: sv.ownerId || null,
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
        const sv = publicServers.get(msg.serverId);
        if (sv && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "server_info", server: sv }));
        }
        break;
      }

      case "get_members": {
        const members = [];
        for (const [, info] of clients) { if (info.name) members.push(info); }
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "member_list", serverId: msg.serverId, members }));
        }
        break;
      }

      // ── DMs — queue if recipient offline ──
      case "dm":
        sendToUser(msg.to, msg, true);
        break;

      case "dm_request":
      case "dm_accept":
      case "dm_decline":
      case "friend_request":
      case "friend_accept":
      case "friend_decline":
        sendToUser(msg.to, msg, true); // queue these — deliver when online
        break;

      // ── Shorts & custom emoji — broadcast to all ──
      case "short_post":
      case "short_like":
      case "short_comment":
      case "custom_emoji_add":
        broadcast(msg, ws);
        break;

      default:
        console.log("Unknown message type:", msg.type);
    }
  };

  ws.onclose = () => {
    const info = clients.get(ws);
    if (info) {
      console.log("Disconnected:", info.name);
      broadcast({ type: "member_leave", user: info.name, serverId: "__all__" });
    }
    clients.delete(ws);
  };

  ws.onerror = (err) => console.error("WS error:", err);

  return response;
});
