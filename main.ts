// Nexus WebSocket relay server — Deno Deploy
const clients = new Map(); // ws -> { name, tag, color, pfp }
const publicServers = new Map(); // serverId -> server info

function broadcast(data, exclude = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
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
      case "identify":
        clients.set(ws, {
          name: msg.user,
          tag: msg.tag,
          color: msg.color,
          pfp: msg.pfp || null,
        });
        break;

      case "message":
      case "typing":
      case "delete_message":
      case "reaction":
      case "member_join":
      case "member_leave":
      case "kick_member":
      case "role_assign":
      case "profile_update":
        broadcast(msg, ws);
        break;

      // ── Server lifecycle — update in-memory list ──
      case "server_create":
        if (msg.isPublic !== false) {
          publicServers.set(msg.serverId, {
            id: msg.serverId,
            name: msg.name,
            desc: msg.desc || "",
            icon: msg.icon || null,
            color: msg.color || "#6c63ff",
            memberCount: 1,
            createdAt: msg.createdAt || Date.now(),
          });
        }
        broadcast(msg, ws);
        break;

      case "server_update":
        if (publicServers.has(msg.serverId)) {
          const sv = publicServers.get(msg.serverId);
          if (msg.isPublic === false) {
            publicServers.delete(msg.serverId);
          } else {
            publicServers.set(msg.serverId, { ...sv, ...msg });
          }
        } else if (msg.isPublic === true) {
          publicServers.set(msg.serverId, {
            id: msg.serverId,
            name: msg.name,
            desc: msg.desc || "",
            icon: msg.icon || null,
            color: msg.color || "#6c63ff",
            memberCount: msg.memberCount || 1,
            createdAt: msg.createdAt || Date.now(),
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

      // ── Announce public servers on connect / re-announce ──
      case "announce_servers":
        (msg.servers || []).forEach((sv) => {
          if (!publicServers.has(sv.id)) {
            publicServers.set(sv.id, {
              id: sv.id,
              name: sv.name,
              desc: sv.desc || "",
              icon: sv.icon || null,
              color: sv.color || "#6c63ff",
              memberCount: sv.memberCount || 1,
              createdAt: sv.createdAt || Date.now(),
            });
          }
        });
        break;

      case "get_server_list":
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: "server_list",
            servers: [...publicServers.values()],
          }));
        }
        break;

      case "get_members": {
        const members = [];
        for (const [, info] of clients) {
          if (info.name) members.push(info);
        }
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: "member_list",
            serverId: msg.serverId,
            members,
          }));
        }
        break;
      }

      case "dm":
      case "dm_request":
      case "dm_accept":
      case "dm_decline":
        for (const [client, info] of clients) {
          if (info.name === msg.to && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(msg));
          }
        }
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
