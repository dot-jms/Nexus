// Nexus WebSocket relay server — Deno Deploy
const clients = new Map(); // ws -> { name, tag, color, pfp }

function broadcast(data, exclude = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  }
}

Deno.serve((req) => {
  // Health check for UptimeRobot / browser visits
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
      case "server_create":
      case "server_delete":
      case "leave_server":
      case "kick_member":
      case "role_assign":
      case "profile_update":
        broadcast(msg, ws);
        break;

      case "dm":
      case "dm_request":
      case "dm_accept":
      case "dm_decline":
        // Forward only to the target user
        for (const [client, info] of clients) {
          if (info.name === msg.to && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(msg));
          }
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
