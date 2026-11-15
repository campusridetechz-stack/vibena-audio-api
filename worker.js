const ALLOWED_ORIGIN = "https://vibena.pages.dev";

const json = (data, status = 200, origin = ALLOWED_ORIGIN) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin"
    }
  });

function base64url(input) {
  const bytes = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input;

  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function createLiveKitToken(env, user, room, role, displayName) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const claims = {
    iss: env.LIVEKIT_API_KEY,
    sub: user.id,
    name: displayName,
    nbf: now,
    iat: now,
    exp: now + 600,
    video: {
      roomJoin: true,
      room: room.id,
      canSubscribe: true,
      canPublish: role === "host" || role === "speaker",
      canPublishData: false,
      canPublishSources:
        role === "host" || role === "speaker"
          ? ["microphone"]
          : []
    },
    metadata: JSON.stringify({ role })
  };

  const unsigned =
    base64url(JSON.stringify(header)) + "." +
    base64url(JSON.stringify(claims));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.LIVEKIT_API_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(unsigned)
  );

  return unsigned + "." + base64url(signature);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (origin !== ALLOWED_ORIGIN) {
      return json({ error: "Origin not allowed" }, 403, ALLOWED_ORIGIN);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
          "Vary": "Origin"
        }
      });
    }

    const url = new URL(request.url);

    if (request.method !== "POST" || url.pathname !== "/token") {
      return json({ error: "Endpoint not found" }, 404);
    }

    try {
      if (
        !env.SUPABASE_URL ||
        !env.SUPABASE_SERVICE_ROLE_KEY ||
        !env.LIVEKIT_API_KEY ||
        !env.LIVEKIT_API_SECRET ||
        !env.LIVEKIT_URL
      ) {
        return json({ error: "Backend configuration incomplete" }, 500);
      }

      const authorization = request.headers.get("Authorization") || "";

      if (!authorization.startsWith("Bearer ")) {
        return json({ error: "Please log in first" }, 401);
      }

      const accessToken = authorization.slice(7);

      // Verify the user's Supabase session.
      const authResponse = await fetch(
        `${env.SUPABASE_URL}/auth/v1/user`,
        {
          headers: {
            "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": `Bearer ${accessToken}`
          }
        }
      );

      if (!authResponse.ok) {
        return json({ error: "Invalid or expired login session" }, 401);
      }

      const user = await authResponse.json();

      if (!user.id) {
        return json({ error: "User authentication failed" }, 401);
      }

      const body = await request.json();
      const roomId = body.roomId;

      if (
        typeof roomId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(roomId)
      ) {
        return json({ error: "A valid room ID is required" }, 400);
      }

      const supabaseHeaders = {
        "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Accept": "application/json"
      };

      // Confirm that the room exists and is open.
      const roomResponse = await fetch(
        `${env.SUPABASE_URL}/rest/v1/vibena_rooms?id=eq.${roomId}&select=id,title,status,host_user_id&limit=1`,
        { headers: supabaseHeaders }
      );

      if (!roomResponse.ok) {
        return json({ error: "Could not verify room" }, 502);
      }

      const rooms = await roomResponse.json();
      const room = rooms[0];

      if (!room || room.status !== "open") {
        return json({ error: "This room is not open" }, 404);
      }

      // Determine the user's actual room role.
      let role = "listener";

      if (room.host_user_id === user.id) {
        role = "host";
      } else {
        const seatResponse = await fetch(
          `${env.SUPABASE_URL}/rest/v1/vibena_room_seats?room_id=eq.${roomId}&user_id=eq.${user.id}&released_at=is.null&select=seat_number,seat_role&limit=1`,
          { headers: supabaseHeaders }
        );

        if (!seatResponse.ok) {
          return json({ error: "Could not verify speaking seat" }, 502);
        }

        const seats = await seatResponse.json();

        if (seats.length > 0) {
          role = seats[0].seat_role === "host" ? "host" : "speaker";
        }
      }

      const displayName =
        typeof body.displayName === "string" &&
        body.displayName.trim().length > 0
          ? body.displayName.trim().slice(0, 40)
          : "VIBENA Member";

      const participantToken = await createLiveKitToken(
        env,
        user,
        room,
        role,
        displayName
      );

      return json({
        success: true,
        serverUrl: env.LIVEKIT_URL,
        participantToken,
        roomId: room.id,
        roomName: room.title,
        role,
        expiresIn: 600
      });

    } catch (error) {
      return json({
        error: "Unable to create audio access token"
      }, 500);
    }
  }
};
