const ALLOWED_ORIGINS = new Set([
  "https://vibena.pages.dev",
  "https://vibena.campusridetechz.workers.dev"
]);

function getHeaders(origin) {
  const headers = {
    "Content-Type": "application/json",
    "Vary": "Origin"
  };

  if (ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] =
      "Authorization, Content-Type";
    headers["Access-Control-Max-Age"] = "86400";
  }

  return headers;
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: getHeaders(origin)
  });
}

function base64url(input) {
  const bytes = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input;

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function createLiveKitToken(
  env,
  user,
  room,
  role,
  displayName
) {
  const now = Math.floor(Date.now() / 1000);

  const canPublish =
    role === "host" || role === "speaker";

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
      canPublish,
      canPublishData: false,
      canPublishSources: canPublish
        ? ["microphone"]
        : []
    },

    metadata: JSON.stringify({ role })
  };

  const unsigned =
    base64url(JSON.stringify(header)) +
    "." +
    base64url(JSON.stringify(claims));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.LIVEKIT_API_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
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
    const url = new URL(request.url);

    // Reject unapproved browser origins.
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return json({
        success: false,
        error: "Origin not allowed"
      }, 403);
    }

    // Handle browser preflight requests.
    if (request.method === "OPTIONS") {
      if (!origin || url.pathname !== "/token") {
        return json({
          success: false,
          error: "Invalid preflight request"
        }, 400);
      }

      return new Response(null, {
        status: 204,
        headers: getHeaders(origin)
      });
    }

    // Public health check. No login required.
    if (
      request.method === "GET" &&
      (url.pathname === "/" || url.pathname === "/health")
    ) {
      return json({
        success: true,
        service: "VIBENA Audio API",
        status: "online",
        endpoints: ["/token"]
      }, 200, origin);
    }

    // Token endpoint.
    if (
      request.method !== "POST" ||
      url.pathname !== "/token"
    ) {
      return json({
        success: false,
        error: "Endpoint not found"
      }, 404, origin);
    }

    try {
      // Check backend configuration.
      if (
        !env.SUPABASE_URL ||
        !env.SUPABASE_SERVICE_ROLE_KEY ||
        !env.LIVEKIT_API_KEY ||
        !env.LIVEKIT_API_SECRET ||
        !env.LIVEKIT_URL
      ) {
        return json({
          success: false,
          error: "Backend configuration incomplete"
        }, 500, origin);
      }

      // Require an authenticated user.
      const authorization =
        request.headers.get("Authorization") || "";

      if (!authorization.startsWith("Bearer ")) {
        return json({
          success: false,
          error: "Please log in first"
        }, 401, origin);
      }

      const accessToken = authorization.slice(7);

      const supabaseUrl = env.SUPABASE_URL.replace(/\/+$/, "");

      // Verify Supabase session.
      const authResponse = await fetch(
        `${supabaseUrl}/auth/v1/user`,
        {
          headers: {
            "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": `Bearer ${accessToken}`
          }
        }
      );

      if (!authResponse.ok) {
        return json({
          success: false,
          error: "Invalid or expired login session"
        }, 401, origin);
      }

      const user = await authResponse.json();

      if (!user.id) {
        return json({
          success: false,
          error: "User authentication failed"
        }, 401, origin);
      }

      // Read request body.
      let body;

      try {
        body = await request.json();
      } catch {
        return json({
          success: false,
          error: "Invalid JSON request"
        }, 400, origin);
      }

      if (!body || typeof body !== "object") {
        return json({
          success: false,
          error: "Invalid request body"
        }, 400, origin);
      }

      const roomId = body.roomId;

      const validUUID =
        typeof roomId === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
          .test(roomId);

      if (!validUUID) {
        return json({
          success: false,
          error: "A valid room ID is required"
        }, 400, origin);
      }

      const supabaseHeaders = {
        "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
        "Authorization":
          `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Accept": "application/json"
      };

      // Verify room exists and is open.
      const roomResponse = await fetch(
        `${supabaseUrl}/rest/v1/vibena_rooms?id=eq.${roomId}&select=id,title,status,host_user_id&limit=1`,
        {
          headers: supabaseHeaders
        }
      );

      if (!roomResponse.ok) {
        return json({
          success: false,
          error: "Could not verify room"
        }, 502, origin);
      }

      const rooms = await roomResponse.json();
      const room = rooms[0];

      if (!room || room.status !== "open") {
        return json({
          success: false,
          error: "This room is not open"
        }, 404, origin);
      }

      // Determine actual room role.
      let role = "listener";

      if (room.host_user_id === user.id) {
        role = "host";
      } else {
        const seatResponse = await fetch(
          `${supabaseUrl}/rest/v1/vibena_room_seats?room_id=eq.${roomId}&user_id=eq.${user.id}&released_at=is.null&select=seat_number,seat_role&limit=1`,
          {
            headers: supabaseHeaders
          }
        );

        if (!seatResponse.ok) {
          return json({
            success: false,
            error: "Could not verify speaking seat"
          }, 502, origin);
        }

        const seats = await seatResponse.json();

        if (seats.length > 0) {
          role =
            seats[0].seat_role === "host"
              ? "host"
              : "speaker";
        }
      }

      const displayName =
        typeof body.displayName === "string" &&
        body.displayName.trim()
          ? body.displayName.trim().slice(0, 40)
          : "VIBENA Member";

      // Generate LiveKit access token.
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
      }, 200, origin);

    } catch (error) {
      console.error("VIBENA token error:", error);

      return json({
        success: false,
        error: "Unable to create audio access token"
      }, 500, origin);
    }
  }
};
