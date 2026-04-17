const http = require("http");
const path = require("path");

const cors = require("cors");
const express = require("express");
const redis = require("redis");
const { Server } = require("socket.io");
const axios = require("axios");

const fs = require("fs");
// The illegal direct import of ML has been completely removed.

const {
  normalizeProxyRequestEvent,
  normalizeSuricataAlertEvent
} = require("./src/eventNormalizer");
const { mapMitreTechniques } = require("./src/mitreMapping");
const { startSuricataTailer } = require("./src/suricataTailer");
const { addAlert, listAlerts } = require("./src/alertStore");

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT || 3000);
const REDIS_URL = process.env.REDIS_URL || "redis://redis:6379";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:3001";
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://ml-engine:5000";
const SURICATA_EVE_PATH =
  process.env.SURICATA_EVE_PATH ||
  path.resolve(__dirname, "../sensors/suricata/logs/eve.json");

const RATE_SUSPICIOUS_THRESHOLD = Number(process.env.RATE_SUSPICIOUS_THRESHOLD || 3);
const ML_SUSPICIOUS_THRESHOLD = Number(process.env.ML_SUSPICIOUS_THRESHOLD || 0.65);
const BRUTE_FORCE_THRESHOLD = Number(process.env.BRUTE_FORCE_THRESHOLD || 5);

const io = new Server(server, {
  cors: {
    origin: FRONTEND_ORIGIN,
    methods: ["GET"]
  }
});

const redisClient = redis.createClient({ url: REDIS_URL });

redisClient.on("error", (err) => {
  console.error("Redis client error:", err.message);
});

app.use(
  cors({
    origin: FRONTEND_ORIGIN
  })
);
app.use(express.json());

async function ensureRedisConnected() {
  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
}

async function getThreatScore(normalizedEvent) {
  const rpsCandidate =
    Number(normalizedEvent?.telemetry?.requestCount || 0) ||
    Number(normalizedEvent?.telemetry?.failedLoginAttemptCount || 0) ||
    1;

  try {
    const response = await axios.post(`${ML_SERVICE_URL}/score`, {
      rps: rpsCandidate,
      source: normalizedEvent.source,
      event_type: normalizedEvent.eventType
    });
    const score = Number(response?.data?.threat_score);
    if (Number.isFinite(score)) {
      return Math.max(0, Math.min(1, score));
    }
  } catch (error) {
    // Fail silently so the proxy doesn't crash if the ML engine is rebooting
  }

  return 0;
}

async function publishAlert(normalizedEvent) {
  const threatScore = await getThreatScore(normalizedEvent);
  normalizedEvent.telemetry = {
    ...(normalizedEvent.telemetry || {}),
    threatScore
  };

  const techniques = mapMitreTechniques(normalizedEvent, {
    bruteForceThreshold: BRUTE_FORCE_THRESHOLD
  });
  const record = addAlert(normalizedEvent, techniques);
  const enrichedRecord = {
    ...record,
    threat_score: threatScore
  };

  io.emit("alert", enrichedRecord);
  return enrichedRecord;
}

async function handleSuricataAlert(rawEvent) {
  const normalizedEvent = normalizeSuricataAlertEvent(rawEvent);
  const record = await publishAlert(normalizedEvent);
  console.log("[suricata.alert]", JSON.stringify(record));
}

startSuricataTailer({
  evePath: SURICATA_EVE_PATH,
  onAlert: handleSuricataAlert
});

io.on("connection", (socket) => {
  console.log(`WebSocket client connected: ${socket.id}`);
  socket.on("disconnect", () => {
    console.log(`WebSocket client disconnected: ${socket.id}`);
  });
});

app.get("/api/alerts", (req, res) => {
  return res.status(200).json({
    alerts: listAlerts()
  });
});

app.all("*", async (req, res) => {
  const ipHeader = req.headers["x-forwarded-for"];
  const rawIp = Array.isArray(ipHeader) ? ipHeader[0] : ipHeader;
  const clientIp = (rawIp || req.socket.remoteAddress || "unknown").toString();
  const requestPath = req.originalUrl || req.path || "/";

  console.log(`[request] ip=${clientIp} path=${requestPath}`);

  try {
    await ensureRedisConnected();

    const key = `ip:${clientIp}:count`;
    const requestCount = await redisClient.incr(key);

    // Call the ML Engine via HTTP instead of a direct file import
    let mlScore = 0;
    try {
      const mlRes = await axios.post(`${ML_SERVICE_URL}/score`, {
        rps: requestCount,
        source: "proxy",
        event_type: "http_request"
      });
      if (mlRes && mlRes.data) mlScore = Number(mlRes.data.threat_score) || 0;
    } catch (err) {
       // ML engine not ready yet, default to 0
    }

    const normalizedEvent = normalizeProxyRequestEvent({
      clientIp,
      method: req.method,
      path: requestPath,
      requestCount,
      mlScore,
      mlSuspiciousThreshold: ML_SUSPICIOUS_THRESHOLD,
      rateSuspiciousThreshold: RATE_SUSPICIOUS_THRESHOLD
    });

    const suspicious = normalizedEvent.indicators.isSuspicious;
    if (suspicious) {
   const record = await publishAlert(normalizedEvent);

   // Serve the fake AWS Decoy
   const decoyPath = path.join(__dirname, "decoy.html");
   if (fs.existsSync(decoyPath)) {
       return res.status(200).sendFile(decoyPath);
   } else {
       return res.status(403).send("<h1>403 Forbidden</h1>");
   }
 }

    return res.status(200).json({
      status: "ok",
      message: "Welcome to ShadowNet local stack.",
      meta: {
        requestCount,
        mlScore
      }
    });
  } catch (error) {
    console.error("Proxy handling error:", error.message);
    return res.status(500).json({
      status: "error",
      message: "Proxy encountered an internal error."
    });
  }
});

server.listen(PORT, () => {
  console.log(`ShadowNet backend listening on port ${PORT}`);
  console.log(`Watching Suricata eve.json at ${SURICATA_EVE_PATH}`);
});