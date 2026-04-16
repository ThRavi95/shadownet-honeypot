const express = require("express");
const redis = require("redis");

const dummyJson = require("./dummy.json");
const { scoreRequest } = require("../ml-engine/ml");
const { normalizeProxyRequestEvent } = require("./src/eventNormalizer");
const { mapMitreTechniques } = require("./src/mitreMapping");

const app = express();
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || "redis://redis:6379";

// Detection thresholds
const RATE_SUSPICIOUS_THRESHOLD = Number(process.env.RATE_SUSPICIOUS_THRESHOLD || 3);
const ML_SUSPICIOUS_THRESHOLD = Number(process.env.ML_SUSPICIOUS_THRESHOLD || 0.65);
const BRUTE_FORCE_THRESHOLD = Number(process.env.BRUTE_FORCE_THRESHOLD || 5);

const redisClient = redis.createClient({ url: REDIS_URL });
redisClient.on("error", (err) => {
  console.error("Redis client error:", err.message);
});

async function ensureRedisConnected() {
  if (!redisClient.isOpen) {
    await redisClient.connect();
  }
}

app.all("*", async (req, res) => {
  const ipHeader = req.headers["x-forwarded-for"];
  const rawIp = Array.isArray(ipHeader) ? ipHeader[0] : ipHeader;
  const clientIp = (rawIp || req.socket.remoteAddress || "unknown").toString();
  const path = req.originalUrl || req.path || "/";

  // Required logging per spec.
  console.log(`[request] ip=${clientIp} path=${path}`);

  try {
    await ensureRedisConnected();

    const key = `ip:${clientIp}:count`;
    const requestCount = await redisClient.incr(key);

    const mlScore = await scoreRequest({
      requestCount,
      pathLength: path.length,
      isPost: req.method === "POST" ? 1 : 0
    });

    const normalizedEvent = normalizeProxyRequestEvent({
      clientIp,
      method: req.method,
      path,
      requestCount,
      mlScore,
      mlSuspiciousThreshold: ML_SUSPICIOUS_THRESHOLD,
      rateSuspiciousThreshold: RATE_SUSPICIOUS_THRESHOLD
    });

    const techniques = mapMitreTechniques(normalizedEvent, {
      bruteForceThreshold: BRUTE_FORCE_THRESHOLD
    });

    const suspicious = normalizedEvent.indicators.isSuspicious;
    if (suspicious) {
      return res.status(200).json({
        ...dummyJson,
        mitre: { techniques },
        normalizedEvent
      });
    }

    return res.status(200).json({
      status: "ok",
      message: "Welcome to ShadowNet local stack.",
      meta: {
        requestCount,
        mlScore
      },
      mitre: { techniques }
    });
  } catch (error) {
    console.error("Proxy handling error:", error.message);
    return res.status(500).json({
      status: "error",
      message: "Proxy encountered an internal error."
    });
  }
});

app.listen(PORT, () => {
  console.log(`ShadowNet proxy listening on port ${PORT}`);
});

