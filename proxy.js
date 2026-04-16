const express = require("express");
const pathModule = require("path");
const redis = require("redis");
const { scoreRequest } = require("./ml");

const app = express();
const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || "redis://redis:6379";
const SUSPICIOUS_THRESHOLD = 0.65;

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

    const suspiciousByRate = requestCount > 3;
    const suspiciousByModel = mlScore >= SUSPICIOUS_THRESHOLD;

    if (suspiciousByRate || suspiciousByModel) {
      const dummyPath = pathModule.join(__dirname, "dummy.json");
      return res.status(200).sendFile(dummyPath);
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

app.listen(PORT, () => {
  console.log(`ShadowNet proxy listening on port ${PORT}`);
});
