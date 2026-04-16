function toIsoTimestamp(ts) {
  try {
    return new Date(ts).toISOString();
  } catch {
    return new Date().toISOString();
  }
}

function normalizeProxyRequestEvent({
  clientIp,
  method,
  path,
  requestCount,
  mlScore,
  mlSuspiciousThreshold,
  rateSuspiciousThreshold = 3
}) {
  const suspiciousByRate = Number(requestCount) > Number(rateSuspiciousThreshold);
  const suspiciousByModel = Number(mlScore) >= Number(mlSuspiciousThreshold);
  const isSuspicious = suspiciousByRate || suspiciousByModel;

  return {
    schemaVersion: 1,
    timestamp: toIsoTimestamp(Date.now()),
    source: "proxy",
    eventType: "http.request",
    actor: {
      ip: (clientIp || "unknown").toString()
    },
    network: {
      protocol: "http",
      method: (method || "GET").toString().toUpperCase(),
      path: (path || "/").toString()
    },
    telemetry: {
      requestCount: Number(requestCount || 0),
      pathLength: (path || "/").toString().length,
      mlScore: Number(mlScore || 0)
    },
    indicators: {
      isSuspicious,
      suspiciousByRate,
      suspiciousByModel
    }
  };
}

function normalizeCowrieEvent(cowrieEvent, { failedLoginAttemptCount = 0 } = {}) {
  // This normalizer is intentionally tolerant: Cowrie log formats can vary.
  // In later phases we’ll tighten parsing based on real ingestion.
  const ev = cowrieEvent && typeof cowrieEvent === "object" ? cowrieEvent : {};

  const eventName =
    ev.event ||
    ev.eventName ||
    ev.command ||
    ev.type ||
    (typeof cowrieEvent === "string" ? cowrieEvent : "");

  const lower = (eventName || "").toString().toLowerCase();

  const isFailed =
    lower.includes("login.failed") ||
    lower.includes("auth.fail") ||
    lower.includes("password fail") ||
    ev.result === "failed";

  const srcIp = ev.src_ip || ev.remote_ip || ev.peerip || ev.ip || "unknown";
  const username = ev.username || ev.user || "unknown";

  return {
    schemaVersion: 1,
    timestamp: toIsoTimestamp(ev.timestamp || ev.time || Date.now()),
    source: "cowrie",
    eventType: "ssh.login",
    actor: {
      ip: (srcIp || "unknown").toString(),
      username: (username || "unknown").toString()
    },
    network: {
      protocol: "ssh",
      port: ev.dst_port || ev.port || 22
    },
    telemetry: {
      result: isFailed ? "failed" : "success",
      failedLoginAttemptCount: Number(failedLoginAttemptCount || ev.failedLoginAttemptCount || 0),
      rawEventName: (eventName || "").toString()
    },
    indicators: {
      isFailed
    }
  };
}

module.exports = {
  normalizeProxyRequestEvent,
  normalizeCowrieEvent
};

