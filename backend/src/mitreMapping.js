const { techniques } = require("./mitreTechniques");

function mapMitreTechniques(normalizedEvent, { bruteForceThreshold = 5 } = {}) {
  if (!normalizedEvent || typeof normalizedEvent !== "object") return [];

  const { source, eventType, telemetry, indicators } = normalizedEvent;
  const out = [];

  if (source === "proxy" && eventType === "http.request") {
    // Rapid proxy requests -> Active Scanning (T1595).
    // We also tag ML-based suspicion under T1595 so every detection/alert has a MITRE mapping.
    const requestCount = Number(telemetry?.requestCount || 0);
    const suspiciousByRate = Boolean(indicators?.suspiciousByRate);
    const suspiciousByModel = Boolean(indicators?.suspiciousByModel);

    if (suspiciousByRate || suspiciousByModel || requestCount > 3) {
      out.push({
        ...techniques.T1595,
        evidence: {
          requestCount,
          mlScore: Number(telemetry?.mlScore || 0),
          suspiciousByRate,
          suspiciousByModel
        }
      });
    }
  }

  if (source === "cowrie" && eventType === "ssh.login") {
    const failedAttemptCount = Number(telemetry?.failedLoginAttemptCount || 0);
    const isFailed = Boolean(indicators?.isFailed) || telemetry?.result === "failed";

    // Brute-force SSH attempts -> Brute Force (T1110).
    if (isFailed && failedAttemptCount >= bruteForceThreshold) {
      out.push({
        ...techniques.T1110,
        evidence: {
          failedLoginAttemptCount: failedAttemptCount,
          rawEventName: telemetry?.rawEventName
        }
      });
    }
  }

  if (source === "suricata" && eventType === "ids.alert") {
    const isAlert = Boolean(indicators?.isAlert);
    if (isAlert) {
      out.push({
        ...techniques.T1046,
        evidence: {
          alertSignature: telemetry?.alertSignature,
          alertCategory: telemetry?.alertCategory,
          severity: Number(telemetry?.severity || 0),
          destPort: Number(normalizedEvent?.network?.destPort || 0),
          protocol: normalizedEvent?.network?.protocol || "unknown"
        }
      });
    }
  }

  return out;
}

module.exports = { mapMitreTechniques };

