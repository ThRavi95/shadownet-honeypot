const MAX_ALERTS = Number(process.env.MAX_ALERTS || 1000);

const alerts = [];

function makeAlertRecord(normalizedEvent, techniques) {
  return {
    id: `${normalizedEvent.source}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: normalizedEvent.timestamp,
    sensor: normalizedEvent.source,
    sourceIp: normalizedEvent.actor?.ip || "unknown",
    normalizedEvent,
    mitre: {
      techniques
    }
  };
}

function addAlert(normalizedEvent, techniques) {
  const record = makeAlertRecord(normalizedEvent, techniques);
  alerts.unshift(record);

  if (alerts.length > MAX_ALERTS) {
    alerts.length = MAX_ALERTS;
  }

  return record;
}

function listAlerts() {
  return alerts;
}

module.exports = {
  addAlert,
  listAlerts
};
