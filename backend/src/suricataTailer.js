const fs = require("fs");
const path = require("path");

function startSuricataTailer({
  evePath,
  onAlert,
  pollIntervalMs = 1000
}) {
  const resolvedPath = path.resolve(evePath);
  let offset = 0;
  let remainder = "";
  let running = false;

  async function processChunk(chunk) {
    remainder += chunk;
    const lines = remainder.split("\n");
    remainder = lines.pop() || "";

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        const parsed = JSON.parse(trimmed);
        if (parsed.event_type === "alert") {
          await onAlert(parsed);
        }
      } catch (error) {
        console.error("Failed to parse Suricata eve.json line:", error.message);
      }
    }
  }

  async function pollFile() {
    if (running) return;
    running = true;

    try {
      const stats = await fs.promises.stat(resolvedPath);

      if (stats.size < offset) {
        offset = 0;
        remainder = "";
      }

      if (stats.size > offset) {
        const stream = fs.createReadStream(resolvedPath, {
          encoding: "utf8",
          start: offset,
          end: stats.size - 1
        });

        let chunk = "";
        for await (const piece of stream) {
          chunk += piece;
        }

        offset = stats.size;
        await processChunk(chunk);
      }
    } catch (error) {
      if (error.code !== "ENOENT") {
        console.error("Suricata tailer error:", error.message);
      }
    } finally {
      running = false;
    }
  }

  const timer = setInterval(() => {
    pollFile().catch((error) => {
      console.error("Suricata polling error:", error.message);
    });
  }, pollIntervalMs);

  pollFile().catch((error) => {
    console.error("Initial Suricata poll error:", error.message);
  });

  return {
    stop() {
      clearInterval(timer);
    }
  };
}

module.exports = { startSuricataTailer };
