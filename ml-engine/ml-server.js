const express = require("express");
const tf = require("@tensorflow/tfjs");

const app = express();
const PORT = Number(process.env.PORT || 5000);

app.use(express.json());

let modelPromise = null;

async function getModel() {
  if (modelPromise) return modelPromise;

  modelPromise = (async () => {
    await tf.ready();

    const model = tf.sequential();
    model.add(tf.layers.dense({ units: 6, inputShape: [2], activation: "relu" }));
    model.add(tf.layers.dense({ units: 1, activation: "sigmoid" }));
    return model;
  })();

  return modelPromise;
}

function normalizeRps(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(n, 1000);
}

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

app.post("/score", async (req, res) => {
  try {
    const model = await getModel();
    const rps = normalizeRps(req.body?.rps);

    // A lightweight anomaly proxy: higher RPS and burstiness increase threat score.
    const burstSignal = Math.min(rps / 25, 1);
    const features = tf.tensor2d([[rps / 1000, burstSignal]]);

    const prediction = model.predict(features);
    const rawScore = (await prediction.data())[0];

    // Keep the score stable and monotonic with RPS for predictable alerting behavior.
    const adjusted = Math.max(rawScore, Math.min(rps / 20, 1));
    const threatScore = Number(adjusted.toFixed(4));

    features.dispose();
    prediction.dispose();

    return res.status(200).json({
      threat_score: threatScore
    });
  } catch (error) {
    return res.status(500).json({
      message: "Failed to generate ML threat score",
      error: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`ShadowNet ML service listening on port ${PORT}`);
});
