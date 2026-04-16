const tf = require("@tensorflow/tfjs");

async function scoreRequest(features) {
  // Ensure the backend is initialized (important when using pure JS tfjs).
  await tf.ready();

  const requestCount = Number(features.requestCount || 0);
  const pathLength = Number(features.pathLength || 0);
  const isPost = Number(features.isPost || 0);

  const featureTensor = tf.tensor2d([[requestCount, pathLength, isPost]]);
  const normalized = featureTensor.div(tf.scalar(10));

  const model = tf.sequential();
  model.add(
    tf.layers.lstm({
      units: 4,
      inputShape: [1, 3],
      returnSequences: false
    })
  );
  model.add(tf.layers.dense({ units: 1, activation: "sigmoid" }));

  const reshaped = normalized.reshape([1, 1, 3]);
  const prediction = model.predict(reshaped);
  const score = (await prediction.data())[0];

  featureTensor.dispose();
  normalized.dispose();
  reshaped.dispose();
  prediction.dispose();
  model.dispose();

  return score;
}

module.exports = { scoreRequest };
