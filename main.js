const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs');
const fsp = require('fs').promises;
const { Tokenizer } = require('./tokenizer');
const csv = require('csv-parser');

async function loadModel() {
  console.log('Loading pre-trained model...');
  const model = await tf.loadLayersModel('file://./xss_model/model.json');
  console.log('Model loaded successfully.');
  return model;
}

async function loadTokenizer() {
  console.log('Loading tokenizer...');
  const tokenizerData = await fsp.readFile('tokenizer.json', 'utf8');
  const tokenizer = Tokenizer.fromJson(tokenizerData);
  console.log('Tokenizer loaded successfully.');
  return tokenizer;
}

function preprocessSentence(sentence) {
  return sentence.toLowerCase().replace(/[^\w\s]/gi, '').trim();
}

async function readCSV(filePath) {
  return new Promise((resolve, reject) => {
    const results = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', () => resolve(results))
      .on('error', (error) => reject(error));
  });
}

async function useModel(model, tokenizer, dataset) {
  const maxLength = 500;
  let correctPredictions = 0;

  dataset.forEach(({ Sentence, Label }) => {
    const preprocessedSentence = preprocessSentence(Sentence);
    const encoded = tokenizer.encode(preprocessedSentence);
    const padded = encoded.length > maxLength ? encoded.slice(0, maxLength) : encoded.concat(new Array(maxLength - encoded.length).fill(0));

    const inputTensor = tf.tensor2d([padded]);
    const prediction = model.predict(inputTensor);
    const score = prediction.dataSync()[0];
    const predictedLabel = score > 0.5 ? 1 : 0;

    console.log(`Sentence: "${Sentence}"`);
    console.log(`True Label: ${Label}`);
    console.log(`Predicted Score: ${score.toFixed(4)}`);
    console.log(`Predicted Label: ${predictedLabel}`);
    console.log(`XSS Detected: ${predictedLabel ? 'Yes' : 'No'}`);
    console.log();

    if (predictedLabel === parseInt(Label)) {
      correctPredictions++;
    }
  });

  const accuracy = (correctPredictions / dataset.length) * 100;
  console.log(`Model Accuracy on Test Dataset: ${accuracy.toFixed(2)}%`);
}

async function main() {
  try {
    console.log('Starting inference with pre-trained model...');
    const model = await loadModel();
    const tokenizer = await loadTokenizer();
    const dataset = await readCSV('XSS_dataset.csv');
    await useModel(model, tokenizer, dataset);
    console.log('Inference completed successfully.');
  } catch (error) {
    console.error('An error occurred during the process:', error);
  }
}

main().catch(console.error);
