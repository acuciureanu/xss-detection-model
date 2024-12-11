const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs');
const fsp = require('fs').promises;
const { Tokenizer } = require('./tokenizer');
const csv = require('csv-parser');
const readline = require('readline');
const path = require('path');

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

async function readPayloadsFile(filePath) {
  const payloads = [];
  
  const fileStream = fs.createReadStream(filePath);
  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });

  for await (const line of rl) {
    if (line.trim()) {  // Skip empty lines
      payloads.push(line.trim());
    }
  }

  return payloads;
}

async function analyzePayloads(model, tokenizer, payloads) {
  const maxLength = 500;
  console.log('\nAnalyzing payloads for XSS...\n');
  
  const stats = {
    total: payloads.length,
    detected: 0,
    undetected: 0,
    undetectedPayloads: []
  };

  for (const payload of payloads) {
    const preprocessedPayload = preprocessSentence(payload);
    const encoded = tokenizer.encode(preprocessedPayload);
    const padded = encoded.length > maxLength ? 
      encoded.slice(0, maxLength) : 
      encoded.concat(new Array(maxLength - encoded.length).fill(0));

    const inputTensor = tf.tensor2d([padded]);
    const prediction = model.predict(inputTensor);
    const score = prediction.dataSync()[0];
    const isXSS = score > 0.5;

    console.log(`Payload: "${payload}"`);
    console.log(`Confidence Score: ${(score * 100).toFixed(2)}%`);
    console.log(`XSS Detected: ${isXSS ? 'YES' : 'NO'}`);
    console.log('-'.repeat(80) + '\n');

    if (isXSS) {
      stats.detected++;
    } else {
      stats.undetected++;
      stats.undetectedPayloads.push(payload);
    }

    inputTensor.dispose();
    prediction.dispose();
  }

  // Save undetected payloads to file
  if (stats.undetectedPayloads.length > 0) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outputFile = `undetected_payloads_${timestamp}.txt`;
    await fsp.writeFile(outputFile, stats.undetectedPayloads.join('\n'));
    console.log(`\nUndetected payloads saved to: ${outputFile}`);
  }

  // Print summary statistics
  console.log('\nSummary Statistics:');
  console.log('='.repeat(50));
  console.log(`Total Payloads Analyzed: ${stats.total}`);
  console.log(`XSS Detected: ${stats.detected} (${((stats.detected/stats.total)*100).toFixed(2)}%)`);
  console.log(`XSS Not Detected: ${stats.undetected} (${((stats.undetected/stats.total)*100).toFixed(2)}%)`);
  console.log('='.repeat(50));

  return stats;
}

async function main() {
  try {
    console.log('Starting XSS payload analysis...');
    const model = await loadModel();
    const tokenizer = await loadTokenizer();
    
    // const payloads = await readPayloadsFile('payloads.txt');
    const payloads = await readPayloadsFile('payloads.txt');
    console.log(`Loaded ${payloads.length} payloads for analysis`);
    
    await analyzePayloads(model, tokenizer, payloads);
    console.log('Analysis completed successfully.');
  } catch (error) {
    console.error('An error occurred during the process:', error);
  }
}

main().catch(console.error);
