const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs').promises;
const path = require('path');

class RNNAgent {
  constructor(config) {
    this.config = config;
    this.model = null;
    this.tokenizer = null;
    this.vocabSize = 0;
  }

  async loadModel() {
    try {
      await this.loadOrCreateTokenizer();
      const modelPath = path.resolve(this.config.modelPath);
      const modelExists = await this.checkFileExists(`${modelPath}.json`);

      if (modelExists) {
        this.model = await tf.loadLayersModel(`file://${modelPath}`);
        console.log('Loaded existing model');
      } else {
        this.model = this.buildModel();
        console.log('Built new model');
      }
      
      console.log('RNN model and tokenizer loaded successfully.');
    } catch (error) {
      console.error('Error loading model or tokenizer:', error);
      throw error;
    }
  }

  async loadOrCreateTokenizer() {
    const tokenizerPath = path.resolve(this.config.tokenizerPath);
    try {
      const tokenizerData = await fs.readFile(tokenizerPath, 'utf8');
      const tokenizerJson = JSON.parse(tokenizerData);
      this.tokenizer = tokenizerJson;
      this.vocabSize = Object.keys(this.tokenizer.wordIndex).length + 1;
    } catch (error) {
      console.log('Tokenizer file not found or invalid. Creating a new one.');
      this.tokenizer = this.createBasicTokenizer();
      await this.saveTokenizer();
    }
  }

  createBasicTokenizer() {
    const basicVocab = ['<', '>', '/', '=', '"', "'", ' ', 'script', 'img', 'src', 'onerror', 'alert'];
    const wordIndex = {};
    const indexWord = {};
    basicVocab.forEach((word, index) => {
      wordIndex[word] = index + 1;
      indexWord[index + 1] = word;
    });
    this.vocabSize = basicVocab.length + 1;
    return { wordIndex, indexWord };
  }

  async saveTokenizer() {
    await fs.writeFile(this.config.tokenizerPath, JSON.stringify(this.tokenizer, null, 2));
  }

  buildModel() {
    const model = tf.sequential();
    model.add(tf.layers.embedding({
      inputDim: this.vocabSize,
      outputDim: 128,
      inputLength: this.config.maxLength
    }));
    model.add(tf.layers.lstm({ units: 64, returnSequences: false }));
    model.add(tf.layers.dense({ units: this.vocabSize, activation: 'softmax' }));
    model.compile({ optimizer: 'adam', loss: 'categoricalCrossentropy' });
    return model;
  }

  async generatePayloads(batchSize = 32) {
    console.log(`Generating ${batchSize} payloads...`);
    const payloads = [];
    
    for (let i = 0; i < batchSize; i++) {
      const payload = await this.generateSinglePayload();
      payloads.push(payload);
    }

    console.log(`Generated ${payloads.length} payloads.`);
    return payloads;
  }

  async generateSinglePayload() {
    let sequence = ['<'];
    while (sequence.length < this.config.maxLength) {
      const paddedSequence = this.padSequence(sequence);
      const input = tf.tensor2d([paddedSequence], [1, this.config.maxLength]);
      const prediction = this.model.predict(input);
      const nextTokenIndex = this.sampleFromPrediction(prediction);
      const nextToken = this.tokenizer.indexWord[nextTokenIndex];
      
      sequence.push(nextToken);
      
      if (nextToken === '>' || nextToken === '\n' || sequence.length >= this.config.maxLength) break;
    }

    return sequence.join('');
  }

  padSequence(sequence) {
    const paddedSequence = sequence.map(token => this.tokenizer.wordIndex[token] || 0);
    while (paddedSequence.length < this.config.maxLength) {
      paddedSequence.push(0);
    }
    return paddedSequence;
  }

  sampleFromPrediction(prediction) {
    const predictionArray = prediction.dataSync();
    const sum = predictionArray.reduce((a, b) => a + b, 0);
    const sample = Math.random() * sum;
    let currentSum = 0;
    for (let i = 0; i < predictionArray.length; i++) {
      currentSum += predictionArray[i];
      if (currentSum > sample) {
        return i;
      }
    }
    return predictionArray.length - 1;
  }

  async checkFileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}

module.exports = { RNNAgent };