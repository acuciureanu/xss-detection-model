const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs').promises;
const path = require('path');

class CNNAgent {
    constructor(model, tokenizer, config) {
      this.model = model;
      this.tokenizer = tokenizer;
      this.config = config;
    }
  
    async generateSinglePayload(temperature = 0.8, maxLength = 100) {
      let sequence = ['<'];
      while (sequence.length < maxLength) {
        const paddedSequence = this.padSequence(sequence);
        const input = tf.tensor2d([paddedSequence], [1, this.config.maxLength]);
        const prediction = this.model.predict(input);
        const nextTokenIndex = this.sampleFromPrediction(prediction, temperature);
        const nextToken = this.tokenizer.indexToWord[nextTokenIndex] || '';
        
        sequence.push(nextToken);
        
        if (nextToken === '>' || nextToken === '\n') {
          if (this.isValidXSS(sequence.join(''))) {
            break;
          }
        }
        
        if (sequence.length >= maxLength) {
          break;
        }
      }
  
      return sequence.join('');
    }
  
    sampleFromPrediction(prediction, temperature = 1.0) {
      const logits = prediction.dataSync();
      const probabilities = tf.softmax(tf.div(tf.tensor1d(logits), temperature)).dataSync();
      
      let sum = 0;
      const sample = Math.random();
      for (let i = 0; i < probabilities.length; i++) {
        sum += probabilities[i];
        if (sum > sample) {
          return i;
        }
      }
      return probabilities.length - 1;
    }
  
    padSequence(sequence) {
      const padding = Array(this.config.maxLength - sequence.length).fill(this.tokenizer.wordToIndex['<PAD>']);
      return padding.concat(sequence.map(token => this.tokenizer.wordToIndex[token] || this.tokenizer.wordToIndex['<UNK>']));
    }
  
    isValidXSS(payload) {
      const lowerPayload = payload.toLowerCase();
      const xssPatterns = [
        '<script>',
        'javascript:',
        'onerror=',
        'onload=',
        'onmouseover=',
        '<img',
        '<iframe',
        '<svg',
        '<math',
        '<body',
        '<input',
        '<link',
        '<style',
        'expression(',
        'src=',
        'href=',
        'data:'
      ];
      
      return xssPatterns.some(pattern => lowerPayload.includes(pattern));
    }
  
    async generateMultiplePayloads(n, temperature = 0.8, maxLength = 100) {
      const payloads = [];
      for (let i = 0; i < n; i++) {
        const payload = await this.generateSinglePayload(temperature, maxLength);
        payloads.push(payload);
      }
      return payloads;
    }
  
    async generateFuzzingPayloads(batchSize = 10, temperature = 0.8, maxLength = 100) {
      const payloads = await this.generateMultiplePayloads(batchSize, temperature, maxLength);
      return payloads.filter(payload => this.isValidXSS(payload));
    }
  }
  

module.exports = { CNNAgent };