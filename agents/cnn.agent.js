const tf = require('@tensorflow/tfjs-node-gpu');

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
            // Change this line to create a 2D tensor instead of 3D
            const input = tf.tensor2d([paddedSequence], [1, this.config.maxLength]);
            
            console.log('Input tensor shape:', input.shape);
            
            let prediction;
            try {
                prediction = this.model.predict(input);
                console.log('Prediction tensor shape:', prediction.shape);
                console.log('Prediction values (first 10):', prediction.dataSync().slice(0, 10));
            } catch (error) {
                console.error('Error during model prediction:', error);
                break;
            }

            const nextTokenIndex = this.sampleFromPrediction(prediction, temperature);
            console.log('Next token index:', nextTokenIndex);

            const nextToken = this.tokenizer.indexToWord[nextTokenIndex] || '';
            console.log('Next token:', nextToken);
            
            sequence.push(nextToken);
            console.log('Updated sequence:', sequence);
            
            if (nextToken === '>' || nextToken === '\n' || sequence.length >= maxLength) {
                console.log('Ending condition met');
                break;
            }

            // Dispose of tensors to free memory
            input.dispose();
            prediction.dispose();
        }

        const payload = sequence.join('');
        console.log('Final payload:', payload);
        return payload;
    }

    padSequence(sequence) {
        const paddedSequence = sequence.map(token => this.tokenizer.wordToIndex[token] || 0);
        while (paddedSequence.length < this.config.maxLength) {
            paddedSequence.push(0);
        }
        return paddedSequence;
    }

    sampleFromPrediction(prediction, temperature = 1.0) {
        const logits = prediction.dataSync();
        console.log('Logits (first 10):', logits.slice(0, 10));

        const probabilities = tf.softmax(tf.div(tf.tensor1d(logits), temperature)).dataSync();
        console.log('Probabilities (first 10):', probabilities.slice(0, 10));
        
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

    isValidXSS(payload) {
        const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', '<img', '<iframe', '<svg', '<math'];
        return xssPatterns.some(pattern => payload.toLowerCase().includes(pattern));
    }
}

module.exports = { CNNAgent };