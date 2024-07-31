const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');
const fsp = require('fs').promises;
const csv = require('csv-parser');
const { Tokenizer } = require('./tokenizer');

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

async function trainModel() {
  // Load your dataset
  const data = await readCSV('XSS_dataset.csv');
  
  // Extract sentences and labels
  const sentences = data.map(row => row.Sentence);
  const labels = data.map(row => parseInt(row.Label));

  // Initialize and fit the tokenizer
  const tokenizer = new Tokenizer();
  tokenizer.fit(sentences);

  // Prepare the training data
  const maxLength = 500; // Adjust based on your data
  const paddedSequences = sentences.map(sentence => {
    const encoded = tokenizer.encode(sentence);
    return encoded.length > maxLength ? encoded.slice(0, maxLength) : encoded.concat(new Array(maxLength - encoded.length).fill(0));
  });

  const x = tf.tensor2d(paddedSequences);
  const y = tf.tensor1d(labels, 'int32');

  // Define the model
  const model = tf.sequential();
  model.add(tf.layers.embedding({inputDim: tokenizer.getVocabSize(), outputDim: 256, inputLength: maxLength}));
  model.add(tf.layers.flatten()); // Flatten the input
  model.add(tf.layers.dense({units: 64, activation: 'relu'}));
  model.add(tf.layers.dense({units: 1, activation: 'sigmoid'}));

  model.compile({optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy']});

  // Train the model
  const history = await model.fit(x, y, {
    batchSize: 32,
    epochs: 10,
    validationSplit: 0.2
  });

  // Print training results
  console.log('Training history:', history.history);

  // Save the model
  await model.save('file://./xss_model');

  // Save the tokenizer
  await fsp.writeFile('tokenizer.json', JSON.stringify(tokenizer));

  console.log('Model training complete and saved.');
}

trainModel().catch(console.error);
