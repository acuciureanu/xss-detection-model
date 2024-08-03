const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs');
const fsp = require('fs').promises;
const csv = require('csv-parser');
const readline = require('readline');
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

function preprocessSentence(sentence) {
  return sentence.toLowerCase().replace(/[^\w\s]/gi, '').trim();
}

function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

function createModel(maxLength, vocabSize) {
  const model = tf.sequential();
  model.add(tf.layers.embedding({ inputDim: vocabSize, outputDim: 64, inputLength: maxLength }));
  model.add(tf.layers.spatialDropout1d({ rate: 0.3 }));
  model.add(tf.layers.globalAveragePooling1d());
  model.add(tf.layers.dense({ units: 32, activation: 'relu', kernelRegularizer: tf.regularizers.l2({ l2: 1e-4 }) }));
  model.add(tf.layers.dropout({ rate: 0.5 }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid', kernelRegularizer: tf.regularizers.l2({ l2: 1e-4 }) }));

  return model;
}

function dataAugmentation(sentence) {
  const words = sentence.split(' ');
  const augmentedWords = words.filter(() => Math.random() > 0.1);
  if (Math.random() < 0.5) {
    const indexToDuplicate = Math.floor(Math.random() * augmentedWords.length);
    augmentedWords.splice(indexToDuplicate, 0, augmentedWords[indexToDuplicate]);
  }
  return augmentedWords.join(' ');
}

class CustomCallback extends tf.Callback {
  constructor(validationData, totalEpochs, totalBatches, earlyStoppingPatience = 10) {
    super();
    this.validationData = validationData;
    this.totalEpochs = totalEpochs;
    this.totalBatches = totalBatches;
    this.bestValLoss = Infinity;
    this.patience = earlyStoppingPatience;
    this.wait = 0;
  }

  async onEpochBegin(epoch) {
    this.currentEpoch = epoch + 1;
    this.epochStartTime = Date.now();
    this.batchesCompleted = 0;
    console.log(`\nEpoch ${this.currentEpoch}/${this.totalEpochs}`);
  }

  async onBatchEnd(batch, logs) {
    this.batchesCompleted++;
    const progress = (this.batchesCompleted / this.totalBatches) * 100;
    const eta = ((Date.now() - this.epochStartTime) / 1000 / 60 * (this.totalBatches - this.batchesCompleted) / this.batchesCompleted).toFixed(1);
    
    const loss = logs.loss ? logs.loss.dataSync()[0].toFixed(4) : 'N/A';
    const acc = logs.acc ? (logs.acc.dataSync()[0] * 100).toFixed(2) : 'N/A';

    readline.cursorTo(process.stdout, 0);
    readline.clearLine(process.stdout, 0);
    process.stdout.write(
      `Batch ${this.batchesCompleted}/${this.totalBatches} | ` +
      `Loss: ${loss}, Acc: ${acc}% | ` +
      `ETA: ${eta}m | ${progress.toFixed(1)}%`
    );
  }

  async onEpochEnd(epoch, logs) {
    readline.cursorTo(process.stdout, 0);
    readline.clearLine(process.stdout, 0);

    const [valX, valY] = this.validationData;
    const valLoss = await this.model.evaluate(valX, valY, { verbose: 0 });
    const valLossValue = valLoss[0].dataSync()[0];
    const valAccValue = valLoss[1].dataSync()[0];

    const epochEndTime = Date.now();
    const epochTime = (epochEndTime - this.epochStartTime) / 1000;

    const trainLoss = logs.loss ? logs.loss.dataSync()[0].toFixed(4) : 'N/A';
    const trainAcc = logs.acc ? (logs.acc.dataSync()[0] * 100).toFixed(2) : 'N/A';

    console.log(`\nTrain Loss: ${trainLoss}, Train Accuracy: ${trainAcc}%`);
    console.log(`Validation Loss: ${valLossValue.toFixed(4)}, Validation Accuracy: ${(valAccValue * 100).toFixed(2)}%`);
    console.log(`Time taken: ${epochTime.toFixed(2)} seconds`);

    if (valLossValue < this.bestValLoss) {
      this.bestValLoss = valLossValue;
      this.wait = 0;
      console.log('New best validation loss, saving model...');
      await this.model.save('file://./best_model');
    } else {
      this.wait++;
      if (this.wait >= this.patience) {
        this.model.stopTraining = true;
        console.log("Early stopping triggered");
      }
    }
  }
}

function createCNNModel(maxLength, vocabSize) {
  const model = tf.sequential();
  model.add(tf.layers.embedding({ inputDim: vocabSize, outputDim: 64, inputLength: maxLength }));
  model.add(tf.layers.spatialDropout1d({ rate: 0.3 }));
  model.add(tf.layers.conv1d({ filters: 64, kernelSize: 5, activation: 'relu', kernelRegularizer: tf.regularizers.l2({ l2: 1e-4 }) }));
  model.add(tf.layers.globalMaxPooling1d());
  model.add(tf.layers.dense({ units: 64, activation: 'relu', kernelRegularizer: tf.regularizers.l2({ l2: 1e-4 }) }));
  model.add(tf.layers.dropout({ rate: 0.5 }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

  return model;
}

async function trainModel() {
  try {
    console.log('Loading and preprocessing data...');
    const data = await readCSV('XSS_dataset.csv');
    
    const sentences = data.map(row => preprocessSentence(row.Sentence));
    const labels = data.map(row => parseInt(row.Label));

    const combinedData = sentences.map((sentence, index) => ({ sentence, label: labels[index] }));
    shuffleArray(combinedData);
    const shuffledSentences = combinedData.map(item => item.sentence);
    const shuffledLabels = combinedData.map(item => item.label);

    console.log('Applying data augmentation...');
    const augmentedSentences = shuffledSentences.map(sentence => dataAugmentation(sentence));
    const allSentences = [...shuffledSentences, ...augmentedSentences];
    const allLabels = [...shuffledLabels, ...shuffledLabels];

    console.log('Tokenizing and padding sequences...');
    const tokenizer = new Tokenizer();
    tokenizer.fit(allSentences);
    const maxLength = 500;
    const paddedSequences = allSentences.map(sentence => {
      const encoded = tokenizer.encode(sentence);
      return encoded.length > maxLength ? encoded.slice(0, maxLength) : encoded.concat(new Array(maxLength - encoded.length).fill(0));
    });

    console.log('Splitting data into train and validation sets...');
    const splitIndex = Math.floor(paddedSequences.length * 0.7);
    const trainX = paddedSequences.slice(0, splitIndex);
    const trainY = allLabels.slice(0, splitIndex);
    const valX = paddedSequences.slice(splitIndex);
    const valY = allLabels.slice(splitIndex);

    const trainXTensor = tf.tensor2d(trainX);
    const trainYTensor = tf.tensor1d(trainY, 'int32');
    const valXTensor = tf.tensor2d(valX);
    const valYTensor = tf.tensor1d(valY, 'int32');

    console.log('Creating and compiling CNN model...');
    const vocabSize = tokenizer.getVocabSize();
    const model = createCNNModel(maxLength, vocabSize);

    const initialLearningRate = 0.001;
    const decay = initialLearningRate / 200;
    const optimizer = tf.train.adamax(initialLearningRate, 0.9, 0.999, 1e-7);

    model.compile({
      optimizer: optimizer,
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });
  
    console.log('Starting CNN model training...');
    const batchSize = 32;
    const epochs = 100;
    const totalBatches = Math.ceil(trainX.length / batchSize);
  
    const customCallback = new CustomCallback([valXTensor, valYTensor], epochs, totalBatches);
  
    const history = await model.fit(trainXTensor, trainYTensor, {
      batchSize,
      epochs,
      validationData: [valXTensor, valYTensor],
      callbacks: [customCallback],
      verbose: 0
    });

    console.log('Training complete. Saving model and tokenizer...');
    await model.save('file://./xss_model');
    await fsp.writeFile('tokenizer.json', JSON.stringify(tokenizer));

    console.log('Evaluating model...');
    await evaluateModel(model, valXTensor, valYTensor);

    console.log('Training history:', history.history);

    // Clean up tensors
    trainXTensor.dispose();
    trainYTensor.dispose();
    valXTensor.dispose();
    valYTensor.dispose();

  } catch (error) {
    console.error('An error occurred during the training process:', error);
  }
}

async function evaluateModel(model, testX, testY) {
  try {
    const predictions = await model.predict(testX).array();
    const thresholdedPreds = predictions.map(p => p[0] > 0.5 ? 1 : 0);
    const testYArray = await testY.array();
    
    const truePositives = thresholdedPreds.filter((pred, i) => pred === 1 && testYArray[i] === 1).length;
    const falsePositives = thresholdedPreds.filter((pred, i) => pred === 1 && testYArray[i] === 0).length;
    const falseNegatives = thresholdedPreds.filter((pred, i) => pred === 0 && testYArray[i] === 1).length;
    const trueNegatives = thresholdedPreds.filter((pred, i) => pred === 0 && testYArray[i] === 0).length;
    
    const accuracy = (truePositives + trueNegatives) / testYArray.length;
    const precision = truePositives / (truePositives + falsePositives) || 0;
    const recall = truePositives / (truePositives + falseNegatives) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;
    
    console.log(`Accuracy: ${accuracy}`);
    console.log(`Precision: ${precision}`);
    console.log(`Recall: ${recall}`);
    console.log(`F1 Score: ${f1Score}`);
  } catch (evalError) {
    console.error('Error during model evaluation:', evalError);
  }
}

trainModel().catch(console.error);