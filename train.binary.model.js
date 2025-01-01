const tf = require('@tensorflow/tfjs-node-gpu');
const fs = require('fs').promises;
const csv = require('csv-parser');
const { Tokenizer } = require('./tokenizer');
const path = require('path');
const createReadStream = require('fs').createReadStream;

// Custom binary activation function using tf.sign
class BinaryActivation extends tf.layers.Layer {
    constructor(config) {
        super(config);
    }

    call(inputs) {
        return tf.sign(inputs);
    }

    static get className() {
        return 'BinaryActivation';
    }

    getConfig() {
        const config = super.getConfig();
        return config;
    }
}

// Register the custom activation layer
tf.serialization.registerClass(BinaryActivation);

// Custom layer for binary weights
class BinaryDense extends tf.layers.Layer {
    constructor(units, config) {
        super({
            units,
            ...config,
        });
        this.units = units;
    }

    build(inputShape) {
        this.kernel = this.addWeight(
            'kernel',
            [inputShape[1], this.units],
            'float32',
            tf.initializers.randomNormal({
                mean: 0,
                stddev: 0.05,
                seed: null
            })
        );
        this.built = true;
    }

    call(inputs) {
        return tf.tidy(() => {
            // Binarize weights during forward pass
            const binaryWeights = tf.sign(this.kernel.read());
            return tf.matMul(inputs, binaryWeights);
        });
    }

    getConfig() {
        const config = super.getConfig();
        config.units = this.units;
        return config;
    }

    static get className() {
        return 'BinaryDense';
    }
}

// Register the custom layer
tf.serialization.registerClass(BinaryDense);

async function createBinaryModel(vocabSize, maxLength) {
    const model = tf.sequential();
    
    // Input layer with embedding - reduced embedding dimension
    model.add(tf.layers.embedding({
        inputDim: vocabSize,
        outputDim: 16,  // Reduced from 32
        inputLength: maxLength
    }));

    // Add a Conv1D layer with fewer filters and L2 regularization
    model.add(tf.layers.conv1d({
        filters: 16,    // Reduced from 32
        kernelSize: 3,
        padding: 'same',
        activation: 'relu',
        kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
    }));

    // Add batch normalization for stability
    model.add(tf.layers.batchNormalization());

    // Add Global Average Pooling
    model.add(tf.layers.globalAveragePooling1d());

    // Dense layers with proper dimensions and regularization
    model.add(tf.layers.dense({
        units: 32,      // Reduced from 64
        activation: 'relu',
        kernelRegularizer: tf.regularizers.l2({ l2: 0.01 })
    }));
    model.add(tf.layers.batchNormalization());
    model.add(tf.layers.dropout({ rate: 0.3 }));  // Reduced dropout rate

    // Output Layer
    model.add(tf.layers.dense({
        units: 1,
        activation: 'sigmoid'
    }));

    // Compile with binary crossentropy and reduced learning rate
    model.compile({
        optimizer: tf.train.adam(0.0001),  // Reduced learning rate
        loss: 'binaryCrossentropy',
        metrics: ['accuracy']
    });

    return model;
}

function preprocessText(text) {
    return text.toLowerCase()
              .replace(/[^\w\s]/gi, '')
              .trim();
}

async function loadDataset(filePath) {
    return new Promise((resolve, reject) => {
        const data = [];
        const labels = [];
        
        createReadStream(filePath)
            .pipe(csv({
                skipLines: 1, // Skip header if present
                headers: ['text', 'label'] // Explicitly define headers
            }))
            .on('data', (row) => {
                // Add null checks and validation
                if (row && row.text && row.label !== undefined) {
                    const processedText = preprocessText(row.text);
                    if (processedText) {
                        data.push(processedText);
                        labels.push(parseInt(row.label, 10));
                    }
                }
            })
            .on('end', () => {
                if (data.length === 0) {
                    reject(new Error('No valid data found in CSV file'));
                } else {
                    resolve({ data, labels });
                }
            })
            .on('error', (error) => {
                reject(error);
            });
    });
}

async function main() {
    try {
        console.log('Starting binary model training...');

        // Parameters
        const maxLength = 100;
        const epochs = 10;
        const batchSize = 64;  // Increased batch size for stability

        // Load and preprocess data
        console.log('Loading dataset...');
        const { data, labels } = await loadDataset('XSS_dataset_training.csv');
        
        if (!data || data.length === 0) {
            throw new Error('Dataset is empty');
        }
        
        console.log(`Loaded ${data.length} samples`);

        // Create tokenizer instance
        console.log('Creating tokenizer...');
        const tokenizer = new Tokenizer();
        
        console.log('Tokenizing and padding sequences...');
        tokenizer.fit(data);
        
        const sequences = data.map(text => tokenizer.encode(text));
        
        // Pad sequences
        const paddedSequences = sequences.map(seq => {
            if (seq.length > maxLength) {
                return seq.slice(0, maxLength);
            }
            return [...seq, ...new Array(maxLength - seq.length).fill(0)];
        });

        // Convert to tensors with validation
        const xTrain = tf.tensor2d(paddedSequences, [paddedSequences.length, maxLength]);
        const xTrainNorm = xTrain.div(tf.scalar(tokenizer.getVocabSize()));  // Normalize inputs
        
        // Ensure labels are proper float32
        const yTrain = tf.tensor2d(labels, [labels.length, 1], 'float32');

        // Update vocabSize
        const vocabSize = tokenizer.getVocabSize();
        
        // Create model
        console.log('Creating binary model...');
        const model = await createBinaryModel(vocabSize, maxLength);
        
        console.log('Model architecture:');
        model.summary();

        // Training with gradient clipping
        console.log('\nTraining binary model...');
        await model.fit(xTrainNorm, yTrain, {
            epochs,
            batchSize,
            validationSplit: 0.2,
            shuffle: true,
            callbacks: {
                onBatchEnd: async (batch, logs) => {
                    await tf.nextFrame(); // Prevents UI freezing
                },
                onEpochEnd: (epoch, logs) => {
                    console.log(
                        `Epoch ${epoch + 1}: ` +
                        `loss = ${logs.loss ? logs.loss.toFixed(4) : 'NaN'}, ` +
                        `accuracy = ${logs.accuracy ? logs.accuracy.toFixed(4) : 'N/A'}, ` +
                        `val_loss = ${logs.val_loss ? logs.val_loss.toFixed(4) : 'NaN'}, ` +
                        `val_accuracy = ${logs.val_accuracy ? logs.val_accuracy.toFixed(4) : 'N/A'}`
                    );
                }
            }
        });

        // Ensure the save directory exists
        const saveDir = path.resolve(__dirname, 'binary_model');
        try {
            await fs.access(saveDir);
        } catch (err) {
            // Directory does not exist, create it
            await fs.mkdir(saveDir, { recursive: true });
        }

        // Cleanup and save
        try {
            await model.save(`file://${saveDir}`);
            await fs.writeFile('binary_tokenizer.json', JSON.stringify(tokenizer.toJson()));
            console.log('Model and tokenizer saved successfully');
        } finally {
            // Cleanup tensors
            xTrain.dispose();
            xTrainNorm.dispose();
            yTrain.dispose();
        }

    } catch (error) {
        console.error('An error occurred:', error);
        process.exit(1);
    }
}

main();
