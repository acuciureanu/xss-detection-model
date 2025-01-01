# XSS Detection Model with Hybrid Neural Network 🛡️

This project implements a hybrid neural network model to detect Cross-Site Scripting (XSS) attacks, combining traditional deep learning layers with binary neural network components for optimized performance and efficiency.

## Prerequisites 🚀

- Node.js (preferably the latest LTS version)
- npm (comes with Node.js)
- A CUDA-capable GPU for faster training (optional but recommended)

## Installation 📦

1. Clone this repository
2. Run `npm install` to install the required dependencies (including @tensorflow/tfjs-node-gpu)

## Training the Model 🏋️‍♀️

To train the hybrid model, follow these steps:

1. Ensure you have the training dataset file `XSS_dataset_training.csv` in the project root directory
2. Open a terminal and navigate to the project directory
3. Run the following command:

```sh
node train.binary.model.js
```

4. The script will start training the binary neural network. This process may take some time, depending on your hardware
5. Once training is complete, the model will be saved in the `binary_model` directory and the tokenizer as `binary_tokenizer.json`

## Using the Model 🧪

To analyze potential XSS payloads:

1. Place your payloads in a file named `payloads.txt` (one payload per line)
2. Run the following command:

```sh
node main.js
```

3. The script will analyze each payload and provide:
   - A confidence score for XSS detection
   - A clear YES/NO verdict for each payload
   - Summary statistics of the analysis
4. Undetected payloads will be saved to a separate file for further analysis

### Example Output 📊

When running the analysis, you'll see detailed results for each payload followed by summary statistics:

```
Summary Statistics:
==================================================
Total Payloads Analyzed: 2666
XSS Detected: 2666 (100.00%)
XSS Not Detected: 0 (0.00%)
==================================================
```

## Notes 📝

- The hybrid neural network approach combines traditional deep learning with binary components for balanced performance
- Training on a GPU will significantly speed up the process using @tensorflow/tfjs-node-gpu
- The model's performance may vary depending on the quality and quantity of your training data
- The hybrid approach provides a good balance between model complexity and inference speed

## Technical Approach 🧠

This project uses a hybrid neural network architecture combining traditional deep learning layers (embedding, CNN) with binary neural network components:

1. **Text Processing**: Input payloads are preprocessed by converting to lowercase and removing special characters.

2. **Tokenization**: The text is converted into numerical sequences using a custom tokenizer, making it suitable for neural network processing.

3. **Model Architecture**:
   - Embedding Layer: Converts tokenized text into dense vectors (16 dimensions)
   - Convolutional Layer: Extracts local patterns using 16 filters
   - Batch Normalization: Stabilizes training
   - Global Average Pooling: Reduces dimensionality while maintaining feature information
   - Dense Layers: Final classification layers with dropout for regularization

4. **Training**:
   - Uses binary cross-entropy loss
   - Adam optimizer with a low learning rate (0.0001)
   - Includes L2 regularization to prevent overfitting
   - Batch normalization for training stability

5. **Inference**:
   - Outputs a confidence score between 0 and 1
   - Scores above 0.5 indicate potential XSS attacks
   - Higher scores suggest higher confidence in XSS detection

The model is designed to be lightweight while maintaining high accuracy, making it suitable for real-time detection scenarios.

Happy XSS detection! 🎉🔍
