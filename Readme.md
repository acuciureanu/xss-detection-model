# XSS Detection Model 🛡️

This project trains and uses a machine learning model to detect Cross-Site Scripting (XSS) attacks.

## Prerequisites 🚀

- Node.js (preferably the latest LTS version)
- npm (comes with Node.js)
- A CUDA-capable GPU for faster training (optional but recommended)

## Installation 📦

1. Clone this repository
2. Run `npm install` to install the required dependencies

## Training the Model 🏋️‍♀️

To train the model, follow these steps:

1. Ensure you have the training dataset file `XSS_dataset_training.csv` in the project root directory
2. Open a terminal and navigate to the project directory
3. Run the following command:

```sh
node train.model.js
```

4. The script will start training the model. This process may take some time, depending on your hardware
5. Once training is complete, the model will be saved as `xss_model/model.json` and the tokenizer as `tokenizer.json`

## Testing the Model 🧪

To test the trained model, follow these steps:

1. Ensure you have the test dataset file `XSS_dataset_test.csv` in the project root directory
2. Open a terminal and navigate to the project directory
3. Run the following command:

```sh
node main.js
```

4. The script will load the trained model and tokenizer, then run inference on the test dataset
5. You'll see the results for each test case, including the true label, predicted score, and whether XSS was detected
6. At the end, the script will display the overall accuracy of the model on the test dataset

## Notes 📝

- Make sure you have sufficient disk space for the model and dataset files
- Training on a GPU will significantly speed up the process. If you don't have a GPU, you can modify the TensorFlow import in the scripts to use the CPU version instead
- The model's performance may vary depending on the quality and quantity of your training data

Happy XSS detection! 🎉🔍
