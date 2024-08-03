const fs = require('fs').promises;
const { Tokenizer } = require('./tokenizer');

async function createSampleTokenizer() {
  const tokenizer = new Tokenizer();

  // Sample XSS payloads
  const sampleTexts = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '<iframe src="javascript:alert(`XSS`)"></iframe>'
  ];

  tokenizer.fit(sampleTexts);

  const tokenizerJson = {
    wordToIndex: tokenizer.wordToIndex,
    indexToWord: tokenizer.indexToWord
  };

  await fs.writeFile('tokenizer.json', JSON.stringify(tokenizerJson, null, 2));
  console.log('Sample tokenizer created successfully.');
}

createSampleTokenizer().catch(console.error);