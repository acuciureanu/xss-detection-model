class Tokenizer {
  constructor() {
    this.vocab = new Set();
    this.wordToIndex = {};
    this.indexToWord = {};
    this.nextIndex = 0;
  }

  fit(texts) {
    for (const text of texts) {
      for (const char of text) {
        if (!this.vocab.has(char)) {
          this.vocab.add(char);
          this.wordToIndex[char] = this.nextIndex;
          this.indexToWord[this.nextIndex] = char;
          this.nextIndex++;
        }
      }
    }
  }

  encode(text) {
    return text.split('').map(char => {
      if (this.wordToIndex[char] !== undefined) {
        return this.wordToIndex[char];
      } else {
        return this.wordToIndex['<UNK>'] || 0;
      }
    });
  }

  decode(sequence) {
    return sequence.map(index => this.indexToWord[index] || '<UNK>').join('');
  }

  getVocabSize() {
    return Object.keys(this.wordToIndex).length;
  }

  toJson() {
    return JSON.stringify({
      vocab: Array.from(this.vocab),
      wordToIndex: this.wordToIndex,
      indexToWord: this.indexToWord,
      nextIndex: this.nextIndex
    });
  }

  static fromJson(jsonString) {
    const data = JSON.parse(jsonString);
    console.log("Parsed JSON data:", data);

    if (typeof data.vocab !== 'object' || data.vocab === null) {
      throw new TypeError("Expected vocab to be an object");
    }

    const tokenizer = new Tokenizer();
    tokenizer.wordToIndex = data.wordToIndex;
    tokenizer.indexToWord = data.indexToWord;
    tokenizer.nextIndex = data.nextIndex;

    // Populate the vocab set
    for (const char in data.wordToIndex) {
      tokenizer.vocab.add(char);
    }

    return tokenizer;
  }
}

module.exports = { Tokenizer };
