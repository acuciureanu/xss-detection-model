class Tokenizer {
    constructor() {
      this.vocab = new Set(['<', '>', '/', '=', '"', "'", ' ']);
      this.wordToIndex = {};
      this.indexToWord = {};
      this.nextIndex = this.vocab.size;
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
      return this.vocab.size;
    }
  }
  
  module.exports = { Tokenizer };