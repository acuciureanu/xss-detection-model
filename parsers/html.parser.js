class HTMLParser {
    constructor() {
      this.openTags = [];
    }
  
    isValid(payload) {
      this.openTags = [];
      const tokens = this.tokenize(payload);
  
      for (const token of tokens) {
        if (token.type === 'openTag') {
          this.openTags.push(token.name);
        } else if (token.type === 'closeTag') {
          if (this.openTags.pop() !== token.name) {
            return false;
          }
        }
      }
  
      return this.openTags.length === 0;
    }
  
    tokenize(payload) {
      const tokens = [];
      let currentToken = '';
      let inTag = false;
      let inQuote = false;
      let quoteChar = '';
  
      for (const char of payload) {
        if (char === '<' && !inTag && !inQuote) {
          if (currentToken) {
            tokens.push({ type: 'text', content: currentToken });
            currentToken = '';
          }
          inTag = true;
          currentToken += char;
        } else if (char === '>' && inTag && !inQuote) {
          currentToken += char;
          tokens.push(this.parseTag(currentToken));
          currentToken = '';
          inTag = false;
        } else if ((char === '"' || char === "'") && inTag) {
          if (!inQuote) {
            inQuote = true;
            quoteChar = char;
          } else if (char === quoteChar) {
            inQuote = false;
          }
          currentToken += char;
        } else {
          currentToken += char;
        }
      }
  
      if (currentToken) {
        tokens.push({ type: 'text', content: currentToken });
      }
  
      return tokens;
    }
  
    parseTag(tagString) {
      if (tagString.startsWith('</')) {
        return { type: 'closeTag', name: tagString.slice(2, -1).trim().toLowerCase() };
      } else {
        const name = tagString.slice(1, -1).split(/\s+/)[0].toLowerCase();
        return { type: 'openTag', name: name };
      }
    }
  }
  
  module.exports = { HTMLParser };