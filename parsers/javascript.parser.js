class JavaScriptParser {
    constructor() {
      this.stack = [];
    }
  
    isValid(payload) {
      this.stack = [];
      const tokens = this.tokenize(payload);
  
      for (const token of tokens) {
        if (token.type === 'openParen' || token.type === 'openBrace' || token.type === 'openBracket') {
          this.stack.push(token.type);
        } else if (token.type === 'closeParen' || token.type === 'closeBrace' || token.type === 'closeBracket') {
          if (!this.matchingPair(this.stack.pop(), token.type)) {
            return false;
          }
        }
      }
  
      return this.stack.length === 0;
    }
  
    tokenize(payload) {
      const tokens = [];
      let currentToken = '';
      let inString = false;
      let stringChar = '';
  
      for (const char of payload) {
        if ((char === '"' || char === "'") && !inString) {
          if (currentToken) {
            tokens.push({ type: 'identifier', value: currentToken });
            currentToken = '';
          }
          inString = true;
          stringChar = char;
          currentToken += char;
        } else if (char === stringChar && inString) {
          currentToken += char;
          tokens.push({ type: 'string', value: currentToken });
          currentToken = '';
          inString = false;
        } else if (inString) {
          currentToken += char;
        } else if (/[a-zA-Z0-9_$]/.test(char)) {
          currentToken += char;
        } else {
          if (currentToken) {
            tokens.push({ type: 'identifier', value: currentToken });
            currentToken = '';
          }
          if (char === '(') tokens.push({ type: 'openParen' });
          else if (char === ')') tokens.push({ type: 'closeParen' });
          else if (char === '{') tokens.push({ type: 'openBrace' });
          else if (char === '}') tokens.push({ type: 'closeBrace' });
          else if (char === '[') tokens.push({ type: 'openBracket' });
          else if (char === ']') tokens.push({ type: 'closeBracket' });
          else if (char !== ' ') tokens.push({ type: 'operator', value: char });
        }
      }
  
      if (currentToken) {
        tokens.push({ type: 'identifier', value: currentToken });
      }
  
      return tokens;
    }
  
    matchingPair(open, close) {
      if (open === 'openParen' && close === 'closeParen') return true;
      if (open === 'openBrace' && close === 'closeBrace') return true;
      if (open === 'openBracket' && close === 'closeBracket') return true;
      return false;
    }
  }
  
  module.exports = { JavaScriptParser };