const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const crypto = require('crypto');
const fs = require('fs').promises;

class PayloadGenerator {
  constructor(config) {
    this.config = config;
    this.window = new JSDOM('', { runScripts: "dangerously" }).window;
    this.DOMPurify = createDOMPurify(this.window);
    this.uniquePayloads = new Set();
    this.results = [];

    this.basePayloads = [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert(1)>",
      "<svg><script>alert(1)</script></svg>",
      "<iframe src=\"javascript:alert(1)\"></iframe>",
      "<a href=\"javascript:alert(1)\">Click me</a>",
      "<div onmouseover=\"alert(1)\">Hover me</div>",
      "<input type=\"text\" onfocus=\"alert(1)\" autofocus>",
      "<details open ontoggle=\"alert(1)\">",
      "<audio src=x onerror=alert(1)>",
      "<video src=x onerror=alert(1)>",
      "<body onload=alert(1)>",
      "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
      "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
      "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert(1)\">click",
      "<table background=\"javascript:alert(1)\"></table>"
    ];

    this.eventHandlers = [
      "onload", "onerror", "onmouseover", "onclick", "onmouseout", "onfocus", "onblur", "onkeypress", "onsubmit"
    ];

    this.tags = [
      "a", "abbr", "acronym", "address", "applet", "area", "article", "aside", "audio", "b", "base", "basefont", 
      "bdo", "big", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite", "code", "col", 
      "colgroup", "command", "datalist", "dd", "del", "details", "dfn", "dialog", "dir", "div", "dl", "dt", "em", 
      "embed", "fieldset", "figcaption", "figure", "font", "footer", "form", "frame", "frameset", "h1", "h2", "h3", 
      "h4", "h5", "h6", "head", "header", "hr", "html", "i", "iframe", "img", "input", "ins", "kbd", "keygen", 
      "label", "legend", "li", "link", "map", "mark", "menu", "meta", "meter", "nav", "noframes", "noscript", 
      "object", "ol", "optgroup", "option", "output", "p", "param", "pre", "progress", "q", "rp", "rt", "ruby", 
      "s", "samp", "script", "section", "select", "small", "source", "span", "strike", "strong", "style", "sub", 
      "summary", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track", 
      "tt", "u", "ul", "var", "video", "wbr"
    ];
  }

  generatePayload() {
    const payloadTypes = [
      this.generateScriptPayload,
      this.generateEventHandlerPayload,
      this.generateURIPayload,
      this.generateDataURIPayload,
      this.generateSVGPayload
    ];
    const selectedType = payloadTypes[Math.floor(Math.random() * payloadTypes.length)];
    return selectedType.call(this);
  }

  generateScriptPayload() {
    return `<script>alert('XSS')</script>`;
  }

  generateEventHandlerPayload() {
    const tag = this.getRandomItem(this.tags);
    const event = this.getRandomItem(this.eventHandlers);
    return `<${tag} ${event}="alert('XSS')">XSS</${tag}>`;
  }

  generateURIPayload() {
    return `<a href="javascript:alert('XSS')">Click me</a>`;
  }

  generateDataURIPayload() {
    const encodedScript = Buffer.from("<script>alert('XSS')</script>").toString('base64');
    return `<object data="data:text/html;base64,${encodedScript}">`;
  }

  generateSVGPayload() {
    return `<svg><script>alert('XSS')</script></svg>`;
  }

  getRandomItem(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  mutatePayload(payload) {
    const mutations = [
      p => this.insertRandomCharacters(p),
      p => this.changeCase(p),
      p => this.addEncoding(p),
      p => this.nestTags(p),
      p => this.splitAttributes(p),
      p => p // Identity function to sometimes return the original payload
    ];
    return mutations[Math.floor(Math.random() * mutations.length)](payload);
  }

  insertRandomCharacters(payload) {
    return payload.split('').map(c => 
      Math.random() < 0.1 ? c + ['\u200b', '\u200c', '\u200d', '\ufeff'][Math.floor(Math.random() * 4)] : c
    ).join('');
  }

  changeCase(payload) {
    return payload.split('').map(c => 
      Math.random() < 0.5 ? c.toUpperCase() : c.toLowerCase()
    ).join('');
  }

  addEncoding(payload) {
    return encodeURIComponent(payload);
  }

  nestTags(payload) {
    const tag = this.getRandomItem(this.tags);
    return `<${tag}>${payload}</${tag}>`;
  }

  splitAttributes(payload) {
    return payload.replace(/(\w+)=(['"])([^'"]*?)[']/g, 
      (match, attr, quote, value) => `${attr}=${quote} ${attr}=${quote}`
    );
  }

  isUniquePayload(payload) {
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    if (this.uniquePayloads.has(hash)) {
      return false;
    }
    this.uniquePayloads.add(hash);
    return true;
  }

  testPayload(payload) {
    const sanitized = this.DOMPurify.sanitize(payload);
    const potentiallyDangerous = this.containsPotentiallyDangerousContent(sanitized);
    const alertTriggered = this.checkAlertTriggered(sanitized);
    
    // Only consider it bypassed if it contains potentially dangerous content AND triggered an alert
    const bypassed = potentiallyDangerous && alertTriggered;
    
    return {
      original: payload,
      sanitized: sanitized,
      potentiallyDangerous: potentiallyDangerous,
      alertTriggered: alertTriggered,
      bypassed: bypassed
    };
  }

  containsPotentiallyDangerousContent(sanitized) {
    const lowerCased = sanitized.toLowerCase();
    return lowerCased.includes('<script') ||
           lowerCased.includes('javascript:') ||
           lowerCased.includes('data:') ||
           /<\w+[^>]*on\w+=/i.test(lowerCased) ||
           /<(iframe|object|embed|audio|video|img|svg)/i.test(lowerCased);
  }

  checkAlertTriggered(sanitized) {
    let alertTriggered = false;
    const originalAlert = this.window.alert;
    const originalTimeout = this.window.setTimeout;
    const originalSetInterval = this.window.setInterval;
  
    this.window.alert = () => { alertTriggered = true; };
    this.window.setTimeout = (callback) => { callback(); };
    this.window.setInterval = (callback) => { callback(); };
  
    try {
      const newWindow = new JSDOM('', { runScripts: "dangerously" }).window;
      newWindow.alert = () => { alertTriggered = true; };
      newWindow.setTimeout = (callback) => { callback(); };
      newWindow.setInterval = (callback) => { callback(); };
  
      // Extract script content and execute it
      const scriptMatches = sanitized.match(/<script[^>]*>([\s\S]*?)<\/script>/gi);
      if (scriptMatches) {
        scriptMatches.forEach(scriptTag => {
          const scriptContent = scriptTag.replace(/<script[^>]*>|<\/script>/gi, '');
          try {
            newWindow.eval(scriptContent);
          } catch (e) {
            // Ignore script errors
          }
        });
      }
  
      // Simulate events on the sanitized DOM
      const div = newWindow.document.createElement('div');
      div.innerHTML = sanitized;
      const elements = div.getElementsByTagName('*');
      for (let el of elements) {
        for (let attr of el.attributes) {
          if (attr.name.toLowerCase().startsWith('on')) {
            try {
              const event = new newWindow.Event(attr.name.slice(2));
              el.dispatchEvent(event);
            } catch (e) {
              // Ignore errors
            }
          }
        }
      }
    } catch (e) {
      // Log the error for debugging purposes
      console.error('Error while testing payload:', e);
    } finally {
      // Restore original functions
      this.window.alert = originalAlert;
      this.window.setTimeout = originalTimeout;
      this.window.setInterval = originalSetInterval;
    }
  
    return alertTriggered;
  }  

  async fuzz(maxIterations = Infinity) {
    let iterations = 0;
    let bypassedPayloads = 0;
    let startTime = Date.now();

    console.log('Starting fuzzing process...');

    while (iterations < maxIterations) {
      const basePayload = this.generatePayload();
      const payload = this.mutatePayload(basePayload);
      
      if (!this.isUniquePayload(payload)) continue;

      const result = this.testPayload(payload);
      
      if (result.bypassed) {
        this.results.push(result);
        bypassedPayloads++;
        console.log(`[${new Date().toISOString()}] Bypass found:`, {
          original: result.original,
          sanitized: result.sanitized,
          alertTriggered: result.alertTriggered
        });
      }

      iterations++;
      if (iterations % 10000 === 0) {
        const elapsedTime = (Date.now() - startTime) / 1000;
        const payloadsPerSecond = iterations / elapsedTime;
        console.log(`[${new Date().toISOString()}] Progress: ${iterations} payloads processed, ` +
                    `${bypassedPayloads} bypassed (alert-triggering). ` +
                    `Speed: ${payloadsPerSecond.toFixed(2)} payloads/sec`);
        
        // Periodically save results to file
        await this.saveResults();
      }

      // Introduce a small delay every 1000 iterations to prevent blocking the event loop
      if (iterations % 1000 === 0) {
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const totalTime = (Date.now() - startTime) / 1000;
    console.log(`\nFuzzing completed in ${totalTime.toFixed(2)} seconds.`);
    console.log(`Total payloads tested: ${iterations}`);
    console.log(`Bypassed (alert-triggering) payloads found: ${bypassedPayloads}`);

    // Save final results
    await this.saveResults();

    return this.results;
  }

  async saveResults() {
    try {
      await fs.writeFile('xss_fuzzer_results.json', JSON.stringify(this.results, null, 2));
    } catch (error) {
      console.error('Error saving results to file:', error);
    }
  }
}

async function runFuzzer() {
  const config = {
    payloadCount: 1000000,
    maxPayloadLength: 200
  };

  const generator = new PayloadGenerator(config);
  console.log('Initializing fuzzer...');
  const results = await generator.fuzz(config.payloadCount);

  console.log('\nFinal Results:');
  console.log('Top 10 bypassed payloads:');
  results.slice(0, 10).forEach((result, index) => {
    console.log(`${index + 1}. Original: ${result.original}`);
    console.log(`   Sanitized: ${result.sanitized}`);
    console.log(`   Alert Triggered: ${result.alertTriggered}\n`);
  });
}

// Main execution
if (require.main === module) {
  runFuzzer().catch(console.error);
}

module.exports = { PayloadGenerator, runFuzzer };