const puppeteer = require('puppeteer');
const fs = require('fs').promises;
const path = require('path');
const JSDOM = require('jsdom').JSDOM;
const DOMPurify = require('dompurify')(new JSDOM().window);

const { RNNAgent } = require('./agents/rnn.agent');
const { AnomalyDetector } = require('./detectors/anomaly.detector');
const { HTMLParser } = require('./parsers/html.parser');
const { JavaScriptParser } = require('./parsers/javascript.parser');

class XSSFuzzer {
  constructor(config) {
    this.config = config;
    this.rnnAgent = new RNNAgent(config.rnnConfig);
    this.anomalyDetector = new AnomalyDetector(config.anomalyConfig);
    this.htmlParser = new HTMLParser();
    this.jsParser = new JavaScriptParser();
    this.browserPool = [];
    this.results = [];
    this.DOMPurify = DOMPurify;
    this.payloadLog = [];
  }

  async initialize() {
    console.log('Initializing XSS Fuzzer...');
    try {
      await this.rnnAgent.loadModel();
      for (let i = 0; i < this.config.concurrency; i++) {
        const browser = await puppeteer.launch(this.config.puppeteerOptions);
        this.browserPool.push(browser);
      }
      console.log('Initialization complete.');
    } catch (error) {
      console.error('Initialization failed:', error);
      throw error;
    }
  }

  async testPayload(payload) {
    const browser = await this.getAvailableBrowser();
    const page = await browser.newPage();

    try {
      this.payloadLog.push(payload);

      const rawResult = await this.testInBrowser(page, payload);
      const sanitizedPayload = this.DOMPurify.sanitize(payload);
      const sanitizedResult = await this.testInBrowser(page, sanitizedPayload);

      return {
        payload,
        sanitizedPayload,
        rawSuccess: rawResult.executed,
        sanitizedSuccess: sanitizedResult.executed,
        rawActions: rawResult.actions,
        sanitizedActions: sanitizedResult.actions,
        bypassedDOMPurify: rawResult.executed && sanitizedResult.executed
      };
    } finally {
      await page.close();
    }
  }

  async testInBrowser(page, payload) {
    await page.setContent('<div id="test"></div>');
    await page.evaluate((payload) => {
      document.getElementById('test').innerHTML = payload;
    }, payload);

    return await page.evaluate(() => {
      let executed = false;
      let actions = [];

      window.alert = window.confirm = window.prompt = () => {
        executed = true;
        actions.push('dialog');
      };

      const observer = new MutationObserver(() => {
        executed = true;
        actions.push('dom_mutation');
      });
      observer.observe(document.body, { childList: true, subtree: true });

      return new Promise(resolve => {
        setTimeout(() => {
          observer.disconnect();
          resolve({ executed, actions });
        }, 1000);
      });
    });
  }

  async fuzz(iterations) {
    console.log(`Starting fuzzing process for ${iterations} iterations...`);
    const batchSize = 32;
    for (let i = 0; i < iterations; i += batchSize) {
      try {
        console.log(`Generating payloads for batch ${Math.floor(i / batchSize) + 1}...`);
        const payloads = await this.rnnAgent.generatePayloads(batchSize);
        console.log(`Testing ${payloads.length} payloads...`);

        for (const payload of payloads) {
          if (this.isValidPayload(payload)) {
            const result = await this.testPayload(payload);
            this.results.push(result);

            if (this.anomalyDetector.isAnomaly(result) || result.bypassedDOMPurify) {
              console.log(`Interesting payload found: ${payload}`);
              console.log(`Result: ${JSON.stringify(result)}`);
            }
          }
        }

        if (i % 1000 === 0 || i + batchSize >= iterations) {
          await this.saveResults();
          await this.savePayloadLog();
          console.log(`Completed ${i + batchSize} iterations...`);
        }
      } catch (batchError) {
        console.error(`Error processing batch starting at iteration ${i}:`, batchError);
      }
    }
    console.log('Fuzzing process completed.');
  }

  isValidPayload(payload) {
    return this.htmlParser.isValid(payload) && this.jsParser.isValid(payload);
  }

  async getAvailableBrowser() {
    const browser = this.browserPool.shift();
    this.browserPool.push(browser);
    return browser;
  }

  async saveResults() {
    const filename = `xss_fuzzer_results_${Date.now()}.json`;
    await fs.writeFile(filename, JSON.stringify(this.results, null, 2));
    console.log(`Results saved to ${filename}`);
  }

  async savePayloadLog() {
    const filename = `payload_log_${Date.now()}.txt`;
    await fs.writeFile(filename, this.payloadLog.join('\n'));
    console.log(`Payload log saved to ${filename}`);
  }

  async cleanup() {
    console.log('Cleaning up...');
    for (const browser of this.browserPool) {
      await browser.close();
    }
    console.log('Cleanup complete.');
  }
}

async function main() {
  const config = {
    concurrency: 4,
    iterations: 10000,
    tabCount: 3, // Number of tabs to test each payload in
    puppeteerOptions: {
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    },
    rnnConfig: {
      modelPath: path.join(__dirname, 'xss_model', 'model.json'),
      tokenizerPath: path.join(__dirname, 'tokenizer.json'),
      maxLength: 500
    },
    anomalyConfig: {
      threshold: 0.8,
      minSamples: 100,
      maxSamples: 1000
    }
  };

  const fuzzer = new XSSFuzzer(config);

  try {
    await fuzzer.initialize();
    await fuzzer.fuzz(config.iterations);
  } catch (error) {
    console.error('Error during fuzzing:', error);
  } finally {
    await fuzzer.cleanup();
  }

  console.log('Fuzzing process finished.');
}

main().catch(console.error);