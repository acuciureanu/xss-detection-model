const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { PayloadGenerator } = require('./payload_generator');

if (isMainThread) {
  const numWorkers = require('os').cpus().length - 1;
  const payloadCount = 1000000;
  const payloadsPerWorker = Math.ceil(payloadCount / numWorkers);
  const workers = [];

  for (let i = 0; i < numWorkers; i++) {
    workers.push(new Promise((resolve, reject) => {
      const worker = new Worker(__filename, {
        workerData: { payloadsPerWorker }
      });
      worker.on('message', resolve);
      worker.on('error', reject);
      worker.on('exit', code => {
        if (code !== 0)
          reject(new Error(`Worker stopped with exit code ${code}`));
      });
    }));
  }

  Promise.all(workers).then(results => {
    const combinedResults = results.flat();
    console.log('\nFinal Results:');
    console.log('Top 10 interesting payloads:');
    combinedResults.sort((a, b) => (b.alertTriggered - a.alertTriggered) || (b.bypassed - a.bypassed))
      .slice(0, 10)
      .forEach((result, index) => {
        console.log(`${index + 1}. Original: ${result.original}`);
        console.log(`   Sanitized: ${result.sanitized}`);
        console.log(`   Bypassed: ${result.bypassed}`);
        console.log(`   Alert Triggered: ${result.alertTriggered}\n`);
      });

    // Analysis of results
    const totalPayloads = combinedResults.length;
    const bypassedCount = combinedResults.filter(r => r.bypassed).length;
    const alertTriggeredCount = combinedResults.filter(r => r.alertTriggered).length;

    console.log('\nAnalysis:');
    console.log(`Total unique payloads tested: ${totalPayloads}`);
    console.log(`Payloads that bypassed sanitization: ${bypassedCount} (${(bypassedCount / totalPayloads * 100).toFixed(2)}%)`);
    console.log(`Payloads that triggered alerts: ${alertTriggeredCount} (${(alertTriggeredCount / totalPayloads * 100).toFixed(2)}%)`);
  }).catch(err => {
    console.error(err);
  });
} else {
  const config = {
    payloadCount: workerData.payloadsPerWorker,
    maxPayloadLength: 200,
  };

  async function runFuzzer(config) {
    const generator = new PayloadGenerator(config);
    const results = await generator.fuzz(config.payloadCount);
    return results;
  }

  runFuzzer(config).then(results => {
    parentPort.postMessage(results);
  }).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
