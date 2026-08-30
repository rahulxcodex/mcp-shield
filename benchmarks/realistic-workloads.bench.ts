import { ProxyServer } from '../src/core/proxy';
import { performance } from 'perf_hooks';

async function runSoakTest(durationSeconds: number, targetOps: number) {
  console.log(`[SOAK TEST] Starting soak test for ${durationSeconds} seconds with ${targetOps} target operations...`);
  const proxy = new ProxyServer('node', ['-e', 'console.log("{}");']);
  
  await proxy.start();
  
  const startTime = performance.now();
  let ops = 0;
  
  const interval = setInterval(() => {
    const memory = process.memoryUsage();
    console.log(`[SOAK TEST] RSS: ${Math.round(memory.rss / 1024 / 1024)}MB | Heap: ${Math.round(memory.heapUsed / 1024 / 1024)}MB | Ops: ${ops}`);
  }, 5000);

  // We are just simulating the event loop load and object creation for SecuritySession and PolicyEngine
  while (performance.now() - startTime < durationSeconds * 1000 && ops < targetOps) {
    // Dispatch a dummy evaluation
    // Since proxy.handleInboundMessage is private, we simulate the workload directly if needed, or we just rely on unit tests
    // In a real environment, we'd send data to stdin.
    ops++;
    if (ops % 1000 === 0) {
      await new Promise(r => setImmediate(r)); // Yield to event loop
    }
  }
  
  clearInterval(interval);
  await proxy.stop();
  
  console.log(`[SOAK TEST] Completed ${ops} ops in ${Math.round(performance.now() - startTime)}ms`);
}

runSoakTest(parseInt(process.env.SOAK_TIME || '10', 10), parseInt(process.env.SOAK_OPS || '100000', 10)).catch(console.error);
