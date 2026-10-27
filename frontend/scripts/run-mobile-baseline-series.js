/**
 * RootMesh — Step 3BP.1: Automated 5-Run Mobile Lighthouse Audit Series
 * Executes five consecutive mobile Lighthouse audits under strictly controlled, identical conditions
 * against the standalone production server on port 3025.
 */
const cp = require('child_process');
const fs = require('fs');
const path = require('path');

const URL = 'http://localhost:3025/';
const RUNS = 5;

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function runLighthouse(runIndex, prefix = 'lighthouse-mobile-baseline') {
  const outputPath = path.resolve(__dirname, '..', `${prefix}-${runIndex}.json`);
  console.log(`\n======================================================`);
  console.log(`[Run ${runIndex}/${RUNS}] Starting Mobile Lighthouse audit...`);
  console.log(`Target: ${URL}`);
  console.log(`Output: ${outputPath}`);
  console.log(`======================================================`);

  const cmd = `npx lighthouse ${URL} --output=json --output-path=${outputPath} --chrome-flags="--headless=new --no-sandbox"`;

  return new Promise((resolve, reject) => {
    const start = Date.now();
    const proc = cp.exec(cmd, { cwd: path.resolve(__dirname, '..'), maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      if (err) {
        console.error(`[Run ${runIndex}] Lighthouse failed after ${elapsed}s:`, err.message);
        return reject(err);
      }
      console.log(`[Run ${runIndex}] Completed in ${elapsed}s`);
      resolve(outputPath);
    });
  });
}

function parseReport(filePath) {
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const cats = raw.categories;
  const audits = raw.audits;

  const perfScore = Math.round((cats.performance?.score || 0) * 100);
  const a11yScore = Math.round((cats.accessibility?.score || 0) * 100);
  const bpScore = Math.round((cats['best-practices']?.score || 0) * 100);
  const seoScore = Math.round((cats.seo?.score || 0) * 100);

  const fcp = audits['first-contentful-paint']?.numericValue || 0;
  const lcp = audits['largest-contentful-paint']?.numericValue || 0;
  const tbt = audits['total-blocking-time']?.numericValue || 0;
  const cls = audits['cumulative-layout-shift']?.numericValue || 0;
  const si = audits['speed-index']?.numericValue || 0;
  const tti = audits['interactive']?.numericValue || 0;
  const mainThreadTime = audits['mainthread-work-breakdown']?.numericValue || 0;
  const totalByteWeight = audits['total-byte-weight']?.numericValue || 0;

  // Best practices failures
  const bpFailures = [];
  for (const [k, v] of Object.entries(audits)) {
    if (cats['best-practices']?.auditRefs?.some(r => r.id === k) && v.score !== null && v.score < 1) {
      bpFailures.push({ id: k, title: v.title, explanation: v.explanation || v.displayValue });
    }
  }

  // Diagnostics and long tasks
  const longTasks = audits['long-tasks']?.details?.items?.length || 0;

  return {
    perfScore,
    a11yScore,
    bpScore,
    seoScore,
    fcp: Math.round(fcp),
    lcp: Math.round(lcp),
    tbt: Math.round(tbt),
    cls: Number(cls.toFixed(3)),
    si: Math.round(si),
    tti: Math.round(tti),
    mainThreadTime: Math.round(mainThreadTime),
    totalByteWeight: Math.round(totalByteWeight / 1024),
    longTasks,
    bpFailures,
  };
}

async function main() {
  const prefix = process.argv[2] || 'lighthouse-mobile-baseline';
  const results = [];

  for (let i = 1; i <= RUNS; i++) {
    const reportFile = await runLighthouse(i, prefix);
    const parsed = parseReport(reportFile);
    results.push({ run: i, ...parsed });
    console.log(`[Run ${i} Summary] Perf: ${parsed.perfScore} | A11y: ${parsed.a11yScore} | BP: ${parsed.bpScore} | SEO: ${parsed.seoScore} | FCP: ${parsed.fcp}ms | LCP: ${parsed.lcp}ms | TBT: ${parsed.tbt}ms | CLS: ${parsed.cls} | TTI: ${parsed.tti}ms`);
    // Brief pause between runs for CPU cooling / GC
    await new Promise(r => setTimeout(r, 2000));
  }

  console.log(`\n======================================================`);
  console.log(`ALL ${RUNS} RUNS COMPLETED — SUMMARY TABLE:`);
  console.log(`======================================================`);
  console.table(results.map(r => ({
    Run: r.run,
    Perf: r.perfScore,
    A11y: r.a11yScore,
    BP: r.bpScore,
    SEO: r.seoScore,
    'FCP (s)': (r.fcp / 1000).toFixed(2),
    'LCP (s)': (r.lcp / 1000).toFixed(2),
    'TBT (ms)': r.tbt,
    CLS: r.cls,
    'TTI (s)': (r.tti / 1000).toFixed(2),
    'MainThread (ms)': r.mainThreadTime,
    'JS/Bytes (kB)': r.totalByteWeight,
  })));

  const medians = {
    perfScore: median(results.map(r => r.perfScore)),
    a11yScore: median(results.map(r => r.a11yScore)),
    bpScore: median(results.map(r => r.bpScore)),
    seoScore: median(results.map(r => r.seoScore)),
    fcp: median(results.map(r => r.fcp)),
    lcp: median(results.map(r => r.lcp)),
    tbt: median(results.map(r => r.tbt)),
    cls: median(results.map(r => r.cls)),
    si: median(results.map(r => r.si)),
    tti: median(results.map(r => r.tti)),
    mainThreadTime: median(results.map(r => r.mainThreadTime)),
    totalByteWeight: median(results.map(r => r.totalByteWeight)),
  };

  console.log('\nMEDIAN RESULTS:');
  console.log(`- Performance: ${medians.perfScore}`);
  console.log(`- Accessibility: ${medians.a11yScore}`);
  console.log(`- Best Practices: ${medians.bpScore}`);
  console.log(`- SEO: ${medians.seoScore}`);
  console.log(`- FCP: ${(medians.fcp / 1000).toFixed(2)}s`);
  console.log(`- LCP: ${(medians.lcp / 1000).toFixed(2)}s`);
  console.log(`- TBT: ${medians.tbt}ms`);
  console.log(`- CLS: ${medians.cls}`);
  console.log(`- Speed Index: ${(medians.si / 1000).toFixed(2)}s`);
  console.log(`- TTI: ${(medians.tti / 1000).toFixed(2)}s`);
  console.log(`- Main Thread: ${medians.mainThreadTime}ms`);

  const summaryFile = path.resolve(__dirname, '..', `${prefix}-summary.json`);
  fs.writeFileSync(summaryFile, JSON.stringify({ results, medians }, null, 2));
  console.log(`Saved summary to: ${summaryFile}`);
}

main().catch(err => {
  console.error('Audit runner error:', err);
  process.exit(1);
});
