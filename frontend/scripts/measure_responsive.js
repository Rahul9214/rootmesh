const cp = require('child_process');
const http = require('http');

async function sendCDP(ws, method, params = {}, id = 1) {
  return new Promise((resolve, reject) => {
    const handler = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id === id) {
        ws.removeEventListener('message', handler);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      }
    };
    ws.addEventListener('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function main() {
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const proc = cp.spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=9222',
    '--no-sandbox',
    '--disable-gpu',
    'about:blank'
  ]);

  await new Promise(r => setTimeout(r, 1200));

  try {
    const targets = await new Promise((resolve, reject) => {
      http.get('http://127.0.0.1:9222/json/list', res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => resolve(JSON.parse(data)));
      }).on('error', reject);
    });

    const pageTarget = targets.find(t => t.type === 'page') || targets[0];
    const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);

    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
    });

    let msgId = 1;
    await sendCDP(ws, 'Page.enable', {}, msgId++);
    await sendCDP(ws, 'Runtime.enable', {}, msgId++);
    await sendCDP(ws, 'DOM.enable', {}, msgId++);

    const viewports = [375, 390, 440, 768, 1280, 1920];
    const results = [];

    for (const w of viewports) {
      await sendCDP(ws, 'Emulation.setDeviceMetricsOverride', {
        width: w,
        height: 900,
        deviceScaleFactor: 1,
        mobile: w < 1024,
      }, msgId++);

      await sendCDP(ws, 'Page.navigate', { url: 'http://localhost:3025/' }, msgId++);
      // Wait for page to settle
      await new Promise(r => setTimeout(r, 1500));

      const evalRes = await sendCDP(ws, 'Runtime.evaluate', {
        expression: `(() => {
          const docWidth = document.documentElement.scrollWidth;
          const winWidth = window.innerWidth;
          const bodyWidth = document.body.scrollWidth;
          const hasOverflow = docWidth > winWidth;

          // Check if any element exceeds the viewport width
          const overflowing = [];
          document.querySelectorAll('*').forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.right > winWidth + 1) {
              overflowing.push({
                tag: el.tagName,
                id: el.id,
                className: (el.className || '').toString().slice(0, 40),
                right: Math.round(rect.right),
                excess: Math.round(rect.right - winWidth)
              });
            }
          });

          // Check main landmark and heading
          const main = !!document.querySelector('main');
          const h1 = !!document.querySelector('h1');
          const navbar = !!document.querySelector('nav');

          return {
            viewport: winWidth,
            docWidth,
            winWidth,
            bodyWidth,
            hasOverflow,
            overflowCount: overflowing.length,
            overflowSample: overflowing.slice(0, 3),
            hasMain: main,
            hasH1: h1,
            hasNavbar: navbar
          };
        })()`,
        returnByValue: true
      }, msgId++);

      results.push(evalRes.result.value);
    }

    ws.close();
    console.log(JSON.stringify(results, null, 2));
  } finally {
    proc.kill();
  }
}

main().catch(e => {
  console.error('Test error:', e);
  process.exit(1);
});
