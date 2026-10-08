// Accessibility check: opens every screen of the browser preview (example
// assessments from fixtures/, see vite.config.ts) in light and dark themes
// and runs axe-core against WCAG 2.1 A and AA. Fails on any violation.
//
// Needs `npm run build` and the preview data
// (`cargo run -p dca-core --bin preview-data`). Set CHROMIUM_PATH to use a
// Chromium other than the one `npx playwright-core install chromium` fetched.
//
// Usage: node tests/a11y.mjs

import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { chromium } from 'playwright-core';

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const PORT = 4179;
const BASE = `http://localhost:${PORT}/`;

const server = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], { stdio: 'ignore' });
const stop = () => server.kill();
process.on('exit', stop);

async function waitForServer() {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(BASE)).ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('vite preview did not start');
}

const results = [];
async function audit(page, name) {
  await page.waitForTimeout(300);
  await page.evaluate(axeSource);
  const r = await page.evaluate(() =>
    // eslint-disable-next-line no-undef
    axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } }),
  );
  results.push({ name, violations: r.violations });
}

await waitForServer();
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  for (const theme of ['light', 'dark']) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: theme });
    // Light is the default; dark is a saved choice (lib/theme.ts).
    await page.addInitScript((t) => localStorage.setItem('dca-theme', t), theme);
    const at = (n) => `${theme} · ${n}`;
    await page.goto(BASE);
    await page.getByRole('heading', { name: 'Recent assessments' }).waitFor();
    await audit(page, at('Start'));

    await page.getByRole('button', { name: 'Settings' }).click();
    await audit(page, at('Settings'));
    await page.goto(BASE);

    await page.getByRole('button', { name: 'New assessment' }).click();
    await audit(page, at('New assessment'));
    await page.goto(BASE);

    await page.locator('button.run').first().click();
    const nav = page.getByRole('navigation', { name: 'Assessment' });
    await nav.waitFor();
    await audit(page, at('Dashboard'));
    await page.getByRole('button', { name: 'Export report', exact: true }).click();
    await audit(page, at('Export'));
    await page.getByRole('button', { name: 'Results', exact: true }).click();
    await nav.waitFor();
    const labels = await nav.locator('button.rbtn').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')));
    for (const name of labels) {
      // Home and Settings leave the assessment; they are audited above.
      if (name === 'Home' || name === 'Settings') continue;
      await nav.getByRole('button', { name, exact: true }).click();
      await audit(page, at(name));
      if (name.startsWith('Findings')) {
        await page.locator('main table tbody tr').first().click();
        await audit(page, at('Finding detail'));
      }
      if (name === 'Directory') {
        await page.locator('main table tbody tr').first().click();
        await audit(page, at('Object detail'));
      }
    }
    await page.close();
  }
} finally {
  await browser.close();
  stop();
}

let total = 0;
for (const { name, violations } of results) {
  for (const v of violations) {
    total += v.nodes.length;
    console.error(`${name}: [${v.impact}] ${v.id}: ${v.help} (${v.nodes.length})`);
    for (const n of v.nodes.slice(0, 3)) console.error(`    ${n.target.join(' ')}  ${n.failureSummary?.split('\n')[1]?.trim() ?? ''}`);
  }
}
console.log(`${results.length} screens checked, ${total} accessibility problems`);
process.exit(total ? 1 : 0);
