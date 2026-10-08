// README screenshots: opens the browser preview (the real interface with the
// example assessments from fixtures/) and saves each main screen to
// docs/screenshots/.
//
// Needs `npm run build` and the preview data
// (`cargo run -p dca-core --bin preview-data`). Set CHROMIUM_PATH to use a
// Chromium other than the one `npx playwright-core install chromium` fetched.
//
// Usage: node tests/screenshots.mjs

import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { chromium } from 'playwright-core';

const PORT = 4181;
const BASE = `http://localhost:${PORT}/`;
const OUT = new URL('../../docs/screenshots/', import.meta.url).pathname;
mkdirSync(OUT, { recursive: true });

const server = spawn('npx', ['vite', 'preview', '--port', String(PORT), '--strictPort'], { stdio: 'ignore' });
process.on('exit', () => server.kill());
for (let i = 0; ; i++) {
  try {
    if ((await fetch(BASE)).ok) break;
  } catch {}
  if (i > 100) throw new Error('vite preview did not start');
  await new Promise((r) => setTimeout(r, 200));
}

const launch = { args: ['--no-sandbox'] };
if (process.env.CHROMIUM_PATH) launch.executablePath = process.env.CHROMIUM_PATH;
const browser = await chromium.launch(launch);

async function shoot(page, name, css = '') {
  // No hover tooltips, and no folder path of the machine taking the shots.
  await page.mouse.move(720, 2);
  const style = await page.addStyleTag({ content: `footer .mono { visibility: hidden; } ${css}` });
  await page.waitForTimeout(600);
  await page.screenshot({ path: `${OUT}${name}.png` });
  await style.evaluate((e) => e.remove());
  console.log(`saved ${name}.png`);
}

async function open(theme) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: theme });
  await page.addInitScript((t) => localStorage.setItem('dca-theme', t), theme);
  await page.goto(BASE);
  await page.getByRole('heading', { name: 'Recent assessments' }).waitFor();
  return page;
}

async function assessment(page) {
  await page.goto(BASE);
  await page.locator('button.run').first().click();
  const nav = page.getByRole('navigation', { name: 'Assessment' });
  await nav.waitFor();
  return nav;
}

try {
  const page = await open('light');
  await page.getByRole('button', { name: 'New assessment' }).click();
  await shoot(page, 'new-assessment');

  const nav = await assessment(page);
  await shoot(page, 'dashboard');
  const go = (name) => nav.locator('button.rbtn').filter({ has: page.locator('*') }).and(nav.locator(`[aria-label^="${name}"]`)).first().click();
  await go('Findings');
  await shoot(page, 'findings');
  await page.locator('main table tbody tr').first().click();
  await shoot(page, 'finding-detail');
  await go('Attack paths');
  await shoot(page, 'attack-paths');
  await go('Relationship graph');
  await shoot(page, 'relationship-graph');
  await go('Directory');
  await shoot(page, 'directory');
  await go('Account ages');
  await shoot(page, 'account-ages');
  await go('Compliance');
  await shoot(page, 'compliance');
  await go('Compare and combine');
  await shoot(page, 'compare');
  await go('Dashboard');
  await page.getByRole('button', { name: 'Export report', exact: true }).click();
  // The preview's note that export runs only in the desktop app.
  await shoot(page, 'export', 'footer.actionbar > span.muted { visibility: hidden !important; }');
  await page.close();

  const dark = await open('dark');
  await assessment(dark);
  await shoot(dark, 'dashboard-dark');
  await dark.close();
} finally {
  await browser.close();
  server.kill();
}
