// Full-page captures of the dashboards the Splunkbase listing images are cut
// from.
//
// These are a SECOND set, not the gallery's. The gallery wants a viewport-sized
// card per page; tools/make_listing_shots.sh wants the whole scrolled page,
// because it crops regions that sit thousands of pixels down, the container
// chain on Exposure and the weakness-to-technique panel on ATT&CK among them.
// Keeping one set for both is what broke the listing images: the gallery was
// recaptured at 1600x1000 on 2026-09-03, every crop below y=1000 silently
// became a blank 348-byte file, and nothing said so.
//
//   RK_BASE=http://127.0.0.1:8000/share/<prefix> RK_PW=... node tools/capture_full_pages.js
//
// Output goes to docs/screenshots-full/, which is gitignored: it is an
// intermediate for the listing assets, not repository content.
process.env.LD_LIBRARY_PATH = '/opt/code/tools/browser/sysdeps/extracted/usr/lib/x86_64-linux-gnu';
const { chromium } = require('/opt/code/tools/browser/node_modules/playwright');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'docs', 'screenshots-full');
const BASE = process.env.RK_BASE || 'http://127.0.0.1:8000/en-US';
const USER = process.env.RK_USER || 'admin';
const PW = process.env.RK_PW;

// Only the pages make_listing_shots.sh cuts from.
const PAGES = [
  ['riskability_exposure', 'exposure'],
  ['riskability_overview', 'fleet-overview'],
  ['riskability_findings', 'findings'],
  ['riskability_mitre', 'mitre-attack'],
  ['riskability_coverage', 'coverage'],
  ['riskability_hosts', 'hosts'],
  ['riskability_admin', 'feed-administration'],
];

const stamp = () => new Date().toISOString().slice(11, 19);

(async () => {
  if (!PW) { console.error('set RK_PW'); process.exit(2); }
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
  const page = await ctx.newPage();
  await page.goto(BASE + '/account/login', { waitUntil: 'domcontentloaded', timeout: 120000 });
  await page.waitForTimeout(2000);
  await page.fill('#username', USER);
  await page.fill('#password', PW);
  await page.press('#password', 'Enter');
  await page.waitForTimeout(9000);

  for (const [view, name] of PAGES) {
    await page.goto(BASE + '/app/riskability/' + view, { waitUntil: 'domcontentloaded', timeout: 200000 }).catch(() => {});
    // Panels below the fold do not dispatch until they are scrolled to, so a
    // full-page shot taken without scrolling captures spinners.
    await page.waitForTimeout(20000);
    await page.evaluate(async () => {
      const step = window.innerHeight;
      for (let y = 0; y < document.body.scrollHeight; y += step) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 900));
      }
      window.scrollTo(0, 0);
    });
    await page.waitForTimeout(15000);
    const file = path.join(OUT, name + '.png');
    await page.screenshot({ path: file, fullPage: true });
    // Dimensions straight out of the PNG header (IHDR at byte 16), rather than
    // shelling out to read them.
    const head = fs.readFileSync(file).subarray(16, 24);
    console.log(`${stamp()} ${name.padEnd(22)} ${head.readUInt32BE(0)}x${head.readUInt32BE(4)}`);
  }
  await browser.close();
})().catch((e) => { console.error('FATAL ' + e.message); process.exit(1); });
