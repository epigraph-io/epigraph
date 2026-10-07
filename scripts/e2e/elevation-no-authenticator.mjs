// The browser half of `probe-elevation-no-authenticator.sh` (elevation plan
// EL-14; DESIGN §10 check 7, "the no-authenticator ceremony fails").
//
//   node elevation-no-authenticator.mjs <ceremony page URL> <arm>
//
// Opens the REAL ceremony page (`/elevate/<ticket>`, or `/elevate/act/<id>`)
// in headless Chromium, clicks Confirm, and waits for the page's own status
// line. Arms:
//
//   empty   a virtual platform authenticator (user verification capable)
//           holding NO credential: the browser has an authenticator but no
//           passkey of the ticket's person, so `navigator.credentials.get`
//           rejects (NotAllowedError) and the page must say "Not elevated:"
//           (or "Not confirmed:") and post nothing to `/assert`.
//   none    no authenticator at all (no virtual authenticator attached):
//           the request can only time out or be refused; the page must end in
//           the same "Not ..." state within the wait (`NOAUTH_WAIT_MS`,
//           default 330000: past the ceremony's own WebAuthn timeout).
//
// Prints one JSON line {arm, status, asserted} and exits 0 when the page
// failed closed (status starts "Not "), 1 otherwise. `asserted` counts the
// requests the page sent to `/assert`; it must be 0. Whether the TICKET stayed
// unconfirmed is the shell script's check, read from the database.
//
// Needs Node 18+ and the `playwright` package with Chromium installed
// (`npx playwright install chromium`). Nothing here holds a credential.

import { chromium } from 'playwright';

const [url, arm = 'empty'] = process.argv.slice(2);
if (!url || !['empty', 'none'].includes(arm)) {
  console.error('usage: node elevation-no-authenticator.mjs <ceremony page URL> <empty|none>');
  process.exit(2);
}

const browser = await chromium.launch();
let failedClosed = false;
let status = '';
let asserted = 0;
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on('request', (r) => {
    if (r.method() === 'POST' && new URL(r.url()).pathname.endsWith('/assert')) {
      asserted += 1;
    }
  });
  if (arm === 'empty') {
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    });
  }
  const resp = await page.goto(url);
  if (!resp || !resp.ok()) {
    throw new Error(`the ceremony page answered ${resp ? resp.status() : 'nothing'}`);
  }
  await page.click('#confirm');
  await page.waitForFunction(
    () => /^Not /.test(document.getElementById('status')?.textContent || ''),
    null,
    { timeout: Number(process.env.NOAUTH_WAIT_MS || 330_000) },
  );
  status = await page.textContent('#status');
  failedClosed = /^Not /.test(status || '') && asserted === 0;
} catch (e) {
  status = `probe error: ${e && e.message ? e.message : String(e)}`;
} finally {
  await browser.close();
}
console.log(JSON.stringify({ arm, status, asserted }));
process.exit(failedClosed ? 0 : 1);
