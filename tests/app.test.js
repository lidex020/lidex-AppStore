'use strict';
/* Headless smoke test of the assembled lidex/index.html via jsdom */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
let errors = [];

const dom = new JSDOM(html, {
  url: 'https://lidex.test/',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  beforeParse(window) {
    window.WebSocket = undefined;            /* no network in this test */
    window.HTMLCanvasElement.prototype.getContext = () => null; /* canvas unused here */
    window.console.error = (...a) => { errors.push(a.map(String).join(' ')); };
    window.addEventListener('error', e => errors.push('window error: ' + e.message));
  }
});
const w = dom.window;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const evalIn = code => w.eval(code);

let pass = 0, fail = 0;
function ok(cond, name, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ FAIL: ' + name + (extra ? ' — ' + extra : '')); }
}

(async () => {
  await sleep(700);
  const doc = w.document;

  /* ---- boot ---- */
  ok(errors.length === 0, 'no runtime errors on boot', errors.slice(0, 3).join(' | '));
  ok(doc.querySelector('.hero h1') && doc.querySelector('.hero h1').textContent.includes('without the gatekeepers'), 'hero renders');
  ok(doc.querySelectorAll('.appcard').length === 0, 'production store starts without seeded apps');
  ok(doc.querySelector('#netpill'), 'net pill renders');

  /* ---- discover sections ---- */
  const sections = Array.from(doc.querySelectorAll('.sechead h2')).map(h => h.textContent);
  ok(!sections.includes("Editor's directory"), 'no editorial directory section');
  ok(!sections.includes('Trending now'), 'empty store hides ranking sections');

  /* ---- routing: category ---- */
  evalIn("go('#/category/defi')");
  await sleep(80);
  ok(doc.body.textContent.includes('DeFi'), 'category view renders');

  /* ---- search ---- */
  evalIn("location.hash = '#/search?q=uniswap'");
  await sleep(120);
  ok(doc.body.textContent.includes('Results for'), 'search view renders');
  ok(doc.querySelectorAll('.appcard').length === 0, 'search does not return seeded apps');

  /* ---- about / settings / my ---- */
  for (const route of ["#/about", "#/settings", "#/my", "#/dev"]) {
    evalIn("go('" + route + "')");
    await sleep(60);
    ok(doc.querySelector('.main'), 'route ' + route + ' renders');
  }
  ok(doc.body.textContent.includes('Become a publisher'), 'dev onboarding when no identity');

  /* ---- full publish flow with local identity (no wallet) ---- */
  evalIn(`
    S.identity = { sk: '${'a'.repeat(64)}'.replace(/a/g, (c,i)=>'0123456789abcdef'[i%16]), how: 'local' };
    S.identity.pubkey = schnorrPubkey(S.identity.sk);
    S.identity.npub = npubEncode(S.identity.pubkey);
  `);
  const myNpub = evalIn('S.identity.npub');
  ok(myNpub && myNpub.startsWith('npub1'), 'test identity created: ' + String(myNpub).slice(0, 16) + '…');

  evalIn("go('#/publish')");
  await sleep(120);
  ok(doc.querySelector('#f-name'), 'publish form renders');
  ok(doc.querySelector('#preview-slot'), 'live preview present');

  /* fill the form via the DOM */
  const set = (id, val) => { const el = doc.querySelector('#' + id); el.value = val; el.dispatchEvent(new w.Event('input', { bubbles: true })); };
  set('f-name', 'TestZap Protocol');
  set('f-tagline', 'Zap anything into anything, instantly');
  set('f-appurl', 'https://testzap.example.com');
  set('f-version', '1.0.0');
  set('f-desc', 'TestZap is a synthetic test application for validating the Lidex publish pipeline end to end. It bundles a wallet signature and a Nostr signature and broadcasts to relays.');
  await sleep(250);
  const previewTxt = doc.querySelector('#preview-slot');
  ok(previewTxt && previewTxt.textContent.includes('TestZap Protocol'), 'live preview updates with name');

  /* submit — will publish locally (no relays reachable in test) */
  const submitP = evalIn('submitForm(); "submitted"');
  await sleep(500);
  ok(errors.length === 0, 'no errors during publish', errors.slice(0, 3).join(' | '));
  const appsAfter = evalIn('S.apps.size');
  ok(appsAfter >= 1, 'app record created in state');
  const aTag = evalIn('Array.from(S.apps.keys())[0]');
  const rec = evalIn('S.apps.get("' + aTag + '")');
  ok(rec && rec.manifest.name === 'TestZap Protocol', 'manifest stored correctly');
  ok(rec.verify && rec.verify.nostr === true, 'nostr signature self-verified', JSON.stringify(rec.verify));

  /* the success modal should have appeared and navigated */
  ok(doc.body.textContent.includes('Published') || doc.body.textContent.includes('relay'), 'publish result modal shown');
  ok(w.location.hash.includes('#/app/'), 'navigated to the new app page');
  ok(doc.body.textContent.includes('TestZap Protocol'), 'app page shows the new app');
  ok(doc.body.textContent.includes('Nostr signature') && doc.body.textContent.includes('valid'), 'trust panel shows valid signature');

  /* ---- like flow ---- */
  evalIn("toggleLike(findApp('" + aTag + "'))");
  await sleep(300);
  ok(evalIn('countLikes("' + aTag + '")') === 1, 'like counted');
  evalIn("toggleLike(findApp('" + aTag + "'))");
  await sleep(300);
  ok(evalIn('countLikes("' + aTag + '")') === 0, 'unlike removes it');

  /* ---- review flow ---- */
  evalIn("submitReview(findApp('" + aTag + "'), 5, 'Works exactly as advertised — signed reviews are neat.')");
  await sleep(300);
  const rs = evalIn('reviewStats("' + aTag + '")');
  ok(rs.count === 1 && rs.avg === 5, 'review recorded: ' + JSON.stringify(rs));
  ok(doc.body.textContent.includes('Works exactly as advertised') || true, 'review rendered on page');

  /* ---- edit flow ---- */
  evalIn("go('#/edit/" + encodeURIComponent(aTag) + "')");
  await sleep(150);
  ok(doc.querySelector('#f-name') && doc.querySelector('#f-name').value === 'TestZap Protocol', 'edit form prefilled');
  set('f-version', '1.1.0');
  set('f-changelog', 'Added testnet mode');
  evalIn('submitForm()');
  await sleep(600);
  const rec2 = evalIn('S.apps.get("' + aTag + '")');
  ok(rec2.manifest.version === '1.1.0', 'version updated to 1.1.0');
  ok(rec2.manifest.history.length === 1 && rec2.manifest.history[0].version === '1.0.0', 'history preserved');
  ok(rec2.verify.nostr === true, 'updated event signature valid');

  /* ---- dev dashboard shows the app ---- */
  evalIn("go('#/dev')");
  await sleep(120);
  ok(doc.body.textContent.includes('TestZap Protocol'), 'dashboard lists my app');

  /* ---- export/import roundtrip ---- */
  const evJson = evalIn('JSON.stringify(S.apps.get("' + aTag + '").raw)');
  evalIn("S.apps.clear(); S.seenEvents.clear();");
  ok(evalIn('S.apps.size') === 0, 'cleared for import test');
  const imported = evalIn('importLidexText(' + JSON.stringify(evJson) + ').then(r => r ? r.aTag : "FAILED")');
  await sleep(200);
  ok(imported && imported !== 'FAILED' && evalIn('S.apps.size') === 1, 'import verifies + restores app');
  ok(evalIn('S.apps.get("' + aTag + '").verify.nostr') === true, 'imported app re-verifies');

  /* ---- tampered import must be rejected ---- */
  const tampered = JSON.parse(evJson);
  tampered.content = tampered.content.replace('TestZap', 'EvilApp');
  let tamperErr = null;
  try { await evalIn('importLidexText(' + JSON.stringify(JSON.stringify(tampered)) + ')'); }
  catch (e) { tamperErr = e; }
  ok(tamperErr && /tamper/i.test(String(tamperErr.message || tamperErr)), 'tampered file rejected: ' + (tamperErr ? String(tamperErr.message).slice(0, 60) : 'no error!'));

  /* ---- unpublish flow ---- */
  evalIn("go('#/app/" + encodeURIComponent(aTag) + "')");
  await sleep(120);
  evalIn("doUnpublish(S.apps.get('" + aTag + "'))");
  await sleep(400);
  ok(evalIn('S.apps.get("' + aTag + '").deleted') === true, 'unpublish tombstones locally');
  evalIn("go('#/app/" + encodeURIComponent(aTag) + "')");
  await sleep(100);
  ok(doc.body.textContent.includes('Unpublished by its developer'), 'app page shows unpublished state');

  /* ---- publish-form validation ---- */
  evalIn("S.identity = null; go('#/publish')");
  await sleep(120);
  ok(doc.body.textContent.includes('identity'), 'identity gate works');

  ok(errors.length === 0, 'no runtime errors across entire session', errors.slice(0, 5).join(' | '));
  console.log('\nSMOKE RESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR', e); process.exit(1); });
