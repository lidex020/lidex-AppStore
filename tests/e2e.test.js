'use strict';
/* E2E: publish a Lidex app event to REAL relays, then boot the real app in
   jsdom with real WebSockets and confirm it discovers + verifies the app. */
const fs = require('fs');
const path = require('path');
const C = require(path.join(__dirname, '..', 'core.js'));
const WS = require('ws');
const { JSDOM } = require('jsdom');

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'];
const D = 'e2e-' + C.randomHex(4);
const sk = C.randomHex(32);
const pubkey = C.schnorrPubkey(sk);
const aTag = '30078:' + pubkey + ':' + D;
const APP_NAME = 'Lidex E2E ' + D.slice(5);

function send(url, event, wantId) {
  return new Promise(res => {
    let ws; try { ws = new WS(url); } catch (e) { return res(null); }
    const t = setTimeout(() => { try { ws.close(); } catch (e) {} res(null); }, 10000);
    ws.on('open', () => ws.send(JSON.stringify(['EVENT', event])));
    ws.on('message', data => {
      try {
        const f = JSON.parse(data.toString());
        if (f[0] === 'OK' && f[1] === wantId) { clearTimeout(t); try { ws.close(); } catch (e) {} res(f[2] === true); }
      } catch (e) {}
    });
    ws.on('error', () => { clearTimeout(t); res(null); });
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  /* ---- 1. publish (simulating the publisher's Lidex client) ---- */
  const manifest = {
    spec: C.LIDEX_SPEC, name: APP_NAME, tagline: 'End-to-end test of the Lidex pipeline',
    description: 'This listing was published by an automated end-to-end test to prove that the Lidex app store discovers and verifies signed listings from public Nostr relays with zero backend. It will be unpublished shortly.',
    category: 'tools', tags: ['test'], chains: ['Ethereum'], version: '1.0.0',
    appUrl: 'https://example.com/lidex-e2e', links: { website: '', github: '', twitter: '' },
    icon: '', screenshots: [], developer: { name: 'E2E Bot', address: '' },
    createdAt: Math.floor(Date.now() / 1000), updatedAt: Math.floor(Date.now() / 1000), history: []
  };
  const ev = {
    pubkey, created_at: Math.floor(Date.now() / 1000), kind: 30078,
    tags: [['d', D], ['l', 'lidex'], ['alt', 'Lidex app listing: ' + APP_NAME],
           ['name', APP_NAME], ['category', 'tools'], ['client', 'lidex'], ['t', 'test']],
    content: JSON.stringify(manifest)
  };
  C.signNostrEvent(sk, ev);
  console.log('publishing', APP_NAME, 'as', C.npubEncode(pubkey).slice(0, 20) + '…');
  const results = [];
  for (const url of RELAYS) results.push({ url, ok: await send(url, ev, ev.id) });
  results.forEach(r => console.log('  ' + (r.ok ? '✓' : '✗') + ' ' + r.url));
  if (!results.some(r => r.ok)) { console.log('E2E: could not publish to any relay — aborting'); process.exit(1); }

  /* also publish a like + a review, signed with the same test key */
  const like = { pubkey, created_at: Math.floor(Date.now() / 1000), kind: 7,
    tags: [['a', aTag], ['e', ev.id], ['p', pubkey], ['l', 'lidex-like'], ['client', 'lidex']], content: '+' };
  C.signNostrEvent(sk, like);
  for (const url of RELAYS) await send(url, like, like.id);
  const review = { pubkey, created_at: Math.floor(Date.now() / 1000), kind: 1,
    tags: [['a', aTag], ['p', pubkey], ['l', 'lidex-review'], ['client', 'lidex'], ['alt', 'Lidex review: 5 stars']],
    content: JSON.stringify({ app: aTag, rating: 5, text: 'E2E: the pipeline works — this review arrived over relays.' }) };
  C.signNostrEvent(sk, review);
  for (const url of RELAYS) await send(url, review, review.id);
  console.log('published app + like + review; waiting 6s for propagation…');
  await sleep(6000);

  /* ---- 2. boot the real app (simulating the discoverer's Lidex client) ---- */
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const errors = [];
  const dom = new JSDOM(html, {
    url: 'https://lidex.test/discover.html',
    runScripts: 'dangerously', pretendToBeVisual: true,
    beforeParse(w) {
      w.WebSocket = WS;               /* real network sockets */
      w.addEventListener('error', e => errors.push(e.message));
    }
  });
  const w = dom.window;
  let pass = 0, fail = 0;
  const ok = (c, name, extra) => { if (c) { pass++; console.log('  ✓ ' + name); } else { fail++; console.log('  ✗ FAIL: ' + name + (extra ? ' — ' + extra : '')); } };

  console.log('booting real app with live relays…');
  const deadline = Date.now() + 40000;
  let found = false;
  while (Date.now() < deadline && !found) {
    await sleep(1500);
    found = w.eval('!!S.apps.get("' + aTag + '")');
  }
  ok(found, 'app discovered from relays');
  if (found) {
    const rec = JSON.parse(w.eval('JSON.stringify(S.apps.get("' + aTag + '"))'));
    ok(rec.manifest.name === APP_NAME, 'manifest intact', rec.manifest.name);
    ok(rec.manifest.appUrl === 'https://example.com/lidex-e2e', 'appUrl intact');
    /* wait for background verification */
    let verified = false;
    const vDeadline = Date.now() + 15000;
    while (Date.now() < vDeadline && !verified) {
      await sleep(1000);
      verified = w.eval('S.apps.get("' + aTag + '")?.verify?.nostr') === true;
    }
    ok(verified, 'nostr signature verified in-browser');
    /* likes & reviews */
    let likes = 0;
    const lDeadline = Date.now() + 10000;
    while (Date.now() < lDeadline && likes === 0) { await sleep(1000); likes = w.eval('countLikes("' + aTag + '")'); }
    ok(likes >= 1, 'like discovered (' + likes + ')');
    let revs = 0;
    const rDeadline = Date.now() + 10000;
    while (Date.now() < rDeadline && revs === 0) { await sleep(1000); revs = w.eval('reviewStats("' + aTag + '").count'); }
    ok(revs >= 1, 'review discovered (' + revs + ')');
    /* open the app page in the client */
    w.eval('go("#/app/' + encodeURIComponent(aTag) + '")');
    await sleep(400);
    const body = w.document.body.textContent;
    ok(body.includes(APP_NAME), 'app page renders the listing');
    ok(body.includes('valid'), 'trust panel shows signature valid');
    ok(body.includes('the pipeline works'), 'review text rendered');
  }
  ok(errors.length === 0, 'no runtime errors in live client', errors.slice(0, 3).join('|'));

  /* ---- 3. cleanup: tombstone + deletion ---- */
  const tomb = { pubkey, created_at: Math.floor(Date.now() / 1000), kind: 30078,
    tags: [['d', D], ['l', 'lidex'], ['alt', 'removed'], ['client', 'lidex']],
    content: JSON.stringify({ spec: C.LIDEX_SPEC, name: APP_NAME, deleted: true, deletedAt: Math.floor(Date.now() / 1000) }) };
  C.signNostrEvent(sk, tomb);
  const del = { pubkey, created_at: Math.floor(Date.now() / 1000), kind: 5,
    tags: [['a', aTag], ['e', ev.id], ['l', 'lidex'], ['client', 'lidex']], content: 'e2e cleanup' };
  C.signNostrEvent(sk, del);
  for (const url of RELAYS) { await send(url, tomb, tomb.id); await send(url, del, del.id); }
  console.log('cleanup broadcast (tombstone + NIP-09 deletion)');
  console.log('\nE2E RESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR', e); process.exit(1); });
