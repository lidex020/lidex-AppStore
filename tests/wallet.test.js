'use strict';
/* Wallet flow tests: EIP-6963 discovery, picker, friendly errors, and the
   full wallet-signed publish path (mock provider backed by a real ethers key). */
const fs = require('fs');
const { JSDOM } = require('jsdom');
const { ethers } = require('ethers');

const html = fs.readFileSync('/home/user/lidex/index.html', 'utf8');

function makeMockWallet(name, rdns, behavior) {
  /* behavior: 'ok' | 'reject' | 'pending' */
  const wallet = ethers.Wallet.createRandom();
  const provider = {
    isMock: true,
    async request(args) {
      const { method, params } = args || {};
      if (method === 'eth_requestAccounts') {
        if (behavior === 'reject') { const e = new Error('User rejected the request'); e.code = 4001; throw e; }
        if (behavior === 'pending') { const e = new Error('already pending'); e.code = -32002; throw e; }
        return [wallet.address];
      }
      if (method === 'personal_sign') {
        let [message] = params || [];
        if (typeof message === 'string' && /^0x[0-9a-fA-F]*$/.test(message) && message.length % 2 === 0 && message.length > 2) {
          return await wallet.signMessage(ethers.utils.arrayify(message));
        }
        return await wallet.signMessage(String(message));
      }
      throw new Error('mock: method not supported ' + method);
    }
  };
  return { wallet, detail: { info: { uuid: 'uuid-' + rdns, name, icon: '', rdns }, provider } };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (c, name, extra) => { if (c) { pass++; console.log('  ✓ ' + name); } else { fail++; console.log('  ✗ FAIL: ' + name + (extra ? ' — ' + extra : '')); } };

async function freshDom(extraSetup) {
  const dom = new JSDOM(html, {
    url: 'https://lidex.test/',
    runScripts: 'dangerously', pretendToBeVisual: true,
    beforeParse(w) {
      w.WebSocket = undefined;
      if (extraSetup) extraSetup(w);
    }
  });
  await sleep(600);
  return dom;
}

(async () => {
  /* ---------- 1. no wallet at all: helpful modal, silent error ---------- */
  {
    const dom = await freshDom();
    const w = dom.window;
    let threw = null;
    try { await w.eval('Wallet.connect()'); } catch (e) { threw = e; }
    ok(threw !== null, 'connect rejects when no wallet');
    ok(threw && threw.silent === true, 'error is silent (no duplicate toast)');
    const modal = w.document.querySelector('.modal');
    ok(!!modal && modal.textContent.includes('No wallet detected'), 'no-wallet modal shown');
    ok(modal && modal.textContent.includes('local publisher key'), 'modal offers local-key fallback');
    ok(modal && modal.textContent.includes('MetaMask'), 'modal offers install links');
    const embedded = w.eval('embeddedContext()');
    ok(embedded === false, 'embeddedContext() correctly reports a top-level page as not embedded');
    dom.window.close();
  }

  /* ---------- 2. single EIP-6963 wallet: direct connect ---------- */
  {
    const mock = makeMockWallet('TestMask', 'io.testmask', 'ok');
    const dom = await freshDom(w => {
      setTimeout(() => {
        w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: mock.detail }));
      }, 50);
    });
    const w = dom.window;
    await sleep(300);
    ok(w.eval('Wallet.announced.length') === 1, 'EIP-6963 provider discovered');
    const addr = await w.eval('Wallet.connect()');
    ok(/^0x[0-9a-fA-F]{40}$/.test(addr), 'connected via announced provider: ' + addr);
    ok(w.eval('S.wallet.name') === 'TestMask', 'wallet name captured');
    ok(w.eval('Wallet.activeName') === 'TestMask', 'active provider tracked');
    dom.window.close();
  }

  /* ---------- 3. two wallets: picker, choose the second ---------- */
  {
    const m1 = makeMockWallet('AlphaMask', 'io.alpha', 'ok');
    const m2 = makeMockWallet('BetaMask', 'io.beta', 'ok');
    const dom = await freshDom(w => {
      setTimeout(() => {
        w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: m1.detail }));
        w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: m2.detail }));
      }, 50);
    });
    const w = dom.window;
    await sleep(300);
    ok(w.eval('Wallet.candidates().length') === 2, 'two candidates');
    const p = w.eval('Wallet.connect()');           /* opens picker, pending */
    await sleep(250);
    const modal = w.document.querySelector('.modal');
    ok(modal && modal.textContent.includes('Choose a wallet'), 'picker modal shown');
    ok(modal && modal.textContent.includes('AlphaMask') && modal.textContent.includes('BetaMask'), 'picker lists both wallets');
    const cards = modal.querySelectorAll('[data-pick]');
    ok(cards.length === 2, 'picker has two options');
    cards[1].click();                               /* choose BetaMask */
    const addr = await p;
    ok(/^0x[0-9a-fA-F]{40}$/.test(addr), 'connected after picking');
    ok(w.eval('S.wallet.name') === 'BetaMask', 'the picked wallet is active');
    dom.window.close();
  }

  /* ---------- 4. friendly error mapping ---------- */
  {
    const rej = makeMockWallet('RejectMask', 'io.reject', 'reject');
    const dom = await freshDom(w => setTimeout(() =>
      w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: rej.detail })), 50));
    const w = dom.window;
    await sleep(300);
    let msg = '';
    try { await w.eval('Wallet.connect()'); } catch (e) { msg = e.message; }
    ok(/rejected/i.test(msg), '4001 mapped to friendly message: ' + msg);
    dom.window.close();
  }
  {
    const pend = makeMockWallet('PendMask', 'io.pend', 'pending');
    const dom = await freshDom(w => setTimeout(() =>
      w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: pend.detail })), 50));
    const w = dom.window;
    await sleep(300);
    let msg = '';
    try { await w.eval('Wallet.connect()'); } catch (e) { msg = e.message; }
    ok(/pending/.test(msg), '-32002 mapped to friendly message: ' + msg);
    dom.window.close();
  }

  /* ---------- 5. full flow: connect → derive identity → publish wallet-signed app ---------- */
  {
    const mock = makeMockWallet('FullMask', 'io.full', 'ok');
    const dom = await freshDom(w => setTimeout(() =>
      w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: mock.detail })), 50));
    const w = dom.window;
    await sleep(300);

    const out = await w.eval(`(async () => {
      try {
        const addr = await Wallet.connect();
        const identity = await deriveIdentityFromWallet();
        const vals = {
          name: 'FullFlow App', tagline: 'Wallet-signed end to end',
          category: 'defi', chains: ['Ethereum'], tags: ['test'],
          version: '1.0.0', appUrl: 'https://fullflow.example.com',
          links: { website: '', github: '', twitter: '' },
          description: 'This app was published through the complete wallet flow: EIP-6963 discovery, connect, identity derivation via personal_sign, and a wallet-signed manifest. It validates the whole pipeline.',
          developerName: 'FullFlow Dev', developerAddress: '',
          icon: emojiTile('🚀', 0), screenshots: [], changelog: ''
        };
        const r = await doPublish(vals, null, () => {});
        return JSON.stringify({ addr, npub: identity.npub, aTag: r.aTag });
      } catch (e) { return 'ERR: ' + e.message; }
    })()`);
    const res = JSON.parse(out);
    ok(!out.startsWith('ERR:'), 'full wallet flow completed', out.slice(0, 80));
    ok(res.addr && res.addr.toLowerCase() === mock.wallet.address.toLowerCase(), 'connected to the mock wallet address');
    ok(res.npub && res.npub.startsWith('npub1'), 'identity derived from wallet signature');

    /* wait for background verification of the eth signature */
    let ethVerified = null;
    for (let i = 0; i < 20 && ethVerified === null; i++) {
      await sleep(500);
      ethVerified = w.eval('S.apps.get("' + res.aTag + '")?.verify?.eth');
    }
    ok(ethVerified === true, 'wallet signature on manifest verified in-browser (ecrecover matches)');
    const recAddr = w.eval('S.apps.get("' + res.aTag + '")?.manifest?.developer?.address');
    ok(recAddr === mock.wallet.address.toLowerCase(), 'developer address bound in manifest');

    /* app page shows the wallet-verified badge */
    w.eval('go("#/app/' + encodeURIComponent(res.aTag) + '")');
    await sleep(400);
    const body = w.document.body.textContent;
    ok(body.includes('wallet signature') && body.toLowerCase().includes('matches developer address'), 'trust panel reports matching wallet signature');
    dom.window.close();
  }

  /* ---------- 6. dedupe: same wallet announced twice ---------- */
  {
    const mock = makeMockWallet('DupeMask', 'io.dupe', 'ok');
    const dom = await freshDom(w => setTimeout(() => {
      w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: mock.detail }));
      w.dispatchEvent(new w.CustomEvent('eip6963:announceProvider', { detail: mock.detail }));
    }, 50));
    const w = dom.window;
    await sleep(300);
    ok(w.eval('Wallet.announced.length') === 1, 'duplicate announcements deduped');
    dom.window.close();
  }

  console.log('\nWALLET RESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR', e); process.exit(1); });
