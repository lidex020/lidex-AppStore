'use strict';
const assert = require('assert');
const path = require('path');
const C = require(path.join(__dirname, '..', 'core.js'));
const { schnorr } = require('@noble/curves/secp256k1.js');

let pass = 0, fail = 0;
function ok(cond, name) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ FAIL: ' + name); }
}

(async () => {
  console.log('— hash vectors —');
  ok(C.sha256Hex(C.utf8ToBytes('')) === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256("")');
  ok(C.sha256Hex(C.utf8ToBytes('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'sha256("abc")');
  ok(C.keccak256Hex(C.utf8ToBytes('')) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', 'keccak256("")');
  // vector from Solidity docs: keccak256("testing")
  const { createHash } = require('crypto');
  // Node has no keccak; use ethers for cross-check below.

  console.log('— bech32 / nip19 vs nostr-tools —');
  const { nip19 } = require('nostr-tools');
  for (let i = 0; i < 5; i++) {
    const pub = C.randomHex(32);
    ok(C.npubEncode(pub) === nip19.npubEncode(pub), 'npub encode #' + i);
    const sk = C.randomHex(32);
    ok(C.nsecEncode(sk) === nip19.nsecEncode(C.hexToBytes(sk)), 'nsec encode #' + i);
    ok(C.decodeNsec(nip19.nsecEncode(C.hexToBytes(sk))) === sk, 'nsec decode #' + i);
  }
  const nip19vec = { sec: '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa' };
  ok(C.nsecEncode(nip19vec.sec) === 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5', 'nsec NIP-19 spec vector');
  const pubOf = C.schnorrPubkey(nip19vec.sec);
  const noblePubOf = Buffer.from(await schnorr.getPublicKey(C.hexToBytes(nip19vec.sec))).toString('hex');
  ok(pubOf === noblePubOf, 'pubkey derivation matches noble (nip19 secret)');
  ok(C.npubEncode(pubOf) === nip19.npubEncode(pubOf), 'npub of derived pubkey matches nostr-tools');

  console.log('— schnorr vs @noble/curves —');
  for (let i = 0; i < 8; i++) {
    const sk = C.randomHex(32);
    const msg = C.randomHex(32);
    const myPub = C.schnorrPubkey(sk);
    const noblePub = Buffer.from(await schnorr.getPublicKey(C.hexToBytes(sk))).toString('hex');
    ok(myPub === noblePub, 'pubkey #' + i);
    const aux = new Uint8Array(32);
    const mySig = Buffer.from(C.schnorrSign(sk, C.hexToBytes(msg))).toString('hex');
    const nobleSig = Buffer.from(await schnorr.sign(C.hexToBytes(msg), C.hexToBytes(sk), aux)).toString('hex');
    ok(mySig === nobleSig, 'deterministic sig (aux=0) #' + i);
    ok(C.schnorrVerify(myPub, C.hexToBytes(msg), C.hexToBytes(nobleSig)), 'verify noble sig #' + i);
  }
  // official BIP340 vector 0
  const v0 = {
    seckey: '0000000000000000000000000000000000000000000000000000000000000003',
    pubkey: 'F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9',
    aux: '00'.repeat(32), msg: '00'.repeat(32),
    sig: 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'
  };
  ok(C.schnorrPubkey(v0.seckey) === v0.pubkey.toLowerCase(), 'BIP340 vector 0 pubkey');
  ok(Buffer.from(C.schnorrSign(v0.seckey, C.hexToBytes(v0.msg))).toString('hex').toUpperCase() === v0.sig, 'BIP340 vector 0 signature');
  ok(C.schnorrVerify(v0.pubkey.toLowerCase(), C.hexToBytes(v0.msg), C.hexToBytes(v0.sig)), 'BIP340 vector 0 verify');

  console.log('— ecrecover vs ethers v5 —');
  const { ethers } = require('ethers');
  const { keccak_256 } = require('@noble/hashes/sha3');
  // noble keccak vs mine
  for (let i = 0; i < 5; i++) {
    const data = C.hexToBytes(C.randomHex(64 + i * 7));
    ok(C.keccak256Hex(data) === Buffer.from(keccak_256(data)).toString('hex'), 'keccak vs noble #' + i);
  }
  // larger inputs crossing the rate boundary (136-byte blocks)
  for (const len of [135, 136, 137, 1000, 10000, 60000]) {
    const data = C.hexToBytes(C.randomHex(len));
    ok(C.keccak256Hex(data) === Buffer.from(keccak_256(data)).toString('hex'), 'keccak vs noble len=' + len);
  }
  for (let i = 0; i < 8; i++) {
    const wallet = ethers.Wallet.createRandom();
    const hash32 = C.randomHex(32);
    // wallet signs the raw 32-byte hash as a binary message (personal_sign semantics)
    const flat = await wallet.signMessage(ethers.utils.arrayify('0x' + hash32));
    const sig = ethers.utils.splitSignature(flat);
    const recoveryHash = C.keccak256(C.concatBytes(
      C.utf8ToBytes('\u0019Ethereum Signed Message:\n32'), C.hexToBytes(hash32)));
    const addr = C.ecrecover(recoveryHash, BigInt(sig.r), BigInt(sig.s), sig.v);
    ok(addr && '0x' + C.bytesToHex(addr).toLowerCase() === wallet.address.toLowerCase(), 'ecrecover address #' + i);
    // also verify via the manifest protocol path
    const core = C.buildManifestCore({
      name: 'Test App ' + i, appUrl: 'https://example.com', version: '1.0.0',
      description: 'x'.repeat(1000), createdAt: 1234567890, updatedAt: 1234567890
    });
    const msgHash = C.manifestHashHex(core);
    const ethSig = await wallet.signMessage(ethers.utils.arrayify('0x' + msgHash));
    const recovered = C.recoverManifestSigner({ ...core, eth: { address: wallet.address, msgHash, sig: ethSig } });
    ok(recovered === wallet.address.toLowerCase(), 'manifest eth-sig verify #' + i);
    // tamper test
    const tampered = { ...core, name: 'Evil' };
    ok(C.recoverManifestSigner({ ...tampered, eth: { address: wallet.address, msgHash, sig: ethSig } }) === null, 'tamper detection #' + i);
  }

  console.log('— nostr event vs nostr-tools —');
  const { validateEvent, verifyEvent, finalizeEvent } = require('nostr-tools');
  for (let i = 0; i < 5; i++) {
    const sk = C.randomHex(32);
    const ev = {
      pubkey: C.schnorrPubkey(sk),
      created_at: 1700000000 + i,
      kind: 30078,
      tags: [['d', 'test-app-' + i], ['l', 'lidex-selftest'], ['name', 'Test'], ['alt', 'test']],
      content: JSON.stringify({ spec: C.LIDEX_SPEC, name: 'Test ' + i, appUrl: 'https://example.com', version: '1.0.0', description: 'd', createdAt: 1, updatedAt: 1, tags: [], chains: [], links: { website: '', github: '', twitter: '' }, icon: '', screenshots: [], developer: { name: 't', address: '' }, history: [] })
    };
    C.signNostrEvent(sk, ev);
    ok(validateEvent(ev) && verifyEvent(ev), 'nostr-tools accepts my event #' + i);
    // and I accept nostr-tools' signatures
    const ev2 = finalizeEvent({
      created_at: 1700000100, kind: 1, tags: [['l', 'x']], content: 'hello'
    }, C.hexToBytes(sk));
    ok(C.verifyNostrEvent(ev2), 'I verify nostr-tools event #' + i);
    ok(C.computeEventId(ev2) === ev2.id, 'event id matches nostr-tools #' + i);
    // event → app record roundtrip
    const rec = C.eventToAppRecord(ev);
    ok(rec && rec.manifest.name === 'Test ' + i && rec.aTag === '30078:' + ev.pubkey + ':test-app-' + i, 'eventToAppRecord #' + i);
  }

  console.log('— identity derivation —');
  const fakeSig = '0x' + C.randomHex(65);
  const sk1 = C.deriveNostrSecret(fakeSig);
  const sk2 = C.deriveNostrSecret(fakeSig);
  ok(sk1 === sk2 && sk1.length === 64, 'deterministic identity derivation');

  console.log('\nRESULT: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
