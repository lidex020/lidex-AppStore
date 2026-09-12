/* =====================================================================
   LIDEX CORE — self-contained cryptography & protocol library
   Pure JS, zero dependencies, sync. Safe for browser + Node.
   - sha256, keccak256 (Ethereum flavor)
   - secp256k1 group ops, ECDSA public-key recovery (ecrecover)
   - BIP-340 Schnorr sign/verify (Nostr signatures)
   - bech32 (npub/nsec)
   - Nostr event id / serialization
   - Lidex manifest canonicalization + wallet-signature verification
   ===================================================================== */
'use strict';

/* ---------------- byte & hex utils ---------------- */
const CORE = {};

let _TextEncoder = null;
try { _TextEncoder = new TextEncoder(); } catch (e) { _TextEncoder = null; }
function utf8ToBytes(str) {
  if (_TextEncoder) return _TextEncoder.encode(str);
  /* pure-JS UTF-8 fallback (surrogate-pair safe) */
  const out = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.codePointAt(i);
    if (c > 0xffff) i++;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return new Uint8Array(out);
}
function bytesToHex(b) {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBytes(hex) {
  hex = hex.replace(/^0x/i, '');
  if (hex.length % 2) hex = '0' + hex;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function concatBytes() {
  let n = 0;
  for (let i = 0; i < arguments.length; i++) n += arguments[i].length;
  const out = new Uint8Array(n);
  let o = 0;
  for (let i = 0; i < arguments.length; i++) { out.set(arguments[i], o); o += arguments[i].length; }
  return out;
}
function numTo32(n) {
  return hexToBytes(n.toString(16).padStart(64, '0'));
}
function bytesToNum(b) { return BigInt('0x' + bytesToHex(b)); }
function randomHex(nBytes) {
  const b = new Uint8Array(nBytes);
  (globalThis.crypto || require('crypto')).getRandomValues(b);
  return bytesToHex(b);
}
function isValidHex(s, len) {
  return typeof s === 'string' && (len ? s.length === len : s.length % 2 === 0) && /^[0-9a-fA-F]*$/.test(s);
}

/* ---------------- SHA-256 (pure JS, sync) ---------------- */
const SHA256_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

function sha256(msg) {
  const len = msg.length;
  const bitLenHi = Math.floor(len / 0x20000000);
  const bitLenLo = (len << 3) >>> 0;
  const total = (((len + 9) + 63) >> 6) * 64;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, bitLenHi, false);
  dv.setUint32(total - 4, bitLenLo, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
      h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Int32Array(64);

  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i-15] >>> 7) | (w[i-15] << 25)) ^ ((w[i-15] >>> 18) | (w[i-15] << 14)) ^ (w[i-15] >>> 3);
      const s1 = ((w[i-2] >>> 17) | (w[i-2] << 15)) ^ ((w[i-2] >>> 19) | (w[i-2] << 13)) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  odv.setInt32(0, h0, false); odv.setInt32(4, h1, false); odv.setInt32(8, h2, false); odv.setInt32(12, h3, false);
  odv.setInt32(16, h4, false); odv.setInt32(20, h5, false); odv.setInt32(24, h6, false); odv.setInt32(28, h7, false);
  return out;
}
function sha256Hex(msg) { return bytesToHex(sha256(msg)); }

/* ---------------- Keccak-256 (Ethereum flavor) ---------------- */
const KECCAK_M64 = (1n << 64n) - 1n;
const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n];
/* rotation offsets r[x][y], flat index = x*5 + y */
const KECCAK_ROT = [0,36,3,41,18, 1,44,10,45,2, 62,6,43,15,61, 28,55,25,21,56, 27,20,39,8,14];

function rotl64(x, n) {
  if (n === 0n) return x & KECCAK_M64;
  return ((x << n) | (x >> (64n - n))) & KECCAK_M64;
}
function keccakF(A) {
  for (let round = 0; round < 24; round++) {
    const C = new Array(5), D = new Array(5);
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D[x];
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], BigInt(KECCAK_ROT[x * 5 + y]));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      const i = x + 5 * y, i1 = (x + 1) % 5 + 5 * y, i2 = (x + 2) % 5 + 5 * y;
      A[i] = B[i] ^ ((~B[i1] & KECCAK_M64) & B[i2]);
    }
    A[0] ^= KECCAK_RC[round];
  }
}
function keccak256(msg) {
  const rate = 136;
  const len = msg.length;
  const total = Math.ceil((len + 1) / rate) * rate;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[len] ^= 0x01;
  buf[total - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < total; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      const p = off + i * 8;
      for (let b = 0; b < 8; b++) lane |= BigInt(buf[p + b]) << BigInt(8 * b);
      A[i] ^= lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let b = 0; b < 32; b++) out[b] = Number((A[b >> 3] >> BigInt(8 * (b % 8))) & 0xffn);
  return out;
}
function keccak256Hex(msg) { return bytesToHex(keccak256(msg)); }

/* ---------------- secp256k1 group operations ---------------- */
const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP_G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
                0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n, 1n];

function modP(a) { a %= SECP_P; return a < 0n ? a + SECP_P : a; }
function modN(a) { a %= SECP_N; return a < 0n ? a + SECP_N : a; }
function invMod(a, m) {
  a = a % m; if (a < 0n) a += m;
  let x0 = 1n, x1 = 0n;
  let aa = a, bb = m;
  while (bb !== 0n) {
    const q = aa / bb;
    let t = aa - q * bb; aa = bb; bb = t;
    t = x0 - q * x1; x0 = x1; x1 = t;
  }
  if (aa !== 1n) return null; /* not invertible */
  return ((x0 % m) + m) % m;
}
function powMod(base, exp, m) {
  if (m === 1n) return 0n;
  let result = 1n;
  base %= m; if (base < 0n) base += m;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % m;
    base = base * base % m;
    exp >>= 1n;
  }
  return result;
}
/* Jacobian points: [X, Y, Z], null = point at infinity */
function jacDouble(p) {
  if (!p) return null;
  const X = p[0], Y = p[1], Z = p[2];
  if (Y === 0n) return null;
  const Y2 = Y * Y % SECP_P;
  const S = 4n * X % SECP_P * Y2 % SECP_P;
  const M = 3n * X % SECP_P * X % SECP_P;
  const X3 = modP(M * M % SECP_P - 2n * S);
  const Y3 = modP(M * (S - X3) % SECP_P - 8n * Y2 % SECP_P * Y2 % SECP_P);
  const Z3 = modP(2n * Y * Z);
  return [X3, Y3, Z3];
}
function jacAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  const X1 = p[0], Y1 = p[1], Z1 = p[2], X2 = q[0], Y2 = q[1], Z2 = q[2];
  const Z1Z1 = Z1 * Z1 % SECP_P, Z2Z2 = Z2 * Z2 % SECP_P;
  const U1 = X1 * Z2Z2 % SECP_P, U2 = X2 * Z1Z1 % SECP_P;
  const S1 = Y1 * Z2 % SECP_P * Z2Z2 % SECP_P, S2 = Y2 * Z1 % SECP_P * Z1Z1 % SECP_P;
  if (modP(U2 - U1) === 0n) {
    if (modP(S2 - S1) !== 0n) return null;
    return jacDouble(p);
  }
  const H = modP(U2 - U1);
  const HH = H * H % SECP_P;
  const I = 4n * HH % SECP_P;
  const J = H * I % SECP_P;
  const r = modP(2n * (S2 - S1));
  const V = U1 * I % SECP_P;
  const X3 = modP(r * r % SECP_P - J - 2n * V);
  const Y3 = modP(r * (V - X3) % SECP_P - 2n * S1 % SECP_P * J % SECP_P);
  const W = modP((Z1 + Z2) * (Z1 + Z2) % SECP_P - Z1Z1 - Z2Z2);
  const Z3 = modP(W * H);
  return [X3, Y3, Z3];
}
function jacMul(k, p) {
  k = modN(k);
  if (k === 0n) return null;
  let R = null, Q = p;
  while (k > 0n) {
    if (k & 1n) R = jacAdd(R, Q);
    Q = jacDouble(Q);
    k >>= 1n;
  }
  return R;
}
function jacToAffine(p) {
  if (!p) return null;
  const zi = invMod(p[2], SECP_P);
  if (zi === null) return null;
  const zi2 = zi * zi % SECP_P;
  return [p[0] * zi2 % SECP_P, p[1] * zi2 % SECP_P * zi % SECP_P];
}
function liftX(x) {
  if (x <= 0n || x >= SECP_P) return null;
  const ySq = modP(x * x % SECP_P * x + 7n);
  const y = powMod(ySq, (SECP_P + 1n) / 4n, SECP_P);
  if (y * y % SECP_P !== ySq) return null;
  if (y === 0n) return null;
  return [x, y % 2n === 0n ? y : SECP_P - y]; /* even-y */
}
function pointNeg(p) { return p ? [p[0], modP(-p[1]), p[2]] : null; }

/* ECDSA public key recovery (Ethereum ecrecover) */
function ecrecover(msgHash32, r, s, v) {
  let recId = Number(v);
  if (recId >= 27) recId -= 27;
  if (!(recId >= 0 && recId <= 3)) return null;
  if (!(r > 0n && r < SECP_P && s > 0n && s < SECP_N)) return null;
  const x = recId >> 1 ? r + SECP_N : r;
  if (x >= SECP_P) return null;
  const ySq = modP(x * x % SECP_P * x + 7n);
  let y = powMod(ySq, (SECP_P + 1n) / 4n, SECP_P);
  if (y * y % SECP_P !== ySq) return null;
  const yIsEven = y % 2n === 0n;
  if (yIsEven !== (recId % 2 === 0)) y = SECP_P - y;
  const R = [x, y, 1n];
  const e = bytesToNum(msgHash32) % SECP_N;
  const eG = jacMul(modN(SECP_N - e), SECP_G);
  const sR = jacMul(s, R);
  const Q = jacAdd(sR, eG);
  if (!Q) return null;
  const rInv = invMod(r % SECP_N, SECP_N);
  if (rInv === null) return null;
  const Qa = jacToAffine(jacMul(rInv, Q));
  if (!Qa) return null;
  const pub = concatBytes(numTo32(Qa[0]), numTo32(Qa[1]));
  return keccak256(pub).slice(12);
}

/* ---------------- BIP-340 Schnorr (Nostr) ---------------- */
function taggedHash(tag, msg) {
  const th = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(th, th, msg));
}
function schnorrPubkey(skHex) {
  const d = BigInt('0x' + skHex);
  if (!(d > 0n && d < SECP_N)) throw new Error('invalid secret key');
  const Pa = jacToAffine(jacMul(d, SECP_G));
  return bytesToHex(numTo32(Pa[0]));
}
function schnorrSign(skHex, msg32, aux32) {
  const d = BigInt('0x' + skHex);
  if (!(d > 0n && d < SECP_N)) throw new Error('invalid secret key');
  const Pa = jacToAffine(jacMul(d, SECP_G));
  const dEven = Pa[1] % 2n === 0n ? d : SECP_N - d;
  const px = numTo32(Pa[0]);
  /* t = d' XOR int(tagged_hash("BIP0340/aux", aux)); aux defaults to all zeros */
  const t = dEven ^ bytesToNum(taggedHash('BIP0340/aux', aux32 || new Uint8Array(32)));
  const rand = taggedHash('BIP0340/nonce', concatBytes(numTo32(t), px, msg32));
  let k = bytesToNum(rand) % SECP_N;
  if (k === 0n) throw new Error('nonce failure');
  const Ra = jacToAffine(jacMul(k, SECP_G));
  if (Ra[1] % 2n === 1n) k = SECP_N - k;
  const e = bytesToNum(taggedHash('BIP0340/challenge', concatBytes(numTo32(Ra[0]), px, msg32))) % SECP_N;
  const sig = new Uint8Array(64);
  sig.set(numTo32(Ra[0]));
  sig.set(numTo32(modN(k + e * dEven)), 32);
  return sig;
}
function schnorrVerify(pubXHex, msg32, sig64) {
  try {
    if (typeof pubXHex !== 'string' || pubXHex.length !== 64) return false;
    const px = BigInt('0x' + pubXHex);
    if (!(px > 0n && px < SECP_P)) return false;
    if (!sig64 || sig64.length !== 64) return false;
    const rx = bytesToNum(sig64.slice(0, 32));
    const s = bytesToNum(sig64.slice(32));
    if (!(rx > 0n && rx < SECP_P && s > 0n && s < SECP_N)) return false;
    const Pxy = liftX(px);
    if (!Pxy) return false;
    const P = [Pxy[0], Pxy[1], 1n];
    const e = bytesToNum(taggedHash('BIP0340/challenge', concatBytes(sig64.slice(0, 32), numTo32(px), msg32))) % SECP_N;
    const R = jacAdd(jacMul(s, SECP_G), jacMul(modN(SECP_N - e), P));
    if (!R) return false;
    const Ra = jacToAffine(R);
    if (!Ra) return false;
    if (Ra[1] % 2n !== 0n) return false;
    return Ra[0] === rx;
  } catch (e) { return false; }
}

/* ---------------- bech32 (npub / nsec) ---------------- */
const B32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const B32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function bech32Polymod(values) {
  let chk = 1;
  for (let i = 0; i < values.length; i++) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ values[i];
    for (let j = 0; j < 5; j++) if ((b >> j) & 1) chk ^= B32_GEN[j];
  }
  return chk;
}
function bech32HrpExpand(hrp) {
  const r = [];
  for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) >> 5);
  r.push(0);
  for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) & 31);
  return r;
}
function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    if (v < 0 || (v >> from) !== 0) return null;
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}
function bech32Encode(hrp, data5) {
  const values = bech32HrpExpand(hrp).concat(data5, [0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ 1;
  let out = hrp + '1';
  for (let i = 0; i < data5.length; i++) out += B32_ALPHABET[data5[i]];
  for (let i = 0; i < 6; i++) out += B32_ALPHABET[(polymod >> (5 * (5 - i))) & 31];
  return out;
}
function bech32Decode(str) {
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) return null;
  str = str.toLowerCase();
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 7 > str.length || str.length > 90) return null;
  const hrp = str.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < str.length; i++) {
    const d = B32_ALPHABET.indexOf(str[i]);
    if (d === -1) return null;
    data.push(d);
  }
  if (bech32Polymod(bech32HrpExpand(hrp).concat(data)) !== 1) return null;
  return { hrp, data: data.slice(0, data.length - 6) };
}
function npubEncode(pubHex) { return bech32Encode('npub', convertBits(hexToBytes(pubHex), 8, 5, true)); }
function nsecEncode(skHex) { return bech32Encode('nsec', convertBits(hexToBytes(skHex), 8, 5, true)); }
function decodeNsec(str) {
  const dec = bech32Decode(str);
  if (!dec || dec.hrp !== 'nsec') return null;
  const bytes = convertBits(dec.data, 5, 8, false);
  if (!bytes || bytes.length !== 32) return null;
  const sk = bytesToHex(bytes);
  return BigInt('0x' + sk) > 0n && BigInt('0x' + sk) < SECP_N ? sk : null;
}

/* ---------------- Nostr events ---------------- */
function computeEventId(ev) {
  return sha256Hex(utf8ToBytes(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content])));
}
function signNostrEvent(skHex, ev) {
  ev.id = computeEventId(ev);
  ev.sig = bytesToHex(schnorrSign(skHex, hexToBytes(ev.id)));
  return ev;
}
function verifyNostrEvent(ev) {
  try {
    if (!ev || typeof ev !== 'object') return false;
    if (!isValidHex(ev.pubkey, 64) || !isValidHex(ev.id, 64) || !isValidHex(ev.sig, 128)) return false;
    if (typeof ev.created_at !== 'number' || typeof ev.kind !== 'number') return false;
    if (!Array.isArray(ev.tags) || typeof ev.content !== 'string') return false;
    if (computeEventId(ev) !== ev.id) return false;
    return schnorrVerify(ev.pubkey, hexToBytes(ev.id), hexToBytes(ev.sig));
  } catch (e) { return false; }
}

/* ---------------- Lidex identity & manifest protocol ---------------- */
const LIDEX_SPEC = 'lidex.app/manifest@1';
const LIDEX_KIND_APP = 30078;       /* NIP-78 parameterized replaceable app data */
const LIDEX_KIND_REVIEW = 1;
const LIDEX_KIND_LIKE = 7;
const LIDEX_KIND_DELETE = 5;
const LIDEX_TAG = 'lidex';

function deriveNostrSecret(sigHex, counter) {
  counter = counter || 0;
  for (;;) {
    const h = sha256Hex(utf8ToBytes('lidex/identity/v1/' + counter + '/' + sigHex.toLowerCase()));
    const d = BigInt('0x' + h);
    if (d > 0n && d < SECP_N) return h;
    counter++;
  }
}
function identityMessage(address) {
  return 'Lidex — create your publisher identity\n\n' +
    'Wallet: ' + address.toLowerCase() + '\n\n' +
    'This is a free signature — not a transaction, no gas, nothing is spent.\n' +
    'It deterministically derives your Lidex publisher key (Nostr) that lets\n' +
    'you publish and update apps on the permissionless Lidex network.';
}
/* canonical core manifest — FIXED key order is part of the protocol */
function buildManifestCore(m) {
  return {
    spec: LIDEX_SPEC,
    name: String(m.name || ''),
    tagline: String(m.tagline || ''),
    description: String(m.description || ''),
    category: String(m.category || 'other'),
    tags: (Array.isArray(m.tags) ? m.tags : []).map(String).slice(0, 8),
    chains: (Array.isArray(m.chains) ? m.chains : []).map(String).slice(0, 12),
    version: String(m.version || '1.0.0'),
    appUrl: String(m.appUrl || ''),
    links: {
      website: String((m.links && m.links.website) || ''),
      github: String((m.links && m.links.github) || ''),
      twitter: String((m.links && m.links.twitter) || '')
    },
    icon: String(m.icon || ''),
    screenshots: (Array.isArray(m.screenshots) ? m.screenshots : []).map(String).slice(0, 6),
    developer: {
      name: String((m.developer && m.developer.name) || 'Anonymous'),
      address: String((m.developer && m.developer.address) || '')
    },
    createdAt: Number(m.createdAt) || 0,
    updatedAt: Number(m.updatedAt) || 0,
    history: (Array.isArray(m.history) ? m.history : []).slice(-40)
  };
}
function manifestHashHex(core) {
  return keccak256Hex(utf8ToBytes(JSON.stringify(core)));
}
/* message handed to the wallet for personal_sign: the raw 32-byte manifest hash */
function ethSignMessageForManifest(core) {
  return '0x' + manifestHashHex(core);
}
/* verify wallet signature over a manifest; returns recovered address or null */
function recoverManifestSigner(contentObj) {
  try {
    if (!contentObj || !contentObj.eth || !contentObj.eth.sig) return null;
    const core = buildManifestCore(contentObj);
    if (contentObj.eth.msgHash !== manifestHashHex(core)) return null;
    const sig = hexToBytes(contentObj.eth.sig);
    if (sig.length !== 65) return null;
    let v = sig[64];
    if (v < 27) v += 27;
    const r = bytesToNum(sig.slice(0, 32));
    const s = bytesToNum(sig.slice(32, 64));
    const recoveryHash = keccak256(concatBytes(utf8ToBytes('\u0019Ethereum Signed Message:\n32'), hexToBytes(contentObj.eth.msgHash)));
    const addr = ecrecover(recoveryHash, r, s, v);
    return addr ? '0x' + bytesToHex(addr) : null;
  } catch (e) { return null; }
}
function eventToAppRecord(ev) {
  /* parse a kind 30078 event into a Lidex app record */
  try {
    const d = (ev.tags.find(t => t[0] === 'd') || [])[1];
    if (!d) return null;
    const aTag = LIDEX_KIND_APP + ':' + ev.pubkey + ':' + d;
    let content = null, deleted = false;
    try { content = JSON.parse(ev.content); } catch (e) { return null; }
    if (!content || typeof content !== 'object') return null;
    if (content.deleted) deleted = true;
    const core = buildManifestCore(content);
    if (!deleted && (!core.name || !core.appUrl)) return null;
    return {
      aTag: aTag,
      d: d,
      pubkey: ev.pubkey,
      eventId: ev.id,
      createdAt: ev.created_at,
      deleted: deleted,
      manifest: core,
      eth: deleted ? null : (content.eth || null),
      raw: ev
    };
  } catch (e) { return null; }
}

/* exports (Node tests) / namespace (browser) */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    utf8ToBytes, bytesToHex, hexToBytes, concatBytes, numTo32, bytesToNum, randomHex, isValidHex,
    sha256, sha256Hex, keccak256, keccak256Hex,
    SECP_P, SECP_N, SECP_G, modP, modN, invMod, powMod, jacDouble, jacAdd, jacMul, jacToAffine, liftX,
    ecrecover, taggedHash, schnorrPubkey, schnorrSign, schnorrVerify,
    bech32Encode, bech32Decode, convertBits, npubEncode, nsecEncode, decodeNsec,
    computeEventId, signNostrEvent, verifyNostrEvent,
    LIDEX_SPEC, LIDEX_KIND_APP, LIDEX_KIND_REVIEW, LIDEX_KIND_LIKE, LIDEX_KIND_DELETE, LIDEX_TAG,
    deriveNostrSecret, identityMessage, buildManifestCore, manifestHashHex,
    ethSignMessageForManifest, recoverManifestSigner, eventToAppRecord
  };
}
