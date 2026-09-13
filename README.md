# Lidex — the permissionless app store for web3

**Discover and publish web3 apps. No gatekeepers, no fees, no backend, no database.**
The entire product is a single self-contained HTML file: `index.html` (~184 KB, zero dependencies, zero build step).

```
┌──────────────────────────────────────────────────────────────────────┐
│  USER BROWSER (everything happens here)                              │
│                                                                      │
│   Connect wallet ──personal_sign (free)──▶ publisher key (Nostr)     │
│   App listing   ──keccak256 + wallet sig + BIP-340 sig──▶ event      │
│   Reviews/likes ──signed Nostr notes/reactions──▶ events             │
│                                                                      │
│   Discovery  ◀── REQ {kinds:[30078,1,7,5], #l:[lidex…]} ──┐         │
│   Verify    ── every signature checked in-browser ────────┤         │
└───────────────────────────────────────────────────────────┼─────────┘
                                                            ▼
                              PUBLIC NOSTR RELAYS (open, federated infra
                              anyone can run — not "our backend")
```

## Quick start

- **Hosted:** serve this folder statically (`python3 -m http.server 8080`) and open it — or just open `index.html` directly in your browser. It works from `file://` too.
- **As a user:** browse, search, pin apps, read/write reviews and likes.
- **As a developer:** Connect wallet → sign one free message (creates your publisher key) → fill the publish form → done. Your listing is live on the network instantly.

> In sandboxed embedded previews (no network, no storage) the app shows an empty production store and an ephemeral-state warning. Open it as a normal page for the full experience.

## How "no backend, no database" is possible

| Concern | Lidex answer |
|---|---|
| Accounts | Your wallet (or a local/imported Nostr key). `sha256(wallet signature)` deterministically derives your publisher key. |
| Publishing | An app **manifest** (name, tagline, description, links, icon, screenshots, version, history) hashed with keccak256 and signed via `personal_sign` — free, no transaction. |
| Storage | The signed manifest is the content of a **Nostr event** (kind 30078, NIP-78) broadcast to public relays. Relays are open infrastructure, not owned by Lidex. |
| Updates | Re-publish with the same `d` tag (parameterized replaceable event). Only the original publisher key can replace it. Version history is embedded. |
| Unpublish | Tombstone event + NIP-09 deletion broadcast. |
| Reviews / likes | Signed Nostr notes (kind 1) and reactions (kind 7) with `l` tags `lidex-review` / `lidex-like`. |
| Trust | Every client verifies every signature locally: BIP-340 Schnorr for Nostr, ECDSA public-key recovery (ecrecover) for wallet signatures. App pages show a **Trust panel** with the computed results. |
| Offline | Local-first: IndexedDB (→ localStorage → memory fallback) caches events so the store renders instantly and works offline. |

## Protocol (interoperable by design)

```
App listing     kind 30078   tags: d=<id>, l=lidex, name, category, t…, addr
Review          kind 1       tags: l=lidex-review, a=30078:<pubkey>:<d>   content: {app, rating, text}
Like            kind 7       tags: l=lidex-like, a=…, e=<listing event>
Deletion        kind 5       NIP-09 (a-tag for listings, e-tag for own likes/reviews)
Manifest sig    EIP-191 personal_sign over keccak256(canonical manifest)
Identity        sha256("lidex/identity/v1/<count>/<wallet-sig>") → Nostr secret key
```

The canonical manifest key order (part of the signature) is defined in `core.js → buildManifestCore()`.

## Files

- `index.html` — the whole app (HTML + CSS + hand-rolled crypto + UI). Host anywhere static; IPFS-friendly.
- `core.js` — the cryptography/protocol core, inlined into `index.html`; kept standalone so it can be tested against reference libraries.
- `tests/` — three suites (see below).

## Brand

The visual identity follows the Lidex logo: green-black base (`#060a08`), emerald accent ramp (`#00e08a → #00a55c`, hue ~153°), mint highlights, and a cyan secondary drawn from the logo's edge glow. The logo itself is embedded three times as optimized data URIs (64px PNG favicon, 128px WebP topbar mark, 384px WebP hero glyph with a radial fade mask) — the file stays fully self-contained.

## Tests (all passing)

```bash
cd tests && npm install
npx node core.test.js    # 104 checks — sha256/keccak vs @noble, BIP-340 vs official vectors (8/8 sign, 19/19 verify),
                         # ecrecover vs ethers, bech32/nip19 vs nostr-tools, tamper detection
npx node app.test.js     # 45 checks — headless (jsdom) full product loop: boot, discover, search, publish,
                         # verify, like, review, update+history, dashboard, export/import, tamper-reject, unpublish
npx node wallet.test.js  # 25 checks — EIP-6963 wallet discovery, multi-wallet picker, friendly error mapping,
                         # and the complete wallet-signed publish flow (mock wallet backed by a real key)
npx node e2e.test.js     # 10 checks — LIVE: publishes a signed listing to real relays (damus/nos.lol/primal),
                         # boots a blind client, confirms discovery + in-browser verification, then cleans up
```

### Wallet support

Any EVM wallet works: discovered via **EIP-6963** (the modern multi-wallet standard) with a legacy `window.ethereum` fallback, and a picker when several wallets are installed. Inside embedded preview frames — where browsers block wallet injection entirely — Lidex shows clear guidance (open in a new tab / install links) plus a no-wallet **local publisher key** path so publishing always works. Wallet errors are humanized: rejections, already-pending requests, and locked wallets each get a plain-language message.

Layout was additionally verified headlessly (desktop 1440px & mobile 390px: no overflow, responsive nav, live search, card/detail/publish flows, zero page errors).

## Honest limitations

- Relay events are capped around 64 KB → screenshots/icons are compressed client-side to fit.
- Permissionless means permissionless: anyone can publish anything; trust comes from signatures (verified badges), reviews, and your own judgment — never from a server.
- Deletion is best-effort (NIP-09 + replaceable tombstone); archives may retain copies.
- Reviews/likes are tied to Nostr keys and are public by design (like the rest of Nostr).
- Discover contains only signed listings published to the network. There are no built-in apps, editorial entries, or seeded ratings.

## Roadmap ideas

NIP-50 relay-side search · ENS/name display for publishers · curated feed tag (`l=lidex-featured`) · optional IPFS pinning of big screenshots via NIP-96 · categories as tags for community curation · WASM-optimized crypto (current BigInt crypto verifies ~100 events/sec, fine for now).
