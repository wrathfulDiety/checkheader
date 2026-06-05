# checkHEADer

**Paste raw HTTP response headers → get a standardised, report-ready security observation.**
Built for web/API penetration-test reporting. 100% client-side — the data you paste never leaves the browser.

**▶ Live demo:** https://wrathfuldiety.github.io/checkheader/

---

## What it does

Classifies each response header as **missing / misconfigured / OK** and generates copy-paste observation prose across four tabs:

- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Cache-Control, X-XSS-Protection
- **Cookies & Session** — Secure / HttpOnly / SameSite attributes
- **Information Disclosure** — Server / X-Powered-By / version banners / charset
- **Additional Hardening** — Referrer-Policy, Permissions-Policy, COOP / COEP / CORP

Toggle **Web ⇄ API** to switch the wording. Each tab produces a report-ready paragraph plus severity-rated detail.

## Privacy

- No backend, no API, no telemetry — all analysis runs in your browser.
- The built site ships a `Content-Security-Policy` with **`connect-src 'none'`**: the page is *forbidden* from making any outbound network request.
- Verify it yourself: open DevTools → **Network** → paste headers → **zero requests**.

## Run locally

```bash
npm install
npm run dev
```

## Build

```bash
npm run build          # static site -> dist/  (auto-deployed to GitHub Pages)
npm run build:single   # one self-contained file -> dist-single/index.html  (offline / email)
```

## Use the engine in your own tool

The analysis engine is framework-agnostic — no React, no DOM, no network — so it imports cleanly into any reporting tool:

```js
import { analyze, formatSecurityObservation } from './src/lib/headerAnalysis.js'

const result = analyze(rawHeaderText)
console.log(formatSecurityObservation(result.security, 'web')) // or 'api'
```

## License

MIT © [wrathfuldiety](https://github.com/wrathfuldiety)
