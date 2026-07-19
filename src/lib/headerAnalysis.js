/* ============================================================================
 * checkHEADer — header analysis engine
 * ----------------------------------------------------------------------------
 * Pure, framework-agnostic. No React, no DOM, no network. Safe to import into
 * any JS/TS project (e.g. a reporting tool) and drive headlessly:
 *
 *     import { analyze, formatSecurityObservation } from './headerAnalysis.js'
 *     const result = analyze(rawHeaderText)
 *     const prose  = formatSecurityObservation(result.security, 'web')
 *
 * Every finding carries BOTH a `web` and an `api` observation string, written
 * in a neutral, professional report register. The caller picks the voice at render time;
 * switching voice never requires re-analysis.
 * ========================================================================== */

export const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS'];

/* ---------------------------------------------------------------- parsing -- */

/**
 * Parse a raw block of response headers (Burp / curl -I / dev-tools paste).
 * Returns a lowercase-keyed map plus the raw Set-Cookie lines kept separate
 * (Set-Cookie must never be comma-joined — Expires contains commas).
 */
export function parseHeaders(raw) {
  const headers = {};
  const setCookies = [];
  const lines = String(raw || '').split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t) continue;
    if (/^HTTP\/\d/i.test(t)) continue;            // status line
    const idx = line.indexOf(':');
    if (idx < 1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (!name) continue;
    if (name === 'set-cookie') { setCookies.push(val); continue; }
    headers[name] = name in headers ? headers[name] + ', ' + val : val;
  }
  return { headers, setCookies };
}

/* -------------------------------------------------------------- utilities -- */

export function listPhrase(arr) {
  const a = arr.filter(Boolean);
  if (a.length === 0) return '';
  if (a.length === 1) return a[0];
  if (a.length === 2) return a[0] + ' and ' + a[1];
  return a.slice(0, -1).join(', ') + ', and ' + a[a.length - 1];
}

function clip(s, n = 240) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function finding(o) {
  return {
    key: o.key, label: o.label, state: o.state, severity: o.severity,
    evidence: o.evidence || '', web: o.web || '', api: o.api || '',
  };
}

/* ===========================================================================
 * SEVERITY POLICY
 *
 * A response-header check observes configuration only — it cannot demonstrate
 * impact. Missing or weak security headers are defence-in-depth controls whose
 * risk is realised only when chained with a separately-proven exploit (e.g. a
 * missing CSP matters only where an injection already exists). Rating such
 * standalone findings HIGH/MEDIUM over-states them and is routinely rejected by
 * triage. This tool therefore caps ratings accordingly:
 *   - Missing / weak security header (CSP, HSTS, X-Frame-Options, X-Content-
 *     Type-Options, Cache-Control)  -> LOW  (ceiling; no exploit is asserted)
 *   - Pure version / technology disclosure (Server, X-Powered-By, ASP.NET, charset) -> INFO
 *   - Deprecated header (X-XSS-Protection) and defence-in-depth extras (COOP/COEP/CORP) -> INFO
 * Consumers who have demonstrated a chained exploit should escalate manually in
 * their report; the scanner does not do it for them.
 * ======================================================================== */

/* ===========================================================================
 * TAB 1 — SECURITY HEADERS  (core security header set)
 * ======================================================================== */

function analyzeCSP(h) {
  const label = 'Content-Security-Policy';
  let val = h['content-security-policy'];
  let reportOnly = false;
  if (!val && h['content-security-policy-report-only']) {
    val = h['content-security-policy-report-only'];
    reportOnly = true;
  }
  if (!val) {
    return finding({
      key: 'csp', label, state: 'missing', severity: 'LOW',
      evidence: 'Header not present in response',
      web: "The application does not implement a Content-Security-Policy (CSP) header in the HTTP response. As a result, the browser is not provided with granular control over permitted sources and does not align with best practice security standards.",
      api: "The API does not implement a Content-Security-Policy (CSP) header in the HTTP response. As a result, no granular control is enforced over the sources permitted to interact with the response, and the configuration does not align with best practice security standards.",
    });
  }

  const ro = reportOnly ? ' (delivered in report-only mode and therefore not enforced)' : '';
  const low = val.toLowerCase();
  const dirs = val.split(';').map(d => d.trim()).filter(Boolean);
  const dirNames = dirs.map(d => d.split(/\s+/)[0].toLowerCase());
  const defaultSrc = dirs.find(d => /^default-src\b/i.test(d));
  const fa = dirs.find(d => /^frame-ancestors\b/i.test(d));

  const perm = [];
  if (low.includes('unsafe-inline')) perm.push("'unsafe-inline'");
  if (low.includes('unsafe-eval')) perm.push("'unsafe-eval'");
  if (/(^|[\s;])data:/.test(low)) perm.push('data:');
  if (/(^|[\s;])blob:/.test(low)) perm.push('blob:');
  const hasWildcard = /(^|\s)\*([\s;]|$)/.test(val);
  const domains = val.match(/(?:[a-z0-9-]+\.)+[a-z]{2,}/gi) || [];
  const manyDomains = new Set(domains.map(d => d.toLowerCase())).size >= 3;

  // overly permissive
  if (perm.length || hasWildcard) {
    const items = perm.slice();
    if (hasWildcard && !items.length) items.push("the wildcard '*' source");
    const phrase = listPhrase(items);
    const extra = manyDomains
      ? ' Additionally, a large number of external domains are allowed for scripts, images, styles, frames, and connections.'
      : '';
    return finding({
      key: 'csp', label, state: 'misconfigured', severity: 'LOW', evidence: clip(val),
      web: `The application implements a Content-Security-Policy header${ro}; however, it is configured with overly permissive directives such as ${phrase}.${extra} As a result, the header does not provide granular control over permitted sources and does not align with best practice security standards.`,
      api: `The API implements a Content-Security-Policy header${ro}; however, it is configured with overly permissive directives such as ${phrase}.${extra} As a result, the header does not provide granular control over permitted sources and does not align with best practice security standards.`,
    });
  }

  // limited to frame-ancestors only
  const meaningful = dirNames.filter(d => !['upgrade-insecure-requests', 'block-all-mixed-content', ''].includes(d));
  if (fa && meaningful.length && meaningful.every(d => d === 'frame-ancestors')) {
    const faVal = fa.replace(/^frame-ancestors\s*/i, '').trim();
    return finding({
      key: 'csp', label, state: 'misconfigured', severity: 'LOW', evidence: clip(val),
      web: `The application implements a limited Content-Security-Policy header${ro} restricted to frame-ancestors ${faVal}. While this provides protection against framing, the policy does not define source restrictions for scripts, styles, images, or network connections. As a result, the browser is not provided with granular control over permitted resources, and the configuration does not fully align with best practice security standards.`,
      api: `The API implements a limited Content-Security-Policy header${ro} restricted to frame-ancestors ${faVal}. While this provides protection against framing, the policy does not define source restrictions for scripts, styles, images, or network connections. As a result, no granular control is enforced over permitted resources, and the configuration does not fully align with best practice security standards.`,
    });
  }

  // present but missing granular directives
  const granular = ['script-src', 'connect-src', 'img-src', 'style-src'];
  const missing = granular.filter(g => !dirNames.includes(g));
  if (missing.length) {
    const ds = defaultSrc ? ` (default-src ${defaultSrc.replace(/^default-src\s*/i, '').trim()})` : '';
    const missList = listPhrase(missing);
    return finding({
      key: 'csp', label, state: 'misconfigured', severity: 'LOW', evidence: clip(val),
      web: `The application implements a Content-Security-Policy header${ro}${ds}; however, it does not define granular directives (${missList}) for permitted sources such as scripts, connections, images, and styles. As a result, the browser is not provided with granular control over these resource types and the configuration does not fully align with best practice security standards.`,
      api: `The API implements a Content-Security-Policy header${ro}${ds}; however, it does not define granular directives (${missList}) for permitted sources such as scripts, connections, images, and styles. As a result, no granular control is enforced over these resource types and the configuration does not fully align with best practice security standards.`,
    });
  }

  // report-only but otherwise complete is still worth flagging
  if (reportOnly) {
    return finding({
      key: 'csp', label, state: 'misconfigured', severity: 'LOW', evidence: clip(val),
      web: `The application defines a Content-Security-Policy but delivers it through the Content-Security-Policy-Report-Only header. As a result, violations are only reported and the policy is not enforced by the browser.`,
      api: `The API defines a Content-Security-Policy but delivers it through the Content-Security-Policy-Report-Only header. As a result, the policy is not enforced.`,
    });
  }

  return finding({ key: 'csp', label, state: 'ok', severity: 'PASS', evidence: clip(val) });
}

/**
 * X-XSS-Protection assessment for the Additional Hardening tab.
 *
 * The header is deprecated: modern browsers have removed the reflected-XSS
 * auditor it controlled, and setting '1' (without mode=block) can itself
 * introduce vulnerabilities in legacy engines. It is therefore surfaced as an
 * informational/defence-in-depth item — always shown (even when absent) with a
 * note explaining its deprecated status — rather than flagged as a missing core
 * security header. Some client managers still expect to see it addressed.
 *
 * Returns an analyzeAdditional-shaped row ({ key, label, status, state, value, note, ... }).
 */
function analyzeXXPAdditional(h) {
  const label = 'X-XSS-Protection';
  const v = h['x-xss-protection'];
  if (!v) {
    return {
      key: 'xxp', label, status: 'dep', state: 'deprecated', severity: 'INFO', value: 'not set',
      note: 'Deprecated — modern browsers no longer support this header; intentionally omitted. Reported for completeness; no action required.',
      web: "The application does not set the X-XSS-Protection header. This header is deprecated and is no longer supported by current browsers, which have removed the reflected-XSS filter it controlled; its absence therefore does not weaken the security posture and no remediation is required. Protection against reflected cross-site scripting should instead be provided through a correctly configured Content-Security-Policy together with contextual output encoding. This item is recorded for completeness only.",
      api: "The API does not set the X-XSS-Protection header. This header is deprecated and is no longer supported by current browsers, which have removed the reflected-XSS filter it controlled; its absence therefore does not weaken the security posture and no remediation is required. Where the API also serves browser-rendered content, protection against reflected cross-site scripting should be provided through a Content-Security-Policy and contextual output encoding. This item is recorded for completeness only.",
    };
  }
  const norm = v.trim().toLowerCase().replace(/\s+/g, '');
  if (norm === '0') {
    return {
      key: 'xxp', label, status: 'ok', state: 'ok', severity: 'PASS', value: clip(v, 120),
      note: "Explicitly disabled ('0') — the modern recommended configuration.",
    };
  }
  if (norm === '1;mode=block') {
    return {
      key: 'xxp', label, status: 'dep', state: 'deprecated', severity: 'INFO', value: clip(v, 120),
      note: "Deprecated header set to the legacy best-practice value; retained for compliance. Modern guidance is to remove it and rely on Content-Security-Policy.",
      web: `The application sets the X-XSS-Protection header to '${clip(v, 80)}'. This header is deprecated and is ignored by current browsers, which have removed the reflected-XSS filter it controlled, so it provides no effective protection; the value is retained only for legacy or compliance purposes. Reflected cross-site scripting should be mitigated through a correctly configured Content-Security-Policy together with contextual output encoding. The header may be removed, or set to '0', without reducing the security posture.`,
      api: `The API sets the X-XSS-Protection header to '${clip(v, 80)}'. This header is deprecated and is ignored by current browsers, so it provides no effective protection; the value is retained only for legacy or compliance purposes. Reflected cross-site scripting should be mitigated through a Content-Security-Policy and contextual output encoding. The header may be removed, or set to '0', without reducing the security posture.`,
    };
  }
  // Any other value (e.g. bare '1') — the filter mode that can be abused in legacy browsers.
  return {
    key: 'xxp', label, status: 'weak', state: 'misconfigured', severity: 'LOW', value: clip(v, 120),
    note: "Deprecated and set to a value that can introduce vulnerabilities in legacy browsers; set '0' or remove it.",
    web: `The application sets the deprecated X-XSS-Protection header to '${clip(v, 80)}'. In legacy browsers this filter mode could be abused to introduce cross-site scripting conditions, and modern browsers ignore the header entirely. It should be set to '0' or removed, with reflected-XSS defence provided by a Content-Security-Policy.`,
    api: `The API sets the deprecated X-XSS-Protection header to '${clip(v, 80)}'. Modern clients ignore it and in legacy browsers this value could be abused; it should be set to '0' or removed.`,
  };
}

function analyzeXCTO(h) {
  const label = 'X-Content-Type-Options';
  const v = h['x-content-type-options'];
  if (!v) {
    return finding({
      key: 'xcto', label, state: 'missing', severity: 'LOW', evidence: 'Header not present in response',
      web: "The application does not include the X-Content-Type-Options header set to nosniff. Without this header, web browsers may attempt to infer the MIME type of response content, which could allow an attacker to deliver malicious content disguised as a legitimate resource. This configuration does not comply with best-practice security standards.",
      api: "The API does not include the X-Content-Type-Options header set to nosniff. Without this header, clients may attempt to infer the MIME type of response content, which could allow an attacker to deliver malicious content disguised as a legitimate resource. This configuration does not comply with best-practice security standards.",
    });
  }
  if (v.trim().toLowerCase() !== 'nosniff') {
    return finding({
      key: 'xcto', label, state: 'misconfigured', severity: 'LOW', evidence: 'X-Content-Type-Options: ' + v,
      web: `The application sets the X-Content-Type-Options header to '${clip(v, 80)}'; however, the only valid value is nosniff. As a result, browsers may still attempt to MIME-sniff the response content, which could allow an attacker to deliver malicious content disguised as a legitimate resource.`,
      api: `The API sets the X-Content-Type-Options header to '${clip(v, 80)}'; however, the only valid value is nosniff. As a result, clients may still attempt to MIME-sniff the response content, which could allow an attacker to deliver malicious content disguised as a legitimate resource.`,
    });
  }
  return finding({ key: 'xcto', label, state: 'ok', severity: 'PASS', evidence: 'X-Content-Type-Options: ' + v });
}

function analyzeXFO(h) {
  const label = 'X-Frame-Options';
  const v = h['x-frame-options'];
  if (!v) {
    return finding({
      key: 'xfo', label, state: 'missing', severity: 'LOW', evidence: 'Header not present in response',
      web: "The application does not include the X-Frame-Options header in the response. Without this protection, the application may be embedded within a malicious third-party website using an iframe, potentially exposing users to clickjacking or cross-frame scripting attacks.",
      api: "The API does not include the X-Frame-Options header in the response. While framing is less relevant for non-rendered API responses, the header is recommended so that any response cannot be embedded within a malicious third-party website using an iframe.",
    });
  }
  if (!['DENY', 'SAMEORIGIN'].includes(v.trim().toUpperCase())) {
    return finding({
      key: 'xfo', label, state: 'misconfigured', severity: 'LOW', evidence: 'X-Frame-Options: ' + v,
      web: `The application sets the X-Frame-Options header to '${clip(v, 80)}', which is not a recognised value. Only DENY or SAMEORIGIN provide effective protection; as configured the application may be embedded within a malicious third-party website using an iframe, exposing users to clickjacking.`,
      api: `The API sets the X-Frame-Options header to '${clip(v, 80)}', which is not a recognised value. Only DENY or SAMEORIGIN provide effective protection.`,
    });
  }
  return finding({ key: 'xfo', label, state: 'ok', severity: 'PASS', evidence: 'X-Frame-Options: ' + v });
}

function analyzeHSTS(h) {
  const label = 'HTTP Strict-Transport-Security (HSTS)';
  const v = h['strict-transport-security'];
  if (!v) {
    return finding({
      key: 'hsts', label, state: 'missing', severity: 'LOW', evidence: 'Header not present in response',
      web: "The application does not return the Strict-Transport-Security (HSTS) header. In the absence of this header, browsers are not instructed to enforce HTTPS-only communication, which may expose users to SSL stripping or downgrade attacks if HTTPS is supported by the application.",
      api: "The API does not return the Strict-Transport-Security (HSTS) header. In the absence of this header, clients are not instructed to enforce HTTPS-only communication, which may expose API traffic to SSL stripping or downgrade attacks.",
    });
  }
  const m = v.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = m ? parseInt(m[1], 10) : null;
  const hasSub = /includesubdomains/i.test(v);
  const issues = [];
  if (maxAge === 0) issues.push('the max-age directive is set to 0, which disables HSTS entirely');
  else if (maxAge !== null && maxAge < 31536000) issues.push(`the max-age value (${maxAge}) is below the recommended minimum of 31536000 seconds (one year)`);
  else if (maxAge === null) issues.push('a valid max-age directive is not defined');
  if (!hasSub) issues.push('the includeSubDomains directive is not set, allowing subdomains to be accessed without HSTS enforcement');
  if (issues.length) {
    const phrase = listPhrase(issues);
    return finding({
      key: 'hsts', label, state: 'misconfigured', severity: 'LOW', evidence: 'Strict-Transport-Security: ' + v,
      web: `The application returns the Strict-Transport-Security header; however, ${phrase}. As a result, the protection against SSL stripping and downgrade attacks is not fully enforced.`,
      api: `The API returns the Strict-Transport-Security header; however, ${phrase}. As a result, the protection against SSL stripping and downgrade attacks is not fully enforced.`,
    });
  }
  return finding({ key: 'hsts', label, state: 'ok', severity: 'PASS', evidence: 'Strict-Transport-Security: ' + v });
}

function analyzeCache(h) {
  const label = 'Cache-Control Headers';
  const cc = h['cache-control'];
  const pragma = h['pragma'];
  const expires = h['expires'];
  const low = (cc || '').toLowerCase();
  const ev = [cc && 'Cache-Control: ' + cc, pragma && 'Pragma: ' + pragma, expires && 'Expires: ' + expires]
    .filter(Boolean).join('\n') || 'No Cache-Control / Pragma / Expires present';

  if (cc && low.includes('no-store')) {
    // no-store already prevents current browsers from storing the response, so
    // this is never a real weakness on a modern client. Many hardening
    // checklists nevertheless require the HTTP/1.0-era companions Pragma:
    // no-cache and an already-expired Expires value, so report those gaps as a
    // partial-compliance item rather than passing outright.
    const pragmaOk = !!pragma && /no-cache/i.test(pragma);
    const expRaw = (expires || '').trim();
    const expParsed = Date.parse(expRaw);
    const expiresOk = expRaw !== '' &&
      (['0', '-1'].includes(expRaw) || (!isNaN(expParsed) && expParsed <= Date.now()));

    if (pragmaOk && expiresOk) {
      return finding({ key: 'cache', label, state: 'ok', severity: 'PASS', evidence: ev });
    }

    const gaps = [];
    if (!pragmaOk) {
      gaps.push(pragma
        ? `the Pragma header is set to '${clip(pragma, 40)}' rather than 'no-cache'`
        : 'the Pragma: no-cache header is not set');
    }
    if (!expiresOk) {
      gaps.push(expRaw === ''
        ? 'the Expires header is not set'
        : `the Expires header is set to '${clip(expRaw, 40)}', which is not an already-expired value`);
    }
    const phrase = listPhrase(gaps);
    return finding({
      key: 'cache', label, state: 'misconfigured', severity: 'INFO', evidence: ev,
      web: `The application sets the Cache-Control: no-store directive, which prevents current browsers from storing the response; however, ${phrase}. These HTTP/1.0-era headers are ignored by modern browsers, but are still mandated by a number of hardening checklists so that legacy intermediary caches do not retain sensitive content. Setting Pragma: no-cache together with Expires: -1 alongside the existing Cache-Control directive would achieve full compliance.`,
      api: `The API sets the Cache-Control: no-store directive, which prevents current clients from storing the response; however, ${phrase}. These HTTP/1.0-era headers are ignored by modern clients, but are still mandated by a number of hardening checklists so that legacy intermediary caches do not retain sensitive content. Setting Pragma: no-cache together with Expires: -1 alongside the existing Cache-Control directive would achieve full compliance.`,
    });
  }

  const nothing = !cc && !(pragma && /no-cache/i.test(pragma)) && !expires;
  if (nothing) {
    return finding({
      key: 'cache', label, state: 'missing', severity: 'LOW', evidence: ev,
      web: "The application does not implement cache-control directives to prevent the caching of potentially sensitive content. Specifically, the Cache-Control: no-store, Pragma: no-cache, and Expires headers are not set. As a result, sensitive information contained within web pages may be stored in the browser cache or intermediary systems, increasing the risk of unauthorized access.",
      api: "The API does not implement cache-control directives to prevent the caching of potentially sensitive content. Specifically, the Cache-Control: no-store, Pragma: no-cache, and Expires headers are not set. As a result, sensitive information returned by the API may be stored in client or intermediary caches, increasing the risk of unauthorized access.",
    });
  }
  if (cc && low.includes('public')) {
    return finding({
      key: 'cache', label, state: 'misconfigured', severity: 'LOW', evidence: ev,
      web: "The application does not disable client-side content storage features, as the Cache-Control header includes the public directive and does not include the required no-store directive. As a result, sensitive information contained within web pages may be stored on a user's device and could potentially be accessed by an attacker with access to the cached data.",
      api: "The API does not disable client-side content storage features, as the Cache-Control header includes the public directive and does not include the required no-store directive. As a result, sensitive information returned by the API may be cached by client applications or intermediary caches and could potentially be accessed by an attacker with access to the cached data.",
    });
  }
  if (cc && low.includes('no-cache')) {
    return finding({
      key: 'cache', label, state: 'misconfigured', severity: 'LOW', evidence: ev,
      web: "The application sets the Cache-Control: no-cache directive; however, it does not include the no-store directive. As a result, sensitive information contained within web pages may still be stored on a user's device. An attacker may be able to access sensitive data through the browser's temporary cache.",
      api: "The API sets the Cache-Control: no-cache directive; however, it does not include the no-store directive. As a result, sensitive information returned by the API may still be cached by client applications or intermediary caches and could potentially be accessed by an attacker with access to the cached data.",
    });
  }
  if (cc) {
    return finding({
      key: 'cache', label, state: 'misconfigured', severity: 'LOW', evidence: ev,
      web: `The application sets the Cache-Control header to '${clip(cc, 80)}'; however, it does not include the no-store directive. As a result, sensitive information contained within web pages may still be stored on a user's device and could be accessed through the browser's temporary cache.`,
      api: `The API sets the Cache-Control header to '${clip(cc, 80)}'; however, it does not include the no-store directive. As a result, sensitive information returned by the API may still be cached by client applications or intermediary caches.`,
    });
  }
  // Pragma/Expires present but Cache-Control absent
  return finding({
    key: 'cache', label, state: 'misconfigured', severity: 'LOW', evidence: ev,
    web: "The application does not set the Cache-Control: no-store directive to fully prevent the caching of sensitive content. As a result, sensitive information contained within web pages may still be stored on a user's device or in intermediary caches.",
    api: "The API does not set the Cache-Control: no-store directive to fully prevent the caching of sensitive content. As a result, sensitive information returned by the API may still be stored in client or intermediary caches.",
  });
}

export function analyzeSecurity(headers) {
  // X-XSS-Protection is deprecated; it is assessed in analyzeAdditional (defence-in-depth) rather than the core set.
  return [analyzeCSP, analyzeXCTO, analyzeXFO, analyzeHSTS, analyzeCache].map(fn => fn(headers));
}

/* ===========================================================================
 * TAB 2 — COOKIES & SESSION
 * ======================================================================== */

function parseCookie(str) {
  const parts = str.split(';').map(p => p.trim()).filter(Boolean);
  const c = { name: '', secure: false, httponly: false, samesite: '', hasMaxAgeOrExpires: false };
  parts.forEach((part, i) => {
    const eq = part.indexOf('=');
    const key = (eq === -1 ? part : part.slice(0, eq)).trim().toLowerCase();
    const val = eq === -1 ? '' : part.slice(eq + 1).trim();
    if (i === 0) { c.name = eq === -1 ? part : part.slice(0, eq).trim(); return; }
    if (key === 'secure') c.secure = true;
    else if (key === 'httponly') c.httponly = true;
    else if (key === 'samesite') c.samesite = val.toLowerCase();
    else if (key === 'max-age' || key === 'expires') c.hasMaxAgeOrExpires = true;
  });
  return c;
}

export function analyzeCookies(setCookies) {
  const out = [];
  for (const raw of setCookies || []) {
    const c = parseCookie(raw);
    if (!c.name) continue;
    const issues = [];
    if (!c.secure) issues.push('the Secure flag is not set');
    if (!c.httponly) issues.push('the HttpOnly flag is not set');
    if (!c.samesite) issues.push('the SameSite attribute is not set');
    else if (c.samesite === 'none' && !c.secure) issues.push('SameSite is set to None without the Secure flag');
    if (!issues.length) continue;

    const phrase = listPhrase(issues);
    const why = [];
    if (!c.httponly) why.push('exposes it to theft via client-side script (cross-site scripting)');
    if (!c.secure) why.push('permits transmission over unencrypted HTTP');
    if (!c.samesite || (c.samesite === 'none' && !c.secure)) why.push('increases exposure to cross-site request forgery');
    const consequence = why.length ? ' This ' + listPhrase(why) + '.' : '';

    out.push(finding({
      key: 'cookie:' + c.name, label: `Cookie: ${c.name}`, state: 'misconfigured', severity: 'LOW',
      evidence: clip(raw, 200),
      web: `The cookie "${c.name}" is set without one or more recommended security attributes: ${phrase}.${consequence} As a result, the cookie does not align with best-practice session management.`,
      api: `The cookie "${c.name}" is set without one or more recommended security attributes: ${phrase}.${consequence} As a result, the cookie does not align with best-practice session management.`,
    }));
  }
  return out;
}

/* ===========================================================================
 * TAB 3 — INFORMATION DISCLOSURE
 * ======================================================================== */

export function analyzeInfo(headers) {
  const out = [];
  const server = headers['server'];
  if (server) {
    const hasVersion = /[\d.]{2,}|\/\d/.test(server);
    out.push(finding({
      key: 'server', label: 'Server Banner', state: hasVersion ? 'misconfigured' : 'ok',
      severity: 'INFO', evidence: 'Server: ' + server,
      web: hasVersion
        ? `The application discloses the web server product and version in the Server response header (${clip(server, 80)}). This information assists an attacker in identifying known vulnerabilities for that specific version.`
        : '',
      api: hasVersion
        ? `The API discloses the web server product and version in the Server response header (${clip(server, 80)}). This information assists an attacker in fingerprinting the backend.`
        : '',
    }));
  }
  const xpb = headers['x-powered-by'];
  if (xpb) {
    out.push(finding({
      key: 'xpb', label: 'X-Powered-By', state: 'misconfigured', severity: 'INFO',
      evidence: 'X-Powered-By: ' + xpb,
      web: `The application exposes the X-Powered-By header (${clip(xpb, 80)}), disclosing the underlying technology stack. This assists an attacker in targeting framework-specific vulnerabilities and should be suppressed.`,
      api: `The API exposes the X-Powered-By header (${clip(xpb, 80)}), disclosing the underlying technology stack. This assists an attacker in targeting framework-specific vulnerabilities and should be suppressed.`,
    }));
  }
  const aspnet = headers['x-aspnet-version'] || headers['x-aspnetmvc-version'];
  if (aspnet) {
    out.push(finding({
      key: 'aspnet', label: 'ASP.NET Version', state: 'misconfigured', severity: 'INFO',
      evidence: (headers['x-aspnet-version'] ? 'X-AspNet-Version: ' + headers['x-aspnet-version'] : 'X-AspNetMvc-Version: ' + headers['x-aspnetmvc-version']),
      web: `The application discloses the ASP.NET framework version (${clip(aspnet, 60)}) in the response headers, assisting an attacker in identifying version-specific vulnerabilities.`,
      api: `The API discloses the ASP.NET framework version (${clip(aspnet, 60)}) in the response headers, assisting an attacker in identifying version-specific vulnerabilities.`,
    }));
  }
  const ct = headers['content-type'];
  if (ct && /^\s*text\//i.test(ct) && !/charset\s*=/i.test(ct)) {
    out.push(finding({
      key: 'charset', label: 'Content-Type Charset', state: 'misconfigured', severity: 'INFO',
      evidence: 'Content-Type: ' + ct,
      web: `The Content-Type header (${clip(ct, 60)}) does not define a character set (for example charset=utf-8). Browsers may then interpret the response using an inferred encoding, which in some cases can be leveraged for character-set based injection.`,
      api: `The Content-Type header (${clip(ct, 60)}) does not define a character set. This may lead to encoding inconsistencies for consuming clients.`,
    }));
  }
  return out;
}

/* ===========================================================================
 * TAB 4 — ADDITIONAL HARDENING (informational, outside the EY observation)
 * ======================================================================== */

export function analyzeAdditional(headers) {
  const out = [];

  // X-XSS-Protection (deprecated) — always surfaced here with a deprecation note.
  out.push(analyzeXXPAdditional(headers));

  // Headers that follow a simple "recommended value" pattern (COOP / COEP / CORP).
  const recHeader = (key, label, rec, okValues, missWeb, missApi, weakWeb, weakApi, sev = 'INFO') => {
    const v = headers[key];
    if (!v) {
      out.push({ key, label, status: 'miss', state: 'missing', severity: sev, value: 'not set', note: `Recommended: ${rec}`, web: missWeb, api: missApi });
      return;
    }
    if (okValues.includes(v.trim().toLowerCase())) {
      out.push({ key, label, status: 'ok', state: 'ok', severity: 'PASS', value: clip(v, 120), note: 'Configured' });
      return;
    }
    out.push({ key, label, status: 'weak', state: 'misconfigured', severity: sev, value: clip(v, 120), note: `Recommended: ${rec}`, web: weakWeb(v), api: weakApi(v) });
  };

  // Referrer-Policy
  {
    const v = headers['referrer-policy'];
    const rec = 'strict-origin-when-cross-origin';
    if (!v) {
      out.push({ key: 'referrer-policy', label: 'Referrer-Policy', status: 'miss', state: 'missing', severity: 'LOW', value: 'not set', note: `Recommended: ${rec}`,
        web: `The application does not set a Referrer-Policy header. As a result, the full request URL — including any sensitive path or query-string parameters — may be disclosed in the Referer header to third-party origins when a user navigates away from the application or loads an external resource. A restrictive policy such as ${rec} is recommended.`,
        api: `The API does not set a Referrer-Policy header. As a result, the full request URL, including any sensitive query-string parameters, may be disclosed in the Referer header to third-party origins. A restrictive policy such as ${rec} is recommended.` });
    } else {
      const low = v.trim().toLowerCase();
      const known = ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin', 'origin', 'unsafe-url', 'origin-when-cross-origin'];
      if (['unsafe-url', 'origin-when-cross-origin'].includes(low)) {
        out.push({ key: 'referrer-policy', label: 'Referrer-Policy', status: 'weak', state: 'misconfigured', severity: 'LOW', value: clip(v, 120), note: 'Leaks full URLs (including query strings) to third parties',
          web: `The application sets the Referrer-Policy header to '${clip(v, 80)}', which permits the full URL — including query strings — to be transmitted to third-party origins in the Referer header. A more restrictive policy such as ${rec} is recommended.`,
          api: `The API sets the Referrer-Policy header to '${clip(v, 80)}', which permits the full URL, including query strings, to be transmitted to third-party origins in the Referer header. A more restrictive policy such as ${rec} is recommended.` });
      } else if (!known.includes(low)) {
        out.push({ key: 'referrer-policy', label: 'Referrer-Policy', status: 'weak', state: 'misconfigured', severity: 'INFO', value: clip(v, 120), note: 'Unrecognised value — verify intent',
          web: `The application sets the Referrer-Policy header to an unrecognised value ('${clip(v, 80)}'); the intended policy should be confirmed. A value such as ${rec} is recommended.`,
          api: `The API sets the Referrer-Policy header to an unrecognised value ('${clip(v, 80)}'); the intended policy should be confirmed. A value such as ${rec} is recommended.` });
      } else {
        out.push({ key: 'referrer-policy', label: 'Referrer-Policy', status: 'ok', state: 'ok', severity: 'PASS', value: clip(v, 120), note: 'Configured' });
      }
    }
  }

  // Permissions-Policy
  {
    const v = headers['permissions-policy'];
    const rec = 'camera=(), microphone=(), geolocation=()';
    if (!v) {
      out.push({ key: 'permissions-policy', label: 'Permissions-Policy', status: 'miss', state: 'missing', severity: 'LOW', value: 'not set', note: `Recommended: ${rec}`,
        web: `The application does not set a Permissions-Policy header. Without it, powerful browser features (such as camera, microphone, geolocation, and payment) are governed only by browser defaults, and embedded third-party content is not explicitly prevented from requesting access to them. Unused features should be explicitly disabled, for example ${rec}.`,
        api: `The API does not set a Permissions-Policy header. This control governs browser feature access and is primarily relevant where the API also serves browser-rendered content; it is recommended in that case, for example ${rec}.` });
    } else if (v.includes('*')) {
      out.push({ key: 'permissions-policy', label: 'Permissions-Policy', status: 'weak', state: 'misconfigured', severity: 'LOW', value: clip(v, 120), note: "Wildcard '*' grants features to all origins",
        web: `The application sets a Permissions-Policy header that uses a wildcard '*', granting one or more powerful features to all origins. Features that are not required should be explicitly disabled, for example ${rec}.`,
        api: `The API sets a Permissions-Policy header that uses a wildcard '*', granting one or more powerful features to all origins. Features that are not required should be explicitly disabled.` });
    } else {
      out.push({ key: 'permissions-policy', label: 'Permissions-Policy', status: 'ok', state: 'ok', severity: 'PASS', value: clip(v, 120), note: 'Configured' });
    }
  }

  recHeader('cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', 'same-origin', ['same-origin'],
    "The application does not set a Cross-Origin-Opener-Policy header. Without the 'same-origin' value, the document shares its browsing-context group with cross-origin windows it opens or that open it, which can facilitate cross-origin side-channel (Spectre-class) and tab-nabbing style attacks.",
    "The API does not set a Cross-Origin-Opener-Policy header; this control applies to browser-rendered documents rather than API responses and can be omitted for pure API endpoints.",
    v => `The application sets Cross-Origin-Opener-Policy to '${clip(v, 80)}'; the recommended value is 'same-origin' to isolate the document's browsing-context group from cross-origin windows.`,
    v => `The API sets Cross-Origin-Opener-Policy to '${clip(v, 80)}'; where the API serves browser-rendered content the recommended value is 'same-origin'.`);

  recHeader('cross-origin-embedder-policy', 'Cross-Origin-Embedder-Policy', 'require-corp', ['require-corp'],
    "The application does not set a Cross-Origin-Embedder-Policy header. In the absence of 'require-corp' the document cannot be cross-origin isolated, and cross-origin resources are loaded without an explicit opt-in.",
    "The API does not set a Cross-Origin-Embedder-Policy header; this control applies to browser-rendered documents rather than API responses and can be omitted for pure API endpoints.",
    v => `The application sets Cross-Origin-Embedder-Policy to '${clip(v, 80)}'; the recommended value is 'require-corp'.`,
    v => `The API sets Cross-Origin-Embedder-Policy to '${clip(v, 80)}'; where the API serves browser-rendered content the recommended value is 'require-corp'.`);

  recHeader('cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', 'same-origin / same-site', ['same-origin', 'same-site'],
    "The application does not set a Cross-Origin-Resource-Policy header. Without 'same-origin' or 'same-site', the resource may be embedded or read by any cross-origin document, which can facilitate cross-origin information leakage via side-channel attacks.",
    "The API does not set a Cross-Origin-Resource-Policy header. Setting 'same-origin' or 'same-site' prevents the response from being read by unauthorised cross-origin documents and is recommended for sensitive endpoints.",
    v => `The application sets Cross-Origin-Resource-Policy to '${clip(v, 80)}'; the recommended value is 'same-origin' or 'same-site'.`,
    v => `The API sets Cross-Origin-Resource-Policy to '${clip(v, 80)}'; the recommended value is 'same-origin' or 'same-site' for sensitive endpoints.`);

  return out;
}

/* ===========================================================================
 * ORCHESTRATION
 * ======================================================================== */

export function analyze(raw) {
  const { headers, setCookies } = parseHeaders(raw);
  return {
    headers,
    setCookies,
    count: Object.keys(headers).length + setCookies.length,
    security: analyzeSecurity(headers),
    cookies: analyzeCookies(setCookies),
    info: analyzeInfo(headers),
    additional: analyzeAdditional(headers),
  };
}

/* ===========================================================================
 * OBSERVATION FORMATTERS (report-ready plain text)
 * ======================================================================== */

const pickFor = mode => f => (mode === 'web' ? f.web : f.api);
const subjWord = mode => (mode === 'web' ? 'application' : 'API');

/**
 * Group findings into a "misconfigured" block, then a "missing" block, then an
 * optional "deprecated" block, each led by a caller-supplied sentence ({subj} is
 * replaced with application/API). The deprecated block is emitted last because
 * it is recorded for completeness rather than as a remediation item, and only
 * when the caller supplies a `leads.dep` sentence.
 */
function groupObservation(findings, mode, leads) {
  const pick = pickFor(mode);
  const subj = subjWord(mode);
  const block = (list, lead) => lead.replace('{subj}', subj) + '\n\n' + list.map(f => `${f.label}:\n${pick(f)}`).join('\n\n');
  const mis = findings.filter(f => f.state === 'misconfigured' && pick(f));
  const miss = findings.filter(f => f.state === 'missing' && pick(f));
  const dep = leads.dep ? findings.filter(f => f.state === 'deprecated' && pick(f)) : [];
  const blocks = [];
  if (mis.length) blocks.push(block(mis, leads.mis));
  if (miss.length) blocks.push(block(miss, leads.miss));
  if (dep.length) blocks.push(block(dep, leads.dep));
  if (!blocks.length) return leads.empty.replace('{subj}', subj);
  return blocks.join('\n\n');
}

/** Report observation for the core security-header set: misconfigured then missing. */
export function formatSecurityObservation(findings, mode) {
  return groupObservation(findings, mode, {
    mis: 'It was observed that the following HTTP headers are misconfigured in the {subj}:',
    miss: 'It was observed that the following HTTP headers are missing in the {subj}:',
    empty: 'No missing or misconfigured headers from the core security header set were identified in the supplied response.',
  });
}

/** Report observation for the additional (defence-in-depth) hardening headers. */
export function formatAdditionalObservation(findings, mode) {
  return groupObservation(findings, mode, {
    mis: 'It was observed that the following additional security headers are weakly configured in the {subj}:',
    miss: 'It was observed that the following additional (defence-in-depth) security headers are not implemented in the {subj}:',
    dep: 'The following deprecated security header was also assessed in the {subj}. It is recorded for completeness and does not require remediation:',
    empty: 'All additional hardening headers assessed were present and adequately configured.',
  });
}

/** Generic observation paragraph for the cookie / info-disclosure tabs. */
export function formatGenericObservation(findings, mode, opts) {
  const pick = pickFor(mode);
  const subj = mode === 'web' ? 'application' : 'API';
  const real = findings.filter(pick);
  if (!real.length) return (opts.empty || 'No relevant findings were identified in the {subj}.').replace('{subj}', subj);
  return `${opts.lead.replace('{subj}', subj)}\n\n` + real.map(f => `${f.label}:\n${pick(f)}`).join('\n\n');
}

/** Roll up severity counts across the analysed tabs for summary display. */
export function summarize(result) {
  const counts = {};
  let pass = 0;
  const bump = arr => arr.forEach(f => {
    if (f.state === 'ok') { pass++; return; }
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });
  bump(result.security);
  bump(result.cookies);
  bump(result.info);
  return { counts, pass };
}
