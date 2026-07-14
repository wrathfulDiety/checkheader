import { useState, useMemo, useEffect, useCallback } from 'react'
import {
  analyze, summarize, SEV_ORDER,
  formatSecurityObservation, formatGenericObservation, formatAdditionalObservation,
} from './lib/headerAnalysis.js'

const SEV_COLOR = { CRITICAL: '#ff2d55', HIGH: '#ff6b35', MEDIUM: '#f5a623', LOW: '#4d9fff', INFO: '#8a8fa8', PASS: '#30d158' }
const SEV_BG = { CRITICAL: 'rgba(255,45,85,.1)', HIGH: 'rgba(255,107,53,.1)', MEDIUM: 'rgba(245,166,35,.08)', LOW: 'rgba(77,159,255,.08)', INFO: 'rgba(138,143,168,.05)', PASS: 'rgba(48,209,88,.07)' }
const SEV_BD = { CRITICAL: 'rgba(255,45,85,.3)', HIGH: 'rgba(255,107,53,.3)', MEDIUM: 'rgba(245,166,35,.28)', LOW: 'rgba(77,159,255,.28)', INFO: 'rgba(138,143,168,.22)', PASS: 'rgba(48,209,88,.26)' }

const SAMPLE = `HTTP/2 200
content-type: text/html; charset=utf-8
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://a.example.com https://b.example.com https://cdn.thirdparty.io data:; img-src * blob:
cache-control: no-cache
strict-transport-security: max-age=300
server: Apache/2.4.49 (Unix)
x-powered-by: Express
referrer-policy: unsafe-url
set-cookie: SESSION=abc123; Path=/
set-cookie: pref=dark; Secure; SameSite=None; Path=/`

const TABS = [
  { key: 'security', label: 'Security Headers' },
  { key: 'cookies', label: 'Cookies & Session' },
  { key: 'info', label: 'Info Disclosure' },
  { key: 'additional', label: 'Additional Hardening' },
]

function useLocal(key, init) {
  const [v, setV] = useState(() => {
    try { const s = localStorage.getItem(key); return s === null ? init : s } catch { return init }
  })
  useEffect(() => { try { localStorage.setItem(key, v) } catch { /* ignore */ } }, [key, v])
  return [v, setV]
}

function Pill({ color, bg, bd, n, txt }) {
  return <span className="pill" style={{ '--c': color, '--pbg': bg, '--bd': bd }}><b>{n}</b> {txt}</span>
}

function FindingCard({ f, mode }) {
  const [open, setOpen] = useState(false)
  const c = SEV_COLOR[f.severity] || SEV_COLOR.LOW
  const bd = SEV_BD[f.severity] || SEV_BD.LOW
  const body = mode === 'web' ? f.web : f.api
  const stateLabel = f.state === 'ok' ? 'configured' : f.state
  return (
    <div className="fc" style={{ '--c': c, '--bd': bd }}>
      <div className="fc-head" onClick={() => setOpen(o => !o)}>
        <span className="fc-sev">{f.severity}</span>
        <span className="fc-title">{f.label} — {stateLabel}</span>
        <span className="fc-chev">{open ? '▴' : '▾'}</span>
      </div>
      {open && (
        <div className="fc-body">
          <div className="fc-sec"><div className="fc-sl">Evidence</div><pre className="fc-pre">{f.evidence}</pre></div>
          {body && <div className="fc-sec"><div className="fc-sl">Observation</div><p className="fc-p">{body}</p></div>}
        </div>
      )}
    </div>
  )
}

function Section({ title, obs, onCopy, children }) {
  return (
    <section className="block">
      <div className="block-head">
        <span className="block-title">{title}</span>
        <div className="spacer" />
        <button className="btn primary" onClick={onCopy}>Copy observation</button>
      </div>
      <pre className="obs-box">{obs}</pre>
      <div className="cards">{children}</div>
    </section>
  )
}

export default function App() {
  const [input, setInput] = useLocal('chr_input', '')
  const [mode, setMode] = useLocal('chr_mode', 'web')
  const [tab, setTab] = useState('security')
  const [toast, setToast] = useState('')

  const result = useMemo(() => analyze(input), [input])
  const hasInput = input.trim().length > 0 && result.count > 0

  const showToast = useCallback((m) => { setToast(m); setTimeout(() => setToast(''), 1400) }, [])

  const copy = useCallback(async (text) => {
    if (!text) { showToast('Nothing to copy'); return }
    try { await navigator.clipboard.writeText(text); showToast('Copied') }
    catch {
      const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select()
      try { document.execCommand('copy'); showToast('Copied') } catch { showToast('Copy failed') }
      ta.remove()
    }
  }, [showToast])

  const { counts, pass } = summarize(result)
  const securityObs = formatSecurityObservation(result.security, mode)
  const cookieObs = formatGenericObservation(result.cookies, mode, {
    lead: 'It was observed that the following cookies are configured without one or more recommended security attributes in the {subj}:',
    empty: 'No cookie attribute weaknesses were identified in the {subj}.',
  })
  const infoObs = formatGenericObservation(result.info, mode, {
    lead: 'It was observed that the {subj} discloses the following information through its HTTP response headers:',
    empty: 'No information-disclosure issues were identified in the {subj} response headers.',
  })
  const additionalObs = formatAdditionalObservation(result.additional, mode)
  const securityCards = result.security

  return (
    <div className="app">
      <div className="scanlines" />

      <header className="hdr">
        <div className="logo">
          <span className="logo-b">[</span><span className="logo-d">check</span><span className="logo-a">HEAD</span><span className="logo-d">er</span><span className="logo-b">]</span>
          <span className="logo-mode">Report Mode</span>
        </div>
        <div className="hdr-r">
          <div className="hdr-top">
            <a className="home-btn" href="https://wrathfuldiety.github.io/" target="_blank" rel="noreferrer noopener">↗ All tools</a>
            <span className="local-badge">100% Local · No Network</span>
          </div>
          <span className="hdr-sub">HTTP Header Observation Generator</span>
        </div>
      </header>

      <div className="controls">
        <span className="seg-label">Report voice</span>
        <div className="seg">
          <button className={mode === 'web' ? 'on' : ''} onClick={() => setMode('web')}>Web</button>
          <button className={mode === 'api' ? 'on' : ''} onClick={() => setMode('api')}>API</button>
        </div>
        <div className="spacer" />
        <button className="btn ghost" onClick={() => setInput(SAMPLE)}>Load sample</button>
        <button className="btn ghost" onClick={() => setInput('')}>Clear</button>
      </div>

      <div className="io">
        <div className="panel-label">
          Paste raw HTTP response headers
          <span className="hint">— from Burp, curl -I, or dev-tools. Analysis runs as you type. Nothing leaves this tab.</span>
        </div>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          spellCheck="false"
          placeholder={"HTTP/2 200\ncontent-security-policy: default-src 'self'\ncache-control: no-cache\nstrict-transport-security: max-age=300\n..."}
        />
      </div>

      {!hasInput ? (
        <div className="idle">
          <h2>Paste headers above to generate the observation</h2>
          <p>Four tabs — Security Headers, Cookies &amp; Session, Information Disclosure, and Additional Hardening — each with a report-ready observation you can copy straight into a finding, plus severity-rated detail. Toggle Web/API to switch the wording. All processing happens in this browser tab.</p>
        </div>
      ) : (
        <>
          <div className="summary">
            <Pill color="var(--cyan)" bg="rgba(0,216,255,.08)" bd="rgba(0,216,255,.25)" n={result.count} txt="parsed" />
            {SEV_ORDER.filter(s => counts[s]).map(s => (
              <Pill key={s} color={SEV_COLOR[s]} bg={SEV_BG[s]} bd={SEV_BD[s]} n={counts[s]} txt={s} />
            ))}
            {pass > 0 && <Pill color={SEV_COLOR.PASS} bg={SEV_BG.PASS} bd={SEV_BD.PASS} n={pass} txt="pass" />}
          </div>

          <div className="tabs">
            {TABS.map(t => (
              <button key={t.key} className={`tab-btn ${tab === t.key ? 'on' : ''}`} onClick={() => setTab(t.key)}>
                {t.label}
              </button>
            ))}
          </div>

          {tab === 'security' && (
            <Section title="Observation — Security Headers" obs={securityObs} onCopy={() => copy(securityObs)}>
              {securityCards.map(f => <FindingCard key={f.key} f={f} mode={mode} />)}
            </Section>
          )}

          {tab === 'cookies' && (
            <Section title="Observation — Cookies & Session" obs={cookieObs} onCopy={() => copy(cookieObs)}>
              {result.cookies.length
                ? result.cookies.map(f => <FindingCard key={f.key} f={f} mode={mode} />)
                : <div className="empty">No cookie weaknesses identified. Paste authenticated responses (with Set-Cookie) for full coverage.</div>}
            </Section>
          )}

          {tab === 'info' && (
            <Section title="Observation — Information Disclosure" obs={infoObs} onCopy={() => copy(infoObs)}>
              {result.info.length
                ? result.info.map(f => <FindingCard key={f.key} f={f} mode={mode} />)
                : <div className="empty">No information-disclosure issues identified.</div>}
            </Section>
          )}

          {tab === 'additional' && (
            <section className="block">
              <div className="block-head">
                <span className="block-title">Observation — Additional Hardening</span>
                <span className="block-sub">informational · defence-in-depth</span>
                <div className="spacer" />
                <button className="btn primary" onClick={() => copy(additionalObs)}>Copy observation</button>
              </div>
              <div className="ah-note">Defence-in-depth headers outside the core report set. Include them only if your engagement scope calls for it.</div>
              <pre className="obs-box">{additionalObs}</pre>
              <table className="ah">
                <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Note</th></tr></thead>
                <tbody>
                  {result.additional.map(a => (
                    <tr key={a.label}>
                      <td className="name">{a.label}</td>
                      <td><span className={`st ${a.status}`}>{a.status === 'ok' ? 'PRESENT' : a.status === 'weak' ? 'WEAK' : a.status === 'dep' ? 'DEPRECATED' : 'MISSING'}</span></td>
                      <td className="val">{a.value}</td>
                      <td className="note">{a.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </>
      )}

      <footer className="footer">
        <span>checkHEADer Report Mode</span><span>·</span>
        <span>100% client-side</span><span>·</span>
        <a href="https://wrathfuldiety.github.io/" target="_blank" rel="noreferrer noopener">more tools by wrathfuldiety ↗</a>
      </footer>

      <div className={`toast ${toast ? 'show' : ''}`}>{toast}</div>
    </div>
  )
}
