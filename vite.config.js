import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

// Inject a strict Content-Security-Policy into the BUILT html.
// The key directive is `connect-src 'none'`: the page is forbidden from making
// any outbound network request (fetch / XHR / WebSocket / beacon), so pasted
// headers can never be transmitted. Applied at build only — dev needs the HMR socket.
function cspPlugin() {
  const csp = [
    "default-src 'self'",
    "connect-src 'none'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ')
  return {
    name: 'inject-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '</title>',
        `</title>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`
      )
    },
  }
}

// base: './' -> relative asset paths, so it works on any GitHub Pages subpath.
// `vite build`              -> multi-file build in dist/ (deployed to Pages)
// `vite build --mode single` -> one self-contained dist-single/index.html (offline/email)
export default defineConfig(({ mode }) => {
  const single = mode === 'single'
  return {
    base: './',
    plugins: [react(), cspPlugin(), ...(single ? [viteSingleFile()] : [])],
    build: single ? { outDir: 'dist-single' } : {},
  }
})
