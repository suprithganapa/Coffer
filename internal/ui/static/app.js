/* Coffer web console — vanilla JS, no build step. */
'use strict';

// ---------------------------------------------------------------- helpers
const $ = (s, r = document) => r.querySelector(s);
const S = { token: sessionStorage.getItem('coffer.token') || '', me: null, seal: null, mounts: null, pollT: null, liveT: null };

function h(tag, attrs, ...kids) {
  if (attrs != null && (attrs instanceof Node || typeof attrs !== 'object' || Array.isArray(attrs))) { kids.unshift(attrs); attrs = null; }
  const el = document.createElementNS(tag === 'svg' || attrs?._svg ? 'http://www.w3.org/2000/svg' : 'http://www.w3.org/1999/xhtml', tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false || k === '_svg') continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.setAttribute('class', v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k === 'value' && 'value' in el) el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.appendChild(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return el;
}
const svg = (tag, attrs, ...kids) => h(tag, { ...attrs, _svg: true }, ...kids);
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }

async function api(method, path, body, extraHeaders) {
  const headers = { ...(extraHeaders || {}) };
  if (S.token) headers['X-Coffer-Token'] = S.token;
  let payload;
  if (body !== undefined && body !== null) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch('/v1/' + path.replace(/^\//, ''), { method, headers, body: payload });
  if (res.status === 204) return {};
  const text = await res.text();
  let json = {};
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  if (!res.ok) {
    const msg = (json.errors && json.errors.length) ? json.errors.join('; ') : `Request failed (${res.status})`;
    if (res.status === 503 && /sealed/i.test(msg)) setTimeout(boot, 50);
    throw new ApiError(msg, res.status);
  }
  return json;
}
const list = async (path) => { try { return (await api('LIST', path)).data?.keys || []; } catch (e) { if (e.status === 404) return []; throw e; } };
const fsPath = (p) => '/v1/fs' + encodeURI(p).replace(/#/g, '%23').replace(/\?/g, '%3F');
async function fsApi(method, p, query, body) {
  const qs = query ? '?' + new URLSearchParams(query).toString() : '';
  const headers = { 'X-Coffer-Token': S.token };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(fsPath(p) + qs, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  if (res.status === 204) return {};
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError((json.errors || []).join('; ') || `Request failed (${res.status})`, res.status);
  return json;
}

function toast(msg, err) {
  const t = h('div', { class: 'toast' + (err ? ' err' : '') }, msg);
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), err ? 7000 : 3500);
}
const fail = (e) => toast(e.message || String(e), true);

function modal({ title, body, actions = [], wide = false, onClose }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { class: wide ? 'wide' : '' });
    const done = (v) => { dlg.close(); dlg.remove(); onClose && onClose(); resolve(v); };
    const foot = h('div', { class: 'dlg-foot' });
    const acts = actions.length ? actions : [{ label: 'Close', primary: true, onClick: () => true }];
    for (const a of acts) {
      const b = h('button', { class: a.primary ? 'primary' : a.danger ? 'danger' : '', type: 'button' }, a.label);
      b.addEventListener('click', async () => {
        b.disabled = true;
        try {
          const r = a.onClick ? await a.onClick(dlg) : true;
          if (r !== false) done(r === true ? a.value ?? true : r);
        } catch (e) { fail(e); } finally { b.disabled = false; }
      });
      foot.appendChild(b);
    }
    add(dlg, [h('div', { class: 'dlg-head' }, h('h2', null, title)), h('div', { class: 'dlg-body' }, body), foot]);
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(null); });
    dlg.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.tagName === 'INPUT' && acts.find(a => a.primary)) {
        e.preventDefault(); foot.querySelector('button.primary')?.click();
      }
    });
    document.body.appendChild(dlg);
    dlg.showModal();
    const first = dlg.querySelector('input:not([type=checkbox]),select,textarea');
    if (first) first.focus();
  });
}
const confirmDlg = (title, text, label = 'Delete') =>
  modal({ title, body: h('p', null, text), actions: [{ label: 'Cancel', onClick: () => null, value: false }, { label, danger: true, onClick: () => true }] }).then(v => v === true);

function field(label, input, hint) { return h('label', { class: 'field' }, h('span', null, label), input, hint ? h('small', null, hint) : null); }
function formVals(root) {
  const o = {};
  root.querySelectorAll('[name]').forEach(el => { o[el.name] = el.type === 'checkbox' ? el.checked : el.value.trim(); });
  return o;
}
function copyBtn(text, label = 'Copy') {
  return h('button', { class: 'sm', type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); } catch { toast('Copy failed: select and copy manually', true); } } }, label);
}
function copyable(text) { return h('div', { class: 'copyable' }, h('code', null, text), copyBtn(text)); }
const fmtBytes = (n) => { n = Number(n) || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(1) : n) + ' ' + u[i]; };
const fmtTime = (t) => { if (!t || String(t).startsWith('0001')) return '—'; const d = typeof t === 'number' ? new Date(t * 1000) : new Date(t); return isNaN(d) ? '—' : d.toLocaleString(); };
const ago = (t) => { const d = new Date(t); const s = (Date.now() - d) / 1000; if (s < 60) return Math.max(0, s | 0) + 's ago'; if (s < 3600) return (s / 60 | 0) + 'm ago'; if (s < 86400) return (s / 3600 | 0) + 'h ago'; return d.toLocaleDateString(); };
const fmtTTL = (s) => { s = Number(s) || 0; if (!s) return 'never'; if (s < 3600) return Math.round(s / 60) + 'm'; if (s < 86400 * 2) return Math.round(s / 3600) + 'h'; return Math.round(s / 86400) + 'd'; };
const b64e = (str) => btoa(String.fromCharCode(...new TextEncoder().encode(str)));
const b64d = (b) => { try { return new TextDecoder().decode(Uint8Array.from(atob(b), c => c.charCodeAt(0))); } catch { return b; } };
const splitList = (s) => (s || '').split(',').map(x => x.trim()).filter(Boolean);
const tag = (text, kind) => h('span', { class: 'tag ' + (kind || '') }, text);
const emptyRow = (cols, text, btn) => h('tr', null, h('td', { colspan: cols, class: 'empty' }, h('div', null, text), btn || null));
function table(heads, rows) {
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, heads.map(x => typeof x === 'string' ? h('th', null, x) : h('th', { class: x.cls }, x.t)))),
    h('tbody', null, rows)));
}
function denied(e, what) {
  if (e.status === 403) return h('div', { class: 'panel muted' }, `Your token doesn't have access to ${what}. Ask an operator for a policy that grants it.`);
  return h('div', { class: 'panel' }, h('p', null, e.message));
}
function downloadText(name, text) {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  document.body.appendChild(a); a.click(); a.remove();
}

// ---------------------------------------------------------------- seal dial
// The dial's segments are the Shamir key shares; submitted shares turn brass.
function dial(size, st) {
  const n = Math.max(1, st?.n || 1), t = st?.t || 1, sealed = st ? st.sealed : true, prog = st?.progress || 0;
  const c = 50, r = 42, gap = n > 1 ? 6 : 0;
  const pol = (a, rad) => [c + rad * Math.cos((a - 90) * Math.PI / 180), c + rad * Math.sin((a - 90) * Math.PI / 180)];
  const segs = [];
  for (let i = 0; i < n; i++) {
    const a0 = i * 360 / n + gap / 2, a1 = (i + 1) * 360 / n - gap / 2;
    const [x0, y0] = pol(a0, r), [x1, y1] = pol(a1, r);
    const large = a1 - a0 > 180 ? 1 : 0;
    let col = 'var(--line)';
    if (!sealed) col = 'var(--open)';
    else if (i < prog) col = 'var(--brass)';
    else if (i < t) col = '#AEB8BF';
    const d = n === 1 ? `M ${c} ${c - r} A ${r} ${r} 0 1 1 ${c - 0.01} ${c - r}` : `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`;
    segs.push(svg('path', { d, fill: 'none', stroke: col, 'stroke-width': 7, 'stroke-linecap': 'butt', class: 'dial-seg' }));
  }
  const ticks = [];
  for (let i = 0; i < 40; i++) { const [x0, y0] = pol(i * 9, 33), [x1, y1] = pol(i * 9, i % 5 ? 31 : 29); ticks.push(svg('line', { x1: x0, y1: y0, x2: x1, y2: y1, stroke: '#9AA6AE', 'stroke-width': i % 5 ? .6 : 1.1 })); }
  const body = sealed ? 'var(--sealed)' : 'var(--open)';
  return svg('svg', { viewBox: '0 0 100 100', width: size, height: size, role: 'img', 'aria-label': sealed ? `Sealed, ${prog} of ${t} unseal keys provided` : 'Unsealed' },
    svg('circle', { cx: c, cy: c, r: 46.5, fill: '#fff', stroke: 'var(--line)', 'stroke-width': 1 }),
    segs, ticks,
    svg('g', { class: 'dial-shackle', style: { transform: sealed ? 'none' : 'translateY(-5px)' } },
      svg('path', { d: 'M42 49 V42 a8 8 0 0 1 16 0 V49', fill: 'none', stroke: 'var(--ink)', 'stroke-width': 3.2, 'stroke-linecap': 'round' })),
    svg('rect', { x: 37, y: 48, width: 26, height: 20, rx: 3, fill: body }),
    svg('circle', { cx: 50, cy: 56, r: 2.6, fill: '#fff' }),
    svg('rect', { x: 49, y: 57, width: 2, height: 6, fill: '#fff' }));
}

// ---------------------------------------------------------------- boot & gates
async function sealStatus() { const r = await fetch('/v1/sys/seal-status'); return r.json(); }

async function boot() {
  clearInterval(S.pollT); clearInterval(S.liveT);
  let st;
  try { st = await sealStatus(); } catch { return renderGate(h('div', null, h('h2', null, 'Cannot reach the Coffer API'), h('p', { class: 'sub' }, 'Check that the server is running, then reload this page.'))); }
  S.seal = st;
  if (!st.initialized) return initScreen();
  if (st.sealed) return unsealScreen(st);
  if (!S.token) return loginScreen();
  try { S.me = (await api('GET', 'auth/token/lookup-self')).data; }
  catch (e) { S.token = ''; sessionStorage.removeItem('coffer.token'); return loginScreen(e.status === 403 ? 'Your session expired. Sign in again.' : e.message); }
  renderShell();
  S.pollT = setInterval(async () => {
    try { const s = await sealStatus(); if (s.sealed !== S.seal.sealed || !s.initialized) { S.seal = s; boot(); } else { S.seal = s; } } catch { /* transient */ }
  }, 5000);
}

function renderGate(inner) {
  const app = clear($('#app'));
  app.appendChild(h('div', { class: 'gate' }, h('div', { class: 'gate-box' }, inner)));
}

function initScreen() {
  const shares = h('input', { type: 'number', min: 1, max: 20, value: 5, name: 'shares' });
  const thr = h('input', { type: 'number', min: 1, max: 20, value: 3, name: 'threshold' });
  const form = h('form', { class: 'panel' },
    h('h2', { style: { marginBottom: '6px' } }, 'Initialize Coffer'),
    h('p', { class: 'muted small' }, 'Coffer generates a root key and splits it into unseal key shares. Any threshold of them can unseal; fewer reveal nothing.'),
    h('div', { class: 'form-row' }, field('Key shares', shares), field('Key threshold', thr)),
    h('button', { class: 'primary', type: 'submit', style: { width: '100%', justifyContent: 'center' } }, 'Initialize'));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const res = await api('PUT', 'sys/init', { secret_shares: +shares.value, secret_threshold: +thr.value });
      showInitResult(res, +thr.value);
    } catch (err) { fail(err); }
  });
  renderGate([dial(150, { n: 5, t: 3, sealed: true, progress: 0 }), h('div', { class: 'brand' }, 'Coffer'), h('p', { class: 'sub' }, 'Secrets and distributed storage behind one seal.'), form]);
}

function showInitResult(res, threshold) {
  const text = res.keys.map((k, i) => `Unseal key ${i + 1}: ${k}`).join('\n') + `\n\nInitial root token: ${res.root_token}\n`;
  renderGate(h('div', { class: 'panel wide' },
    h('h2', null, 'Save these keys now'),
    h('p', { class: 'small' }, `They are shown only once. Give each key to a different person. Coffer starts sealed and needs ${threshold} of them to unseal.`),
    h('ol', { class: 'keys-list' }, res.keys.map(k => h('li', null, copyable(k)))),
    h('h3', { style: { margin: '14px 0 6px' } }, 'Initial root token'),
    copyable(res.root_token),
    h('div', { style: { display: 'flex', gap: '8px', marginTop: '14px' } },
      h('button', { onclick: () => downloadText('coffer-init.txt', text) }, 'Download as text file'),
      h('button', { class: 'primary', onclick: boot }, 'Continue to unseal'))));
}

function unsealScreen(st) {
  const dialBox = h('div', null, dial(190, st));
  const key = h('input', { type: 'password', placeholder: 'Unseal key (hex or base64)', autocomplete: 'off' });
  const status = h('p', { class: 'muted small', style: { textAlign: 'center' } }, `${st.progress} of ${st.t} key${st.t > 1 ? "s" : ""} provided`);
  const form = h('form', { class: 'panel' },
    h('h2', { style: { marginBottom: '8px' } }, 'Unseal Coffer'),
    h('p', { class: 'small muted' }, 'Secrets, files and buckets are locked. Each key holder enters their key here; nothing is stored until the threshold is reached.'),
    field('Unseal key', key),
    h('div', { style: { display: 'flex', gap: '8px' } },
      h('button', { class: 'primary', type: 'submit', style: { flex: 1, justifyContent: 'center' } }, 'Submit key'),
      h('button', { type: 'button', onclick: async () => { await api('PUT', 'sys/unseal', { reset: true }); boot(); } }, 'Reset progress')));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!key.value.trim()) return;
    try {
      const s = await api('PUT', 'sys/unseal', { key: key.value.trim() });
      key.value = '';
      clear(dialBox).appendChild(dial(190, s));
      status.textContent = `${s.progress} of ${s.t} key${s.t > 1 ? "s" : ""} provided`;
      if (!s.sealed) { toast('Coffer is unsealed'); setTimeout(boot, 650); }
    } catch (err) { fail(err); boot(); }
  });
  renderGate([dialBox, h('div', { class: 'brand' }, 'Sealed'), status, form]);
}

function loginScreen(msg) {
  let method = 'token';
  const body = h('div');
  const tabs = h('div', { class: 'tabs' });
  const draw = () => {
    clear(tabs); clear(body);
    for (const [k, l] of [['token', 'Token'], ['userpass', 'Username'], ['approle', 'AppRole']])
      tabs.appendChild(h('button', { type: 'button', class: method === k ? 'on' : '', onclick: () => { method = k; draw(); } }, l));
    if (method === 'token') add(body, [field('Token', h('input', { type: 'password', name: 'token', autocomplete: 'off' }))]);
    if (method === 'userpass') add(body, [field('Username', h('input', { name: 'username', autocomplete: 'username' })), field('Password', h('input', { type: 'password', name: 'password', autocomplete: 'current-password' })), field('Mount path', h('input', { name: 'mount', value: 'userpass' }))]);
    if (method === 'approle') add(body, [field('Role ID', h('input', { name: 'role_id' })), field('Secret ID', h('input', { type: 'password', name: 'secret_id' })), field('Mount path', h('input', { name: 'mount', value: 'approle' }))]);
    body.querySelector('input')?.focus();
  };
  const form = h('form', { class: 'panel' }, tabs, body, h('button', { class: 'primary', type: 'submit', style: { width: '100%', justifyContent: 'center' } }, 'Sign in'));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = formVals(form);
    try {
      let tok = v.token;
      if (method === 'userpass') tok = (await api('POST', `auth/${v.mount}/login/${encodeURIComponent(v.username)}`, { password: v.password })).auth.client_token;
      if (method === 'approle') tok = (await api('POST', `auth/${v.mount}/login`, { role_id: v.role_id, secret_id: v.secret_id })).auth.client_token;
      const prev = S.token; S.token = tok;
      try { await api('GET', 'auth/token/lookup-self'); }
      catch (err) { S.token = prev; throw new Error(err.status === 403 ? 'That token is not valid. Copy the "Root token" value printed in the server terminal.' : err.message); }
      sessionStorage.setItem('coffer.token', tok);
      boot();
    } catch (err) { fail(err); }
  });
  draw();
  renderGate([dial(110, { n: S.seal.n, t: S.seal.t, sealed: false }), h('div', { class: 'brand' }, 'Coffer'), h('p', { class: 'sub' }, msg || 'Sign in to manage secrets and storage.'), form]);
}

// ---------------------------------------------------------------- shell & router
const NAV = [
  ['overview', 'Overview'], ['secrets', 'Secrets'], ['files', 'Files'], ['buckets', 'Buckets'],
  ['cluster', 'Storage cluster', 'Operate'], ['access', 'Access'], ['audit', 'Audit log'], ['system', 'System'],
];

function renderShell() {
  const app = clear($('#app'));
  const menu = h('nav', { class: 'menu', 'aria-label': 'Main' });
  for (const [k, label, group] of NAV) {
    if (group) menu.appendChild(h('div', { class: 'group' }, group));
    menu.appendChild(h('a', { href: '#/' + k, 'data-k': k }, label));
  }
  const who = S.me.display_name || 'token';
  const rail = h('aside', { class: 'rail' },
    h('div', { class: 'rail-head' },
      h('button', { class: 'dial-btn', title: 'Seal status', onclick: () => go('system') }, dial(46, S.seal)),
      h('div', null, h('div', { class: 'brand' }, 'Coffer'), h('div', { class: 'state', style: { color: 'var(--open)' } }, 'Unsealed'))),
    menu,
    h('div', { class: 'rail-foot' },
      h('div', null, 'Signed in as'), h('div', { class: 'who' }, who),
      h('div', { class: 'muted small' }, (S.me.policies || []).join(', ')),
      h('div', { class: 'row' }, h('button', { class: 'sm', onclick: logout }, 'Sign out'))));
  app.appendChild(h('div', { class: 'shell' }, rail, h('main', { id: 'main', tabindex: '-1' })));
  route();
}

// Signing out only forgets the token in this browser; it does not revoke it
// (revoking would destroy shared tokens such as the root token).
function logout() {
  S.token = ''; sessionStorage.removeItem('coffer.token'); boot();
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [p, q] = raw.split('?');
  return { parts: (p || 'overview').split('/').map(decodeURIComponent), q: new URLSearchParams(q || '') };
}
function go(page, params) { location.hash = '#/' + page + (params ? '?' + new URLSearchParams(params).toString() : ''); }
window.addEventListener('hashchange', () => { if ($('#main')) route(); });

const PAGES = {};
async function route() {
  clearInterval(S.liveT);
  const { parts, q } = parseHash();
  const page = PAGES[parts[0]] ? parts[0] : 'overview';
  document.querySelectorAll('nav.menu a').forEach(a => a.classList.toggle('active', a.dataset.k === page));
  const main = clear($('#main'));
  main.appendChild(h('p', { class: 'muted' }, 'Loading…'));
  try { await PAGES[page](main, parts.slice(1), q); }
  catch (e) { clear(main).appendChild(denied(e, 'this page')); }
}
function head(title, desc, ...actions) {
  return h('div', { class: 'page-head' }, h('div', null, h('h1', null, title), desc ? h('p', null, desc) : null), h('div', { class: 'actions' }, actions));
}
async function uiMounts() { const r = await api('GET', 'sys/internal/ui/mounts'); S.mounts = r.data; return r.data; }

// ---------------------------------------------------------------- overview
PAGES.overview = async (main) => {
  const [mounts, storage, events] = await Promise.all([
    uiMounts().catch(() => null),
    api('GET', 'sys/storage/status').then(r => r.data).catch(() => null),
    api('GET', 'sys/audit-events?limit=80').then(r => r.data.events.filter(ev => !(ev.operation === 'read' && /^(sys\/internal|sys\/storage\/status|auth\/token\/lookup-self|sys\/audit|sys\/mounts|sys\/key-status)/.test(ev.path))).slice(0, 12)).catch(() => null),
  ]);
  clear(main);
  main.appendChild(head('Overview', `Cluster “${S.seal.cluster_name}” is unsealed. Key threshold ${S.seal.t} of ${S.seal.n}.`,
    h('button', { onclick: () => go('secrets') }, 'Store a secret'),
    h('button', { onclick: () => go('files') }, 'Upload files'),
    h('button', { class: 'primary', onclick: () => go('buckets') }, 'Create a bucket')));
  const topo = storage?.topology, fsS = storage?.filer;
  const cell = (v, k) => h('div', null, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
  main.appendChild(h('div', { class: 'strip' },
    cell(mounts ? Object.keys(mounts.secret).length : '—', 'Secrets engines'),
    cell(fsS ? fsS.files.toLocaleString() : '—', 'Files'),
    cell(fsS ? fmtBytes(fsS.bytes) : '—', 'Stored data'),
    cell(fsS ? fsS.encrypted_files.toLocaleString() : '—', 'Encrypted files'),
    cell(fsS ? fsS.buckets : '—', 'Buckets'),
    cell(topo ? `${topo.totals.alive_nodes || 0} / ${topo.totals.nodes || 0}` : '—', 'Volume servers up'),
    cell(topo ? (topo.totals.volumes || 0) : '—', 'Volumes')));
  const act = h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Recent activity'), h('a', { href: '#/audit' }, 'Open audit log')));
  if (!events) act.appendChild(h('p', { class: 'muted' }, 'Your token cannot read the audit log.'));
  else act.appendChild(table(['When', 'Where', 'Action', 'Path', 'Result'], events.length ? events.map(ev => h('tr', null,
    h('td', { class: 'muted small', style: { whiteSpace: 'nowrap' } }, ago(ev.time)), h('td', null, tag({ request: 'secrets', fs: 'files', s3: 'S3' }[ev.type] || ev.type)),
    h('td', null, ev.operation), h('td', { class: 'mono' }, ev.path), h('td', null, tag(ev.status, ev.status >= 400 ? 'bad' : 'ok')))) : emptyRow(5, 'No activity yet.')));
  const st = h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Storage'), h('a', { href: '#/cluster' }, 'Manage cluster')));
  if (!topo) st.appendChild(h('p', { class: 'muted' }, storage?.master_error || 'Your token cannot read storage status.'));
  else {
    const used = topo.totals.used_bytes || 0, slots = topo.totals.slots || 0;
    add(st, [
      h('p', null, `${topo.totals.volumes || 0} of ${slots} volume slots in use, default replication ${topo.default_replication}, volume size limit ${fmtBytes(topo.volume_size_limit)}.`),
      h('div', { class: 'progress', style: { marginBottom: '8px' } }, h('i', { style: { width: Math.min(100, slots ? (topo.totals.volumes || 0) / slots * 100 : 0) + '%' } })),
      h('p', { class: 'muted small' }, `${fmtBytes(used)} on disk across all replicas.`)]);
  }
  main.appendChild(h('div', { class: 'cols' }, act, st));
};

// ---------------------------------------------------------------- secrets
const ENGINE_TYPES = [['kv-v2', 'Key/value (versioned)'], ['kv', 'Key/value (simple)'], ['transit', 'Transit encryption'], ['pki', 'PKI certificates'], ['totp', 'TOTP one-time codes']];

PAGES.secrets = async (main, parts, q) => {
  const mounts = (await uiMounts()).secret;
  const names = Object.keys(mounts).sort();
  let cur = parts[0] ? parts[0] + '/' : '';
  if (!mounts[cur]) cur = names.find(n => mounts[n].type.startsWith('kv')) || names[0];
  clear(main);
  main.appendChild(head('Secrets', 'Secrets engines mounted in this cluster. Every value is encrypted by the barrier before it touches disk.',
    h('button', { onclick: () => enableEngineDlg().then(p => p && go('secrets/' + p)) }, 'Enable engine')));
  const nav = h('div', { class: 'panel list-nav', style: { padding: '8px' } }, names.map(n =>
    h('a', { href: '#/secrets/' + n.replace(/\/$/, ''), class: n === cur ? 'on' : '' }, h('span', null, n), tag(mounts[n].type))));
  const pane = h('div');
  main.appendChild(h('div', { class: 'split' }, nav, pane));
  if (!cur) { pane.appendChild(h('div', { class: 'panel empty' }, 'No secrets engines are visible to your token.')); return; }
  const m = mounts[cur];
  const view = { 'kv-v2': kvView, kv: m.options?.version === '2' ? kvView : kv1View, cubbyhole: kv1View, transit: transitView, pki: pkiView, totp: totpView }[m.type];
  if (!view) { pane.appendChild(h('div', { class: 'panel' }, 'This engine type has no console view.')); return; }
  await view(pane, cur, m, q);
};

async function enableEngineDlg() {
  const body = h('div',
    field('Type', h('select', { name: 'type' }, ENGINE_TYPES.map(([v, l]) => h('option', { value: v }, l)))),
    field('Path', h('input', { name: 'path', placeholder: 'e.g. team-secrets' }), 'Where the engine is mounted. Defaults to the type name.'),
    field('Description', h('input', { name: 'description' })));
  return modal({ title: 'Enable a secrets engine', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Enable engine', primary: true, onClick: async () => {
    const v = formVals(body); const p = (v.path || v.type).replace(/^\/+|\/+$/g, '');
    await api('POST', 'sys/mounts/' + p, { type: v.type, description: v.description });
    toast(`Enabled ${v.type} at ${p}/`); return p;
  } }] });
}

// --- KV editor dialog shared by v1 and v2
function kvEditor(initial) {
  let jsonMode = false;
  const rows = h('div', { class: 'kv-rows' });
  const ta = h('textarea', { class: 'hidden', rows: 10 });
  const addRow = (k = '', v = '') => {
    const val = typeof v === 'string' ? v : JSON.stringify(v);
    const r = h('div', { class: 'kv-row' }, h('input', { placeholder: 'key', value: k }), h('input', { placeholder: 'value', value: val }),
      h('button', { type: 'button', class: 'ghost', 'aria-label': 'Remove row', onclick: () => r.remove() }, 'Remove'));
    rows.appendChild(r);
  };
  const entries = Object.entries(initial || {});
  entries.length ? entries.forEach(([k, v]) => addRow(k, v)) : addRow();
  const read = () => {
    if (jsonMode) { const o = JSON.parse(ta.value || '{}'); if (typeof o !== 'object' || Array.isArray(o)) throw new Error('JSON must be an object'); return o; }
    const o = {};
    rows.querySelectorAll('.kv-row').forEach(r => { const [k, v] = r.querySelectorAll('input'); if (k.value.trim()) o[k.value.trim()] = v.value; });
    return o;
  };
  const toggle = h('button', { type: 'button', class: 'sm', onclick: () => {
    try {
      if (!jsonMode) { ta.value = JSON.stringify(read(), null, 2); } else { const o = read(); clear(rows); const e = Object.entries(o); e.length ? e.forEach(([k, v]) => addRow(k, v)) : addRow(); }
      jsonMode = !jsonMode; rows.classList.toggle('hidden', jsonMode); ta.classList.toggle('hidden', !jsonMode); addBtn.classList.toggle('hidden', jsonMode);
      toggle.textContent = jsonMode ? 'Edit as fields' : 'Edit as JSON';
    } catch (e) { fail(e); }
  } }, 'Edit as JSON');
  const addBtn = h('button', { type: 'button', class: 'sm', onclick: () => addRow() }, 'Add field');
  return { el: h('div', null, rows, ta, h('div', { style: { display: 'flex', gap: '8px' } }, addBtn, toggle)), read };
}

function secretTable(data) {
  const entries = Object.entries(data || {});
  return table(['Key', 'Value', ''], entries.length ? entries.map(([k, v]) => {
    const val = typeof v === 'string' ? v : JSON.stringify(v);
    const cell = h('span', { class: 'secret-val' }, '••••••••');
    let shown = false;
    return h('tr', null, h('td', { style: { fontWeight: 600 } }, k), h('td', null, cell),
      h('td', { class: 'actions' }, h('button', { class: 'sm ghost', onclick: (e) => { shown = !shown; cell.textContent = shown ? val : '••••••••'; e.target.textContent = shown ? 'Hide' : 'Reveal'; } }, 'Reveal'), copyBtn(val)));
  }) : emptyRow(3, 'This secret has no fields.'));
}

function crumbsFor(mount, path, base) {
  const segs = path.split('/').filter(Boolean);
  const out = [h('a', { href: `#/secrets/${mount.replace(/\/$/, '')}` }, mount)];
  let acc = '';
  segs.forEach((s, i) => {
    acc += s + '/';
    out.push(h('span', { class: 'sep' }, '/'));
    out.push(i === segs.length - 1 && !path.endsWith('/') ? h('span', { class: 'cur' }, s) : h('a', { href: `#/secrets/${mount.replace(/\/$/, '')}?path=${encodeURIComponent(acc)}` }, s));
  });
  return h('div', { class: 'crumbs' }, out);
}

async function kvView(pane, mount, m, q) {
  const path = q.get('path') || '';
  const isSecret = path && !path.endsWith('/');
  if (isSecret) return kvSecret(pane, mount, path, q);
  const keys = await list(`${mount}metadata/${path}`);
  const create = () => kvCreateDlg(mount, path);
  pane.appendChild(h('div', { class: 'panel' },
    h('div', { class: 'panel-head' }, crumbsFor(mount, path), h('button', { class: 'primary', onclick: create }, 'Create secret')),
    table(['Name', ''], keys.length ? keys.map(k => h('tr', { class: 'clickable', onclick: () => go('secrets/' + mount.replace(/\/$/, ''), { path: path + k }) },
      h('td', null, k.endsWith('/') ? h('strong', null, k) : k), h('td', { class: 'muted small actions' }, k.endsWith('/') ? 'folder' : 'secret')))
      : emptyRow(2, path ? 'This folder is empty.' : 'No secrets yet. Paths with slashes create folders, e.g. app/prod/db.', h('button', { onclick: create }, 'Create secret')))));
}

function kvCreateDlg(mount, prefix, v1) {
  const ed = kvEditor({});
  const pathIn = h('input', { value: prefix, placeholder: 'app/prod/database' });
  return modal({ title: 'Create secret', wide: true, body: h('div', null, field('Path', pathIn, `Stored under ${mount}`), ed.el),
    actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save secret', primary: true, onClick: async () => {
      const p = pathIn.value.trim().replace(/^\/+/, '');
      if (!p || p.endsWith('/')) throw new Error('Enter a secret path that does not end with /');
      const data = ed.read();
      if (!Object.keys(data).length) throw new Error('Add at least one field');
      if (v1) await api('POST', mount + p, data); else await api('POST', `${mount}data/${p}`, { data });
      toast('Secret saved'); go('secrets/' + mount.replace(/\/$/, ''), { path: p });
    } }] });
}

async function kvSecret(pane, mount, path, q) {
  const ver = q.get('version');
  const [meta, cur] = await Promise.all([
    api('GET', `${mount}metadata/${path}`).then(r => r.data),
    api('GET', `${mount}data/${path}${ver ? '?version=' + ver : ''}`).then(r => r.data).catch(e => e.status === 404 ? null : Promise.reject(e)),
  ]);
  const shown = ver ? +ver : meta.current_version;
  const vmeta = meta.versions[String(shown)] || {};
  const deleted = vmeta.deletion_time, destroyed = vmeta.destroyed;
  const base = 'secrets/' + mount.replace(/\/$/, '');
  const refresh = () => route();
  const edit = async () => {
    const ed = kvEditor(cur?.data || {});
    await modal({ title: 'Create new version', wide: true, body: h('div', null, h('p', { class: 'small muted' }, `Saving creates version ${meta.current_version + 1}. Older versions stay available.`), ed.el),
      actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save version', primary: true, onClick: async () => {
        await api('POST', `${mount}data/${path}`, { data: ed.read(), options: { cas: meta.current_version } });
        toast('New version saved'); go(base, { path });
      } }] });
  };
  const vAct = async (action, v) => {
    if (action === 'destroy' && !await confirmDlg('Destroy version ' + v, 'Destroying permanently removes this version’s data. It cannot be undone.', 'Destroy')) return;
    try { await api('POST', `${mount}${action}/${path}`, { versions: [v] }); toast(`Version ${v} ${action === 'delete' ? 'deleted' : action + 'ed'}`); refresh(); } catch (e) { fail(e); }
  };
  const nums = Object.keys(meta.versions).map(Number).sort((a, b) => b - a);
  pane.appendChild(h('div', { class: 'panel' },
    h('div', { class: 'panel-head' }, crumbsFor(mount, path),
      h('div', { class: 'actions', style: { display: 'flex', gap: '8px' } },
        h('button', { onclick: edit }, 'Create new version'),
        h('button', { class: 'danger', onclick: async () => { if (await confirmDlg('Delete all versions', `Permanently remove ${path} and its whole history?`, 'Delete everything')) { await api('DELETE', `${mount}metadata/${path}`).catch(fail); go(base, { path: path.includes('/') ? path.slice(0, path.lastIndexOf('/') + 1) : '' }); } } }, 'Delete secret'))),
    h('p', { class: 'small muted' }, `Version ${shown} of ${meta.current_version}, created ${fmtTime(vmeta.created_time)}.`),
    destroyed ? h('p', null, tag('destroyed', 'bad'), ' This version’s data was permanently destroyed.')
      : deleted ? h('p', null, tag('deleted', 'bad'), ' This version is soft-deleted. ', h('button', { class: 'sm', onclick: () => vAct('undelete', shown) }, 'Restore it'))
        : secretTable(cur?.data)));
  pane.appendChild(h('div', { class: 'panel' }, h('h3', null, 'Version history'),
    table(['Version', 'Created', 'State', ''], nums.map(n => {
      const v = meta.versions[String(n)];
      const state = v.destroyed ? tag('destroyed', 'bad') : v.deletion_time ? tag('deleted', 'bad') : n === meta.current_version ? tag('current', 'brass') : tag('available');
      return h('tr', null, h('td', null, h('a', { href: `#/${base}?path=${encodeURIComponent(path)}&version=${n}` }, 'v' + n)), h('td', { class: 'small' }, fmtTime(v.created_time)), h('td', null, state),
        h('td', { class: 'actions' },
          !v.destroyed && !v.deletion_time ? h('button', { class: 'sm ghost', onclick: () => vAct('delete', n) }, 'Delete') : null,
          !v.destroyed && v.deletion_time ? h('button', { class: 'sm ghost', onclick: () => vAct('undelete', n) }, 'Restore') : null,
          !v.destroyed ? h('button', { class: 'sm ghost', onclick: () => vAct('destroy', n) }, 'Destroy') : null));
    }))));
}

async function kv1View(pane, mount, m, q) {
  const path = q.get('path') || '';
  const base = 'secrets/' + mount.replace(/\/$/, '');
  if (path && !path.endsWith('/')) {
    const data = (await api('GET', mount + path).catch(e => e.status === 404 ? { data: null } : Promise.reject(e))).data;
    const edit = async () => {
      const ed = kvEditor(data || {});
      await modal({ title: 'Edit secret', wide: true, body: ed.el, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save secret', primary: true, onClick: async () => { await api('POST', mount + path, ed.read()); toast('Secret saved'); route(); } }] });
    };
    pane.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, crumbsFor(mount, path),
      h('div', { style: { display: 'flex', gap: '8px' } }, h('button', { onclick: edit }, 'Edit'),
        h('button', { class: 'danger', onclick: async () => { if (await confirmDlg('Delete secret', `Delete ${path}?`)) { await api('DELETE', mount + path); go(base); } } }, 'Delete'))),
      m.type === 'cubbyhole' ? h('p', { class: 'small muted' }, 'Cubbyhole data belongs to your token alone and disappears when the token is revoked.') : null,
      secretTable(data)));
    return;
  }
  const keys = await list(mount + path);
  pane.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, crumbsFor(mount, path), h('button', { class: 'primary', onclick: () => kvCreateDlg(mount, path, true) }, 'Create secret')),
    table(['Name'], keys.length ? keys.map(k => h('tr', { class: 'clickable', onclick: () => go(base, { path: path + k }) }, h('td', null, k)))
      : emptyRow(1, m.type === 'cubbyhole' ? 'Your cubbyhole is empty. Data here is private to your token.' : 'No secrets yet.'))));
}

// --- transit
async function transitView(pane, mount, m, q) {
  const keys = await list(mount + 'keys');
  const sel = q.get('key') || keys[0];
  const base = 'secrets/' + mount.replace(/\/$/, '');
  const createKey = () => {
    const body = h('div', field('Key name', h('input', { name: 'name', placeholder: 'payments' })),
      field('Type', h('select', { name: 'type' }, [['aes256-gcm96', 'AES-256-GCM (encrypt/decrypt)'], ['aes128-gcm96', 'AES-128-GCM'], ['ed25519', 'Ed25519 (sign/verify)'], ['ecdsa-p256', 'ECDSA P-256 (sign/verify)'], ['hmac', 'HMAC only']].map(([v, l]) => h('option', { value: v }, l)))),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'derived' }), 'Derive per-context keys (requires a context on every call)'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'exportable' }), 'Allow exporting key material'));
    modal({ title: 'Create encryption key', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create key', primary: true, onClick: async () => {
      const v = formVals(body); if (!v.name) throw new Error('Name is required');
      await api('POST', `${mount}keys/${v.name}`, { type: v.type, derived: v.derived, exportable: v.exportable });
      toast('Key created'); go(base, { key: v.name });
    } }] });
  };
  const nav = h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h3', null, 'Keys'), h('button', { class: 'sm primary', onclick: createKey }, 'Create key')),
    keys.length ? h('div', { class: 'list-nav' }, keys.map(k => h('a', { href: `#/${base}?key=${encodeURIComponent(k)}`, class: k === sel ? 'on' : '' }, k)))
      : h('div', { class: 'empty' }, 'No keys yet. Keys used by encrypted folders and buckets appear here too.'));
  pane.appendChild(nav);
  if (!sel) return;
  const info = (await api('GET', `${mount}keys/${sel}`)).data;
  const latest = info.latest_version;
  const keyPanel = h('div', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, info.name),
      h('div', { style: { display: 'flex', gap: '8px' } },
        h('button', { onclick: async () => { await api('POST', `${mount}keys/${sel}/rotate`).catch(fail); toast('Key rotated; new data uses version ' + (latest + 1)); route(); } }, 'Rotate key'),
        h('button', { onclick: async () => { await api('POST', `${mount}keys/${sel}/config`, { deletion_allowed: !info.deletion_allowed }).catch(fail); route(); } }, info.deletion_allowed ? 'Protect from deletion' : 'Allow deletion'),
        info.deletion_allowed ? h('button', { class: 'danger', onclick: async () => {
          if (await confirmDlg('Delete key ' + sel, 'Anything encrypted with this key — including files in encrypted folders — becomes unreadable forever.', 'Delete key')) { await api('DELETE', `${mount}keys/${sel}`).catch(fail); go(base); }
        } }, 'Delete') : null)),
    h('p', { class: 'small' }, tag(info.type, 'brass'), ' ', info.derived ? tag('derived') : null, ' ', info.exportable ? tag('exportable') : null,
      ` Latest version ${latest}. Decryption allowed from version ${info.min_decryption_version}.`),
    table(['Version', 'Created'], Object.entries(info.keys).sort((a, b) => b[0] - a[0]).map(([v, c]) => h('tr', null, h('td', null, 'v' + v), h('td', { class: 'small' }, fmtTime(typeof c === 'number' ? c : c.creation_time))))));
  pane.appendChild(keyPanel);
  pane.appendChild(transitTools(mount, info));
}

function transitTools(mount, info) {
  const name = info.name;
  const ops = info.supports_encryption ? [['encrypt', 'Encrypt'], ['decrypt', 'Decrypt'], ['rewrap', 'Rewrap'], ['datakey', 'Data key'], ['hmac', 'HMAC']] : info.supports_signing ? [['sign', 'Sign'], ['verify', 'Verify'], ['hmac', 'HMAC']] : [['hmac', 'HMAC']];
  let op = ops[0][0];
  const tabs = h('div', { class: 'tabs' });
  const body = h('div');
  const out = h('div');
  const ctxIn = () => info.derived ? field('Context', h('input', { name: 'context', placeholder: 'e.g. customer-42' }), 'Text; encoded for you') : null;
  const draw = () => {
    clear(tabs); clear(body); clear(out);
    ops.forEach(([k, l]) => tabs.appendChild(h('button', { class: op === k ? 'on' : '', onclick: () => { op = k; draw(); } }, l)));
    const bigIn = (n, label, ph) => field(label, h('textarea', { name: n, rows: 4, placeholder: ph }));
    if (op === 'encrypt') add(body, [bigIn('plaintext', 'Plaintext', 'Text to encrypt'), ctxIn()]);
    if (op === 'decrypt' || op === 'rewrap') add(body, [bigIn('ciphertext', 'Ciphertext', 'coffer:v1:…'), ctxIn()]);
    if (op === 'datakey') add(body, [h('p', { class: 'small muted' }, 'Generates a fresh 256-bit data key and returns it both in plaintext and wrapped by this key, for envelope encryption in your own apps.'), ctxIn()]);
    if (op === 'hmac' || op === 'sign') add(body, [bigIn('input', 'Input', 'Text')]);
    if (op === 'verify') add(body, [bigIn('input', 'Input', 'Text'), field('Signature', h('input', { name: 'signature', placeholder: 'coffer:v1:…' }))]);
    body.appendChild(h('button', { class: 'primary', onclick: run }, ops.find(o => o[0] === op)[1]));
  };
  const run = async () => {
    const v = formVals(body);
    const ctx = v.context ? b64e(v.context) : undefined;
    try {
      let r, show;
      if (op === 'encrypt') { r = await api('POST', `${mount}encrypt/${name}`, { plaintext: b64e(v.plaintext || ''), context: ctx }); show = [['Ciphertext', r.data.ciphertext]]; }
      if (op === 'decrypt') { r = await api('POST', `${mount}decrypt/${name}`, { ciphertext: v.ciphertext, context: ctx }); show = [['Plaintext', b64d(r.data.plaintext)]]; }
      if (op === 'rewrap') { r = await api('POST', `${mount}rewrap/${name}`, { ciphertext: v.ciphertext, context: ctx }); show = [['Ciphertext', r.data.ciphertext]]; }
      if (op === 'datakey') { r = await api('POST', `${mount}datakey/plaintext/${name}`, { context: ctx }); show = [['Plaintext key (base64)', r.data.plaintext], ['Wrapped key', r.data.ciphertext]]; }
      if (op === 'hmac') { r = await api('POST', `${mount}hmac/${name}`, { input: b64e(v.input || '') }); show = [['HMAC', r.data.hmac]]; }
      if (op === 'sign') { r = await api('POST', `${mount}sign/${name}`, { input: b64e(v.input || '') }); show = [['Signature', r.data.signature]]; }
      if (op === 'verify') { r = await api('POST', `${mount}verify/${name}`, { input: b64e(v.input || ''), signature: v.signature }); show = [['Result', r.data.valid ? 'Signature is valid' : 'Signature is NOT valid']]; }
      clear(out); show.forEach(([l, val]) => add(out, [h('h3', { style: { margin: '12px 0 6px' } }, l), copyable(val)]));
    } catch (e) { fail(e); }
  };
  draw();
  return h('div', { class: 'panel' }, h('h3', null, 'Use this key'), tabs, body, out);
}

// --- pki
async function pkiView(pane, mount) {
  const ca = await api('GET', `${mount}cert/ca`).then(r => r.data).catch(() => null);
  if (!ca) {
    const body = h('div', field('Common name', h('input', { name: 'common_name', placeholder: 'Example Corp Root CA' })),
      h('div', { class: 'form-row' }, field('Validity', h('input', { name: 'ttl', value: '87600h' }), 'e.g. 87600h = 10 years'),
        field('Key type', h('select', { name: 'key_type' }, h('option', { value: 'ec' }, 'ECDSA P-256'), h('option', { value: 'rsa' }, 'RSA 2048')))),
      field('Organization', h('input', { name: 'organization' })));
    pane.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Create a certificate authority'),
      h('p', { class: 'muted' }, 'This mount has no CA yet. Generate a root CA; its private key never leaves Coffer.'), body,
      h('button', { class: 'primary', onclick: async () => { try { await api('POST', `${mount}root/generate/internal`, formVals(body)); toast('Root CA created'); route(); } catch (e) { fail(e); } } }, 'Generate root CA')));
    return;
  }
  const roles = await list(`${mount}roles`);
  const serials = await list(`${mount}certs`);
  const certs = await Promise.all(serials.slice(-100).reverse().map(s => api('GET', `${mount}cert/${s}`).then(r => r.data).catch(() => null)));
  const roleDlg = (name, cur) => {
    cur = cur || {};
    const body = h('div', field('Role name', h('input', { name: 'name', value: name || '', disabled: !!name })),
      field('Allowed domains', h('input', { name: 'allowed_domains', value: (cur.allowed_domains || []).join(', '), placeholder: 'example.com, internal.example.com' })),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'allow_subdomains', checked: name ? cur.allow_subdomains : true }), 'Allow subdomains (api.example.com)'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'allow_bare_domains', checked: cur.allow_bare_domains }), 'Allow the bare domain itself'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'allow_any_name', checked: cur.allow_any_name }), 'Allow any name (not recommended)'),
      h('div', { class: 'form-row' }, field('Default TTL', h('input', { name: 'ttl', value: cur.ttl ? cur.ttl + 's' : '720h' })), field('Max TTL', h('input', { name: 'max_ttl', value: cur.max_ttl ? cur.max_ttl + 's' : '8760h' }))));
    modal({ title: name ? 'Edit role ' + name : 'Create role', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save role', primary: true, onClick: async () => {
      const v = formVals(body); const n = name || v.name; if (!n) throw new Error('Role name is required');
      delete v.name; await api('POST', `${mount}roles/${n}`, v); toast('Role saved'); route();
    } }] });
  };
  const issueDlg = () => {
    const body = h('div', field('Role', h('select', { name: 'role' }, roles.map(r => h('option', null, r)))),
      field('Common name', h('input', { name: 'common_name', placeholder: 'api.example.com' })),
      field('Alternative names', h('input', { name: 'alt_names', placeholder: 'www.example.com, 10.0.0.5' })),
      field('TTL', h('input', { name: 'ttl', placeholder: 'role default' })));
    modal({ title: 'Issue certificate', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Issue certificate', primary: true, onClick: async () => {
      const v = formVals(body); const role = v.role; delete v.role;
      const r = (await api('POST', `${mount}issue/${role}`, v)).data;
      const bundle = r.certificate + '\n' + r.private_key + '\n' + r.issuing_ca;
      setTimeout(() => modal({ title: 'Certificate issued', wide: true, body: h('div', null,
        h('p', { class: 'small' }, `Serial ${r.serial_number}, valid until ${fmtTime(r.expiration)}. The private key is not stored by Coffer — save it now.`),
        h('h3', null, 'Certificate'), h('pre', { class: 'block' }, r.certificate), h('h3', null, 'Private key'), h('pre', { class: 'block' }, r.private_key),
        h('button', { onclick: () => downloadText(v.common_name + '.pem', bundle) }, 'Download PEM bundle')), onClose: route }), 50);
    } }] });
  };
  pane.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Certificate authority'),
    h('div', { style: { display: 'flex', gap: '8px' } }, h('a', { class: 'btn', href: `/v1/${mount}ca/pem`, download: 'ca.pem' }, 'Download CA'), h('a', { class: 'btn', href: `/v1/${mount}crl/pem`, download: 'crl.pem' }, 'Download CRL'))),
    h('details', null, h('summary', { class: 'small' }, `Root certificate, serial ${ca.serial_number}`), h('pre', { class: 'block', style: { marginTop: '8px' } }, ca.certificate))));
  pane.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h3', null, 'Roles'), h('div', { style: { display: 'flex', gap: '8px' } }, h('button', { onclick: () => roleDlg() }, 'Create role'), h('button', { class: 'primary', disabled: !roles.length, onclick: issueDlg }, 'Issue certificate'))),
    table(['Role', ''], roles.length ? roles.map(r => h('tr', null, h('td', null, r), h('td', { class: 'actions' },
      h('button', { class: 'sm ghost', onclick: async () => roleDlg(r, (await api('GET', `${mount}roles/${r}`)).data) }, 'Edit'),
      h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Delete role', `Delete role ${r}? Issued certificates stay valid.`)) { await api('DELETE', `${mount}roles/${r}`); route(); } } }, 'Delete'))))
      : emptyRow(2, 'Create a role to define which names certificates may cover.'))));
  pane.appendChild(h('div', { class: 'panel' }, h('h3', null, 'Issued certificates'),
    table(['Common name', 'Serial', 'Expires', 'State', ''], certs.filter(Boolean).length ? certs.filter(Boolean).map(c => h('tr', null,
      h('td', null, c.common_name), h('td', { class: 'mono small' }, c.serial_number.slice(0, 23) + '…'), h('td', { class: 'small' }, fmtTime(c.expiration)),
      h('td', null, c.revocation_time ? tag('revoked', 'bad') : new Date(c.expiration) < new Date() ? tag('expired') : tag('valid', 'ok')),
      h('td', { class: 'actions' }, !c.revocation_time ? h('button', { class: 'sm ghost', onclick: async () => {
        if (await confirmDlg('Revoke certificate', `Revoke ${c.common_name}? It is added to the CRL immediately.`, 'Revoke')) { await api('POST', `${mount}revoke`, { serial_number: c.serial_number }).catch(fail); route(); }
      } }, 'Revoke') : null))) : emptyRow(5, 'No certificates issued yet.'))));
}

// --- totp
async function totpView(pane, mount, m, q) {
  const keys = await list(mount + 'keys');
  const create = () => {
    const body = h('div', field('Key name', h('input', { name: 'name' })), field('Issuer', h('input', { name: 'issuer', placeholder: 'Coffer' })),
      field('Account name', h('input', { name: 'account_name', placeholder: 'alice@example.com' })),
      field('Existing secret (optional)', h('input', { name: 'key', placeholder: 'base32 secret from another service' }), 'Leave empty to generate a new secret'));
    modal({ title: 'Add TOTP key', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Add key', primary: true, onClick: async () => {
      const v = formVals(body); const n = v.name; delete v.name;
      if (!v.key) { v.generate = true; delete v.key; }
      const r = await api('POST', `${mount}keys/${n}`, v);
      if (r.data?.url) setTimeout(() => modal({ title: 'Scan into an authenticator app', body: h('div', null, h('p', { class: 'small' }, 'Add this URL or secret to your authenticator. It is shown only once.'), copyable(r.data.url), copyable(r.data.secret)), onClose: route }), 50);
      else route();
    } }] });
  };
  const rows = await Promise.all(keys.map(async k => {
    const codeCell = h('td', { class: 'mono' }, '······');
    return h('tr', null, h('td', null, k), codeCell, h('td', { class: 'actions' },
      h('button', { class: 'sm', onclick: async () => { const r = (await api('GET', `${mount}code/${k}`)).data; codeCell.textContent = `${r.code}  (${r.seconds_remaining}s)`; } }, 'Show code'),
      h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Delete key', `Delete TOTP key ${k}?`)) { await api('DELETE', `${mount}keys/${k}`); route(); } } }, 'Delete')));
  }));
  const vbody = h('div', { class: 'form-row' }, field('Key', h('select', { name: 'k' }, keys.map(k => h('option', null, k)))), field('Code', h('input', { name: 'code', inputmode: 'numeric' })));
  pane.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'One-time password keys'), h('button', { class: 'primary', onclick: create }, 'Add key')),
    table(['Key', 'Current code', ''], rows.length ? rows : emptyRow(3, 'No keys yet.'))));
  if (keys.length) pane.appendChild(h('div', { class: 'panel' }, h('h3', null, 'Check a code'), vbody, h('button', { onclick: async () => {
    const v = formVals(vbody); try { const r = (await api('POST', `${mount}code/${v.k}`, { code: v.code })).data; toast(r.valid ? 'Code is valid' : 'Code is not valid' + (r.reason ? ': ' + r.reason : ''), !r.valid); } catch (e) { fail(e); }
  } }, 'Check code')));
}

// ---------------------------------------------------------------- files
const parentOf = (p) => p === '/' ? '/' : (p.slice(0, p.lastIndexOf('/')) || '/');
const joinP = (d, n) => (d === '/' ? '' : d) + '/' + n;

PAGES.files = async (main, parts, q) => {
  const dir = q.get('path') || '/';
  const res = await fsApi('GET', dir);
  clear(main);
  const inBucket = dir.startsWith('/buckets/');
  main.appendChild(head('Files', inBucket ? `This folder is S3 bucket “${dir.split('/')[2]}”. Changes here are visible to S3 clients immediately.` : 'Browse, upload and share files stored across the volume servers.',
    h('button', { onclick: () => newFolder(dir) }, 'New folder'),
    dir !== '/' ? h('button', { onclick: () => folderSettings(dir, res) }, 'Folder settings') : null,
    h('button', { class: 'primary', onclick: () => picker.click() }, 'Upload files')));
  const picker = h('input', { type: 'file', multiple: true, class: 'hidden', onchange: () => { upload(dir, [...picker.files]); picker.value = ''; } });
  main.appendChild(picker);

  const segs = dir.split('/').filter(Boolean);
  const crumbs = h('div', { class: 'crumbs' }, h('a', { href: '#/files' }, 'All files'));
  let acc = '';
  segs.forEach((s, i) => { acc += '/' + s; crumbs.appendChild(h('span', { class: 'sep' }, '/')); crumbs.appendChild(i === segs.length - 1 ? h('span', { class: 'cur' }, s) : h('a', { href: '#/files?path=' + encodeURIComponent(acc) }, s)); });

  const eff = res.effective_config || {};
  const flags = h('div', { class: 'small', style: { display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px' } },
    eff.encryption_key ? tag('New files encrypted with key ' + eff.encryption_key, 'brass') : null,
    eff.replication ? tag('Replication ' + eff.replication) : null, eff.ttl ? tag('Files expire after ' + eff.ttl) : null);

  const rows = res.entries.map(e => {
    const open = () => e.is_dir ? go('files', { path: e.path }) : details(e.path);
    return h('tr', { class: 'clickable', onclick: (ev) => { if (!ev.target.closest('button')) open(); } },
      h('td', null, h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '8px' } }, fileGlyph(e.is_dir), e.is_dir ? h('strong', null, e.name) : e.name)),
      h('td', { class: 'num small' }, e.is_dir ? '' : fmtBytes(e.size)),
      h('td', { class: 'small muted' }, fmtTime(e.mtime)),
      h('td', null, e.encrypted ? tag('encrypted', 'brass') : null, ' ', e.config?.encryption_key ? tag('encrypts new files', 'brass') : null, ' ', e.ttl ? tag('ttl ' + e.ttl) : null),
      h('td', { class: 'actions' },
        !e.is_dir ? h('button', { class: 'sm ghost', onclick: () => download(e.path) }, 'Download') : null,
        !e.is_dir ? h('button', { class: 'sm ghost', onclick: () => shareDlg(e.path) }, 'Share') : null,
        h('button', { class: 'sm ghost', onclick: () => moveDlg(e) }, 'Move'),
        h('button', { class: 'sm ghost', onclick: () => removeEntry(e) }, 'Delete')));
  });
  const zone = h('div', { class: 'panel dropzone' }, h('div', { class: 'panel-head' }, crumbs, h('button', { class: 'sm ghost', onclick: route }, 'Refresh')), flags,
    table(['Name', { t: 'Size', cls: 'num' }, 'Modified', '', ''], rows.length ? rows : emptyRow(5, 'This folder is empty. Drop files here or use Upload files.')),
    res.more ? h('p', { class: 'small muted' }, 'Showing the first 1000 entries.') : null);
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', (e) => { if (!zone.contains(e.relatedTarget)) zone.classList.remove('over'); });
  zone.addEventListener('drop', (e) => { e.preventDefault(); zone.classList.remove('over'); if (e.dataTransfer.files.length) upload(dir, [...e.dataTransfer.files]); });
  main.appendChild(zone);
  main.appendChild(h('div', { id: 'uploads' }));
};

function fileGlyph(dir) {
  return dir
    ? svg('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('path', { d: 'M1.5 3.5h4l1.5 1.5h7.5v8.5h-13z', fill: 'var(--brass-wash)', stroke: 'var(--brass)' }))
    : svg('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('path', { d: 'M3.5 1.5h6l3 3v10h-9z', fill: '#fff', stroke: 'var(--ink-3)' }));
}

function upload(dir, files) {
  const box = $('#uploads');
  const row = h('div', { class: 'panel' });
  const bar = h('i', { style: { width: '0%' } });
  const total = files.reduce((a, f) => a + f.size, 0);
  add(row, [h('div', { class: 'panel-head' }, h('strong', null, `Uploading ${files.length} file${files.length > 1 ? 's' : ''} (${fmtBytes(total)})`)), h('div', { class: 'progress' }, bar)]);
  box.prepend(row);
  const fd = new FormData();
  files.forEach(f => fd.append('file', f, f.webkitRelativePath || f.name));
  const xhr = new XMLHttpRequest();
  xhr.open('POST', fsPath(dir) + '?op=upload');
  xhr.setRequestHeader('X-Coffer-Token', S.token);
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) bar.style.width = (e.loaded / e.total * 100).toFixed(1) + '%'; };
  xhr.onload = () => {
    if (xhr.status < 300) { toast(`Uploaded ${files.length} file${files.length > 1 ? 's' : ''}`); route(); }
    else { let m = 'Upload failed'; try { m = JSON.parse(xhr.responseText).errors.join('; '); } catch { /* keep */ } row.remove(); fail(new Error(m)); }
  };
  xhr.onerror = () => { row.remove(); fail(new Error('Upload failed: network error')); };
  xhr.send(fd);
}

async function download(p) {
  try {
    const r = await fsApi('POST', p, { op: 'share' }, { ttl: '2m', max_downloads: 1 });
    const u = new URL(r.share.url); // same file, single use
    location.assign(location.origin + u.pathname);
  } catch (e) { fail(e); }
}

function newFolder(dir) {
  const inp = h('input', { placeholder: 'reports' });
  modal({ title: 'New folder', body: field('Folder name', inp), actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create folder', primary: true, onClick: async () => {
    const n = inp.value.trim(); if (!n || n.includes('/')) throw new Error('Enter a name without slashes');
    await fsApi('POST', joinP(dir, n), { op: 'mkdir' }); toast('Folder created'); route();
  } }] });
}

async function removeEntry(e) {
  const msg = e.is_dir ? `Delete folder ${e.path} and everything inside it? Stored data is freed on the volume servers.` : `Delete ${e.path}?`;
  if (!await confirmDlg(e.is_dir ? 'Delete folder' : 'Delete file', msg)) return;
  try { await fsApi('DELETE', e.path, e.is_dir ? { recursive: 'true' } : null); toast('Deleted'); route(); } catch (err) { fail(err); }
}

function moveDlg(e) {
  const to = h('input', { value: e.path });
  const copy = h('input', { type: 'checkbox' });
  modal({ title: 'Move or copy', body: h('div', field('New path', to, 'Moving only rewrites metadata, so it is instant even for large folders.'), e.is_dir ? null : h('label', { class: 'check' }, copy, 'Keep the original (copy instead of move)')),
    actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save', primary: true, onClick: async () => {
      await fsApi('POST', e.path, { op: copy.checked ? 'copy' : 'rename', to: to.value.trim() }); toast(copy.checked ? 'Copied' : 'Moved'); route();
    } }] });
}

function shareDlg(p) {
  const body = h('div', h('div', { class: 'form-row' }, field('Link expires after', h('select', { name: 'ttl' }, [['1h', '1 hour'], ['24h', '1 day'], ['168h', '7 days'], ['720h', '30 days']].map(([v, l]) => h('option', { value: v, selected: v === '24h' }, l)))),
    field('Download limit', h('input', { name: 'max', type: 'number', min: 0, value: 0 }), '0 means unlimited')));
  modal({ title: 'Share file', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create link', primary: true, onClick: async () => {
    const v = formVals(body);
    const r = await fsApi('POST', p, { op: 'share' }, { ttl: v.ttl, max_downloads: +v.max || 0 });
    setTimeout(() => modal({ title: 'Share link created', body: h('div', null, h('p', { class: 'small' }, `Anyone with this link can download the file until ${fmtTime(r.share.expires_at)}. Revoke it under Access → Share links.`), copyable(r.share.url)) }), 50);
  } }] });
}

async function details(p) {
  try {
    const r = await fsApi('GET', p, { meta: 'true' });
    const e = r.entry;
    const ext = Object.entries(e.extended || {});
    modal({ title: e.name, wide: true, body: h('div', null,
      table(['Property', 'Value'], [
        ['Path', e.path], ['Size', fmtBytes(e.size) + ` (${e.size.toLocaleString()} bytes)`], ['Type', e.mime || 'unknown'], ['Modified', fmtTime(e.mtime)],
        ['Created by', e.owner || '—'], ['MD5', e.md5 || '—'], ['Encryption', e.encrypted ? 'AES-256-GCM, data key wrapped by transit key ' + (e.chunks.find(c => c.key_name)?.key_name || '') : 'none'],
        ['Expires', e.ttl ? 'after ' + e.ttl : 'never'], ...ext.map(([k, v]) => [k, v]),
      ].map(([k, v]) => h('tr', null, h('td', { class: 'muted' }, k), h('td', { class: k === 'MD5' || k === 'Path' ? 'mono' : '' }, v)))),
      h('h3', { style: { margin: '16px 0 6px' } }, `Stored as ${e.chunks.length} chunk${e.chunks.length === 1 ? '' : 's'}`),
      table(['File id', 'Offset', { t: 'Size', cls: 'num' }], e.chunks.map(c => h('tr', null, h('td', { class: 'mono' }, c.fid), h('td', { class: 'small' }, c.offset.toLocaleString()), h('td', { class: 'num small' }, fmtBytes(c.size)))))),
      actions: [{ label: 'Share', onClick: () => { setTimeout(() => shareDlg(p), 30); return true; } }, { label: 'Download', primary: true, onClick: () => { download(p); return true; } }] });
  } catch (err) { fail(err); }
}

async function folderSettings(dir, res) {
  const own = res.entry.config || {};
  const keys = await list('transit/keys').catch(() => []);
  const keySel = h('select', { name: 'encryption_key' }, h('option', { value: '' }, 'Inherit from parent'), h('option', { value: '-' }, 'Do not encrypt'),
    keys.map(k => h('option', { value: k, selected: own.encryption_key === k }, 'Transit key: ' + k)), h('option', { value: '__new' }, 'Create a new key…'));
  if (own.encryption_key === '-') keySel.value = '-';
  const newKey = h('input', { name: 'new_key', class: 'hidden', placeholder: 'new key name', value: 'files-' + (dir.split('/').pop() || 'root').toLowerCase().replace(/[^a-z0-9_.-]/g, '-') });
  keySel.addEventListener('change', () => newKey.classList.toggle('hidden', keySel.value !== '__new'));
  const body = h('div',
    h('p', { class: 'small muted' }, 'Settings apply to files written from now on, in this folder and all folders below it. Existing files keep their current protection.'),
    field('Encryption', keySel, 'Each file gets its own data key, wrapped by the transit key. Sealing Coffer makes encrypted files unreadable.'), newKey,
    h('div', { class: 'form-row' },
      field('Replication', h('select', { name: 'replication' }, [['', 'Inherit (cluster default)'], ['000', 'Single copy (000)'], ['001', '2 copies, same rack (001)'], ['010', '2 copies, different racks (010)'], ['100', '2 copies, different data centers (100)'], ['002', '3 copies, same rack (002)'], ['011', '3 copies across two racks (011)']].map(([v, l]) => h('option', { value: v, selected: own.replication === v }, l)))),
      field('Expire files after', h('input', { name: 'ttl', value: own.ttl || '', placeholder: 'e.g. 7d, 12h (empty = keep)' }))),
    h('p', { class: 'small muted' }, `Currently effective: ${res.effective_config.encryption_key ? 'encrypted with ' + res.effective_config.encryption_key : 'not encrypted'}, replication ${res.effective_config.replication || 'default'}${res.effective_config.ttl ? ', TTL ' + res.effective_config.ttl : ''}.`));
  modal({ title: 'Folder settings', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save settings', primary: true, onClick: async () => {
    const v = formVals(body);
    if (v.encryption_key === '__new') { if (!v.new_key) throw new Error('Enter a key name'); v.encryption_key = v.new_key; }
    await fsApi('POST', dir, { op: 'config' }, { encryption_key: v.encryption_key, replication: v.replication, ttl: v.ttl });
    toast('Folder settings saved'); route();
  } }] });
}

// ---------------------------------------------------------------- buckets
PAGES.buckets = async (main) => {
  const [res, st] = await Promise.all([fsApi('GET', '/buckets').catch(e => e.status === 404 ? { entries: [] } : Promise.reject(e)), api('GET', 'sys/storage/status').then(r => r.data).catch(() => null)]);
  clear(main);
  const s3port = st?.s3_port || 8333;
  const endpoint = `${location.protocol}//${location.hostname}:${s3port}`;
  main.appendChild(head('Buckets', 'S3-compatible buckets. Each bucket is a folder under /buckets with its own storage collection, so deleting a bucket frees space instantly.',
    h('button', { onclick: () => go('access/s3') }, 'Manage S3 keys'),
    h('button', { class: 'primary', onclick: createBucket }, 'Create bucket')));
  const rows = res.entries.filter(e => e.is_dir).map(e => {
    const pub = e.extended?.['s3:public-read'] === 'true';
    return h('tr', null,
      h('td', null, h('a', { href: '#/files?path=' + encodeURIComponent(e.path) }, h('strong', null, e.name))),
      h('td', { class: 'small muted' }, fmtTime(e.crtime)),
      h('td', null, e.config?.encryption_key ? tag('encrypted: ' + e.config.encryption_key, 'brass') : tag('not encrypted'), ' ', pub ? tag('public read', 'bad') : tag('private', 'ok')),
      h('td', { class: 'actions' },
        h('button', { class: 'sm ghost', onclick: () => bucketEncryption(e) }, e.config?.encryption_key ? 'Change encryption' : 'Encrypt'),
        h('button', { class: 'sm ghost', onclick: async () => {
          if (!pub && !await confirmDlg('Make bucket public', `Anyone who knows an object URL will be able to read objects in ${e.name} without credentials.`, 'Make public')) return;
          await fsApi('POST', e.path, { op: 'public' }, { public: !pub }).catch(fail); route();
        } }, pub ? 'Make private' : 'Make public'),
        h('button', { class: 'sm ghost', onclick: async () => {
          if (await confirmDlg('Delete bucket', `Delete bucket ${e.name} and every object in it? This cannot be undone.`, 'Delete bucket')) {
            try { await fsApi('DELETE', e.path, { recursive: 'true' }); toast('Bucket deleted'); route(); } catch (err) { fail(err); }
          }
        } }, 'Delete')));
  });
  main.appendChild(h('div', { class: 'panel' }, table(['Bucket', 'Created', 'Protection', ''], rows.length ? rows : emptyRow(4, 'No buckets yet.', h('button', { onclick: createBucket }, 'Create bucket')))));
  main.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Connect an S3 client'),
    h('p', null, 'Use path-style addressing and Signature Version 4 with an access key from Access → S3 keys. Permissions come from the key’s policies on paths like ', h('code', null, 'fs/buckets/<bucket>/*'), '.'),
    copyable(endpoint),
    h('pre', { class: 'block' }, `# AWS CLI\naws configure set aws_access_key_id <ACCESS_KEY>\naws configure set aws_secret_access_key <SECRET_KEY>\naws --endpoint-url ${endpoint} s3 ls\naws --endpoint-url ${endpoint} s3 cp ./report.pdf s3://my-bucket/reports/\n\n# rclone (rclone.conf)\n[coffer]\ntype = s3\nprovider = Other\nendpoint = ${endpoint}\naccess_key_id = <ACCESS_KEY>\nsecret_access_key = <SECRET_KEY>`)));
};

function createBucket() {
  const inp = h('input', { placeholder: 'team-backups' });
  const enc = h('input', { type: 'checkbox', checked: true });
  modal({ title: 'Create bucket', body: h('div', field('Bucket name', inp, '3–63 characters: lowercase letters, digits, dots and hyphens.'), h('label', { class: 'check' }, enc, 'Encrypt objects with a dedicated transit key')),
    actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create bucket', primary: true, onClick: async () => {
      const n = inp.value.trim();
      if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(n)) throw new Error('Invalid bucket name');
      await fsApi('POST', '/buckets/' + n, { op: 'mkdir' });
      if (enc.checked) await fsApi('POST', '/buckets/' + n, { op: 'config' }, { encryption_key: 's3-' + n.replace(/\./g, '-') });
      toast('Bucket created'); route();
    } }] });
}

async function bucketEncryption(e) {
  const keys = await list('transit/keys').catch(() => []);
  const sel = h('select', null, h('option', { value: '-' }, 'Do not encrypt new objects'), keys.map(k => h('option', { value: k, selected: e.config?.encryption_key === k }, k)), h('option', { value: '__new' }, 'Create key s3-' + e.name));
  if (!e.config?.encryption_key) sel.value = '__new';
  modal({ title: 'Bucket encryption', body: h('div', field('Transit key', sel), h('p', { class: 'small muted' }, 'Applies to objects written from now on. Clients can also request encryption per object with the x-amz-server-side-encryption header.')),
    actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save', primary: true, onClick: async () => {
      const k = sel.value === '__new' ? 's3-' + e.name.replace(/\./g, '-') : sel.value;
      await fsApi('POST', e.path, { op: 'config' }, { ...(e.config || {}), encryption_key: k }); toast('Encryption updated'); route();
    } }] });
}

// ---------------------------------------------------------------- cluster
PAGES.cluster = async (main) => {
  const st = (await api('GET', 'sys/storage/status')).data;
  clear(main);
  main.appendChild(head('Storage cluster', 'Volume servers hold append-only volumes of file chunks. The master assigns file ids, places replicas and reclaims deleted space.',
    h('button', { onclick: vacuumDlg }, 'Reclaim space'), h('button', { class: 'primary', onclick: growDlg }, 'Add volumes')));
  if (!st.topology) { main.appendChild(h('div', { class: 'panel' }, 'The master is unreachable: ' + (st.master_error || 'unknown error'))); return; }
  const t = st.topology;
  const cell = (v, k) => h('div', null, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
  main.appendChild(h('div', { class: 'strip' }, cell(`${t.totals.alive_nodes || 0} / ${t.totals.nodes || 0}`, 'Servers up'), cell(t.totals.volumes || 0, 'Volumes'),
    cell(t.totals.slots || 0, 'Volume slots'), cell(fmtBytes(t.totals.used_bytes), 'On disk (all replicas)'), cell(t.default_replication, 'Default replication'), cell(fmtBytes(t.volume_size_limit), 'Volume size limit')));
  const topo = h('div', { class: 'panel' }, h('h2', null, 'Topology'));
  if (!t.data_centers?.length) topo.appendChild(h('p', { class: 'muted' }, 'No volume servers have joined yet. Start one with: coffer volume -master=<master-address>'));
  for (const dc of t.data_centers || []) {
    topo.appendChild(h('div', { class: 'dc' }, h('h3', null, 'Data center ' + dc.name), h('div', { class: 'racks' }, dc.racks.map(rk => h('div', { class: 'rack' }, h('div', { class: 'rname' }, 'Rack ' + rk.name),
      rk.nodes.map(n => h('div', { class: 'node' }, h('div', { class: 'url' }, h('span', { class: 'dot' + (n.alive ? '' : ' off'), title: n.alive ? 'online' : 'offline' }), n.url),
        h('div', { class: 'small muted', style: { margin: '4px 0' } }, `${n.volumes} of ${n.max_volumes} volumes, ${fmtBytes(n.used_bytes)}${n.alive ? '' : ', last seen ' + ago(n.last_seen)}`),
        h('div', { class: 'bar' }, h('i', { style: { width: Math.min(100, n.volumes / Math.max(1, n.max_volumes) * 100) + '%' } })))))))));
  }
  main.appendChild(topo);
  const vols = (t.volumes || []).map(v => {
    const data = Math.max(1, v.size - 8), garbage = v.deleted_bytes / data;
    return h('tr', null, h('td', null, v.id), h('td', null, v.collection || h('span', { class: 'muted' }, 'default')), h('td', null, v.replication),
      h('td', { class: 'num' }, fmtBytes(v.size)), h('td', { class: 'num' }, v.file_count.toLocaleString()),
      h('td', { class: 'num' }, (garbage * 100).toFixed(1) + '%'), h('td', null, v.ttl_seconds ? fmtTTL(v.ttl_seconds) : '—'),
      h('td', null, v.read_only ? tag('read only') : v.writable ? tag('writable', 'ok') : tag('degraded', 'bad')),
      h('td', { class: 'mono small' }, v.locations.join(', ')));
  });
  main.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Volumes'),
    table(['Id', 'Collection', 'Replication', { t: 'Size', cls: 'num' }, { t: 'Files', cls: 'num' }, { t: 'Garbage', cls: 'num' }, 'TTL', 'State', 'Locations'], vols.length ? vols : emptyRow(9, 'Volumes are created automatically on the first upload.'))));
};

function growDlg() {
  const body = h('div', h('div', { class: 'form-row' }, field('Number of volumes', h('input', { name: 'count', type: 'number', min: 1, value: 1 })), field('Replication', h('input', { name: 'replication', placeholder: 'cluster default' }))),
    field('Collection', h('input', { name: 'collection', placeholder: 'empty = default; bucket name for a bucket' })));
  modal({ title: 'Add volumes', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Add volumes', primary: true, onClick: async () => {
    const v = formVals(body); const r = await api('POST', 'sys/storage/grow', { ...v, count: +v.count || 1 });
    toast('Created volumes ' + (r.data.created || []).join(', ')); route();
  } }] });
}
function vacuumDlg() {
  const body = h('div', field('Minimum garbage ratio', h('input', { name: 'th', type: 'number', min: 0.01, max: 1, step: 0.05, value: 0.3 }), 'Volumes with at least this share of deleted data are compacted. Coffer also does this every 15 minutes.'));
  modal({ title: 'Reclaim space', body, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Compact volumes', primary: true, onClick: async () => {
    const r = await api('POST', 'sys/storage/vacuum', { garbage_threshold: +formVals(body).th });
    const n = Object.keys(r.data.result || {}).length; toast(n ? `Compacted ${n} volume${n > 1 ? 's' : ''}` : 'No volume needed compaction'); route();
  } }] });
}

// ---------------------------------------------------------------- access
const POLICY_TEMPLATES = {
  'Read one KV folder': '# Read secrets under secret/app/*\npath "secret/data/app/*" {\n  capabilities = ["read"]\n}\npath "secret/metadata/app/*" {\n  capabilities = ["list", "read"]\n}\n',
  'Bucket read/write': '# Full object access to one bucket (S3 and Files)\npath "fs/buckets/my-bucket" {\n  capabilities = ["read", "list"]\n}\npath "fs/buckets/my-bucket/*" {\n  capabilities = ["create", "read", "update", "delete", "list"]\n}\n',
  'Encrypt with transit': '# Use one transit key without managing it\npath "transit/encrypt/payments" {\n  capabilities = ["update"]\n}\npath "transit/decrypt/payments" {\n  capabilities = ["update"]\n}\n',
  'Operator': '# Manage everything except seal and audit\npath "*" {\n  capabilities = ["create", "read", "update", "delete", "list"]\n}\npath "sys/audit*" {\n  capabilities = ["deny"]\n}\n',
};

PAGES.access = async (main, parts) => {
  const tab = parts[0] || 'policies';
  clear(main);
  main.appendChild(head('Access', 'One set of policies governs secrets, files, buckets and S3 keys. Paths under fs/ map to files, e.g. fs/buckets/photos/*.'));
  const tabs = h('div', { class: 'tabs' }, [['policies', 'Policies'], ['auth', 'Users and roles'], ['tokens', 'Tokens'], ['s3', 'S3 keys'], ['shares', 'Share links']].map(([k, l]) =>
    h('button', { class: tab === k ? 'on' : '', onclick: () => go('access/' + k) }, l)));
  const body = h('div');
  main.append(tabs, body);
  try { await ({ policies: policiesTab, auth: authTab, tokens: tokensTab, s3: s3Tab, shares: sharesTab }[tab] || policiesTab)(body, parts.slice(1)); }
  catch (e) { body.appendChild(denied(e, 'this section')); }
};

async function policiesTab(body, parts) {
  const names = await list('sys/policies/acl');
  const sel = parts[0] ? decodeURIComponent(parts[0]) : null;
  const nav = h('div', { class: 'panel list-nav', style: { padding: '8px' } },
    h('button', { onclick: () => go('access/policies/' + encodeURIComponent('+new')) }, h('strong', null, 'New policy')),
    names.map(n => h('a', { href: '#/access/policies/' + encodeURIComponent(n), class: n === sel ? 'on' : '' }, n, n === 'root' || n === 'default' ? tag('built-in') : null)));
  const pane = h('div');
  body.appendChild(h('div', { class: 'split' }, nav, pane));
  if (!sel) { pane.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Policies'), h('p', null, 'A policy lists paths and the capabilities granted on them: create, read, update, patch, delete, list, sudo, or deny. The most specific matching path wins and deny always wins. Choose a policy to edit it.'))); return; }
  const isNew = sel === '+new';
  const cur = isNew ? { policy: '' } : (await api('GET', 'sys/policies/acl/' + sel)).data;
  const nameIn = h('input', { value: isNew ? '' : sel, disabled: !isNew, placeholder: 'app-readonly' });
  const ta = h('textarea', { rows: 18, spellcheck: 'false', readonly: sel === 'root' }, cur.policy);
  const tpl = h('select', { onchange: () => { if (tpl.value) ta.value = POLICY_TEMPLATES[tpl.value]; } }, h('option', { value: '' }, 'Start from a template…'), Object.keys(POLICY_TEMPLATES).map(k => h('option', null, k)));
  pane.appendChild(h('div', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, isNew ? 'New policy' : sel),
      sel !== 'root' && sel !== 'default' && !isNew ? h('button', { class: 'danger', onclick: async () => { if (await confirmDlg('Delete policy', `Delete policy ${sel}? Tokens that rely on it lose those permissions immediately.`)) { await api('DELETE', 'sys/policies/acl/' + sel).catch(fail); go('access/policies'); } } }, 'Delete policy') : null),
    isNew ? field('Name', nameIn) : null,
    sel === 'root' ? h('p', { class: 'muted' }, 'The root policy grants every capability and cannot be edited.') : h('div', { style: { marginBottom: '8px', maxWidth: '280px' } }, tpl),
    ta,
    sel !== 'root' ? h('div', { style: { marginTop: '10px', display: 'flex', gap: '8px' } }, h('button', { class: 'primary', onclick: async () => {
      const n = isNew ? nameIn.value.trim() : sel;
      try { await api('PUT', 'sys/policies/acl/' + n, { policy: ta.value }); toast('Policy saved'); go('access/policies/' + encodeURIComponent(n)); } catch (e) { fail(e); }
    } }, 'Save policy')) : null));
}

async function authTab(body, parts) {
  const auths = (await api('GET', 'sys/auth')).data;
  const paths = Object.keys(auths).sort();
  body.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Sign-in methods'),
    h('button', { onclick: () => {
      const b = h('div', field('Type', h('select', { name: 'type' }, h('option', { value: 'userpass' }, 'Username and password'), h('option', { value: 'approle' }, 'AppRole (machines and CI)'))), field('Path', h('input', { name: 'path', placeholder: 'defaults to the type' })));
      modal({ title: 'Enable sign-in method', body: b, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Enable method', primary: true, onClick: async () => { const v = formVals(b); await api('POST', 'sys/auth/' + (v.path || v.type), { type: v.type }); toast('Enabled'); route(); } }] });
    } }, 'Enable method')),
    table(['Path', 'Type', 'Description', ''], paths.map(p => h('tr', null, h('td', { class: 'mono' }, 'auth/' + p), h('td', null, auths[p].type), h('td', { class: 'small muted' }, auths[p].description),
      h('td', { class: 'actions' }, !auths[p].system ? h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Disable method', `Disable auth/${p}? All its users or roles are deleted and tokens issued through it are revoked.`, 'Disable')) { await api('DELETE', 'sys/auth/' + p).catch(fail); route(); } } }, 'Disable') : null))))));
  for (const p of paths) {
    const m = auths[p];
    if (m.type === 'userpass') body.appendChild(await userpassPanel(p.replace(/\/$/, '')));
    if (m.type === 'approle') body.appendChild(await approlePanel(p.replace(/\/$/, '')));
  }
}

async function userpassPanel(mount) {
  const users = await list(`auth/${mount}/users`);
  const userDlg = (name, cur) => {
    const b = h('div', field('Username', h('input', { name: 'username', value: name || '', disabled: !!name })),
      field(name ? 'New password (optional)' : 'Password', h('input', { name: 'password', type: 'password', autocomplete: 'new-password' }), 'At least 8 characters'),
      field('Policies', h('input', { name: 'policies', value: (cur?.token_policies || []).join(', '), placeholder: 'e.g. app-readonly, bucket-rw' })),
      field('Session length', h('input', { name: 'token_ttl', value: cur?.token_ttl ? cur.token_ttl + 's' : '', placeholder: 'default 768h' })));
    modal({ title: name ? 'Edit user ' + name : 'Create user', body: b, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Save user', primary: true, onClick: async () => {
      const v = formVals(b); const n = name || v.username; if (!n) throw new Error('Username is required');
      const payload = { policies: splitList(v.policies) }; if (v.password) payload.password = v.password; if (v.token_ttl) payload.token_ttl = v.token_ttl;
      await api('POST', `auth/${mount}/users/${n}`, payload); toast('User saved'); route();
    } }] });
  };
  return h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h3', null, `Users in auth/${mount}`), h('button', { class: 'primary', onclick: () => userDlg() }, 'Create user')),
    table(['User', ''], users.length ? users.map(u => h('tr', null, h('td', null, u), h('td', { class: 'actions' },
      h('button', { class: 'sm ghost', onclick: async () => userDlg(u, (await api('GET', `auth/${mount}/users/${u}`)).data) }, 'Edit'),
      h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Delete user', `Delete user ${u}?`)) { await api('DELETE', `auth/${mount}/users/${u}`); route(); } } }, 'Delete')))) : emptyRow(2, 'No users yet.')));
}

async function approlePanel(mount) {
  const roles = await list(`auth/${mount}/role`);
  const roleDlg = () => {
    const b = h('div', field('Role name', h('input', { name: 'name', placeholder: 'ci-deployer' })), field('Policies', h('input', { name: 'policies' })),
      h('div', { class: 'form-row' }, field('Token TTL', h('input', { name: 'token_ttl', placeholder: '1h' })), field('Secret ID lifetime', h('input', { name: 'secret_id_ttl', placeholder: 'never' })), field('Secret ID uses', h('input', { name: 'secret_id_num_uses', type: 'number', min: 0, value: 0 }))));
    modal({ title: 'Create AppRole', body: b, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create role', primary: true, onClick: async () => {
      const v = formVals(b); if (!v.name) throw new Error('Role name is required');
      await api('POST', `auth/${mount}/role/${v.name}`, { token_policies: splitList(v.policies), token_ttl: v.token_ttl || undefined, secret_id_ttl: v.secret_id_ttl || undefined, secret_id_num_uses: +v.secret_id_num_uses || 0 });
      toast('Role created'); route();
    } }] });
  };
  const creds = async (r) => {
    const rid = (await api('GET', `auth/${mount}/role/${r}/role-id`)).data.role_id;
    const sid = (await api('POST', `auth/${mount}/role/${r}/secret-id`)).data;
    modal({ title: 'Credentials for ' + r, body: h('div', null, h('p', { class: 'small' }, 'Give both values to the machine. The secret ID is shown only once.'), h('h3', null, 'Role ID'), copyable(rid), h('h3', null, 'Secret ID'), copyable(sid.secret_id),
      h('pre', { class: 'block' }, `curl -X POST ${location.origin}/v1/auth/${mount}/login \\\n  -d '{"role_id":"${rid}","secret_id":"${sid.secret_id}"}'`)) });
  };
  return h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h3', null, `AppRoles in auth/${mount}`), h('button', { class: 'primary', onclick: roleDlg }, 'Create role')),
    table(['Role', ''], roles.length ? roles.map(r => h('tr', null, h('td', null, r), h('td', { class: 'actions' },
      h('button', { class: 'sm', onclick: () => creds(r).catch(fail) }, 'Generate credentials'),
      h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Delete role', `Delete role ${r}?`)) { await api('DELETE', `auth/${mount}/role/${r}`); route(); } } }, 'Delete')))) : emptyRow(2, 'No roles yet.')));
}

async function tokensTab(body) {
  const me = (await api('GET', 'auth/token/lookup-self')).data;
  body.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Your token'),
    table(['Property', 'Value'], [['Display name', me.display_name], ['Policies', me.policies.join(', ')], ['Accessor', me.accessor], ['Expires', me.expire_time ? fmtTime(me.expire_time) + ` (${fmtTTL(me.ttl)} left)` : 'never'], ['Renewable', me.renewable ? 'yes' : 'no']].map(([k, v]) => h('tr', null, h('td', { class: 'muted' }, k), h('td', { class: k === 'Accessor' ? 'mono' : '' }, v)))),
    me.renewable ? h('button', { style: { marginTop: '10px' }, onclick: async () => { await api('POST', 'auth/token/renew-self').catch(fail); toast('Token renewed'); route(); } }, 'Renew my token') : null));
  const b = h('div', h('div', { class: 'form-row' }, field('Policies', h('input', { name: 'policies', placeholder: 'defaults to yours' })), field('TTL', h('input', { name: 'ttl', placeholder: '768h' })), field('Use limit', h('input', { name: 'num_uses', type: 'number', min: 0, value: 0 }), '0 = unlimited')),
    field('Display name', h('input', { name: 'display_name', placeholder: 'deploy-bot' })),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'orphan' }), 'Orphan token (survives revocation of your token)'),
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'wrap' }), 'Return a single-use wrapping token instead of the token itself'));
  body.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Create a token'), b, h('button', { class: 'primary', onclick: async () => {
    const v = formVals(b);
    try {
      const payload = { policies: splitList(v.policies), ttl: v.ttl || undefined, num_uses: +v.num_uses || 0, display_name: v.display_name || undefined, no_parent: v.orphan };
      if (!payload.policies.length) delete payload.policies;
      const r = await api('POST', 'auth/token/create', payload, v.wrap ? { 'X-Coffer-Wrap-TTL': '15m' } : undefined);
      if (r.wrap_info) modal({ title: 'Wrapping token created', body: h('div', null, h('p', { class: 'small' }, 'Send this to the recipient. It can be unwrapped once, within 15 minutes, via System → Response wrapping or POST /v1/sys/wrapping/unwrap.'), copyable(r.wrap_info.token)) });
      else modal({ title: 'Token created', body: h('div', null, h('p', { class: 'small' }, `Policies: ${r.auth.policies.join(', ')}. Expires in ${fmtTTL(r.auth.lease_duration)}. Copy it now; it is not shown again.`), copyable(r.auth.client_token), h('h3', null, 'Accessor'), copyable(r.auth.accessor)) });
    } catch (e) { fail(e); }
  } }, 'Create token')));
  const rb = h('div', { class: 'form-row' }, field('Token accessor', h('input', { name: 'accessor' })));
  body.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Revoke a token'), h('p', { class: 'small muted' }, 'Revoking a token also revokes every token created from it.'), rb,
    h('button', { class: 'danger', onclick: async () => { const a = formVals(rb).accessor; if (!a) return; await api('POST', 'auth/token/revoke-accessor', { accessor: a }).then(() => toast('Token revoked')).catch(fail); } }, 'Revoke token')));
}

async function s3Tab(body) {
  const r = (await api('GET', 'sys/s3/keys')).data;
  const create = () => {
    const b = h('div', field('Policies', h('input', { name: 'policies', placeholder: 'e.g. bucket-rw' }), 'The key can do exactly what these policies allow on fs/buckets/*.'), field('Description', h('input', { name: 'description', placeholder: 'backup job on db-01' })));
    modal({ title: 'Create S3 access key', body: b, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Create key', primary: true, onClick: async () => {
      const v = formVals(b);
      const k = (await api('POST', 'sys/s3/keys', { policies: splitList(v.policies), description: v.description })).data;
      setTimeout(() => modal({ title: 'Access key created', body: h('div', null, h('p', { class: 'small' }, 'The secret key is shown only once.'), h('h3', null, 'Access key'), copyable(k.access_key), h('h3', null, 'Secret key'), copyable(k.secret_key),
        h('p', { class: 'small muted' }, `Endpoint ${location.protocol}//${location.hostname}:${k.endpoint_port}, region ${k.region}, path-style.`)), onClose: route }), 50);
    } }] });
  };
  body.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'S3 access keys'), h('button', { class: 'primary', onclick: create }, 'Create access key')),
    table(['Access key', 'Policies', 'Description', 'Created', ''], r.key_info.length ? r.key_info.map(k => h('tr', null, h('td', { class: 'mono' }, k.access_key), h('td', null, k.policies.join(', ')), h('td', { class: 'small' }, k.description),
      h('td', { class: 'small muted' }, `${fmtTime(k.created_at)} by ${k.created_by}`),
      h('td', { class: 'actions' }, h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Delete access key', `Delete ${k.access_key}? Clients using it stop working within 30 seconds.`)) { await api('DELETE', 'sys/s3/keys/' + k.access_key).catch(fail); route(); } } }, 'Delete'))))
      : emptyRow(5, 'No access keys yet.', h('button', { onclick: create }, 'Create access key')))));
}

async function sharesTab(body) {
  const r = (await api('GET', 'sys/shares')).data.shares;
  body.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Share links'), h('p', { class: 'small muted' }, 'Links created from Files. Anyone holding a link can download the file until it expires or reaches its download limit.'),
    table(['File', 'Created', 'Expires', 'Downloads', ''], r.length ? r.map(s => h('tr', null, h('td', { class: 'mono' }, s.path), h('td', { class: 'small' }, `${ago(s.created_at)} by ${s.created_by}`), h('td', { class: 'small' }, fmtTime(s.expires_at)),
      h('td', null, s.max_downloads ? `${s.downloads} of ${s.max_downloads}` : String(s.downloads)),
      h('td', { class: 'actions' }, copyBtn(s.url, 'Copy link'), h('button', { class: 'sm ghost', onclick: async () => { await api('DELETE', 'sys/shares/' + s.id).catch(fail); toast('Link revoked'); route(); } }, 'Revoke'))))
      : emptyRow(5, 'No active share links.'))));
}

// ---------------------------------------------------------------- audit
PAGES.audit = async (main) => {
  const devices = (await api('GET', 'sys/audit')).data;
  clear(main);
  main.appendChild(head('Audit log', 'Every request to secrets, files and S3 is recorded. Secret values are replaced by salted HMACs so logs can be searched without exposing data.',
    h('button', { onclick: enableDeviceDlg }, 'Add log file')));
  const devRows = Object.values(devices).map(d => h('tr', null, h('td', { class: 'mono' }, d.path), h('td', null, d.type), h('td', { class: 'mono small' }, d.options?.file_path),
    h('td', { class: 'actions' }, h('button', { class: 'sm ghost', onclick: async () => { if (await confirmDlg('Remove log file', `Stop writing audit events to ${d.options?.file_path}? The file itself is kept.`, 'Remove')) { await api('DELETE', 'sys/audit/' + d.path).catch(fail); route(); } } }, 'Remove'))));
  main.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Log destinations'),
    table(['Name', 'Type', 'File', ''], devRows.length ? devRows : emptyRow(4, 'Events are kept in memory (last 1000) only. Add a log file to keep a durable, append-only record.'))));
  const filter = h('input', { placeholder: 'Filter by path, type or operation', style: { maxWidth: '320px' } });
  const live = h('input', { type: 'checkbox', checked: true });
  const tbody = h('tbody');
  const load = async () => {
    try {
      const evs = (await api('GET', 'sys/audit-events?limit=300&filter=' + encodeURIComponent(filter.value.trim()))).data.events;
      clear(tbody);
      if (!evs.length) tbody.appendChild(emptyRow(7, 'No matching events.'));
      for (const ev of evs) tbody.appendChild(h('tr', { class: 'clickable', onclick: () => modal({ title: 'Audit event', wide: true, body: h('pre', { class: 'block' }, JSON.stringify(ev, null, 2)) }) },
        h('td', { class: 'small', title: fmtTime(ev.time) }, new Date(ev.time).toLocaleTimeString()),
        h('td', null, tag({ request: 'secrets', fs: 'files', s3: 'S3' }[ev.type] || ev.type)), h('td', null, ev.operation),
        h('td', { class: 'mono small' }, ev.path), h('td', { class: 'small' }, ev.auth?.display_name || 'anonymous'),
        h('td', null, tag(ev.status, ev.status >= 400 ? 'bad' : 'ok')), h('td', { class: 'small muted' }, ev.error || '')));
    } catch (e) { clear(tbody).appendChild(emptyRow(7, e.message)); }
  };
  let deb;
  filter.addEventListener('input', () => { clearTimeout(deb); deb = setTimeout(load, 250); });
  live.addEventListener('change', () => { clearInterval(S.liveT); if (live.checked) S.liveT = setInterval(load, 3000); });
  main.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Recent events'), h('div', { style: { display: 'flex', gap: '12px', alignItems: 'center' } }, filter, h('label', { class: 'check', style: { margin: 0 } }, live, 'Live'))),
    h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, h('tr', null, ['Time', 'Where', 'Action', 'Path', 'Who', 'Status', 'Error'].map(x => h('th', null, x)))), tbody))));
  await load();
  S.liveT = setInterval(load, 3000);
};

function enableDeviceDlg() {
  const b = h('div', field('Name', h('input', { name: 'name', value: 'file' })), field('File path on the server', h('input', { name: 'file_path', placeholder: '/var/log/coffer/audit.log' }), 'Use "stdout" to write to the server log.'));
  modal({ title: 'Add audit log file', body: b, actions: [{ label: 'Cancel', onClick: () => null }, { label: 'Add log file', primary: true, onClick: async () => {
    const v = formVals(b); await api('PUT', 'sys/audit/' + v.name, { type: 'file', options: { file_path: v.file_path } }); toast('Audit log file added'); route();
  } }] });
}

// ---------------------------------------------------------------- system
PAGES.system = async (main) => {
  const [mounts, keyStatus] = await Promise.all([api('GET', 'sys/mounts').then(r => r.data).catch(() => null), api('GET', 'sys/key-status').then(r => r.data).catch(() => null)]);
  clear(main);
  main.appendChild(head('System', 'Seal, keys, engines and tools for operators.'));
  const st = S.seal;
  main.appendChild(h('div', { class: 'cols' },
    h('div', { class: 'panel' }, h('div', { style: { display: 'flex', gap: '18px', alignItems: 'center' } }, dial(96, st),
      h('div', null, h('h2', null, 'Unsealed'), h('p', { class: 'small muted' }, `Shamir seal, ${st.t} of ${st.n} keys required. Storage: ${st.storage_type}.`),
        h('button', { class: 'danger', onclick: async () => {
          if (await confirmDlg('Seal Coffer', 'Sealing wipes the keys from memory. Secrets, files, buckets and S3 stop working until key holders unseal again.', 'Seal now')) { try { await api('PUT', 'sys/seal'); toast('Coffer is sealed'); setTimeout(boot, 300); } catch (e) { fail(e); } }
        } }, 'Seal now')))),
    h('div', { class: 'panel' }, h('h2', null, 'Encryption key'),
      keyStatus ? h('p', { class: 'small' }, `The barrier encrypts all stored data with key term ${keyStatus.term}, installed ${fmtTime(keyStatus.install_time)}. Rotating adds a new term; older data stays readable.`) : h('p', { class: 'muted small' }, 'Requires sudo on sys/key-status.'),
      h('button', { onclick: async () => { if (await confirmDlg('Rotate encryption key', 'New writes will use a fresh key term. This is safe to do at any time.', 'Rotate')) { await api('PUT', 'sys/rotate').then(r => { toast('Now using term ' + r.data.term); route(); }).catch(fail); } } }, 'Rotate key'))));

  if (mounts) {
    main.appendChild(h('div', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Secrets engines'), h('button', { onclick: () => enableEngineDlg().then(p => p && route()) }, 'Enable engine')),
      table(['Path', 'Type', 'Description', ''], Object.keys(mounts).sort().map(p => h('tr', null, h('td', { class: 'mono' }, p), h('td', null, mounts[p].type), h('td', { class: 'small muted' }, mounts[p].description),
        h('td', { class: 'actions' }, mounts[p].system ? tag('required') : h('button', { class: 'sm ghost', onclick: async () => {
          if (await confirmDlg('Disable engine', `Disable ${p}? All data stored in it is destroyed permanently.`, 'Disable and destroy')) { await api('DELETE', 'sys/mounts/' + p).catch(fail); route(); }
        } }, 'Disable')))))));
  }

  // rekey
  const rk = h('div', field('Current unseal keys', h('textarea', { name: 'keys', rows: 3, placeholder: 'One key per line, at least the threshold' })),
    h('div', { class: 'form-row' }, field('New key shares', h('input', { name: 'shares', type: 'number', value: st.n, min: 1 })), field('New threshold', h('input', { name: 'threshold', type: 'number', value: st.t, min: 1 }))));
  const caps = h('div', { class: 'form-row' }, field('Path', h('input', { name: 'path', placeholder: 'secret/data/app/db or fs/buckets/photos/x.jpg' })));
  const capsOut = h('div');
  const wrapIn = h('textarea', { rows: 4, placeholder: '{"password": "…"}' });
  const unwrapIn = h('input', { placeholder: 'wrapping token' });
  const wrapOut = h('div');
  main.appendChild(h('div', { class: 'cols' },
    h('div', { class: 'panel' }, h('h2', null, 'Check permissions'), h('p', { class: 'small muted' }, 'See which capabilities your token has on any path, including files and buckets.'), caps,
      h('button', { onclick: async () => { try { const p = formVals(caps).path; const r = await api('POST', 'sys/capabilities-self', { path: p }); clear(capsOut).appendChild(h('p', null, (r.data.capabilities || []).map(c => [tag(c, c === 'deny' ? 'bad' : 'ok'), ' ']))); } catch (e) { fail(e); } } }, 'Check'), capsOut),
    h('div', { class: 'panel' }, h('h2', null, 'Response wrapping'), h('p', { class: 'small muted' }, 'Hand a secret to someone through a single-use token instead of pasting it in chat.'),
      field('Data to wrap (JSON)', wrapIn),
      h('button', { onclick: async () => {
        try { const d = JSON.parse(wrapIn.value || '{}'); const r = await api('POST', 'sys/wrapping/wrap', d, { 'X-Coffer-Wrap-TTL': '1h' }); clear(wrapOut).append(h('h3', { style: { margin: '10px 0 6px' } }, 'Wrapping token (valid 1 hour, single use)'), copyable(r.wrap_info.token)); } catch (e) { fail(e); }
      } }, 'Wrap'),
      h('div', { style: { marginTop: '14px' } }, field('Unwrap a token', unwrapIn)),
      h('button', { onclick: async () => { try { const r = await api('POST', 'sys/wrapping/unwrap', { token: unwrapIn.value.trim() }); clear(wrapOut).append(h('h3', { style: { margin: '10px 0 6px' } }, 'Unwrapped data'), h('pre', { class: 'block' }, JSON.stringify(r.data || r.auth, null, 2))); } catch (e) { fail(e); } } }, 'Unwrap'),
      wrapOut)));
  main.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Backup and disaster recovery'),
    h('p', { class: 'small muted' }, 'A snapshot holds all secrets, policies, tokens, the file index and master state in one file. Secrets stay encrypted inside it, so it can only be used together with the unseal keys. File contents stay on the volume servers, protected by replication.'),
    h('button', { class: 'primary', onclick: async () => {
      try {
        const res = await fetch('/v1/sys/storage/snapshot', { headers: { 'X-Coffer-Token': S.token } });
        if (!res.ok) { const j = await res.json().catch(() => ({})); throw new Error((j.errors || []).join('; ') || 'Snapshot failed (' + res.status + ')'); }
        const blob = await res.blob();
        const a = h('a', { href: URL.createObjectURL(blob), download: 'coffer-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.snap' });
        document.body.appendChild(a); a.click(); a.remove(); toast('Snapshot downloaded (' + fmtBytes(blob.size) + ')');
      } catch (e) { fail(e); }
    } }, 'Download snapshot'),
    h('p', { class: 'small muted', style: { marginTop: '10px' } }, 'To restore: stop the server, run ', h('code', null, 'coffer operator snapshot restore -dir=<data-dir> <file>'), ', start it again and unseal.')));
  main.appendChild(h('div', { class: 'panel' }, h('h2', null, 'Rekey unseal keys'), h('p', { class: 'small muted' }, 'Replace the unseal keys, for example when a key holder leaves. Requires the threshold of current keys. Old keys stop working immediately.'), rk,
    h('button', { class: 'danger', onclick: async () => {
      const v = formVals(rk);
      try {
        const r = await api('PUT', 'sys/rekey', { keys: v.keys.split(/\s+/).filter(Boolean), secret_shares: +v.shares, secret_threshold: +v.threshold });
        modal({ title: 'New unseal keys', wide: true, body: h('div', null, h('p', { class: 'small' }, 'Distribute these now. They are shown only once.'), h('ol', { class: 'keys-list' }, r.data.keys.map(k => h('li', null, copyable(k)))),
          h('button', { onclick: () => downloadText('coffer-rekey.txt', r.data.keys.join('\n')) }, 'Download as text file')), onClose: boot });
      } catch (e) { fail(e); }
    } }, 'Rekey')));
};

boot();
