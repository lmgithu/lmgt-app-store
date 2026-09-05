'use strict';

/* =================== utils =================== */
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

function b64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}
function unb64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/* =================== currency catalogue =================== */
const CURRENCIES = [
  ['USD', 'US Dollar'], ['EUR', 'Euro'], ['GBP', 'British Pound'],
  ['CHF', 'Swiss Franc'], ['JPY', 'Japanese Yen'], ['CNY', 'Chinese Yuan'],
  ['HKD', 'Hong Kong Dollar'], ['SGD', 'Singapore Dollar'], ['KRW', 'South Korean Won'],
  ['INR', 'Indian Rupee'], ['CAD', 'Canadian Dollar'], ['AUD', 'Australian Dollar'],
  ['NZD', 'New Zealand Dollar'], ['SEK', 'Swedish Krona'], ['NOK', 'Norwegian Krone'],
  ['DKK', 'Danish Krone'], ['PLN', 'Polish Zloty'], ['CZK', 'Czech Koruna'],
  ['HUF', 'Hungarian Forint'], ['RON', 'Romanian Leu'], ['BGN', 'Bulgarian Lev'],
  ['TRY', 'Turkish Lira'], ['RUB', 'Russian Ruble'], ['BRL', 'Brazilian Real'],
  ['MXN', 'Mexican Peso'], ['ZAR', 'South African Rand'], ['AED', 'UAE Dirham'],
  ['SAR', 'Saudi Riyal'], ['ILS', 'Israeli Shekel'], ['MYR', 'Malaysian Ringgit'],
  ['THB', 'Thai Baht'], ['IDR', 'Indonesian Rupiah'], ['PHP', 'Philippine Peso'],
  ['VND', 'Vietnamese Dong'], ['NGN', 'Nigerian Naira'], ['EGP', 'Egyptian Pound'],
];
const CURRENCY_CODES = CURRENCIES.map(c => c[0]);
const currencyName = code => {
  const found = CURRENCIES.find(c => c[0] === code);
  return found ? found[1] : code;
};

/* =================== encryption (Web Crypto) =================== */
const PBKDF2_ITERATIONS = 310000;

async function deriveKey(password, saltBytes, iterations) {
  const ikm = new TextEncoder().encode(password);
  const keyMaterial = await crypto.subtle.importKey('raw', ikm, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: iterations || PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptBlob(state, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(state)),
  );
  return {
    v: 1,
    iters: PBKDF2_ITERATIONS,
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(new Uint8Array(ct)),
  };
}

async function decryptBlob(blob, password) {
  const { salt, iv, ct, iters } = blob;
  const key = await deriveKey(password, unb64(salt), iters);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(iv) },
    key,
    unb64(ct),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

/* =================== API =================== */
async function fetchBlob() {
  const resp = await fetch('/api/data', { cache: 'no-store' });
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error('Failed to load vault (' + resp.status + ')');
  const data = await resp.json();
  return JSON.parse(data.blob);
}
async function putBlob(blob) {
  const resp = await fetch('/api/data', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(blob),
  });
  if (!resp.ok) throw new Error('Failed to save vault (' + resp.status + ')');
}
async function fetchQuote(symbol, cls) {
  const resp = await fetch('/api/quote?q=' + encodeURIComponent(symbol) + (cls ? '&cls=' + cls : ''), { cache: 'no-store' });
  const data = await resp.json();
  if (!resp.ok) throw new Error((data && data.error) || 'quote failed');
  return data;
}
async function fetchFx(base) {
  const resp = await fetch('/api/fx?base=' + encodeURIComponent(base), { cache: 'no-store' });
  const data = await resp.json();
  if (!resp.ok) throw new Error((data && data.error) || 'fx failed');
  return data;
}

/* =================== store =================== */
let state = null;
let password = null;
let dirty = false;

const defaultState = () => ({
  v: 1,
  base: 'USD',
  cash: [],
  stocks: [],
  crypto: [],
  future: [],
  quotes: {},
  fx: null,
});

function mutateState(fn) {
  fn();
  dirty = true;
  render();
  scheduleSave();
}

const scheduleSave = debounce(async () => {
  if (!dirty || !state || !password) return;
  dirty = false;
  try {
    const blob = await encryptBlob(state, password);
    await putBlob(blob);
  } catch (e) {
    console.error('save failed', e);
    toast('Save failed', 'Your changes could not be written to disk.', 'error');
    dirty = true;
  }
}, 600);

async function changePassword(oldPw, newPw) {
  if (oldPw !== password) throw new Error('Current password is incorrect');
  password = newPw;
  await saveNow();
}

async function saveNow() {
  if (!state || !password) return;
  dirty = false;
  const blob = await encryptBlob(state, password);
  await putBlob(blob);
}

/* =================== calculations =================== */
function yearFraction(a, b) {
  return (b - a) / (365.25 * 24 * 3600 * 1000);
}

function accrueAt(amount, ratePct, startISO, asOf, endISO) {
  if (!ratePct || !startISO) return amount;
  const s = new Date(startISO).getTime();
  const aof = asOf.getTime();
  if (!s || isNaN(s) || aof <= s) return amount;
  const rate = parseFloat(ratePct) / 100;
  if (!isFinite(rate) || rate <= 0) return amount;
  let elapsed = yearFraction(s, aof);
  if (endISO && endISO !== '') {
    const e = new Date(endISO).getTime();
    if (isFinite(e) && e > s) elapsed = Math.min(elapsed, yearFraction(s, e));
  }
  return amount * Math.pow(1 + rate, elapsed);
}

function quoteFor(sym) {
  const q = state.quotes && state.quotes[sym];
  return q && typeof q.price === 'number' ? q : null;
}

function conv(amount, from, base) {
  if (from === base) return amount;
  const rates = state.fx && state.fx.rates;
  if (!rates || !rates[from]) return null;
  return amount / rates[from];
}

function analyze() {
  const now = new Date();
  const eoy = new Date(now.getFullYear(), 11, 31, 23, 59, 59, 999);
  const base = state.base || 'USD';
  const out = {
    now, eoy,
    current: { cash: 0, stocks: 0, crypto: 0 },
    eoyV: { cash: 0, stocks: 0, crypto: 0 },
    missing: [],          // symbols without prices
    fxMissing: false,
    positions: { cash: 0, stocks: 0, crypto: 0, future: 0 },
    cashRows: [], stockRows: [], cryptoRows: [], futureRows: [],
  };

  state.cash.forEach(c => {
    const cur = accrueAt(c.amount, c.interestRate, c.startDate, now, c.endDate);
    const eoyv = accrueAt(c.amount, c.interestRate, c.startDate, eoy, c.endDate);
    const curB = conv(cur, c.currency, base);
    const eoyB = conv(eoyv, c.currency, base);
    if (curB === null || eoyB === null) { out.fxMissing = true; return; }
    out.current.cash += curB;
    out.eoyV.cash += eoyB;
    out.positions.cash++;
    out.cashRows.push({
      ...c, cur, curB, eoyV: eoyB, interest: !!(c.interestRate && c.startDate),
      rate: parseFloat(c.interestRate || 0),
    });
  });

  const priceOf = (sym, cls) => {
    let lower = String(sym).toUpperCase();
    if (cls === 'crypto' && !lower.includes('-')) lower = lower + '-USD';
    const q = quoteFor(lower);
    if (!q) { out.missing.push(lower); return null; }
    const baseVal = conv(q.price, q.currency, base);
    if (baseVal === null) { out.fxMissing = true; return q.price; }
    return baseVal;
  };

  state.stocks.forEach(s => {
    const p = priceOf(s.ticker, 'stock');
    const val = p !== null ? p * s.qty : null;
    if (val === null) return;
    out.current.stocks += val;
    out.eoyV.stocks += val;
    out.positions.stocks++;
    out.stockRows.push({ ...s, priceB: p, value: val });
  });

  state.crypto.forEach(c => {
    const p = priceOf(c.symbol, 'crypto');
    const val = p !== null ? p * c.qty : null;
    if (val === null) return;
    out.current.crypto += val;
    out.eoyV.crypto += val;
    out.positions.crypto++;
    out.cryptoRows.push({ ...c, priceB: p, value: val });
  });

  state.future.forEach(f => {
    const row = { ...f };
    if (f.type === 'cash') {
      const b = conv(f.amount, f.currency, base);
      if (b === null) { out.fxMissing = true; } else { out.eoyV.cash += b; row.value = b; }
    } else if (f.type === 'stock') {
      const p = priceOf(f.ticker, 'stock');
      if (p !== null) { const v = p * f.qty; out.eoyV.stocks += v; row.value = v; row.priceB = p; }
    } else {
      const p = priceOf(f.symbol, 'crypto');
      if (p !== null) { const v = p * f.qty; out.eoyV.crypto += v; row.value = v; row.priceB = p; }
    }
    out.positions.future++;
    out.futureRows.push(row);
  });

  const sum = o => Object.values(o).reduce((a, b) => a + (isFinite(b) ? b : 0), 0);
  out.current.total = sum(out.current);
  out.eoyV.total = sum(out.eoyV);
  out.delta = out.eoyV.total - out.current.total;
  out.missing = Array.from(new Set(out.missing));
  return out;
}

/* =================== formatting =================== */
function fmt(n, base, opts) {
  if (n === null || n === undefined || !isFinite(n)) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency', currency: base || 'USD',
    maximumFractionDigits: opts && opts.frac != null ? opts.frac : 2,
  }).format(n);
}
function fmtShort(n, base) {
  if (!isFinite(n)) return '—';
  const abs = Math.abs(n);
  if (abs >= 1e9) return fmt(n / 1e9, base, { frac: 2 }) + 'B';
  if (abs >= 1e6) return fmt(n / 1e6, base, { frac: 2 }) + 'M';
  if (abs >= 1e4) return fmt(n / 1e3, base, { frac: 1 }) + 'K';
  return fmt(n, base, { frac: n < 20 ? 2 : 0 });
}
function fmtNum(n) {
  if (!isFinite(n)) return '—';
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 4 }).format(n);
}
function fmtAge(ts) {
  if (!ts) return 'never refreshed';
  const mins = Math.round((Date.now() - ts) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  const h = Math.round(mins / 60);
  if (h < 24) return h + 'h ago';
  return Math.round(h / 24) + 'd ago';
}

let counter = 0;
function animateNum(el, target, base) {
  const from = el.__v != null ? el.__v : target;
  el.__v = target;
  const start = performance.now();
  const dur = 700;
  const id = ++counter;
  el.dataset.id = id;
  const step = t => {
    if (el.dataset.id !== String(id)) return;
    const p = clamp((t - start) / dur, 0, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(from + (target - from) * eased, base);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* =================== toasts =================== */
function toast(title, msg, type) {
  const wrap = $('#toasts');
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  const iconMap = { success: 'i-check', error: 'i-alert', info: 'i-refresh' };
  el.innerHTML =
    '<span class="t-ico"><svg><use href="#' + (iconMap[type] || 'i-refresh') + '"/></svg></span>' +
    '<div><b>' + title + '</b>' + (msg ? '<span>' + msg + '</span>' : '') + '</div>';
  wrap.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 350);
  }, 4200);
}

/* =================== app state / boot =================== */
let currentView = 'overview';
let analysis = null;

function viewTitle() {
  const map = {
    overview: ['Overview', 'Your wealth at a glance'],
    cash: ['Cash reserves', 'Money on hand and in deposits'],
    stocks: ['Stocks', 'Live-priced equity holdings'],
    crypto: ['Crypto', 'Coins and tokens, priced live'],
    future: ['Year ahead', 'Contributions planned before New Year'],
    settings: ['Settings', 'Currency, security and backups'],
  };
  return map[currentView] || map.overview;
}

function switchView(v) {
  currentView = v;
  $$('#nav .nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === v));
  $$('.view').forEach(s => s.classList.toggle('active', s.dataset.view === v));
  const [t, sub] = viewTitle();
  $('#view-title').textContent = t;
  $('#view-sub').textContent = sub;
  render();
  if (v !== 'overview' && v !== 'settings') refreshQuotes(false);
}

function unlockApp() {
  $('#lock-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  switchView('overview');
  refreshQuotes(false);
}

function lock() {
  $('#app').classList.add('hidden');
  $('#lock-screen').classList.remove('hidden');
  setupLockScreen();
}

/* =================== lock screen =================== */
async function init() {
  setupLockScreen();
  wireEvents();
}

let hasData = false;
async function setupLockScreen() {
  try {
    const blob = await fetchBlob();
    hasData = !!blob;
  } catch (e) {
    hasData = false;
  }
  $('#lock-title').textContent = hasData ? 'Welcome back' : 'Create your vault';
  $('#lock-sub').textContent = hasData
    ? 'Enter your password to open your encrypted vault.'
    : 'Set a password — it encrypts all your data before it leaves this browser.';
  $('#lock-confirm-wrap').classList.toggle('hidden', hasData);
  $('#lock-btn').innerHTML = hasData ? 'Unlock' : 'Create vault';
  $('#lock-pass').value = '';
  $('#lock-pass2').value = '';
  $('#lock-hint').textContent = '';
  $('#lock-pass').focus();
}

async function onLockSubmit(e) {
  e.preventDefault();
  const pw = $('#lock-pass').value;
  const hint = $('#lock-hint');
  const btn = $('#lock-btn');
  if (pw.length < 6) {
    hint.textContent = 'Use at least 6 characters.';
    return;
  }
  if (!hasData && pw !== $('#lock-pass2').value) {
    hint.textContent = 'Passwords do not match.';
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<svg class="spin"><use href="#i-refresh"/></svg> Working…';
  try {
    if (!hasData) {
      const blob = await encryptBlob(defaultState(), pw);
      await putBlob(blob);
      state = defaultState();
      password = pw;
      toast('Vault created', 'Your data is now encrypted at rest.', 'success');
      unlockApp();
    } else {
      const blob = await fetchBlob();
      state = await decryptBlob(blob, pw);
      password = pw;
      toast('Welcome back', 'Vault unlocked.', 'success');
      unlockApp();
    }
  } catch (err) {
    console.error(err);
    lockScreenShake();
    hint.textContent = hasData ? 'Wrong password — the vault could not be decrypted.' : 'Could not create the vault.';
  } finally {
    btn.disabled = false;
    btn.innerHTML = hasData ? 'Unlock' : 'Create vault';
  }
}
function lockScreenShake() {
  const card = $('.lock-card');
  card.style.animation = 'none';
  void card.offsetWidth;
  card.style.animation = 'shake 0.4s ease';
}
const shakeStyle = document.createElement('style');
shakeStyle.textContent = '@keyframes shake { 0%,100%{transform:translateX(0)} 20%,60%{transform:translateX(-8px)} 40%,80%{transform:translateX(8px)} }';
document.head.appendChild(shakeStyle);

/* =================== quotes & fx =================== */
function neededSymbols() {
  const syms = new Set();
  (state.stocks || []).forEach(s => { if (s.ticker) syms.add([s.ticker.toUpperCase(), 'stock']); });
  (state.crypto || []).forEach(c => { if (c.symbol) syms.add([c.symbol.toUpperCase(), 'crypto']); });
  (state.future || []).forEach(f => {
    if (f.type === 'stock' && f.ticker) syms.add([f.ticker.toUpperCase(), 'stock']);
    if (f.type === 'crypto' && f.symbol) syms.add([f.symbol.toUpperCase(), 'crypto']);
  });
  return Array.from(syms);
}

async function refreshQuotes(force) {
  if (!state) return;
  const items = neededSymbols();
  if (state.base) ensureFx();
  if (!items.length) { updatePricesNote(); render(); return; }
  const btn = $('#btn-refresh');
  if (force) btn.querySelector('svg').classList.add('spin');
  const staleMs = 15 * 60 * 1000;
  const todo = items.filter(([sym]) =>
    force || !state.quotes[sym] || Date.now() - state.quotes[sym].ts > staleMs);
  const results = await Promise.allSettled(todo.map(([sym, cls]) => fetchQuote(sym, cls)));
  let ok = 0, fail = 0;
  results.forEach((r, i) => {
    const [sym, cls] = todo[i];
    if (r.status === 'fulfilled' && typeof r.value.price === 'number') {
      state.quotes[sym] = { price: r.value.price, currency: r.value.currency, name: r.value.name, ts: Date.now(), prevClose: r.value.prevClose };
      ok++;
    } else if (r.status === 'rejected') {
      fail++;
    }
  });
  if (ok || fail) scheduleSave();
  updatePricesNote({ ok, fail });
  render();
}

function updatePricesNote(extra) {
  const el = $('#prices-note');
  if (!state) { el.textContent = ''; return; }
  const item = neededSymbols().length;
  const ages = Object.values(state.quotes || {}).map(q => q.ts);
  const newest = ages.length ? Math.max(...ages) : null;
  let txt = item ? (item + (item === 1 ? ' position' : ' positions') + ' · ' + fmtAge(newest)) : 'no positions to price';
  if (extra && extra.ok) txt += ' · ' + extra.ok + ' updated';
  if (extra && extra.fail) txt += ' · ' + extra.fail + ' failed';
  el.textContent = 'Live pricing via Yahoo — ' + txt;
}

async function ensureFx() {
  const base = state.base || 'USD';
  if (state.fx && state.fx.base === base && Date.now() - state.fx.ts < 12 * 60 * 60 * 1000) return;
  try {
    const fx = await fetchFx(base);
    state.fx = { base, rates: fx.rates, ts: Date.now(), approx: !!fx.approx };
    if (fx.approx) toast('Approximate FX rates', 'Live FX is unreachable — using cached/approximate rates.', 'info');
    scheduleSave();
    render();
  } catch (e) {
    toast('FX rates unavailable', 'Conversions may be empty.', 'error');
  }
}

/* =================== shell helpers =================== */
function setSidebar(an) {
  $('#side-total').textContent = fmt(an.current.total, state.base, { frac: an.current.total < 1000 ? 2 : 0 });
  $('#nav-cash').textContent = an.positions.cash || '';
  $('#nav-stocks').textContent = an.positions.stocks || '';
  $('#nav-crypto').textContent = an.positions.crypto || '';
  $('#nav-future').textContent = an.positions.future || '';
}

const CLASS_COLORS = { cash: '#34d399', stocks: '#22d3ee', crypto: '#a78bfa' };
const CLASS_LABELS = { cash: 'Cash', stocks: 'Stocks', crypto: 'Crypto' };

/* =================== render: overview =================== */
function renderOverview(an) {
  animateNum($('#ov-current'), an.current.total, state.base);
  animateNum($('#ov-eoy'), an.eoyV.total, state.base);
  $('#card-current .hero-break').innerHTML = '';
  ['cash', 'stocks', 'crypto'].forEach(k => {
    const el = document.createElement('span');
    el.className = 'brk';
    el.innerHTML = '<i style="background:' + CLASS_COLORS[k] + '"></i>' + CLASS_LABELS[k] +
      ' <b>' + fmtShort(an.current[k], state.base) + '</b>';
    $('#card-current .hero-break').appendChild(el);
  });
  $('#card-eoy .hero-break').innerHTML = '';
  ['cash', 'stocks', 'crypto'].forEach(k => {
    const el = document.createElement('span');
    el.className = 'brk';
    el.innerHTML = '<i style="background:' + CLASS_COLORS[k] + '"></i>' + CLASS_LABELS[k] +
      ' <b>' + fmtShort(an.eoyV[k], state.base) + '</b>';
    $('#card-eoy .hero-break').appendChild(el);
  });

  renderDonut(an);
  renderSnapshot(an);
  renderYearAhead(an);

  const pill = $('#eoy-pill');
  if (an.delta > 0.005) { pill.textContent = '+' + fmtShort(an.delta, state.base) + ' planned before year-end'; pill.classList.remove('amber'); }
  else if (an.delta < -0.005) { pill.textContent = '-' + fmtShort(-an.delta, state.base) + ' net change'; pill.classList.add('amber'); }
  else { pill.textContent = 'Flat year-end projection'; pill.classList.remove('amber'); }
}

function renderDonut(an) {
  const svg = $('#donut');
  svg.innerHTML = '';
  const R = 52, C = 2 * Math.PI * R;
  const total = an.current.total;
  const mid = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  if (total > 0) {
    const vals = ['cash', 'stocks', 'crypto'].map(k => an.current[k]);
    let offset = 0;
    const gap = 1.5;
    vals.forEach((v, i) => {
      if (v <= 0) return;
      const frac = v / total;
      const len = Math.max(0, frac * C - gap);
      const seg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      seg.setAttribute('cx', 60); seg.setAttribute('cy', 60); seg.setAttribute('r', R);
      seg.setAttribute('class', 'seg');
      seg.setAttribute('stroke', CLASS_COLORS[['cash', 'stocks', 'crypto'][i]]);
      seg.style.strokeDasharray = len + ' ' + (C - len);
      seg.style.strokeDashoffset = -offset;
      offset += frac * C;
      svg.appendChild(seg);
    });
    mid.setAttribute('x', 60); mid.setAttribute('y', 64);
    mid.setAttribute('text-anchor', 'middle');
    mid.setAttribute('fill', '#e9edf3');
    mid.setAttribute('font-size', '13');
    mid.setAttribute('font-weight', '650');
    mid.textContent = '100%';
    svg.appendChild(mid);
  } else {
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    ring.setAttribute('cx', 60); ring.setAttribute('cy', 60); ring.setAttribute('r', R);
    ring.setAttribute('fill', 'none'); ring.setAttribute('stroke', 'rgba(255,255,255,.07)'); ring.setAttribute('stroke-width', '17');
    svg.appendChild(ring);
  }
  const legend = $('#legend');
  legend.innerHTML = '';
  ['cash', 'stocks', 'crypto'].forEach(k => {
    const li = document.createElement('li');
    li.innerHTML = '<i style="background:' + CLASS_COLORS[k] + '"></i><span>' + CLASS_LABELS[k] + '</span><b>' +
      (total > 0 ? Math.round(an.current[k] / total * 100) + '%' : '—') + '</b>';
    legend.appendChild(li);
  });
}

function renderSnapshot(an) {
  const el = $('#snapshot');
  el.innerHTML = '';
  const rows = [
    ['Base currency', state.base],
    ['Positions', String(an.positions.cash + an.positions.stocks + an.positions.crypto)],
    ['Planned events', String(an.positions.future)],
    ['Prices as of', fmtAge(Object.values(state.quotes || {}).length ? Math.max(...Object.values(state.quotes).map(q => q.ts)) : null)],
    ['Year-end projection', fmtShort(an.eoyV.total, state.base)],
    ['Encryption', 'AES-256-GCM'],
  ];
  rows.forEach(([label, val]) => {
    const li = document.createElement('li');
    li.innerHTML = '<span>' + label + '</span><strong class="num">' + val + '</strong>';
    el.appendChild(li);
  });
}

function renderYearAhead(an) {
  const el = $('#year-ahead');
  el.innerHTML = '';
  const base = state.base;
  const max = Math.max(an.current.total, an.eoyV.total, 1);
  [['Current', an.current.total, 'current'], ['End of year', an.eoyV.total, 'future']].forEach(([label, val, cls]) => {
    const row = document.createElement('div');
    row.className = 'ya-line';
    const fill = document.createElement('div');
    fill.className = 'ya-bar';
    const inner = document.createElement('div');
    inner.className = 'ya-fill ' + (cls === 'future' ? 'future' : '');
    inner.style.transform = 'scaleX(0)';
    fill.appendChild(inner);
    const v = document.createElement('div');
    v.className = 'ya-val';
    v.innerHTML = fmt(val, base, { frac: 2 }) + '<small>' + label + '</small>';
    const lab = document.createElement('div');
    lab.className = 'ya-label';
    lab.textContent = label === 'Current' ? 'Today' : label;
    row.appendChild(lab);
    row.appendChild(fill);
    row.appendChild(v);
    el.appendChild(row);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      inner.style.transform = 'scaleX(' + clamp(val / max, 0, 1) + ')';
    }));
  });
}

/* =================== render: generic list helpers =================== */
function rowActions(icon, kind, id) {
  const wrap = document.createElement('div');
  wrap.className = 'row-actions';
  const edit = document.createElement('button');
  edit.className = 'icon-btn'; edit.dataset.edit = kind + ':' + id; edit.title = 'Edit';
  edit.innerHTML = '<svg><use href="#i-edit"/></svg>';
  const del = document.createElement('button');
  del.className = 'icon-btn'; del.dataset.del = kind + ':' + id; del.title = 'Delete';
  del.innerHTML = '<svg><use href="#i-trash"/></svg>';
  wrap.append(edit, del);
  return wrap;
}

function chgBadge(row) {
  const q = quoteFor(row.ticker || row.symbol);
  if (!q || !q.prevClose || !q.price) return '<span class="chg none">·</span>';
  const pct = (q.price - q.prevClose) / q.prevClose * 100;
  const cls = pct > 0.0001 ? 'up' : pct < -0.0001 ? 'down' : 'none';
  return '<span class="chg ' + cls + '">' + (pct > 0 ? '+' : '') + pct.toFixed(2) + '%</span>';
}

/* =================== render: cash =================== */
function renderCash(an) {
  const wrap = $('#cash-list');
  wrap.innerHTML = '';
  $('#cash-sub').textContent = an.cashRows.length
    ? fmt(an.current.cash, state.base) + ' across ' + an.cashRows.length + ' ' + (an.cashRows.length === 1 ? 'entry' : 'entries')
    : '';
  an.cashRows.forEach(r => {
    const row = document.createElement('div');
    row.className = 'row';
    const tag = r.interest ? '<span class="tag" style="background:rgba(251,191,36,.14);color:var(--amber)">interest</span>' : '';
    let sub = '<span class="row-price">' + fmtNum(r.amount) + ' ' + r.currency + '</span>';
    if (r.currency !== state.base) sub += ' · ≈ ' + fmt(r.curB, state.base);
    let interestLine = '';
    if (r.interest) {
      interestLine = '<span class="interest">▲ ' + r.rate + '% p.a.</span>' +
        '<span class="dim">' + (r.startDate || '?') + (r.endDate ? ' → ' + r.endDate : '') + '</span>';
    }
    row.innerHTML =
      '<div class="row-ico ico-cash"><svg><use href="#i-wallet"/></svg></div>' +
      '<div class="row-body"><div class="row-title"><strong>' + esc(r.label || 'Cash') + '</strong>' + tag + '</div>' +
      '<div class="row-sub">' + sub + interestLine + '</div></div>' +
      '<div class="row-value"><strong>' + fmt(r.curB, state.base) + '</strong>' +
      '<small>' + (r.interest ? 'now ·' : '') + ' EOY ' + fmt(r.eoyV, state.base) + '</small></div>';
    row.appendChild(rowActions(null, 'cash', r.id));
    wrap.appendChild(row);
  });
  $('#cash-empty').classList.toggle('hidden', an.cashRows.length > 0);
}

/* =================== render: stocks & crypto =================== */
function renderHolding(rows, emptyEl, kind, an) {
  const wrap = kind === 'stocks' ? $('#stocks-list') : $('#crypto-list');
  const sub = kind === 'stocks' ? $('#stocks-sub') : $('#crypto-sub');
  wrap.innerHTML = '';
  sub.textContent = rows.length
    ? fmt(kind === 'stocks' ? an.current.stocks : an.current.crypto, state.base) +
      ' · ' + rows.length + (rows.length === 1 ? ' position' : ' positions')
    : '';
  rows.forEach(r => {
    const sym = r.ticker || r.symbol;
    const q = quoteFor(sym);
    const row = document.createElement('div');
    row.className = 'row';
    const ico = kind === 'stocks' ? 'row-ico ico-stock' : 'row-ico ico-crypto';
    const icSel = kind === 'stocks' ? '#i-chart' : '#i-coin';
    const priceFmt = q ? fmt(q.price, q.currency, { frac: q.price < 1 ? 4 : 2 }) : '…';
    const rowSub = q
      ? '<div class="row-price">' + priceFmt + ' ' + (q.currency || '') + chgBadge(r) + '</div>' +
        (r.note ? '<span class="dim">' + esc(r.note) + '</span>' : '')
      : '<span class="dim">no price yet — add on refresh</span>';
    row.innerHTML =
      '<div class="row-ico ' + ico + '"><svg><use href="' + icSel + '"/></svg></div>' +
      '<div class="row-body"><div class="row-title"><strong>' + esc(sym) + '</strong>' +
      (q && q.name && q.name.toUpperCase() !== sym ? '<span class="dim">' + esc(trunc(q.name, 34)) + '</span>' : '') +
      '</div><div class="row-sub">' + rowSub + '</div></div>' +
      '<div class="row-value"><strong>' + fmtNum(r.qty) + ' ' + esc(sym) + '</strong>' +
      '<small>worth ' + fmt(r.value, state.base) + '</small></div>';
    row.appendChild(rowActions(null, kind === 'stocks' ? 'stock' : 'crypto', r.id));
    wrap.appendChild(row);
  });
  emptyEl.classList.toggle('hidden', rows.length > 0);
}

/* =================== render: future =================== */
function renderFuture(an) {
  const wrap = $('#future-list');
  wrap.innerHTML = '';
  $('#future-sub').textContent = an.positions.future
    ? an.positions.future + ' planned event' + (an.positions.future === 1 ? '' : 's') + ' before year-end'
    : '';
  an.futureRows.forEach(r => {
    const row = document.createElement('div');
    row.className = 'row';
    const icoMap = { cash: 'ico-cash', stock: 'ico-stock', crypto: 'ico-crypto' };
    const selMap = { cash: '#i-wallet', stock: '#i-chart', crypto: '#i-coin' };
    const typeName = { cash: 'cash', stock: 'stock', crypto: 'crypto' }[r.type];
    let sub;
    if (r.type === 'cash') sub = '<span class="row-price">' + fmtNum(r.amount) + ' ' + r.currency + '</span><span class="dim">extra cash by end of year</span>';
    else sub = '<span class="row-price">' + fmtNum(r.qty) + ' × ' + esc(r.ticker || r.symbol) + '</span><span class="dim">buy by end of year</span>';
    row.innerHTML =
      '<div class="row-ico ' + icoMap[r.type] + '"><svg><use href="' + selMap[r.type] + '"/></svg></div>' +
      '<div class="row-body"><div class="row-title"><strong>' + esc(r.label || typeName) + '</strong>' +
      '<span class="tag" style="background:rgba(251,191,36,.14);color:var(--amber)">' + typeName + '</span></div>' +
      '<div class="row-sub">' + sub + '</div></div>' +
      '<div class="row-value"><strong>+' + fmt(r.value, state.base, { frac: 2 }) + '</strong><small>to EOY</small></div>';
    row.appendChild(rowActions(null, 'future', r.id));
    wrap.appendChild(row);
  });
  $('#future-empty').classList.toggle('hidden', an.positions.future > 0);

  const stats = $('#fut-stats');
  stats.innerHTML = '';
  [['Cash', 'cash'], ['Stocks', 'stock'], ['Crypto', 'crypto']].forEach(([label, type]) => {
    const rowsArr = an.futureRows.filter(f => f.type === type);
    const s = rowsArr.reduce((a, r) => a + r.value, 0);
    const el = document.createElement('div');
    el.className = 'fut-stat';
    el.innerHTML = '<span>' + label + '</span><strong class="num">+' + fmt(s, state.base, { frac: 2 }) + '</strong>';
    stats.appendChild(el);
  });
}

/* =================== main render =================== */
function render() {
  if (!state) return;
  analysis = analyze();
  setSidebar(analysis);
  if (currentView === 'overview') renderOverview(analysis);
  else if (currentView === 'cash') renderCash(analysis);
  else if (currentView === 'stocks') renderHolding(analysis.stockRows, $('#stocks-empty'), 'stocks', analysis);
  else if (currentView === 'crypto') renderHolding(analysis.cryptoRows, $('#crypto-empty'), 'crypto', analysis);
  else if (currentView === 'future') renderFuture(analysis);
  else if (currentView === 'settings') renderSettings();
  updatePricesNote();
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function trunc(s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }

/* =================== settings =================== */
function renderSettings() {
  const sel = $('#set-base');
  const cur = sel.value;
  sel.innerHTML = '';
  CURRENCIES.forEach(([code, name]) => {
    const o = document.createElement('option');
    o.value = code; o.textContent = name + ' (' + code + ')';
    if (code === state.base) o.selected = true;
    sel.appendChild(o);
  });
  if (state.base && !CURRENCY_CODES.includes(state.base)) {
    const o = document.createElement('option');
    o.value = state.base; o.textContent = currencyName(state.base) + ' (' + state.base + ')';
    o.selected = true;
    sel.appendChild(o);
  }
}

/* =================== modals =================== */
function openModal(html) {
  $('#modal-card').innerHTML = html;
  $('#modal').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  const f = $('#modal-card input, #modal-card select');
  if (f && f[0]) setTimeout(() => f[0].focus(), 60);
}
function closeModal() {
  $('#modal').classList.add('hidden');
  $('#modal-card').innerHTML = '';
  document.body.style.overflow = '';
}

function currencySelect(name, value) {
  let opts = '<option value="">Currency…</option>';
  CURRENCIES.forEach(([code, label]) => {
    opts += '<option value="' + code + '"' + (value === code ? ' selected' : '') + '>' + label + ' (' + code + ')</option>';
  });
  return '<select name="' + name + '" class="cur">' + opts + '</select>';
}

function formField(label, inner) {
  return '<div class="field"><label>' + label + '</label>' + inner + '</div>';
}

/* ---- cash modal ---- */
function openCashModal(cash) {
  const isEdit = !!cash;
  const c = cash || { label: '', amount: '', currency: state.base, interestRate: '', startDate: '', endDate: '' };
  const html =
    '<div class="m-ico ico-cash"><svg><use href="#i-wallet"/></svg></div>' +
    '<h3>' + (isEdit ? 'Edit cash' : 'Add cash') + '</h3>' +
    '<p class="m-sub">A bank balance, or a deposit that grows with interest.</p>' +
    '<form class="m-form" id="m-form-cash">' +
    formField('Label', '<input name="label" value="' + esc(c.label) + '" placeholder="e.g. Raiffeisen savings">') +
    '<div class="m-grid">' +
    formField('Amount', '<input name="amount" type="number" step="any" min="0" value="' + esc(c.amount) + '" placeholder="0.00" required>') +
    formField('Currency', currencySelect('currency', c.currency)) +
    '</div>' +
    '<div class="m-grid">' +
    formField('Interest rate % p.a.', '<input name="interestRate" type="number" step="any" min="0" max="1000" value="' + esc(c.interestRate) + '" placeholder="e.g. 4.2">') +
    '<div class="field"><label>« optional — leave blank for plain cash »</label><span></span></div>' +
    '</div>' +
    '<div class="m-grid">' +
    formField('Earning since', '<input name="startDate" type="date" value="' + esc(c.startDate) + '">') +
    formField('Expires', '<input name="endDate" type="date" value="' + esc(c.endDate) + '">') +
    '</div>' +
    '<div class="m-foot"><button type="button" class="btn btn-ghost" data-close="modal">Cancel</button>' +
    '<button type="submit" class="btn btn-primary">' + (isEdit ? 'Save' : 'Add') + '</button></div>' +
    '</form>';
  openModal(html);
  $('#m-form-cash').addEventListener('submit', e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const amount = parseFloat(fd.get('amount'));
    const currency = String(fd.get('currency') || '').toUpperCase();
    if (!isFinite(amount) || amount <= 0) return toast('Check the amount', 'Enter a positive number.', 'error');
    if (!currency) return toast('Pick a currency', 'Select the currency for this cash.', 'error');
    const entry = {
      id: isEdit ? c.id : uid(),
      label: String(fd.get('label') || '').trim() || 'Cash',
      amount,
      currency,
      interestRate: fd.get('interestRate') ? String(fd.get('interestRate')).trim() : '',
      startDate: fd.get('startDate') ? String(fd.get('startDate')).trim() : '',
      endDate: fd.get('endDate') ? String(fd.get('endDate')).trim() : '',
    };
    if (entry.interestRate && !entry.startDate) {
      return toast('Missing start date', 'A deposit earning interest needs a start date.', 'error');
    }
    if (entry.amount && !entry.currency) return;
    mutateState(() => {
      if (isEdit) state.cash = state.cash.map(x => x.id === c.id ? entry : x);
      else state.cash.push(entry);
    });
    closeModal();
    toast(isEdit ? 'Cash updated' : 'Cash added', '', 'success');
  });
}

/* ---- stock/crypto modal ---- */
function openAssetModal(kind, item) {
  const isCrypto = kind === 'crypto';
  const isEdit = !!item;
  const x = item || { ticker: '', symbol: '', qty: '', note: '' };
  const symName = isCrypto ? 'Symbol' : 'Ticker';
  const sym = isCrypto ? x.symbol : x.ticker;
  const placeholder = isCrypto ? 'e.g. BTC · ETH · SOL' : 'e.g. AAPL · TSLA · GGAL.BA';
  const ico = isCrypto ? 'ico-crypto' : 'ico-stock';
  const icon = isCrypto ? '#i-coin' : '#i-chart';
  const title = (isEdit ? 'Edit ' : 'Add ') + (isCrypto ? 'crypto' : 'stock');
  const html =
    '<div class="m-ico ' + ico + '"><svg><use href="' + icon + '"/></svg></div>' +
    '<h3>' + title + '</h3>' +
    '<p class="m-sub">' + (isCrypto ? 'Coins are priced via Yahoo Finance (e.g. BTC → BTC-USD).' : 'Enter a ticker and quantity — value is priced live.') + '</p>' +
    '<form class="m-form" id="m-form-asset">' +
    formField(symName, '<input name="sym" value="' + esc(sym) + '" placeholder="' + placeholder + '" autocomplete="off" autocapitalize="characters" required>') +
    formField('Quantity', '<input name="qty" type="number" step="any" min="0" value="' + esc(x.qty) + '" placeholder="e.g. 12" required>') +
    formField('Note (optional)', '<input name="note" value="' + esc(x.note) + '" placeholder="e.g. ISA account">') +
    '<div class="m-foot"><button type="button" class="btn btn-ghost" data-close="modal">Cancel</button>' +
    '<button type="submit" class="btn btn-primary">' + (isEdit ? 'Save' : 'Add') + '</button></div>' +
    '</form>';
  openModal(html);
  $('#m-form-asset').addEventListener('submit', e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const raw = String(fd.get('sym') || '').trim().toUpperCase();
    const qty = parseFloat(fd.get('qty'));
    if (!raw) return toast('Enter a ' + (isCrypto ? 'symbol' : 'ticker'), 'Required field.', 'error');
    if (!isFinite(qty) || qty <= 0) return toast('Check quantity', 'Enter a positive quantity.', 'error');
    const entry = isCrypto ? { symbol: raw, qty, note: String(fd.get('note') || '').trim() }
      : { ticker: raw, qty, note: String(fd.get('note') || '').trim() };
    entry.id = isEdit ? x.id : uid();
    mutateState(() => {
      setStateEntry(state, kind, entry, isEdit ? x.id : null);
    });
    closeModal();
    refreshQuotes(true).then(() => toast((isCrypto ? 'Crypto' : 'Stock') + ' added', 'Fetching live price…', 'success'));
  });
}

function setStateEntry(st, kind, entry, replaceId) {
  const key = kind === 'stock' ? 'stocks' : 'crypto';
  if (replaceId) st[key] = st[key].map(x => x.id === replaceId ? entry : x);
  else st[key].push(entry);
}

/* ---- future modal ---- */
function openFutureModal(f) {
  const isEdit = !!f;
  const x = f || { type: 'cash', label: '', amount: '', currency: state.base, ticker: '', symbol: '', qty: '' };
  const typeSel = ['cash', 'stock', 'crypto'].map(t =>
    '<option value="' + t + '"' + (x.type === t ? ' selected' : '') + '>' +
    (t === 'cash' ? 'Extra cash' : t === 'stock' ? 'Buy stocks' : 'Buy crypto') + '</option>').join('');
  const html =
    '<div class="m-ico ico-future"><svg><use href="#i-future"/></svg></div>' +
    '<h3>' + (isEdit ? 'Edit event' : 'Planned event') + '</h3>' +
    '<p class="m-sub">A contribution planned before the end of the year — it folds into your year-end projection.</p>' +
    '<form class="m-form" id="m-form-future">' +
    formField('What', '<select name="type">' + typeSel + '</select>') +
    formField('Label (optional)', '<input name="label" value="' + esc(x.label) + '" placeholder="e.g. Year-end bonus">') +
    '<div class="fut-fields" id="ff-cash">' +
    '<div class="m-grid">' +
    formField('Amount', '<input name="amount" type="number" step="any" min="0" value="' + esc(x.amount) + '" placeholder="0.00">') +
    formField('Currency', currencySelect('currency', x.currency)) +
    '</div></div>' +
    '<div class="fut-fields hidden" id="ff-stock">' +
    formField('Ticker', '<input name="ticker" value="' + esc(x.ticker) + '" placeholder="e.g. VWCE">') +
    formField('Quantity', '<input name="qty" type="number" step="any" min="0" value="' + esc(x.qty) + '" placeholder="e.g. 5">') +
    '</div>' +
    '<div class="fut-fields hidden" id="ff-crypto">' +
    formField('Symbol', '<input name="symbol" value="' + esc(x.symbol) + '" placeholder="e.g. BTC">') +
    formField('Quantity', '<input name="qty2" type="number" step="any" min="0" value="' + esc(x.qty) + '" placeholder="e.g. 0.5">') +
    '</div>' +
    '<div class="m-foot"><button type="button" class="btn btn-ghost" data-close="modal">Cancel</button>' +
    '<button type="submit" class="btn btn-primary">' + (isEdit ? 'Save' : 'Add') + '</button></div>' +
    '</form>';
  openModal(html);
  const sync = () => {
    const t = $('#m-form-future [name=type]').value;
    $('#ff-cash').classList.toggle('hidden', t !== 'cash');
    $('#ff-stock').classList.toggle('hidden', t !== 'stock');
    $('#ff-crypto').classList.toggle('hidden', t !== 'crypto');
  };
  $('#m-form-future [name=type]').addEventListener('change', sync);
  sync();
  $('#m-form-future').addEventListener('submit', e => {
    e.preventDefault();
    const form = e.target;
    const fd = new FormData(form);
    const type = fd.get('type');
    const entry = { type, label: String(fd.get('label') || '').trim(), id: isEdit ? x.id : uid() };
    if (type === 'cash') {
      const amount = parseFloat(fd.get('amount'));
      const currency = String(fd.get('currency') || '').toUpperCase();
      if (!isFinite(amount) || amount <= 0) return toast('Check the amount', 'Enter a positive number.', 'error');
      if (!currency) return toast('Pick a currency', 'Required.', 'error');
      entry.amount = amount; entry.currency = currency;
    } else if (type === 'stock') {
      const ticker = String(fd.get('ticker') || '').trim().toUpperCase();
      const qty = parseFloat(fd.get('qty'));
      if (!ticker) return toast('Enter a ticker', 'Required.', 'error');
      if (!isFinite(qty) || qty <= 0) return toast('Check quantity', 'Enter a positive quantity.', 'error');
      entry.ticker = ticker; entry.qty = qty;
    } else {
      const symbol = String(fd.get('symbol') || '').trim().toUpperCase();
      const qty = parseFloat(fd.get('qty2'));
      if (!symbol) return toast('Enter a symbol', 'Required.', 'error');
      if (!isFinite(qty) || qty <= 0) return toast('Check quantity', 'Enter a positive quantity.', 'error');
      entry.symbol = symbol; entry.qty = qty;
    }
    mutateState(() => {
      if (isEdit) state.future = state.future.map(xx => xx.id === x.id ? entry : xx);
      else state.future.push(entry);
    });
    closeModal();
    if (type !== 'cash') refreshQuotes(true);
    toast(isEdit ? 'Event updated' : 'Event added', 'Appears in your year-end projection.', 'success');
  });
}

/* ---- confirm delete modal ---- */
function confirmDelete(kind, id, label) {
  const icoMap = { cash: 'ico-cash', stock: 'ico-stock', crypto: 'ico-crypto', future: 'ico-future' };
  const iconMap = { cash: '#i-wallet', stock: '#i-chart', crypto: '#i-coin', future: '#i-future' };
  const html =
    '<div class="m-ico ' + (icoMap[kind] || 'ico-future') + '"><svg><use href="' + (iconMap[kind] || '#i-future') + '"/></svg></div>' +
    '<h3>Delete ' + kind + '?</h3>' +
    '<p class="m-sub">"' + esc(label) + '" will be removed from your vault.</p>' +
    '<div class="m-foot"><button type="button" class="btn btn-ghost" data-close="modal">Cancel</button>' +
    '<button type="button" class="btn btn-danger" id="m-confirm-del"><svg><use href="#i-trash"/></svg><span>Delete</span></button></div>';
  openModal(html);
  $('#m-confirm-del').addEventListener('click', () => {
    mutateState(() => {
      const key = { cash: 'cash', stock: 'stocks', crypto: 'crypto', future: 'future' }[kind];
      state[key] = state[key].filter(x => x.id !== id);
    });
    closeModal();
    toast('Deleted', 'Removed from your vault.', 'success');
  });
}

/* =================== events =================== */
function wireEvents() {
  $('#lock-form').addEventListener('submit', onLockSubmit);
  $('#lock-toggle').addEventListener('click', () => {
    const i = $('#lock-pass'); const t = $('#lock-toggle');
    const show = i.type === 'password';
    i.type = show ? 'text' : 'password';
    t.innerHTML = '<svg><use href="' + (show ? '#i-eyeoff' : '#i-eye') + '"/></svg>';
  });

  $$('#nav .nav-item').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
  $('#btn-lock').addEventListener('click', () => { password = null; state = null; lock(); });
  $('#btn-refresh').addEventListener('click', () => { ensureFx(); refreshQuotes(true); });
  $('#btn-random').addEventListener('click', loadSampleData);

  document.addEventListener('click', e => {
    const openTarget = e.target.closest('[data-open]');
    if (openTarget) {
      const type = openTarget.dataset.open;
      if (type === 'cash') openCashModal(null);
      else if (type === 'stock') openAssetModal('stock', null);
      else if (type === 'crypto') openAssetModal('crypto', null);
      else if (type === 'future') openFutureModal(null);
      return;
    }
    const closeTarget = e.target.closest('[data-close]');
    if (closeTarget) { closeModal(); return; }
    const editTarget = e.target.closest('[data-edit]');
    if (editTarget) {
      const [kind, id] = editTarget.dataset.edit.split(':');
      if (kind === 'cash') { const it = state.cash.find(x => x.id === id); if (it) openCashModal(it); }
      else if (kind === 'stock') { const it = state.stocks.find(x => x.id === id); if (it) openAssetModal('stock', it); }
      else if (kind === 'crypto') { const it = state.crypto.find(x => x.id === id); if (it) openAssetModal('crypto', it); }
      else if (kind === 'future') { const it = state.future.find(x => x.id === id); if (it) openFutureModal(it); }
      return;
    }
    const delTarget = e.target.closest('[data-del]');
    if (delTarget) {
      const [kind, id] = delTarget.dataset.del.split(':');
      const key = { cash: 'cash', stock: 'stocks', crypto: 'crypto', future: 'future' }[kind];
      const it = state[key].find(x => x.id === id);
      if (it) confirmDelete(kind, id, it.label || it.ticker || it.symbol || kind);
      return;
    }
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
  });

  $('#set-base').addEventListener('change', e => {
    const base = e.target.value.toUpperCase();
    if (base === state.base) return;
    mutateState(() => { state.base = base; state.fx = null; });
    ensureFx();
    toast('Base currency set to ' + base, 'All values now convert to ' + base + '.', 'success');
  });

  $('#btn-change-pw').addEventListener('click', async e => {
    const cur = $('#pw-cur').value, n1 = $('#pw-new').value, n2 = $('#pw-new2').value;
    if (cur !== password) return toast('Wrong current password', 'Could not change password.', 'error');
    if (n1.length < 6) return toast('New password too short', 'Use at least 6 characters.', 'error');
    if (n1 !== n2) return toast('Passwords do not match', 'Re-enter the new password.', 'error');
    const btn = e.target;
    btn.disabled = true;
    try {
      password = n1;
      await saveNow();
      $('#pw-cur, #pw-new, #pw-new2').forEach(x => x.value = '');
      toast('Password changed', 'Your vault is re-encrypted.', 'success');
    } catch (err) {
      password = cur;
      toast('Could not change password', String(err.message || err), 'error');
    } finally {
      btn.disabled = false;
    }
  });

  $('#btn-export').addEventListener('click', exportBackup);
  $('#btn-import').addEventListener('click', () => $('#import-file').click());
  $('#import-file').addEventListener('change', importBackup);
}

function exportBackup() {
  fetchBlob().then(blob => {
    if (!blob) return toast('Nothing to back up', 'Your vault is empty.', 'info');
    const a = document.createElement('a');
    const file = new Blob([JSON.stringify(blob, null, 2)], { type: 'application/json' });
    a.href = URL.createObjectURL(file);
    a.download = 'nestegg-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Backup downloaded', 'Keep it somewhere safe together with your password.', 'success');
  }).catch(() => toast('Export failed', 'Could not read the vault.', 'error'));
}

async function importBackup(e) {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    const text = await file.text();
    const blob = JSON.parse(text);
    if (!blob || !blob.ct || !blob.salt || !blob.iv) throw new Error('not a NestEgg backup');
    await putBlob(blob);
    state = null; password = null;
    toast('Backup restored', 'Enter your password to open it.', 'success');
    lock();
  } catch (err) {
    toast('Import failed', err.message || 'That file is not a valid backup.', 'error');
  }
}

/* =================== sample data =================== */
function loadSampleData() {
  const year = new Date().getFullYear();
  const start = year + '-01-15';
  const end = year + '-12-31';
  mutateState(() => {
    state.cash = [
      { id: uid(), label: 'Checking account', amount: 4200, currency: 'EUR', interestRate: '', startDate: '', endDate: '' },
      { id: uid(), label: 'High-yield savings', amount: 15000, currency: 'EUR', interestRate: '3.4', startDate: start, endDate: end },
    ];
    state.stocks = [
      { id: uid(), ticker: 'AAPL', qty: 10, note: 'Core hold' },
      { id: uid(), ticker: 'VWCE', qty: 25, note: 'All-world ETF' },
    ];
    state.crypto = [
      { id: uid(), symbol: 'BTC', qty: 0.05, note: 'Long-term' },
      { id: uid(), symbol: 'ETH', qty: 1.2, note: '' },
    ];
    state.future = [
      { id: uid(), type: 'cash', label: 'Year-end bonus', amount: 3000, currency: 'EUR' },
      { id: uid(), type: 'stock', label: 'DCA stocks', ticker: 'VWCE', qty: 10 },
      { id: uid(), type: 'crypto', label: 'Stack more', symbol: 'BTC', qty: 0.1 },
    ];
    state.fx = null;
  });
  ensureFx();
  refreshQuotes(true);
  toast('Sample portfolio loaded', 'Edit or clear it to start your own.', 'info');
}

/* =================== boot =================== */
if (window.crypto && window.crypto.subtle) {
  init();
} else {
  document.body.innerHTML = '<div style="padding:60px;text-align:center;font-family:sans-serif">' +
    'NestEgg needs a browser with Web Crypto (modern Chrome, Firefox, Safari or Edge).</div>';
}