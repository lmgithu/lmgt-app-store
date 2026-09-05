'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3910', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_FILE = path.join(DATA_DIR, 'wallet.blob');
const QUOTE_CACHE = new Map();
const FX_CACHE = { ts: 0, base: null, rates: null, approx: false };

const UA = 'Mozilla/5.0 (X11; Linux x86_64; NestEgg/1.0) AppleWebKit/537.36';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.txt': 'text/plain; charset=utf-8',
};

// ---------------------------------------------------------------- helpers

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function fetchWithTimeout(url, opts, ms) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  return fetch(url, { ...opts, signal: ac.signal })
    .finally(() => clearTimeout(t));
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------- data blob (encrypted client-side)

async function apiSaveBlob(req, res) {
  const body = await readBody(req, 5 * 1024 * 1024);
  if (body.length === 0) return json(res, 400, { error: 'empty payload' });
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (!parsed || typeof parsed.ct !== 'string' || !parsed.salt || !parsed.iv) {
      return json(res, 400, { error: 'malformed blob' });
    }
  } catch {
    return json(res, 400, { error: 'invalid JSON' });
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, body);
  fs.renameSync(tmp, DATA_FILE);
  json(res, 200, { ok: true });
}

function apiGetBlob(res) {
  try {
    const raw = fs.readFileSync(DATA_FILE);
    if (raw.length === 0) return json(res, 404, { error: 'no data' });
    json(res, 200, { blob: raw.toString('utf8') });
  } catch {
    json(res, 404, { error: 'no data' });
  }
}

// ---------------------------------------------------------------- quotes (Yahoo Finance)

function parseYahooChart(data, requested) {
  const result = data && data.chart && data.chart.result && data.chart.result[0];
  if (!result) return null;
  const meta = result.meta || {};
  let price = null;
  if (typeof meta.regularMarketPrice === 'number') price = meta.regularMarketPrice;
  const closes = result.indicators && result.indicators.quote && result.indicators.quote[0] && result.indicators.quote[0].close;
  if (closes && Array.isArray(closes)) {
    for (let i = closes.length - 1; i >= 0; i--) {
      if (typeof closes[i] === 'number') {
        if (price === null) price = closes[i];
        break;
      }
    }
  }
  if (price === null) return null;
  const prev = typeof meta.chartPreviousClose === 'number'
    ? meta.chartPreviousClose
    : (typeof meta.previousClose === 'number' ? meta.previousClose : null);
  return {
    symbol: (meta.symbol || requested).toUpperCase(),
    name: meta.shortName || meta.longName || meta.symbol || requested,
    price,
    prevClose: prev,
    currency: meta.currency || 'USD',
    ts: Date.now(),
  };
}

async function yahooQuote(requested, cls) {
  let symbol = String(requested || '').trim().toUpperCase().replace(/[^A-Z0-9.-]/g, '');
  if (!symbol) return { error: 'empty symbol' };
  let candidates;
  if (cls === 'crypto') {
    candidates = symbol.includes('-') ? [symbol] : [symbol + '-USD', symbol];
  } else {
    candidates = symbol.includes('-') ? [symbol] : [symbol, symbol + '.AX', symbol + '.L'];
  }
  let lastErr = null;
  for (const cand of candidates) {
    const url = 'https://query1.finance.yahoo.com/v8/finance/chart/' +
      encodeURIComponent(cand) + '?range=5d&interval=1d';
    try {
      const resp = await fetchWithTimeout(url, { headers: { 'User-Agent': UA, Accept: 'application/json' } }, 9000);
      const text = await resp.text();
      let data = null;
      try { data = JSON.parse(text); } catch { /* ignore */ }
      const quote = parseYahooChart(data, cand);
      if (quote && !(data && data.chart && data.chart.error)) return quote;
      if (data && data.chart && data.chart.error) lastErr = data.chart.error;
    } catch (e) {
      lastErr = { message: String(e.message || e) };
    }
  }
  return { error: (lastErr && (lastErr.message || lastErr.description)) || 'quote unavailable' };
}

async function apiQuote(req, res) {
  const url = new URL(req.url, 'http://x');
  const q = url.searchParams.get('q') || '';
  const cls = url.searchParams.get('cls') || '';
  const key = q.trim().toUpperCase();
  if (!key) return json(res, 400, { error: 'missing ?q=' });
  const cached = QUOTE_CACHE.get(key);
  if (cached && Date.now() - cached.ts < 60 * 1000) {
    return json(res, 200, { ...cached, _cached: true });
  }
  const result = await yahooQuote(q, cls);
  if (result.error) return json(res, 502, { error: result.error, symbol: key });
  QUOTE_CACHE.set(key, result);
  json(res, 200, result);
}

// ---------------------------------------------------------------- FX (open.er-api -> frankfurter -> static fallback)

const FALLBACK_RATES = {
  USD: 1, EUR: 0.91, GBP: 0.77, CHF: 0.85, JPY: 148, CNY: 7.1, INR: 83.5, CAD: 1.36,
  AUD: 1.5, NZD: 1.63, SGD: 1.31, HKD: 7.81, KRW: 1335, SEK: 10.4, NOK: 10.7, DKK: 6.8,
  PLN: 3.92, CZK: 22.8, HUF: 358, RON: 4.53, BGN: 1.78, TRY: 34.2, RUB: 92, BRL: 5.45,
  MXN: 17.9, ZAR: 18.2, AED: 3.67, SAR: 3.75, ILS: 3.68, MYR: 4.35, THB: 33.8, IDR: 15400,
  PHP: 55.9, VND: 24600, NGN: 1550, EGP: 48.4,
};

async function fetchFxRates(base) {
  try {
    const resp = await fetchWithTimeout(
      'https://open.er-api.com/v6/latest/' + encodeURIComponent(base),
      { headers: { 'User-Agent': UA } }, 9000);
    const d = await resp.json();
    if (d && d.result === 'success' && d.rates) return { rates: d.rates, approx: false };
  } catch { /* next */ }
  try {
    const resp = await fetchWithTimeout(
      'https://api.frankfurter.app/latest?from=' + encodeURIComponent(base),
      { headers: { 'User-Agent': UA } }, 9000);
    const d = await resp.json();
    if (d && d.rates && Object.keys(d.rates).length) return { rates: d.rates, approx: false };
  } catch { /* next */ }
  const rates = { ...FALLBACK_RATES, [base]: 1 };
  return { rates, approx: true };
}

async function apiFx(req, res) {
  const url = new URL(req.url, 'http://x');
  const base = (url.searchParams.get('base') || 'USD').toUpperCase().slice(0, 3);
  if (FX_CACHE.base === base && Date.now() - FX_CACHE.ts < 5 * 60 * 1000) {
    return json(res, 200, { rates: FX_CACHE.rates, base, approx: FX_CACHE.approx, ts: FX_CACHE.ts });
  }
  const out = await fetchFxRates(base);
  FX_CACHE.rates = out.rates; FX_CACHE.base = base; FX_CACHE.approx = out.approx; FX_CACHE.ts = Date.now();
  json(res, 200, { rates: out.rates, base, approx: out.approx, ts: FX_CACHE.ts });
}

// ---------------------------------------------------------------- static

function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath.split('?')[0]);
  if (rel === '/' || rel === '') rel = '/index.html';
  if (rel === '/favicon.ico') rel = '/logo.svg';
  const fp = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!fp.startsWith(PUBLIC_DIR) || fp === PUBLIC_DIR) {
    res.writeHead(403); return res.end();
  }
  fs.readFile(fp, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(fp).toLowerCase();
    const etag = '"' + crypto.createHash('sha1').update(data).digest('hex').slice(0, 16) + '"';
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { 'ETag': etag });
      return res.end();
    }
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
      'ETag': etag,
    });
    res.end(data);
  });
}

// ---------------------------------------------------------------- router

const server = http.createServer(async (req, res) => {
  const urlPath = (req.url || '/').split('?')[0];
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');

  try {
    if (urlPath === '/api/data' && req.method === 'PUT') return await apiSaveBlob(req, res);
    if (urlPath === '/api/data' && req.method === 'GET') return apiGetBlob(res);
    if (urlPath === '/api/quote') return await apiQuote(req, res);
    if (urlPath === '/api/fx') return await apiFx(req, res);
    if (urlPath.startsWith('/api/')) return json(res, 404, { error: 'unknown api' });
    return serveStatic(req, res, req.url);
  } catch (e) {
    console.error('[error]', e);
    return json(res, 500, { error: String(e.message || e) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`NestEgg server listening on http://${HOST}:${PORT}`);
  console.log(`Data file: ${DATA_FILE}`);
});

['SIGTERM', 'SIGINT'].forEach((sig) => {
  process.on(sig, () => {
    console.log('Shutting down...');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
});