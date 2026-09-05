(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.nesteggCrypto = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);
  var H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
  var H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(bytes) {
    var len = bytes.length;
    var bitHi = Math.floor(len / 536870912);
    var bitLo = (len * 8) >>> 0;
    var padded = new Uint8Array((len + 9 + 7 >> 3) * 64 + 1);
    var plen = Math.ceil((len + 1 + 8) / 64) * 64;
    if (padded.length < plen) padded = new Uint8Array(plen);
    padded.set(bytes, 0);
    padded[len] = 0x80;
    padded[plen - 8] = (bitHi >>> 24) & 0xff;
    padded[plen - 7] = (bitHi >>> 16) & 0xff;
    padded[plen - 6] = (bitHi >>> 8) & 0xff;
    padded[plen - 5] = bitHi & 0xff;
    padded[plen - 4] = (bitLo >>> 24) & 0xff;
    padded[plen - 3] = (bitLo >>> 16) & 0xff;
    padded[plen - 2] = (bitLo >>> 8) & 0xff;
    padded[plen - 1] = bitLo & 0xff;
    var h = new Int32Array([H0, H1, H2, H3, H4, H5, H6, H7]);
    var w = new Int32Array(64);
    var dv = new DataView(padded.buffer, 0);
    for (var off = 0; off < plen; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    var out = new Uint8Array(32);
    var outDv = new DataView(out.buffer);
    for (i = 0; i < 8; i++) outDv.setUint32(i * 4, h[i], false);
    return out;
  }

  function hmacSha256(key, msg) {
    if (typeof key === 'string') key = new TextEncoder().encode(key);
    if (typeof msg === 'string') msg = new TextEncoder().encode(msg);
    if (key.length > 64) key = sha256(key);
    var block = new Uint8Array(64);
    block.set(key, 0);
    var ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) { ipad[i] = block[i] ^ 0x36; opad[i] = block[i] ^ 0x5c; }
    var inner = new Uint8Array(64 + msg.length);
    inner.set(ipad, 0); inner.set(msg, 64);
    var h = sha256(inner);
    var outer = new Uint8Array(64 + h.length);
    outer.set(opad, 0); outer.set(h, 64);
    return sha256(outer);
  }

  function pbkdf2(password, salt, iterations, dkLen) {
    if (typeof password === 'string') password = new TextEncoder().encode(password);
    if (typeof salt === 'string') salt = new TextEncoder().encode(salt);
    else if (!(salt instanceof Uint8Array)) salt = new Uint8Array(salt);
    var blocks = Math.ceil(dkLen / 32);
    var out = new Uint8Array(blocks * 32);
    for (var b = 1; b <= blocks; b++) {
      var first = new Uint8Array(salt.length + 4);
      first.set(salt, 0);
      first[salt.length] = (b >>> 24) & 0xff;
      first[salt.length + 1] = (b >>> 16) & 0xff;
      first[salt.length + 2] = (b >>> 8) & 0xff;
      first[salt.length + 3] = b & 0xff;
      var u = hmacSha256(password, first);
      var t = new Uint8Array(u);
      for (var i = 1; i < iterations; i++) {
        u = hmacSha256(password, u);
        for (var j = 0; j < 32; j++) t[j] ^= u[j];
      }
      out.set(t, (b - 1) * 32);
    }
    return out.slice(0, dkLen);
  }

  var SBOX = (function () {
    var sb = new Uint8Array(256);
    var log = new Uint8Array(256), alog = new Uint8Array(256);
    var x = 1;
    for (var i = 0; i < 255; i++) {
      alog[i] = x;
      log[x] = i;
      x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0);
    }
    for (i = 0; i < 256; i++) {
      var b = 0;
      if (i === 0) { sb[i] = 0x63; continue; }
      var inv = alog[(255 - log[i]) % 255];
      for (var bit = 0; bit < 8; bit++) {
        var s = ((inv >> bit) & 1) ^ ((inv >> ((bit + 4) % 8)) & 1) ^ ((inv >> ((bit + 5) % 8)) & 1) ^
          ((inv >> ((bit + 6) % 8)) & 1) ^ ((inv >> ((bit + 7) % 8)) & 1) ^ ((0x63 >> bit) & 1);
        b |= s << bit;
      }
      sb[i] = b;
    }
    return sb;
  })();

  function rotWord(w) { return ((w << 8) | (w >>> 24)) >>> 0; }

  function subWord(w) {
    return ((SBOX[(w >>> 24) & 0xff] << 24) | (SBOX[(w >>> 16) & 0xff] << 16) |
      (SBOX[(w >>> 8) & 0xff] << 8) | SBOX[w & 0xff]) >>> 0;
  }

  function mul2(x) { return (x << 1) ^ (x & 0x80 ? 0x1b : 0); }
  function mul3(x) { return mul2(x) ^ x; }

  function expandKey(key) {
    var w = new Uint32Array(60);
    for (var i = 0; i < 8; i++) {
      w[i] = ((key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3]) >>> 0;
    }
    var rcon = 1;
    for (var j = 8; j < 60; j++) {
      var t = w[j - 1];
      if (j % 8 === 0) {
        t = subWord(rotWord(t)) ^ (rcon << 24);
        rcon = (rcon << 1) ^ (rcon & 0x80 ? 0x1b : 0);
      } else if (j % 8 === 4) {
        t = subWord(t);
      }
      w[j] = (w[j - 8] ^ t) >>> 0;
    }
    return w;
  }

  function aesBlockEncrypt(key, state) {
    var w = expandKey(key);
    var s = new Uint8Array(16);
    s.set(state, 0);
    var r, i, kw;
    for (i = 0; i < 16; i++) s[i] ^= (w[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    for (r = 1; r < 14; r++) {
      var t = new Uint8Array(16);
      for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
      var sh = new Uint8Array(16);
      for (var c = 0; c < 4; c++) {
        for (var row = 0; row < 4; row++) {
          sh[c * 4 + row] = t[((c + row) % 4) * 4 + row];
        }
      }
      var out = new Uint8Array(16);
      for (c = 0; c < 4; c++) {
        var b0 = sh[c * 4], b1 = sh[c * 4 + 1], b2 = sh[c * 4 + 2], b3 = sh[c * 4 + 3];
        out[c * 4] = mul2(b0) ^ mul3(b1) ^ b2 ^ b3;
        out[c * 4 + 1] = b0 ^ mul2(b1) ^ mul3(b2) ^ b3;
        out[c * 4 + 2] = b0 ^ b1 ^ mul2(b2) ^ mul3(b3);
        out[c * 4 + 3] = mul3(b0) ^ b1 ^ b2 ^ mul2(b3);
      }
      kw = w[r * 4];
      kw = [w[r * 4], w[r * 4 + 1], w[r * 4 + 2], w[r * 4 + 3]];
      for (i = 0; i < 16; i++) s[i] = out[i] ^ (kw[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    var tf = new Uint8Array(16);
    for (i = 0; i < 16; i++) tf[i] = SBOX[s[i]];
    var shf = new Uint8Array(16);
    for (c = 0; c < 4; c++) {
      for (var roww = 0; roww < 4; roww++) {
        shf[c * 4 + roww] = tf[((c + roww) % 4) * 4 + roww];
      }
    }
    var kwf = [w[56], w[57], w[58], w[59]];
    var outF = new Uint8Array(16);
    for (i = 0; i < 16; i++) outF[i] = shf[i] ^ (kwf[i >> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    return outF;
  }

  var ZERO16;
  function zero16() {
    if (!ZERO16) ZERO16 = new Uint8Array(16);
    return ZERO16;
  }

  function xor16(a, b) {
    var out = new Uint8Array(16);
    for (var i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function gfShiftRight(v) {
    for (var i = 15; i >= 1; i--) {
      v[i] = ((v[i] >>> 1) | ((v[i - 1] & 1) << 7)) & 0xff;
    }
    v[0] = (v[0] >>> 1) & 0xff;
  }

  function gfMul(X, Y) {
    var Z = new Uint8Array(16);
    var V = new Uint8Array(Y);
    for (var bi = 0; bi < 128; bi++) {
      if (X[bi >> 3] & (0x80 >> (bi & 7))) {
        for (var i = 0; i < 16; i++) Z[i] ^= V[i];
      }
      var lsb = V[15] & 1;
      gfShiftRight(V);
      if (lsb) V[0] ^= 0xe1;
    }
    return Z;
  }

  function ghash(H, aad, ct, ctBitLen) {
    var Y = new Uint8Array(16);
    var i;
    for (i = 0; i + 16 <= aad.length; i += 16) {
      Y = gfMul(xor16(Y, aad.subarray(i, i + 16)), H);
    }
    if (aad.length % 16 !== 0) {
      var pad = new Uint8Array(16);
      pad.set(aad.subarray(i), 0);
      Y = gfMul(xor16(Y, pad), H);
    }
    for (i = 0; i + 16 <= ct.length; i += 16) {
      Y = gfMul(xor16(Y, ct.subarray(i, i + 16)), H);
    }
    if (ct.length % 16 !== 0) {
      var pad2 = new Uint8Array(16);
      pad2.set(ct.subarray(i), 0);
      Y = gfMul(xor16(Y, pad2), H);
    }
    var block = new Uint8Array(16);
    var aadBits = aad.length * 8, cBits = ctBitLen;
    var aadHi = Math.floor(aadBits / 4294967296), aadLo = aadBits >>> 0;
    var cHi = Math.floor(cBits / 4294967296), cLo = cBits >>> 0;
    block[0] = (aadHi >>> 24) & 0xff;
    block[1] = (aadHi >>> 16) & 0xff;
    block[2] = (aadHi >>> 8) & 0xff;
    block[3] = aadHi & 0xff;
    block[4] = (aadLo >>> 24) & 0xff;
    block[5] = (aadLo >>> 16) & 0xff;
    block[6] = (aadLo >>> 8) & 0xff;
    block[7] = aadLo & 0xff;
    block[8] = (cHi >>> 24) & 0xff;
    block[9] = (cHi >>> 16) & 0xff;
    block[10] = (cHi >>> 8) & 0xff;
    block[11] = cHi & 0xff;
    block[12] = (cLo >>> 24) & 0xff;
    block[13] = (cLo >>> 16) & 0xff;
    block[14] = (cLo >>> 8) & 0xff;
    block[15] = cLo & 0xff;
    return gfMul(xor16(Y, block), H);
  }

  function inc32(counter) {
    var w = ((counter[12] << 24) | (counter[13] << 16) | (counter[14] << 8) | counter[15]) >>> 0;
    w = (w + 1) >>> 0;
    counter[12] = (w >>> 24) & 0xff;
    counter[13] = (w >>> 16) & 0xff;
    counter[14] = (w >>> 8) & 0xff;
    counter[15] = w & 0xff;
  }

  function aesGcmEncrypt(key, iv, plain) {
    if (iv.length !== 12) throw new Error('invalid iv length');
    var H = aesBlockEncrypt(key, zero16());
    var H8 = new Uint8Array(16);
    for (var i = 0; i < 16; i++) H8[i] = H[i];
    var j0 = new Uint8Array(16);
    j0.set(iv, 0);
    j0[15] = 1;
    var ctr = new Uint8Array(j0);
    inc32(ctr);
    var out = new Uint8Array(plain.length + 16);
    var off = 0;
    while (off < plain.length) {
      var ks = aesBlockEncrypt(key, ctr);
      inc32(ctr);
      var n = Math.min(16, plain.length - off);
      for (i = 0; i < n; i++) out[off + i] = plain[off + i] ^ ks[i];
      off += n;
    }
    var ctView = out.subarray(0, plain.length);
    var S = ghash(H8, new Uint8Array(0), ctView, plain.length * 8);
    var T0 = aesBlockEncrypt(key, j0);
    var T = new Uint8Array(16);
    for (i = 0; i < 16; i++) T[i] = T0[i] ^ S[i];
    out.set(T, plain.length);
    return out;
  }

  function aesGcmDecrypt(key, iv, data) {
    if (iv.length !== 12) throw new Error('invalid iv length');
    if (data.length < 16) throw new Error('ciphertext too short');
    var ctLen = data.length - 16;
    var H = aesBlockEncrypt(key, zero16());
    var H8 = new Uint8Array(16);
    for (var i = 0; i < 16; i++) H8[i] = H[i];
    var j0 = new Uint8Array(16);
    j0.set(iv, 0);
    j0[15] = 1;
    var ctr = new Uint8Array(j0);
    inc32(ctr);
    var plain = new Uint8Array(ctLen);
    var off = 0;
    while (off < ctLen) {
      var ks = aesBlockEncrypt(key, ctr);
      inc32(ctr);
      var n = Math.min(16, ctLen - off);
      for (i = 0; i < n; i++) plain[off + i] = data[off + i] ^ ks[i];
      off += n;
    }
    var ctView = data.subarray(0, ctLen);
    var givenTag = data.subarray(ctLen);
    var S = ghash(H8, new Uint8Array(0), ctView, ctLen * 8);
    var T0 = aesBlockEncrypt(key, j0);
    var diff = 0;
    for (i = 0; i < 16; i++) diff |= givenTag[i] ^ (T0[i] ^ S[i]);
    if (diff !== 0) throw new Error('decryption failed');
    return plain;
  }

  return {
    sha256: sha256,
    hmacSha256: hmacSha256,
    pbkdf2: pbkdf2,
    aesBlockEncrypt: aesBlockEncrypt,
    gcmEncrypt: aesGcmEncrypt,
    gcmDecrypt: aesGcmDecrypt
  };
});