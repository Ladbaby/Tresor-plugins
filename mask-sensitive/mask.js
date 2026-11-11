"use strict";
// Turning spans into placeholders, and the placeholder itself.

const crypto = require("tresor/crypto.v1");

const detect = require("./detect");
const text = require("./text");

// A placeholder is {{KIND_hash8}}. The hash is over the kind and the value, so
// the same value always gets the same placeholder: a conversation's history
// reads the same turn after turn, which keeps a vendor's prefix cache good and
// a thinking block's signature matching the text it was made for. Magpie keys
// its hash with a persisted secret; a plugin has no filesystem and no HMAC, so
// this one is unkeyed. That is weaker — someone who already guesses a value can
// confirm the guess from a placeholder — and it is why values are held in
// per-request state and never written to disk.
const B32 = "abcdefghijklmnopqrstuvwxyz234567";

// The first 40 bits of the digest as 8 base32 characters: exactly what 8
// characters of standard base32 over the first five bytes are.
function digestPrefix(seed) {
  const hex = crypto.sha256Hex(seed);
  const out = [];
  let bits = 0;
  let acc = 0;
  for (let i = 0; out.length < 8; i++) {
    acc = (acc << 4) | parseInt(hex[i], 16);
    bits += 4;
    while (bits >= 5 && out.length < 8) {
      bits -= 5;
      out.push(B32[(acc >> bits) & 31]);
    }
  }
  return out.join("");
}

function placeholder(kind, value) {
  return "{{" + kind + "_" + digestPrefix(kind + "\u0000" + value) + "}}";
}

// A placeholder as Magpie writes one, wherever one is already in the text.
const PLACEHOLDER_RE = /\{\{[A-Z][A-Z0-9_]*_[a-z2-7]{8}\}\}/g;

// The values this request has masked, by placeholder. Held in the request's
// state, never anywhere else, and capped so a long conversation cannot grow the
// request without bound. Past the cap a value is still masked; its placeholder
// simply stops restoring, which is safe: the client sees the placeholder.
const MAX_VALUES = 2000;

function remember(values, key, value) {
  if (Object.prototype.hasOwnProperty.call(values, key)) {
    return;
  }
  const keys = Object.keys(values);
  if (keys.length >= MAX_VALUES) {
    delete values[keys[0]];
  }
  values[key] = value;
}

// spansIn resolves overlapping spans: the first to start and, of those, the
// longest wins. A span inside a placeholder already in the text is dropped, so
// a body sent twice is not masked twice.
function spansIn(s, found) {
  if (found.length === 0) {
    return found;
  }
  let kept = found;
  if (s.indexOf("{{") >= 0) {
    const holes = [];
    PLACEHOLDER_RE.lastIndex = 0;
    let m;
    while ((m = PLACEHOLDER_RE.exec(s)) !== null) {
      holes.push({ start: m.index, end: m.index + m[0].length });
    }
    if (holes.length > 0) {
      kept = found.filter((f) => !holes.some((h) => f.start < h.end && f.end > h.start));
    }
  }
  if (kept.length === 0) {
    return kept;
  }
  kept.sort((a, b) => (a.start !== b.start ? a.start - b.start : b.end - a.end));
  const out = [];
  let next = 0;
  for (const f of kept) {
    if (f.start < next) {
      continue;
    }
    next = f.end;
    out.push(f);
  }
  return out;
}

// maskText swaps each sensitive value in s for its placeholder, and reports
// whether anything changed. `values` is the request's placeholder map.
function maskText(s, options, values) {
  const found = spansIn(s, detect.find(s, options));
  if (found.length === 0) {
    return { text: s, changed: false };
  }
  let out = "";
  let last = 0;
  for (const f of found) {
    const value = text.slice(s, f.start, f.end);
    const p = placeholder(f.kind, value);
    remember(values, p, value);
    out += s.slice(last, f.start) + p;
    last = f.end;
  }
  out += s.slice(last);
  return { text: out, changed: true };
}

const EXPORTS = { maskText: maskText, placeholder: placeholder, remember: remember, PLACEHOLDER_RE: PLACEHOLDER_RE, digestPrefix: digestPrefix };

module.exports = EXPORTS;;
