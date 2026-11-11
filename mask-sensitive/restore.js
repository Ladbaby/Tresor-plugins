"use strict";
// Putting the values back.
//
// A model does not always write a placeholder back as it was given: it writes
// {{ PHONE_b5puzbfv }} as a template has it, drops a brace, or the braces, or
// changes the case. Any of those is put back too when what is left names a
// placeholder this request made: its kind and the 8 of its hash, which no other
// text has by chance.

// A placeholder without its braces, as a model may write one back: API_KEY_
// k3v9x2mq, phone_b5puzbfv, PHONE_B5PUZBFV.
const BODY_RE = /[A-Za-z][A-Za-z0-9_]*_[A-Za-z2-7]{8}/g;

function isWordByte(c) {
  return c === "_" || (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9");
}

// canonical is the placeholder a body names, whatever its case.
function canonical(body) {
  const cut = body.length - 8;
  return "{{" + body.slice(0, cut).toUpperCase() + body.slice(cut).toLowerCase() + "}}";
}

// braces widens s[a:z] over the braces written around it, and the spaces inside
// them: both of {{ and }}, or one of them dropped ({{X} or {X}}), or just {{ or
// just }}. A single brace on one side alone is the text's own ({X as in code)
// and stays.
function braces(s, a, z) {
  let la = a;
  let l = 0;
  while (la > 0 && (s[la - 1] === " " || s[la - 1] === "\t")) {
    la--;
  }
  while (l < 2 && la > 0 && s[la - 1] === "{") {
    la--;
    l++;
  }
  let rz = z;
  let r = 0;
  while (rz < s.length && (s[rz] === " " || s[rz] === "\t")) {
    rz++;
  }
  while (r < 2 && rz < s.length && s[rz] === "}") {
    rz++;
    r++;
  }
  if (l === 2 || (l === 1 && r >= 1)) {
    a = la;
  }
  if (r === 2 || (r === 1 && l >= 1)) {
    z = rz;
  }
  return { start: a, end: z };
}

// restoreText puts the values back in s, and reports whether anything changed.
function restoreText(s, values) {
  if (s.length < 9 || s.indexOf("_") < 0) {
    return { text: s, changed: false };
  }
  const out = [];
  let last = 0;
  let changed = false;
  BODY_RE.lastIndex = 0;
  let m;
  while ((m = BODY_RE.exec(s)) !== null) {
    const a = m.index;
    const z = a + m[0].length;
    if (a < last || (a > 0 && isWordByte(s[a - 1])) || (z < s.length && isWordByte(s[z]))) {
      continue;
    }
    const p = canonical(m[0]);
    if (!Object.prototype.hasOwnProperty.call(values, p)) {
      continue;
    }
    const span = braces(s, a, z);
    if (span.start < last) {
      continue;
    }
    out.push(s.slice(last, span.start), values[p]);
    last = span.end;
    changed = true;
  }
  if (!changed) {
    return { text: s, changed: false };
  }
  out.push(s.slice(last));
  return { text: out.join(""), changed: true };
}

// The kinds this request has made placeholders of, as the tails a model may
// write without braces start with.
function kindsOf(values) {
  const kinds = [];
  for (const p of Object.keys(values)) {
    const body = p.slice(2, -2);
    const kind = body.slice(0, body.length - 9);
    if (kinds.indexOf(kind) < 0) {
      kinds.push(kind);
    }
  }
  return kinds;
}

const MAX_PLACEHOLDER_BODY = 24 + 1 + 8; // a kind, _, the hash

// tailLength is how much of the end of s may be the start of a placeholder the
// next piece of a stream finishes: {{API_, {{ phone_b5, PHONE_b5puzbfv} — or,
// with no brace before it, a last word that starts as a placeholder this request
// made does (PHO, PHONE_b5pu), or is one whose }} may still come.
function tailLength(s, kinds) {
  const braced = braceTail(s, kinds);
  if (braced > 0) {
    return braced;
  }
  return wordTail(s, kinds);
}

function braceTail(s, kinds) {
  let i = s.lastIndexOf("{");
  if (i < 0) {
    return 0;
  }
  if (i > 0 && s[i - 1] === "{") {
    i--;
  }
  const t = s.slice(i);
  if (t.length >= MAX_PLACEHOLDER_BODY + 8 || t.indexOf("}}") >= 0) {
    return 0;
  }
  let body = t.replace(/^\{+/, "").replace(/^[ \t]+/, "");
  if (body === "") {
    return t.length; // {, {{, {{␠
  }
  const first = body[0];
  if (!((first >= "A" && first <= "Z") || (first >= "a" && first <= "z"))) {
    return 0;
  }
  let j = 0;
  while (j < body.length && isWordByte(body[j])) {
    j++;
  }
  const rest = body.slice(j).replace(/^[ \t]+/, "");
  if (rest !== "" && rest !== "}") {
    return 0;
  }
  // The word so far must be the start of a placeholder this request made, so a
  // brace before ordinary text is not held forever.
  const word = body.slice(0, j);
  if (word !== "" && !prefixOfPlaceholder(word, kinds)) {
    return 0;
  }
  return t.length;
}

// wordTail is the last word of s, where it may be a placeholder's body as a
// model writes one without braces.
function wordTail(s, kinds) {
  let i = s.length;
  while (i > 0 && isWordByte(s[i - 1])) {
    i--;
  }
  const w = s.slice(i);
  if (w === "" || !(w[0] >= "A" && w[0] <= "Z")) {
    return 0;
  }
  return prefixOfPlaceholder(w, kinds) ? w.length : 0;
}

// prefixOfPlaceholder says word may be the start of a placeholder's body for
// one of kinds: a kind's name and part of its hash, or part of a kind's name.
function prefixOfPlaceholder(word, kinds) {
  const u = word.toUpperCase();
  for (const kind of kinds) {
    const named = kind + "_";
    if (named.startsWith(u)) {
      return true;
    }
    if (u.startsWith(named) && u.length - named.length <= 8) {
      const tail = u.slice(named.length);
      if (/^[A-Z2-7]*$/.test(tail)) {
        return true;
      }
    }
  }
  return false;
}

const EXPORTS = { restoreText: restoreText, tailLength: tailLength, canonical: canonical, kindsOf: kindsOf };

module.exports = EXPORTS;;
