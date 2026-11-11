"use strict";
// The finder: what in a string is sensitive, and where. This is magpie's
// internal/redact rule engine (redact.go mask/ruleSpans/apply) reduced to what
// a plugin needs: a marker prefilter so a pattern only runs where it can match,
// the rule checks, user words and the user's own rules, the id and decimal
// exclusions, and first-longest-wins where spans overlap.

const checks = require("./checks");
const rules = require("./rules");
const text = require("./text");

const { ALNUM, charAt, containsAny, isWordByte, slice } = text;

// A span is a value found, its kind, and where it sits:
//   start, end  offsets into the text, end exclusive
//   kind        API_KEY, EMAIL, TERM, or a user rule's kind
//   by          "rule" | "yours" (the user's rule) | "word" (the user's word)
const BY_RULE = "rule";
const BY_YOURS = "yours";
const BY_WORD = "word";

// byShortestOfTwoNames: two rules can find the same value; the one tried first
// keeps it.

// groupSpans locates the group whose index is `group` inside a match.
//
// goja compiles RegExp without the `d` flag, so a match carries the group's
// text but not its offsets. The group's text is searched for from where the
// previous group ended, which is the only place a later group can be, and
// which puts the common case (a value after a label the group cannot contain)
// right. A value repeated in its own label would land on the label's copy; the
// rule's own pattern is written so the label part holds no value's form, and
// the checks reject one that does.
function groupSpans(match, group) {
  const out = [];
  let seen = match.index;
  for (let g = 1; g < match.length; g++) {
    const value = match[g];
    if (typeof value !== "string") {
      continue;
    }
    const at = match[0].indexOf(value, seen - match.index);
    const start = at < 0 ? -1 : match.index + at;
    if (start >= 0) {
      seen = start + value.length;
    }
    if (g === group) {
      out.push({ start, end: start < 0 ? -1 : start + value.length, value });
    }
  }
  return out;
}

// Every match of `re` in `s`, each with the offsets of the value group. The
// loop is the standard exec loop: a zero-length match cannot advance lastIndex
// on its own, so it is stepped over.
function matches(re, s) {
  const out = [];
  re.lastIndex = 0;
  let match;
  let guard = 0;
  while ((match = re.exec(s)) !== null) {
    out.push(match);
    if (match[0] === "") {
      re.lastIndex++;
    }
    if (++guard > 100000) {
      break;
    }
  }
  return out;
}

// The value a match names: its `value` group when the rule names one, else the
// first group that matched (a pattern with a group in each alternative), else
// the whole match.
function valueOf(rule, match) {
  if (rule.groups !== undefined) {
    return null; // the rule reads its groups one by one
  }
  if (rule.value === 0) {
    return { start: match.index, end: match.index + match[0].length, value: match[0] };
  }
  if (rule.anyGroup || rule.value === undefined) {
    for (let g = 1; g < match.length; g++) {
      if (typeof match[g] === "string") {
        return groupSpans(match, g)[0];
      }
    }
    return { start: match.index, end: match.index + match[0].length, value: match[0] };
  }
  return groupSpans(match, rule.value)[0];
}

// takes says s[a:b] is a value the rule masks: nothing it may not touch beside
// it, and its checks pass.
function takes(rule, s, a, b, ok) {
  if (a < 0 || b <= a || b > s.length) {
    return false;
  }
  if (rule.bound !== undefined) {
    if ((a > 0 && rule.bound.indexOf(s[a - 1]) >= 0) || (b < s.length && rule.bound.indexOf(s[b]) >= 0)) {
      return false;
    }
  }
  const v = slice(s, a, b);
  if (ok !== undefined && ok !== null && !ok(v)) {
    return false;
  }
  return rule.at === undefined || rule.at(s, a, b);
}

// A rule with `ahead` set takes its words in any case, which is slow over a
// long text: the pattern only runs in windows around each of its fold markers.
function foldWindows(rule, s) {
  const wins = [];
  const lower = s.toLowerCase();
  for (const f of rule.fold) {
    for (let i = 0; ; ) {
      const j = lower.indexOf(f, i);
      if (j < 0) {
        break;
      }
      i = j + f.length;
      // From the line's start, or from where a word starts no further back than
      // `back`, so a pattern's ^ sees the same kind of boundary it would in the
      // whole text.
      let start = Math.max(0, j - rule.back);
      const nl = s.lastIndexOf("\n", j);
      if (nl >= start) {
        start = nl + 1;
      } else if (start > 0) {
        while (start < j && ((ALNUM + "_.-").indexOf(s[start - 1]) >= 0 || (s.charCodeAt(start) & 0xc0) === 0x80)) {
          start++;
        }
        if (start === j && (ALNUM + "_").indexOf(s[j - 1]) >= 0) {
          continue; // inside a longer word
        }
      }
      wins.push({ start, end: Math.min(s.length, i + rule.ahead) });
    }
  }
  if (wins.length === 0) {
    return [];
  }
  wins.sort((x, y) => x.start - y.start);
  const merged = [];
  for (let k = 0; k < wins.length; k++) {
    let w = { start: wins[k].start, end: wins[k].end };
    while (k + 1 < wins.length && wins[k + 1].start <= w.end) {
      k++;
      w.end = Math.max(w.end, wins[k].end);
    }
    merged.push(w);
  }
  return merged;
}

// The matches of one rule in s.
function ruleMatches(rule, s) {
  if (rule.fold === undefined || rule.ahead === undefined) {
    return matches(rule.re, s).map((m) => ({ match: m, offset: 0 }));
  }
  const out = [];
  for (const w of foldWindows(rule, s)) {
    const chunk = s.slice(w.start, w.end);
    for (const m of matches(rule.re, chunk)) {
      m.index += w.start;
      out.push({ match: m, offset: w.start });
    }
  }
  return out;
}

// Where a user's word is. One inside a longer word, where the user asked for
// whole words, is passed over a character at a time, so "XABC ABC" still finds
// the second.
function wordSpans(s, options) {
  const found = [];
  for (const raw of options.words) {
    const w = text.trim(raw, " \t");
    if (w.length < 2) {
      continue;
    }
    const needle = options.wordsAnyCase ? w.toLowerCase() : w;
    const hay = options.wordsAnyCase ? s.toLowerCase() : s;
    for (let i = 0; i <= s.length; ) {
      const at = hay.indexOf(needle, i);
      if (at < 0) {
        break;
      }
      const end = at + w.length;
      if (options.wordsWhole && !wholeWord(s, at, end)) {
        i = at + 1;
        continue;
      }
      found.push({ start: at, end, kind: "TERM", by: BY_WORD });
      i = Math.max(end, at + 1);
    }
  }
  return found;
}

// A whole word: no word character touching it, and a digit-adjacent dot counts
// as touching it, so 123456 is no part of 0.123456 or 123456.78.
function wholeWord(s, a, b) {
  const touching = (i) => i >= 0 && i < s.length && isWordByte(s[i]);
  if (touching(a - 1) || touching(b)) {
    return false;
  }
  if (a >= 2 && s[a - 1] === "." && touching(a - 2)) {
    return false;
  }
  if (b + 1 < s.length && s[b] === "." && touching(b + 1)) {
    return false;
  }
  return true;
}

// The user's own rules, tried before magpie's so that where one of theirs and
// one of these find the same value, it goes by the name they gave it.
function customMatches(s, options) {
  const found = [];
  for (const rule of options.rules) {
    if (rule.prefix !== "") {
      if (s.indexOf(rule.prefix) < 0) {
        continue;
      }
    }
    for (const { match } of ruleMatches(rule, s)) {
      const v = valueOf(rule, match);
      if (v === null || v.start < 0) {
        continue;
      }
      if (takes(rule, s, v.start, v.end, (x) => x.length >= 4)) {
        found.push({ start: v.start, end: v.end, kind: rule.kind, by: BY_YOURS });
      }
    }
  }
  return found;
}

// What the rules find in s.
function ruleSpans(s, options) {
  const found = [];
  for (const candidate of options.rules) {
    if (!covers(options, candidate.cat)) {
      continue;
    }
    if (candidate.markers !== undefined && !containsAny(s, candidate.markers)) {
      continue;
    }
    if (candidate.fold !== undefined && candidate.ahead !== undefined && !containsAny(s.toLowerCase(), candidate.fold)) {
      continue;
    }
    // split are matches a rule took apart into values of their own (rkato@box17
    // as a user and a host): what another rule found from the same place in
    // them, an email, goes.
    const split = [];
    for (const { match } of ruleMatches(candidate, s)) {
      if (candidate.groups !== undefined) {
        const spans = [];
        let consumed = null;
        for (let g = 0; g < candidate.groups.length; g++) {
          const at = groupSpans(match, g + 1)[0];
          if (at === undefined || at.start < 0) {
            continue;
          }
          if (takes(candidate, s, at.start, at.end, candidate.groupOK[g])) {
            spans.push({ start: at.start, end: at.end, kind: candidate.groups[g], by: BY_RULE });
            if (consumed === null) {
              consumed = { start: at.start, end: at.end };
            } else {
              consumed.end = Math.max(consumed.end, at.end);
            }
          }
        }
        if (spans.length > 0) {
          for (const sp of spans) {
            found.push(sp);
          }
          split.push(consumed);
        }
        continue;
      }
      const v = valueOf(candidate, match);
      if (v === null || v.start < 0) {
        continue;
      }
      let start = v.start;
      let end = v.end;
      let ok = candidate.ok;
      if (candidate.fix !== undefined) {
        const fixed = candidate.fix(s, start, end);
        if (fixed === null) {
          continue;
        }
        start = fixed.start;
        end = fixed.end;
        ok = undefined;
      }
      if (takes(candidate, s, start, end, ok)) {
        found.push({ start, end, kind: candidate.kind, by: BY_RULE });
      }
    }
    for (const sp of split) {
      for (let i = found.length - 1; i >= 0; i--) {
        const f = found[i];
        if (f.kind === "EMAIL" && f.start === sp.start && f.end <= sp.end) {
          found.splice(i, 1);
        }
      }
    }
  }
  return found;
}

// covers says the options mask what a rule of category cat finds: "" are the
// secrets, "personal" the personal data always masked with it, any other one of
// the categories.
function covers(options, cat) {
  if (cat === undefined) {
    return options.secrets;
  }
  if (cat === "personal") {
    return options.personal;
  }
  if (!options.personal) {
    return false;
  }
  const on = options.kinds[cat];
  return on === undefined ? DEFAULT_CATEGORIES[cat] === true : on === true;
}

const DEFAULT_CATEGORIES = {
  email: true, phone: true, id_card: true, bank_card: true,
  ssn: true, passport: true, iban: true, birthday: true, mac: true, serial: true,
  home: false, userhost: false, ip: false, bucket: false,
};

// An id a backend made goes as written. The model reads it, matches it and
// writes it back into a tool call, and a backend looks it up by every one of its
// characters: one masked, or a piece of one, is a lookup that finds nothing or
// the wrong row. A piece of one was never a value of its own: the phone rule
// found 13800138000 at the end of …-a13800138000, and the card rule
// 4111-1111-1111-9007 across a UUID's groups.
function noIDs(s, found) {
  return found.filter((f) => {
    if (f.by === BY_WORD || f.by === BY_YOURS) {
      return true;
    }
    const id = checks.idAround(s, f.start, f.end);
    if (id === null) {
      return true;
    }
    if (f.start > id.start || f.end < id.end) {
      return false; // a piece of an id
    }
    switch (f.kind) {
      case "PASSWORD":
      case "API_KEY":
      case "TOKEN":
      case "PRIVATE_KEY":
        return true;
      case "SECRET": {
        // A short digest after a key's name in a sentence (密钥为
        // 5d41402abc4b2a76) is that key; in a field, as a long id.
        if (checks.digestShaped(s.slice(id.start, id.end)) && checks.fieldWords(s, id.start).length === 0) {
          return true;
        }
        return checks.credentialField(s, id.start);
      }
      default:
        return checks.uuidShaped(s.slice(id.start, id.end)) ? false : true;
    }
  });
}

// A personal number that is all of a bare JSON number, or part of a decimal, is
// a number and not a phone or a card: {"order_id": 13800138000} and 0.123456.
const PERSONAL_KINDS = new Set(["EMAIL", "PHONE", "ID_CARD", "BANK_CARD", "SSN", "PASSPORT", "IBAN", "BIRTHDAY", "MAC", "SERIAL", "USERNAME", "HOSTNAME", "IP", "BUCKET"]);
function noNumbers(s, found) {
  return found.filter((f) => {
    if (!PERSONAL_KINDS.has(f.kind) || f.by === BY_WORD || f.by === BY_YOURS) {
      return true;
    }
    return !checks.inDecimal(s, f.start, f.end) && !checks.jsonNumber(s, f.start, f.end);
  });
}

// A value the user lets go as written, in any case.
function allowed(options, v) {
  for (const a of options.allow) {
    if (a.toLowerCase() === v.toLowerCase()) {
      return true;
    }
  }
  return false;
}

// find is what in s is sensitive: the spans, in no particular order, already
// free of ids and numbers.
function find(s, options) {
  if (s === null || s === undefined || s.length < 3) {
    return [];
  }
  let found = wordSpans(s, options);
  found = found.concat(customMatches(s, options));
  found = found.concat(ruleSpans(s, options));
  found = noNumbers(s, noIDs(s, found));
  return found.filter((f) => !allowed(options, slice(s, f.start, f.end)));
}

const EXPORTS = { find: find, BY_RULE: BY_RULE, BY_YOURS: BY_YOURS, BY_WORD: BY_WORD, DEFAULT_CATEGORIES: DEFAULT_CATEGORIES };

module.exports = EXPORTS;;
