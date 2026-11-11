"use strict";
// The rule step's configuration, resolved into the options the finders take.
// The host validates the step's config against manifest.json's config_schema
// and fills in every default, so a field here is always present; the fallbacks
// below exist for a caller that runs this module outside the host (the test
// suite).

const rules = require("./rules");
const text = require("./text");
const detect = require("./detect");

const MAX_RULES = 32;
const MAX_REGEX = 300;
const MIN_CUSTOM_VALUE = 4;

function bool(config, key, fallback) {
  const v = config[key];
  return typeof v === "boolean" ? v : fallback;
}

function strings(config, key) {
  const v = config[key];
  if (!Array.isArray(v)) {
    return [];
  }
  return v.filter((s) => typeof s === "string" && s !== "");
}

// This build's own rules, with the personal categories the user turned on and
// off carried into each rule's `cat`.
const BUILTIN_RULES = buildRules();

function buildRules() {
  const out = [];
  for (const rule of rules.RULES) {
    out.push(rule);
  }
  return out;
}

// A user's kind as a placeholder can have it: upper case letters, digits and _,
// starting with a letter, at most 24 long; "CUSTOM" where nothing is left.
function ruleKind(kind) {
  let k = "";
  for (const c of text.trim(String(kind === undefined ? "" : kind), " \t").toUpperCase()) {
    if ((c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c === "_") {
      k += c;
    } else if (c === " " || c === "-" || c === ".") {
      k += "_";
    }
  }
  k = text.trim(k, "_");
  if (k === "") {
    return "CUSTOM";
  }
  if (!(k[0] >= "A" && k[0] <= "Z")) {
    k = "CUSTOM_" + k;
  }
  if (k.length > 24) {
    k = text.trimRight(k.slice(0, 24), "_");
  }
  return k;
}

// A user's rules as the finder runs them. A pattern that does not compile, is
// too long, or matches the empty string (which would mask everywhere) is
// dropped rather than failing the request: a rule step that stops masking
// silently would send a secret, one that throws fails every request.
function customRules(config) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(config.rules) ? config.rules : []) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const kind = ruleKind(raw.kind);
    const pattern = typeof raw.pattern === "string" ? raw.pattern : "";
    const prefix = typeof raw.prefix === "string" ? raw.prefix.trim() : "";
    if (pattern === "" && prefix === "") {
      continue;
    }
    const key = kind + "\u0000" + prefix + "\u0000" + pattern;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (out.length >= MAX_RULES) {
      break;
    }
    let re;
    try {
      re = prefix !== ""
        ? new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "[A-Za-z0-9_-]{8,}", "g")
        : pattern.length <= MAX_REGEX
          ? new RegExp(pattern, "g")
          : null;
    } catch (e) {
      re = null;
    }
    if (re === null || re.test("")) {
      continue;
    }
    out.push({
      kind,
      re,
      markers: prefix !== "" ? [prefix] : undefined,
      ok: (v) => v.length >= MIN_CUSTOM_VALUE,
      byYours: true,
    });
  }
  return out;
}

// The categories a rule step turns on. `secrets` and `personal` gate the two
// large groups; each personal category has its own switch, defaulting to what
// magpie ships: the ones a coding request rarely means are off.
function kindSwitches(config) {
  const out = {};
  for (const id of Object.keys(detect.DEFAULT_CATEGORIES)) {
    out[id] = bool(config, id, detect.DEFAULT_CATEGORIES[id]);
  }
  return out;
}

function resolve(config) {
  const c = config !== null && typeof config === "object" ? config : {};
  return {
    secrets: bool(c, "secrets", true),
    personal: bool(c, "personal", true),
    kinds: kindSwitches(c),
    words: strings(c, "words"),
    wordsAnyCase: bool(c, "words_any_case", false),
    wordsWhole: bool(c, "words_whole", false),
    allow: strings(c, "allow"),
    // The user's rules first: where one of theirs and one of this build's find
    // the same value, it goes by the name they gave it.
    rules: customRules(c).concat(BUILTIN_RULES),
  };
}

const EXPORTS = { resolve: resolve, BUILTIN_RULES: BUILTIN_RULES };

module.exports = EXPORTS;;
