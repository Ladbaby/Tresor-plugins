"use strict";
// OpenCode id generation, ported from magpie's internal/provider/opencode_client.go.
// An OpenCode id is "prefix_" + 12 hex digits of a 48-bit counter + 14 base62 chars.
// The 48-bit value is (unixMilli * 0x1000 + counterWithinMilli) mod 2^48; sessions
// use a descending (bit-inverted, i.e. 2^48-1 - value) form so the newest sorts first.
// All arithmetic stays in Number (values < 2^53) so no BigInt or 32-bit bitwise ops
// truncate it. The 14 base62 chars carry the randomness (Math.random), matching
// magpie's guarantee that a generated id is unique.

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ID_RE = /^[a-z]{3}_[0-9a-f]{12}[0-9A-Za-z]{14}$/;
const MASK48 = 281474976710655; // 2^48 - 1
const MOD48 = 281474976710656; // 2^48

let lastMs = -1;
let counter = 0;

// newID makes an id as OpenCode does. prefix is "ses" or "msg"; descending is
// true for a session id (inverted counter) and false for a request id.
function newID(prefix, descending) {
  const ms = Date.now();
  if (ms !== lastMs) {
    lastMs = ms;
    counter = 0;
  }
  counter++;
  let cur = (ms * 0x1000 + counter) % MOD48;
  if (descending) cur = MASK48 - cur;
  const hex12 = cur.toString(16).padStart(12, "0");
  let suffix = "";
  for (let i = 0; i < 14; i++) suffix += BASE62[Math.floor(Math.random() * 62)];
  return prefix + "_" + hex12 + suffix;
}

// realSession says whether id is a session id OpenCode could have made: of its
// shape, with a small count in its low 12 bits (inverted). Zen's free tier 403s
// one that isn't (e.g. a hash cut to the same shape).
function realSession(id) {
  if (typeof id !== "string" || !id.startsWith("ses_") || !ID_RE.test(id)) return false;
  const low = parseInt(id.slice(13, 16), 16);
  return 0xfff - low < 16;
}

// sessionFor maps a conversation seed to a stable session id. A seed that is
// already a real OpenCode session id passes through. Otherwise the seed is
// hashed to a bounded key and agreed through the engine KV store, so the same
// conversation keeps one id across turns and two conversations never share one.
// getOrSet is atomic: two concurrent first turns of one conversation would
// otherwise each mint an id and one turn would come back with the wrong
// session. An empty seed gets a fresh id each call (a stateless call is its own
// session).
function sessionFor(seed, kv, ttlMs) {
  const sha = require("./sha256");
  if (realSession(seed)) return seed;
  if (!seed) return newID("ses", true);
  const key = "ses:" + sha.hex(seed).slice(0, 64);
  return kv.getOrSet(key, newID("ses", true), ttlMs || 0);
}

module.exports = { newID: newID, realSession: realSession, sessionFor: sessionFor, BASE62: BASE62, ID_RE: ID_RE };
