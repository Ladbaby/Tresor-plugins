"use strict";

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const fields = [
  "input_tokens",
  "output_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens"
];
const owns = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = value => value !== null && typeof value === "object" &&
  !Array.isArray(value) && !(value instanceof json.NumberToken);

function parse(text) {
  try { return json.parseLossless(text); } catch (_) { return undefined; }
}
function normalize(usage) {
  let changed = false;
  for (const field of fields) {
    if (!owns(usage, field)) {
      Object.defineProperty(usage, field, { value: 0, enumerable: true, writable: true, configurable: true });
      changed = true;
    }
  }
  return changed;
}
function count(value) {
  if (!(value instanceof json.NumberToken)) return "0";
  const raw = value.toString();
  // Keep integer counts exact rather than reproducing native float rounding.
  if (/^-?[0-9]+$/.test(raw)) return raw;
  // Preserve normal decimal/exponent truncation, without unsafe conversions.
  const n = Math.trunc(Number(raw));
  return Number.isSafeInteger(n) ? String(n) : "0";
}
function recordedUsage(state) {
  const usage = {};
  for (const field of fields) {
    usage[field] = new json.NumberToken(state.counts ? state.counts[field] : "0");
  }
  return usage;
}

module.exports = {
  response({ body }) {
    let text;
    try { text = encoding.decode(body); } catch (_) { return; }
    const payload = parse(text);
    if (!isObject(payload) || !owns(payload, "usage") || !isObject(payload.usage)) return;
    if (normalize(payload.usage)) return { body: encoding.encode(json.stringifyLossless(payload)) };
  },
  streamEvent({ event, state }) {
    if (event.type === "message_stop") {
      delete state.counts;
      return;
    }
    if (event.type !== "message_start" && event.type !== "message_delta") return;
    if (event.type === "message_delta" && event.data.includes('"usage"')) return;
    const payload = parse(event.data);
    if (!isObject(payload)) return;
    if (event.type === "message_start") {
      if (!owns(payload, "message") || !isObject(payload.message)) return;
      const message = payload.message;
      if (owns(message, "usage") && !isObject(message.usage)) return;
      if (!owns(message, "usage")) {
        Object.defineProperty(message, "usage", { value: {}, enumerable: true, writable: true, configurable: true });
      }
      state.counts = {};
      for (const field of fields) state.counts[field] = count(message.usage[field]);
      if (!normalize(message.usage)) return;
    } else {
      if (owns(payload, "usage")) return;
      Object.defineProperty(payload, "usage", { value: recordedUsage(state), enumerable: true, writable: true, configurable: true });
    }
    return { events: [{ ...event, data: json.stringifyLossless(payload) }] };
  }
};
