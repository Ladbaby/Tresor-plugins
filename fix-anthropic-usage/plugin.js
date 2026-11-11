"use strict";

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const fields = ["input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"];
const owns = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = value => value !== null && typeof value === "object" &&
  !Array.isArray(value) && !(value instanceof json.NumberToken);
function set(object, key, value) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });
}
function parse(text) {
  try { return json.parseLossless(text); } catch (_) { return undefined; }
}
function normalize(usage, counts) {
  let changed = false;
  for (const field of fields) {
    if (!owns(usage, field)) {
      set(usage, field, counts && owns(counts, field) ? new json.NumberToken(counts[field]) : 0);
      changed = true;
    }
  }
  return changed;
}
function observe(counts, usage) {
  for (const field of fields) {
    // Retain exact wire spelling, including exponent-form counters. Invalid
    // existing fields are preserved on the wire but never replace observations.
    const value = usage[field];
    if (owns(usage, field) && value instanceof json.NumberToken && !value.toString().startsWith("-")) {
      set(counts, field, value.toString());
    }
  }
}
module.exports = {
  response({ context, body }) {
    if (context.formats.current !== "anthropic") return;
    let text;
    try { text = encoding.decode(body); } catch (_) { return; }
    const payload = parse(text);
    if (!isObject(payload) || !owns(payload, "usage") || !isObject(payload.usage)) return;
    if (normalize(payload.usage)) return { body: encoding.encode(json.stringifyLossless(payload)) };
  },
  streamEvent({ context, event, state }) {
    if (context.formats.current !== "anthropic") return;
    if (event.type === "message_stop") { delete state.counts; return; }
    if (event.type !== "message_start" && event.type !== "message_delta") return;
    if (event.type === "message_start") delete state.counts;
    const payload = parse(event.data);
    if (!isObject(payload)) return;
    let changed = false;
    if (event.type === "message_start") {
      if (!owns(payload, "message") || !isObject(payload.message)) return;
      const message = payload.message;
      if (owns(message, "usage") && !isObject(message.usage)) return;
      if (!owns(message, "usage")) { set(message, "usage", {}); changed = true; }
      state.counts = {};
      observe(state.counts, message.usage);
      changed = normalize(message.usage) || changed;
    } else {
      if (owns(payload, "usage") && !isObject(payload.usage)) return;
      if (!state.counts) return; // Without a start, usage is unknown, not zero.
      if (!owns(payload, "usage")) { set(payload, "usage", {}); changed = true; }
      observe(state.counts, payload.usage);
      changed = normalize(payload.usage, state.counts) || changed;
    }
    if (changed) return { events: [{ ...event, data: json.stringifyLossless(payload) }] };
  }
};
