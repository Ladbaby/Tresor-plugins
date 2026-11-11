"use strict";

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const owns = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = value => value !== null && typeof value === "object" &&
  !Array.isArray(value) && !(value instanceof json.NumberToken);

// Match the native Go struct's case-insensitive field lookup. Retained
// messages and text blocks keep their original keys and extension fields.
function field(object, name) {
  let value;
  for (const key of Object.keys(object)) {
    if (key.toLowerCase() === name) value = object[key];
  }
  return value;
}
function textBlocks(content) {
  if (typeof content === "string") return [{ type: "text", text: content }];
  if (!Array.isArray(content)) return undefined;
  for (const block of content) {
    if (!isObject(block) || field(block, "type") !== "text" || typeof field(block, "text") !== "string") return undefined;
  }
  return content;
}
function appendGroup(destination, source) {
  if (destination.length && source.length) destination.push({ type: "text", text: "\n\n" });
  for (const block of source) destination.push(block);
}
function set(object, key, value) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });
}

module.exports = {
  request({ context, body }) {
    // Operate on the selected downstream protocol, including custom paths.
    if (context.formats.current !== "anthropic") return;
    let payload;
    try { payload = json.parseLossless(encoding.decode(body)); } catch (_) { return; }
    if (!isObject(payload) || !owns(payload, "messages") || !Array.isArray(payload.messages)) return;
    const kept = [];
    const moved = [];
    let changed = false;
    for (const message of payload.messages) {
      if (message === null) { kept.push(message); continue; }
      if (!isObject(message)) return;
      const role = field(message, "role");
      if (role !== undefined && role !== null && typeof role !== "string") return;
      if (role !== "system") { kept.push(message); continue; }
      const blocks = textBlocks(field(message, "content"));
      if (blocks === undefined) return;
      appendGroup(moved, blocks);
      changed = true;
    }
    if (!changed) return;
    let existing = [];
    if (owns(payload, "system") && payload.system !== null) {
      existing = textBlocks(payload.system);
      if (existing === undefined) return;
    }
    const system = [...existing];
    appendGroup(system, moved);
    set(payload, "system", system);
    set(payload, "messages", kept);
    return { body: encoding.encode(json.stringifyLossless(payload)) };
  }
};
