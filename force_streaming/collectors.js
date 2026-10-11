"use strict";
const json = require("tresor/json.v1");
const buffers = require("tresor/buffer.v1");
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObject = v => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof json.NumberToken);
const obj = v => isObject(v) ? v : Object.create(null);
const arr = v => Array.isArray(v) ? v : [];
const text = v => typeof v === "string" ? v : "";
function set(o, k, v) { Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true }); }
function merge(a, b) { for (const k of Object.keys(b)) set(a, k, b[k]); return a; }
function index(v) {
  if (v === undefined || v === null) return 0;
  const n = json.toNumber(v);
  if (!Number.isSafeInteger(n) || n < 0) throw Error("invalid stream index");
  return n;
}
const ordered = o => Object.keys(o).sort((a, b) => Number(a) - Number(b)).map(k => o[k]);
function parse(data) { const v = json.parseLossless(data); if (!isObject(v)) throw Error("SSE JSON must be an object"); return v; }
// Opaque buffer leaves retain accumulated text outside traversed metadata.
function appendText(o, k, v) {
  let handle = o[k];
  if (!buffers.isBuffer(handle)) { handle = buffers.create(); buffers.append(handle, text(o[k])); set(o, k, handle); }
  buffers.append(handle, text(v));
}
function start(format) {
  if (!["openai", "anthropic", "openai_responses", "gemini"].includes(format)) throw Error("unsupported collection format");
  return { format, root: Object.create(null), items: Object.create(null), tools: Object.create(null), finished: Object.create(null), done: false, message: null, snapshot: null };
}
function openai(s, data) {
  if (s.done) return;
  if (data.trim() === "[DONE]") { s.done = true; return; }
  const m = parse(data);
  for (const k of ["id", "created", "model", "service_tier", "system_fingerprint", "usage"]) if (own(m, k)) set(s.root, k, m[k]);
  for (const raw of arr(m.choices)) {
    const c = obj(raw), i = index(c.index);
    if (!own(s.items, i)) s.items[i] = { index: i, message: { role: "assistant" } };
    const dst = s.items[i], msg = dst.message, d = obj(c.delta);
    for (const k of ["role", "content", "reasoning_content", "reasoning", "refusal", "function_call"]) if (own(d, k)) {
      if (["content", "reasoning_content", "reasoning", "refusal"].includes(k)) appendText(msg, k, d[k]);
      else if (k === "function_call") {
        const fn = obj(msg[k]);
        for (const key of Object.keys(obj(d[k]))) appendText(fn, key, d[k][key]);
        set(msg, k, fn);
      } else set(msg, k, d[k]);
    }
    for (const rawTool of arr(d.tool_calls)) {
      const t = obj(rawTool), j = index(t.index);
      if (!own(s.tools, i)) s.tools[i] = Object.create(null);
      if (!own(s.tools[i], j)) s.tools[i][j] = { type: "function", function: Object.create(null) };
      const tm = s.tools[i][j], fn = tm.function, fd = obj(t.function);
      for (const k of ["id", "type"]) if (own(t, k)) set(tm, k, t[k]);
      for (const k of ["name", "arguments"]) if (own(fd, k)) appendText(fn, k, fd[k]);
    }
    if (isObject(c.logprobs)) {
      const logs = obj(dst.logprobs);
      for (const k of Object.keys(c.logprobs)) set(logs, k, arr(logs[k]).concat(arr(c.logprobs[k])));
      dst.logprobs = logs;
    }
    if (own(c, "finish_reason") && c.finish_reason !== null) { dst.finish_reason = c.finish_reason; s.finished[i] = true; }
  }
}
function anthropic(s, ev) {
  const m = parse(ev.data), type = ev.type || text(m.type);
  switch (type) {
    case "error": throw Error("Anthropic stream error");
    case "message_start": s.message = obj(m.message); break;
    case "content_block_start": s.items[index(m.index)] = obj(m.content_block); break;
    case "content_block_delta": {
      const i = index(m.index);
      if (!own(s.items, i)) throw Error("Anthropic delta for unknown block");
      const b = s.items[i], d = obj(m.delta);
      switch (text(d.type)) {
        case "text_delta": appendText(b, "text", d.text); break;
        case "thinking_delta": appendText(b, "thinking", d.thinking); break;
        case "signature_delta": appendText(b, "signature", d.signature); break;
        case "citations_delta": set(b, "citations", arr(b.citations).concat([d.citation === undefined ? null : d.citation])); break;
        case "input_json_delta": appendText(b, "partial_json", d.partial_json); break;
      }
      break;
    }
    case "content_block_stop": s.finished[index(m.index)] = true; break;
    case "message_delta": {
      if (s.message === null) throw Error("Anthropic message_delta before start");
      const d = obj(m.delta);
      for (const k of ["stop_reason", "stop_sequence"]) if (own(d, k)) set(s.message, k, d[k]);
      if (own(m, "usage")) set(s.message, "usage", merge(obj(s.message.usage), obj(m.usage)));
      break;
    }
    case "message_stop": s.done = true; break;
  }
}
function responses(s, ev) {
  // Keep authoritative terminal wire text opaque; parse it only at end.
  if (["response.completed", "response.incomplete"].includes(ev.type) ||
      (!ev.type && /"type"\s*:\s*"response\.(completed|incomplete)"/.test(ev.data))) {
    if (s.snapshot !== null) buffers.release(s.snapshot);
    s.snapshot = buffers.create(); buffers.append(s.snapshot, ev.data);
  } else if (ev.type === "error" || ev.type === "response.failed") throw Error("Responses stream failed");
}
function gemini(s, data) {
  const m = parse(data);
  for (const k of Object.keys(m)) if (k !== "candidates") set(s.root, k, m[k]);
  for (const raw of arr(m.candidates)) {
    const c = obj(raw), i = index(c.index);
    if (!own(s.items, i)) s.items[i] = { index: i, content: { role: "model", parts: [] } };
    const dst = s.items[i];
    for (const k of Object.keys(c)) if (k !== "content") set(dst, k, c[k]);
    if (text(c.finishReason)) s.finished[i] = true;
    const incoming = obj(c.content), content = dst.content;
    if (own(incoming, "role")) set(content, "role", incoming.role);
    for (const rawPart of arr(incoming.parts)) {
      const p = obj(rawPart), prev = content.parts[content.parts.length - 1];
      // Preserve tools/signatures and thought boundaries. Position restarts per event.
      if (prev && p.text != null && Object.keys(p).length <= 2 && p.thoughtSignature == null &&
          prev.text != null && Object.keys(prev).length <= 2 && prev.thought === p.thought) {
        appendText(prev, "text", p.text);
      } else content.parts.push(p);
    }
  }
}
function event(s, ev) {
  if (!s) throw Error("collector not started");
  // Native collection skips empty payloads, comments are host-owned.
  if (ev.data === "") return;
  switch (s.format) {
    case "openai": openai(s, ev.data); break;
    case "anthropic": anthropic(s, ev); break;
    case "openai_responses": responses(s, ev); break;
    case "gemini": gemini(s, ev.data); break;
  }
}
function end(s) {
  if (!s) throw Error("collector not started");
  const items = ordered(s.items);
  switch (s.format) {
    case "openai":
      if (!s.done && (!items.length || Object.keys(s.items).some(i => !s.finished[i]))) throw Error("OpenAI stream incomplete");
      for (const i of Object.keys(s.items)) if (own(s.tools, i) && Object.keys(s.tools[i]).length) s.items[i].message.tool_calls = ordered(s.tools[i]);
      set(s.root, "object", "chat.completion"); set(s.root, "choices", items); return s.root;
    case "anthropic":
      if (s.message === null || !s.done || Object.keys(s.items).some(i => !s.finished[i])) throw Error("incomplete Anthropic stream");
      for (const b of items) if (own(b, "partial_json")) {
        const raw = buffers.isBuffer(b.partial_json) ? buffers.materialize(b.partial_json) : text(b.partial_json); delete b.partial_json; set(b, "input", json.parseLossless(raw));
      }
      set(s.message, "content", items); return s.message;
    case "openai_responses":
      if (s.snapshot === null) throw Error("Responses stream missing authoritative terminal snapshot");
      const terminal = parse(buffers.materialize(s.snapshot));
      if (isObject(terminal.type) || (terminal.type !== undefined && !["response.completed", "response.incomplete"].includes(terminal.type)) || !isObject(terminal.response)) throw Error("missing terminal response snapshot");
      return terminal.response;
    case "gemini":
      if (!items.length) {
        if (obj(s.root.promptFeedback).blockReason == null) throw Error("Gemini stream has no candidates");
      } else if (Object.keys(s.items).some(i => !s.finished[i])) throw Error("Gemini candidate missing finishReason");
      set(s.root, "candidates", items); return s.root;
  }
}
module.exports = { start, event, end };
