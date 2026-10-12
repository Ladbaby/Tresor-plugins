"use strict";

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const owns = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const object = o => o !== null && typeof o === "object" && !Array.isArray(o) && !(o instanceof json.NumberToken);
function parse(text) { try { return json.parseLossless(text); } catch (_) { return; } }
function detect(p) {
  if (!object(p)) return;
  if (owns(p, "content") && ((Array.isArray(p.content) && object(p.content[0]) && owns(p.content[0], "type")) || owns(p, "stop_reason"))) return "anthropic";
  if (owns(p, "output")) return "openai_responses";
  if (owns(p, "choices")) return "openai";
  if (owns(p, "candidates")) return "gemini";
}
function format(context, event, p, state) {
  const current = context && context.formats && context.formats.current;
  if (["openai", "anthropic", "openai_responses", "gemini"].includes(current)) return current;
  if (event && /^(message_start|message_delta|message_stop|content_block_start|content_block_delta|content_block_stop|ping)$/.test(event.type)) return "anthropic";
  if (event && event.type.startsWith("response.")) return "openai_responses";
  return detect(p) || (state && state.format);
}
function remove(o, key) {
  if (!object(o) || !owns(o, key)) return false;
  delete o[key]; return true;
}
function filter(o, key, hidden) {
  if (!object(o) || !Array.isArray(o[key])) return false;
  const kept = o[key].filter(item => !hidden(item));
  if (kept.length === o[key].length) return false;
  o[key] = kept; return true;
}
function strip(p, f, streaming) {
  let changed = false;
  if (f === "openai" && Array.isArray(p.choices)) {
    for (const c of p.choices) if (object(c)) {
      if (!streaming) changed = remove(c.message, "reasoning_content") || changed;
      changed = remove(c.delta, "reasoning_content") || changed;
    }
  } else if (f === "anthropic") {
    changed = filter(p, "content", b => object(b) && b.type === "thinking");
    changed = remove(p.usage, "thinking_tokens") || changed;
  } else if (f === "openai_responses") {
    changed = filter(p, "output", b => object(b) && b.type === "reasoning");
  } else if (f === "gemini" && Array.isArray(p.candidates)) {
    for (const c of p.candidates) if (object(c)) {
      changed = filter(c.content, "parts", b => object(b) && (b.thought === true || b.thought === "true")) || changed;
    }
  }
  return changed;
}
// Only structural indices may be converted to numbers. Never round a token.
function index(value) {
  if (!(value instanceof json.NumberToken)) return;
  const raw = value.toString();
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) return;
  const n = Number(raw);
  if (Number.isSafeInteger(n) && n >= 0) return n;
}
function reset(state) { for (const k of Object.keys(state)) delete state[k]; }
function replace(event, p) { return { events: [{ ...event, data: json.stringifyLossless(p) }] }; }
const reasoningEvents = new Set([
  "response.reasoning", "response.reasoning_summary_part.added", "response.reasoning_summary_part.done",
  "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done"
]);

module.exports = {
  response({ body, context }) {
    let text; try { text = encoding.decode(body); } catch (_) { return; }
    const p = parse(text);
    if (!object(p)) return;
    if (strip(p, format(context, null, p), false)) return { body: encoding.encode(json.stringifyLossless(p)) };
  },
  streamEvent({ event, state, context }) {
    let f = format(context, event, undefined, state);
    if ((f === "openai" && event.data.trim() === "[DONE]") || (f === "anthropic" && event.type === "message_stop")) { reset(state); return; }
    if (f === "openai_responses") {
      if (reasoningEvents.has(event.type)) return { events: [] };
      // Deltas and completed tool arguments cannot contain reasoning items.
      // Preserve their original bytes without parsing large tool payloads.
      if (!["response.output_item.added", "response.output_item.done", "response.created", "response.in_progress", "response.completed"].includes(event.type)) return;
    }
    if (f === "anthropic" && !["content_block_start", "content_block_delta", "content_block_stop", "message_delta"].includes(event.type)) return;
    const p = parse(event.data);
    f = f || format(context, event, p, state);
    if (!f) return;
    state.format = f;
    if (!object(p)) {
      if (f === "openai_responses" && event.type === "response.completed") reset(state);
      return;
    }
    if (f === "anthropic") {
      if (["content_block_start", "content_block_delta", "content_block_stop"].includes(event.type)) {
        const n = index(p.index);
        if (n === undefined) return;
        if (!state.hidden) { state.hidden = Object.create(null); state.visible = Object.create(null); state.next = 0; }
        const key = String(n);
        if (event.type === "content_block_start") {
          if (object(p.content_block) && ["thinking", "redacted_thinking"].includes(p.content_block.type)) state.hidden[key] = true;
          else if (!owns(state.visible, key)) state.visible[key] = state.next++;
        }
        if (state.hidden[key]) return { events: [] };
        if (owns(state.visible, key) && state.visible[key] !== n) { p.index = state.visible[key]; return replace(event, p); }
      } else if (event.type === "message_delta" && remove(p.usage, "thinking_tokens")) return replace(event, p);
      return;
    }
    if (f === "openai_responses") {
      if (["response.output_item.added", "response.output_item.done"].includes(event.type)) {
        const n = index(p.output_index);
        const hidden = object(p.item) && p.item.type === "reasoning";
        if (hidden) {
          if (n !== undefined) { if (!state.reasoning) state.reasoning = Object.create(null); state.reasoning[String(n)] = true; }
          return { events: [] };
        }
        if (event.type === "response.output_item.done" && n !== undefined && state.reasoning && state.reasoning[String(n)]) return { events: [] };
      } else if (["response.created", "response.in_progress", "response.completed"].includes(event.type)) {
        const envelope = object(p.response) && Array.isArray(p.response.output) ? p.response : p;
        const changed = strip(envelope, f, false);
        if (event.type === "response.completed") reset(state);
        if (changed) return replace(event, p);
      }
      return;
    }
    if (strip(p, f, true)) return replace(event, p);
  },
  streamEnd({ state }) { reset(state); }
};
