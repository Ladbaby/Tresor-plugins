"use strict";
// Restoring inside a stream.
//
// A model can split a placeholder across deltas: {{EMAIL_ in one event and
// k3v9x2mq}} in the next. The second half alone names nothing, so it would reach
// the client as text and the reader would see a broken placeholder. An event
// whose restored text ends in the start of a placeholder is therefore held, and
// the next event of the same block is emitted with the two deltas' text merged.
//
// Holding is safe because a split placeholder only ever straddles two deltas of
// the same event type in the same block: no event type changes the text field it
// writes partway through a block. Holding across anything else — a different
// block, a different type, a block's end — is never attempted.
//
// Bounded: one held event at a time, and a held text that grows past
// MAX_HELD_TEXT is released rather than held further. The worst case, a
// placeholder that never completes, leaves the client reading
// {{EMAIL_k3v9x2mq}}. That is cosmetic and it is the safe direction: masking
// only ever happens on requests, so no real value can leak outwards here.

const payload = require("./payload");
const restore = require("./restore");

// A placeholder is at most {{ + a 24-character kind + _ + 8 + }}, and a model
// writes it in a handful of deltas. Past this much held text the split is not a
// placeholder and holding further only delays the stream.
const MAX_HELD_TEXT = 256;

// The key a delta belongs to: the block index the protocol numbers its deltas
// by, or an item id where the protocol uses one. Two blocks never join.
function deltaKey(node) {
  if (!payload.isObject(node)) {
    return "";
  }
  if (typeof node.item_id === "string") {
    return "i:" + node.item_id;
  }
  for (const k of ["index", "output_index", "content_block_index"]) {
    if (node[k] !== undefined && node[k] !== null) {
      return k + ":" + node[k].toString();
    }
  }
  return "";
}

// The event types that end a block. Nothing after one of them can complete a
// placeholder, so what is held is released first.
const BLOCK_END = new Set([
  "content_block_stop", "message_stop", "message_delta",
  "response.output_item.done", "response.output_text.done", "response.function_call_arguments.done",
  "response.reasoning_summary_text.done", "response.completed", "response.incomplete",
]);

// The string fields a delta's text arrives in, at the event's top level and one
// wrapper down, as Anthropic's and the Responses API's events have them. Chat
// Completions puts it in choices[].delta.content, which the wrapper loop reaches
// through `delta`.
const DELTA_FIELDS = ["text", "content", "partial_json", "arguments", "thinking", "summary_text", "refusal"];
// Where a delta's text sits below the event, as the key path to the object that
// holds it. The protocols disagree on both halves:
//   Responses    text.delta / function_call_arguments.delta / ...  (top level)
//   Anthropic    delta.text / delta.thinking / delta.partial_json
//   Chat         choices[i].delta.content
// A path whose key names an array is searched element by element, so the same
// table covers a protocol that lists its deltas.
const DELTA_PATHS = [
  [],
  ["delta"],
  ["content_block"],
  ["choices", "delta"],
];

// deltaText is the one text a delta event carries, with where it sits. An event
// with no delta text is not one a placeholder can be split across.
function deltaText(node) {
  for (const path of DELTA_PATHS) {
    const found = textAt(node, path);
    if (found !== null) {
      return found;
    }
  }
  return null;
}

// textAt walks path, searching a key that names an array element by element,
// and returns the first text field the object it reaches holds.
function textAt(node, path) {
  let candidates = [node];
  for (const key of path) {
    const next = [];
    for (const candidate of candidates) {
      if (!payload.isObject(candidate)) {
        continue;
      }
      const value = candidate[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (payload.isObject(item)) {
            next.push(item);
          }
        }
      } else if (payload.isObject(value)) {
        next.push(value);
      }
    }
    candidates = next;
    if (candidates.length === 0) {
      return null;
    }
  }
  for (const candidate of candidates) {
    const found = textField(candidate);
    if (found !== null) {
      return found;
    }
  }
  return null;
}

function textField(node) {
  if (!payload.isObject(node)) {
    return null;
  }
  for (const field of DELTA_FIELDS) {
    if (typeof node[field] === "string") {
      return { holder: node, field };
    }
  }
  return null;
}

function restoreTree(node, values) {
  if (typeof node === "string") {
    const r = restore.restoreText(node, values);
    return { value: r.text, changed: r.changed };
  }
  if (Array.isArray(node)) {
    let changed = false;
    const out = node.map((item) => {
      const r = restoreTree(item, values);
      changed = changed || r.changed;
      return r.value;
    });
    return { value: changed ? out : node, changed };
  }
  if (payload.isObject(node)) {
    let changed = false;
    const out = {};
    for (const k of Object.keys(node)) {
      const r = payload.SEALED_KEYS.has(k) ? { value: node[k], changed: false } : restoreTree(node[k], values);
      changed = changed || r.changed;
      Object.defineProperty(out, k, { value: r.value, writable: true, enumerable: true, configurable: true });
    }
    return { value: changed ? out : node, changed };
  }
  return { value: node, changed: false };
}

// emit turns a restored node back into an event, keeping the event's envelope.
function emit(event, node) {
  const out = payload.serialize(node);
  if (out === null) {
    return event;
  }
  if (out === event.data) {
    return event;
  }
  return { type: event.type, data: out, id: event.id, retry: event.retry };
}

// release emits what is held, unchanged, so no text is lost.
function release(held) {
  return held === null ? [] : [held.event];
}

// restoreEvent restores one event's data and decides whether to hold it.
//
// Returns the events to emit now and the state to carry: the same held event, a
// new one, or null.
function restoreEvent(event, values, held) {
  const data = event.data;
  if (typeof data !== "string" || data === "" || data === "[DONE]") {
    return { events: release(held).concat([event]), held: null };
  }
  const node = payload.parse(data);
  if (node === undefined || !payload.isObject(node) && !Array.isArray(node)) {
    return { events: release(held).concat([event]), held: null };
  }

  const key = deltaKey(node);
  const text = deltaText(node);
  // Only an event of the held event's own type in the held event's own block can
  // complete a placeholder it started.
  const joins = held !== null && text !== null && held.key === key && held.type === event.type;
  if (held !== null && !joins) {
    return { events: release(held).concat(restoreStandalone(event, node, values)), held: null };
  }

  if (joins) {
    const merged = held.text + text.holder[text.field];
    if (merged.length <= MAX_HELD_TEXT) {
      const restored = restore.restoreText(merged, values);
      const kinds = restore.kindsOf(values);
      if (restore.tailLength(restored.text, kinds) === 0) {
        Object.defineProperty(text.holder, text.field, {
          value: restored.text, writable: true, enumerable: true, configurable: true,
        });
        return { events: [emit(event, node)], held: null };
      }
      Object.defineProperty(text.holder, text.field, {
        value: restored.text, writable: true, enumerable: true, configurable: true,
      });
      return { events: [], held: { key, type: event.type, event: emit(event, node), text: restored.text } };
    }
  }

  const r = restoreTree(node, values);
  const out = emit(event, r.value);
  if (text !== null) {
    const restoredText = text.holder[text.field];
    if (restore.tailLength(restoredText, restore.kindsOf(values)) > 0 && restoredText.length <= MAX_HELD_TEXT) {
      return { events: [], held: { key, type: event.type, event: out, text: restoredText } };
    }
  }
  return { events: release(held).concat([out]), held: null };
}

// restoreStandalone restores an event on its own, for the case where it arrived
// while another was held.
function restoreStandalone(event, node, values) {
  const r = restoreTree(node, values);
  const out = emit(event, r.value);
  const text = deltaText(node);
  if (text !== null) {
    const restoredText = text.holder[text.field];
    if (restore.tailLength(restoredText, restore.kindsOf(values)) > 0 && restoredText.length <= MAX_HELD_TEXT) {
      return [];
    }
  }
  return [out];
}

const EXPORTS = { restoreEvent: restoreEvent, deltaKey: deltaKey, release: release, deltaText: deltaText };

module.exports = EXPORTS;;
