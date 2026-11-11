"use strict";
// The request and response bodies.
//
// One format-agnostic walk over the parsed JSON, rather than four navigators,
// because the four client formats put text in different places but agree on
// what a key means: a "content" string is text whichever shape holds it, and a
// "signature" is sealed whichever shape holds it.
//
// The body is parsed losslessly and written back losslessly, so escaping is the
// serializer's job. A placeholder inside a tool call's arguments string comes
// out as valid escaped JSON for free. Magpie edits bytes in place and therefore
// needs an unescaped view and an escape-aware finder; that whole class of bug
// does not exist here. The cost is that a changed body loses its original
// whitespace — an unchanged body is returned byte for byte untouched, which is
// the case that matters for a vendor's prefix cache.

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");

const mask = require("./mask");
const restore = require("./restore");

// Keys whose strings are left alone: ids, names and kinds the vendor needs as
// they are, and what is sealed or encoded. A tool is named by its name and, for
// an MCP tool, its server's — Codex checks a namespace against ^[a-zA-Z0-9_-]+$,
// so one with a word masked in it is a 400 on every turn that replays the call.
const KEPT_KEYS = new Set([
  "signature", "encrypted_content", "data", "thoughtSignature", "thought_signature",
  "model", "id", "tool_use_id", "call_id", "item_id", "type", "role",
  "name", "namespace", "server_label", "server_name", "previous_response_id", "prompt_cache_key",
  "media_type", "mime_type", "mimeType", "url", "image_url", "file_id",
  "reasoning_effort", "effort", "stop_reason", "finish_reason", "status", "object", "event",
]);

// The keys of what a vendor seals the content beside it with: Anthropic's
// thinking signature, Gemini's thought signature, Responses' encrypted
// reasoning. Nothing inside one is masked, masked again, or restored: the
// vendor wrote it and checks it, and a byte changed there is a rejected turn.
const SEALED_KEYS = new Set(["signature", "encrypted_content", "thoughtSignature", "thought_signature", "data"]);

// The request's own keys whose values the agent defines for the vendor to read
// as structure: the tools and the choice among them, the output's schema, how
// the reply streams, and the client's ids no model reads. Only a description is
// masked there: a word masked inside a Lark grammar's rule name left a grammar
// the vendor turned away with 400, and a masked tool name is a call the agent
// cannot make.
const DEF_KEYS = new Set([
  "tools", "tool_choice", "functions", "function_call", "toolConfig", "tool_config",
  "response_format", "text", "reasoning", "include", "output_format", "output_config",
  "generationConfig", "generation_config", "stream_options", "client_metadata",
]);
// The Responses input items that carry tools: Responses Lite's additional_tools,
// and a tool search's output.
const DEF_ITEMS = new Set(["additional_tools", "tool_search_output"]);

// isID says a key holds an identifier the vendor matches against another: a
// tool result's tool_call_id against its call's id. GLM's call_ and 19 digits
// can read as a bank card number; masked on one side only, the two no longer
// match.
function isID(key) {
  return (
    key === "id" ||
    key === "ids" ||
    key.endsWith("_id") ||
    key.endsWith("_ids") ||
    key.endsWith("Id") ||
    key.endsWith("Ids")
  );
}

function isNumberToken(v) {
  return v instanceof json.NumberToken;
}

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !isNumberToken(v);
}

// The mode a child of `key`, sitting in `holder`, is walked in.
//
//   normal  mask by the rules, keep the keys of ids and names
//   args    a tool call's arguments: the keys are the tool's own, so nothing is
//           kept by key — a "signature" or "name" there holds what the agent
//           wrote, not the vendor's sealing
//   defs    what the agent defines for the vendor rather than says: only a
//           description is masked
//   sealed  the vendor's own sealed bytes: nothing is touched
function modeFor(key, holder, mode) {
  if (SEALED_KEYS.has(key)) {
    return "sealed";
  }
  // A tool's arguments are a JSON object of the tool's own making, whichever
  // protocol names them.
  if (key === "args" || key === "arguments") {
    return "args";
  }
  if (mode === "args") {
    return "args";
  }
  if (key === "input" && isObject(holder) && (holder.type === "tool_use" || holder.type === "server_tool_use")) {
    return "args";
  }
  // Gemini's functionResponse carries the structured result the tool gave; its
  // keys are the tool's own too.
  if (key === "response" && isObject(holder) && holder.name !== undefined && holder.response !== undefined) {
    return "args";
  }
  if (DEF_KEYS.has(key) || (isObject(holder) && DEF_ITEMS.has(holder.type))) {
    return "defs";
  }
  return mode;
}

// The strings the mask leaves alone, by where they sit.
function maskSkips(key, value, mode) {
  if (mode === "sealed" || value.startsWith("data:")) {
    return true;
  }
  if (mode === "defs") {
    return key !== "description";
  }
  if (mode === "args") {
    return false;
  }
  return KEPT_KEYS.has(key) || isID(key);
}

// defineValue sets an own enumerable property the way parseLossless does, so a
// key named "__proto__" stays data.
function defineValue(target, key, value) {
  Object.defineProperty(target, key, { value, writable: true, enumerable: true, configurable: true });
}

// copyUpTo builds the pre-change prefix of an object the first time one of its
// keys changes, so an unchanged object is returned by identity.
function copyUpTo(node, upto, target) {
  const out = target === undefined ? {} : target;
  for (const k of Object.keys(node)) {
    if (k === upto) {
      break;
    }
    defineValue(out, k, node[k]);
  }
  return out;
}

// maskNode walks a parsed body, masking what the options cover. It returns the
// same node when nothing changed, so an untouched body keeps its bytes.
function maskNode(node, key, holder, mode, options, values) {
  if (typeof node === "string") {
    if (maskSkips(key, node, mode)) {
      return { value: node, changed: false };
    }
    const r = mask.maskText(node, options, values);
    return { value: r.text, changed: r.changed };
  }
  if (Array.isArray(node)) {
    let changed = false;
    const out = node.map((item) => {
      const r = maskNode(item, key, holder, mode, options, values);
      changed = changed || r.changed;
      return r.value;
    });
    return { value: changed ? out : node, changed };
  }
  if (isObject(node)) {
    let changed = false;
    let out = null;
    for (const k of Object.keys(node)) {
      const r = maskNode(node[k], k, node, modeFor(k, node, mode), options, values);
      if (r.changed) {
        if (out === null) {
          out = copyUpTo(node, k);
        }
        defineValue(out, k, r.value);
        changed = true;
      } else if (out !== null) {
        defineValue(out, k, r.value);
      }
    }
    return { value: changed ? out : node, changed };
  }
  return { value: node, changed: false };
}

// restoreNode walks a parsed body, putting the values back. Everything is
// restored but what the vendor sealed: the request masked a value wherever it
// found one, so the answer gets its value back wherever it is.
function restoreNode(node, key, mode, values) {
  if (typeof node === "string") {
    if (mode === "sealed") {
      return { value: node, changed: false };
    }
    const r = restore.restoreText(node, values);
    return { value: r.text, changed: r.changed };
  }
  if (Array.isArray(node)) {
    let changed = false;
    const out = node.map((item) => {
      const r = restoreNode(item, key, mode, values);
      changed = changed || r.changed;
      return r.value;
    });
    return { value: changed ? out : node, changed };
  }
  if (isObject(node)) {
    let changed = false;
    let out = null;
    for (const k of Object.keys(node)) {
      const r = restoreNode(node[k], k, SEALED_KEYS.has(k) ? "sealed" : mode, values);
      if (r.changed) {
        if (out === null) {
          out = copyUpTo(node, k);
        }
        defineValue(out, k, r.value);
        changed = true;
      } else if (out !== null) {
        defineValue(out, k, r.value);
      }
    }
    return { value: changed ? out : node, changed };
  }
  return { value: node, changed: false };
}

// bodyText decodes a payload. null for bytes that are not UTF-8 text (an image,
// audio): there is nothing to mask in it and rewriting it would corrupt it.
function bodyText(body) {
  if (body === null || typeof body !== "object" || typeof body.data !== "string") {
    return null;
  }
  if (body.encoding === "utf8") {
    return body.data;
  }
  if (body.encoding !== "base64") {
    return null;
  }
  try {
    return encoding.decode(body);
  } catch (e) {
    return null;
  }
}

function parse(text) {
  try {
    return json.parseLossless(text);
  } catch (e) {
    return undefined;
  }
}

function serialize(node) {
  try {
    return json.stringifyLossless(node);
  } catch (e) {
    return null;
  }
}

// maskBody masks a request body. A body that is not JSON is masked as text: it
// is a prompt or a form, and a secret in it is a secret either way.
function maskBody(text, options, values) {
  const parsed = parse(text);
  if (parsed === undefined) {
    return mask.maskText(text, options, values);
  }
  const r = maskNode(parsed, "", undefined, "normal", options, values);
  if (!r.changed) {
    return { text, changed: false };
  }
  const out = serialize(r.value);
  return out === null ? { text, changed: false } : { text: out, changed: true };
}

// restoreBody puts the values back in a response body.
function restoreBody(text, values) {
  const parsed = parse(text);
  if (parsed === undefined) {
    return restore.restoreText(text, values);
  }
  const r = restoreNode(parsed, "", "normal", values);
  if (!r.changed) {
    return { text, changed: false };
  }
  const out = serialize(r.value);
  return out === null ? { text, changed: false } : { text: out, changed: true };
}

const EXPORTS = { maskBody: maskBody, restoreBody: restoreBody, bodyText: bodyText, parse: parse, serialize: serialize, isObject: isObject, isNumberToken: isNumberToken, modeFor: modeFor, KEPT_KEYS: KEPT_KEYS, SEALED_KEYS: SEALED_KEYS };

module.exports = EXPORTS;;
