"use strict";
// OpenCode Zen/Go client behavior, as OpenCode 1.19.0 sends it (magpie's
// internal/provider/opencode_client.go + internal/gateway/opencode_session.go).
// Synthesizes x-opencode-session/-session-id (a stable per-conversation id from
// the engine KV-backed LRU), x-opencode-request, x-opencode-client, x-opencode-
// project and the OpenCode User-Agent; strips foreign session headers the
// gateway would 403 on; and for free-tier models forces streaming, injects the
// bash/read stub tools and rewrites /zen to /inference. Clients need not send a
// session header themselves.

const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const kv = require("tresor/kv.v1");
const sha = require("./sha256");
const idgen = require("./idgen");
const free = require("./free");

// Headers where an agent already names its conversation (port of magpie's
// sessionHeaders). Used as the seed when the client sends one.
const SESSION_HEADERS = [
  "x-opencode-session", "x-session-affinity", "x-session-id", "session_id",
  "session-id", "x-claude-code-session-id", "x-conversation-id", "x-deepseek-harness-session-id"
];
const FOREIGN_STRIP = ["x-session-affinity", "x-session-id"];

function own(o, k) { return o !== null && typeof o === "object" && Object.prototype.hasOwnProperty.call(o, k); }
function object(v) { return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof json.NumberToken); }
function set(o, k, v) { Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true }); }

function headerValue(headers, name) {
  const v = headers && headers[name];
  if (Array.isArray(v) && v.length && typeof v[0] === "string") return v[0].trim();
  return "";
}

// firstUserMessage picks the turn that names the conversation: the first item
// with role "user" (Gemini treats an omitted role as user), else the first item,
// else the raw input, else null.
function firstUserMessage(payload) {
  let items = null, gemini = false;
  if (object(payload) && Array.isArray(payload.messages)) items = payload.messages;
  else if (object(payload) && Array.isArray(payload.contents)) { items = payload.contents; gemini = true; }
  else if (object(payload) && Array.isArray(payload.input)) items = payload.input;
  if (items && items.length) {
    for (const it of items) {
      if (object(it) && (it.role === "user" || (gemini && !own(it, "role")))) return it;
    }
    return items[0];
  }
  if (object(payload) && own(payload, "input")) return payload.input;
  return null;
}

// seed names the conversation a request is a turn of (port of openCodeSeed):
// the client's own session header, else any agent session header, else the body's
// prompt_cache_key, else a hash of the first user message.
function seedFor(headers, payload) {
  const own = headerValue(headers, "x-opencode-session");
  if (own) return own;
  for (const h of SESSION_HEADERS) {
    const v = headerValue(headers, h);
    if (v) return v.slice(0, 128);
  }
  if (object(payload) && typeof payload.prompt_cache_key === "string" && payload.prompt_cache_key.trim()) {
    return "prompt_cache_key\u0000" + payload.prompt_cache_key.trim();
  }
  const first = firstUserMessage(payload);
  const basis = first !== null ? first : payload;
  return "tresor-" + sha.hex(json.stringifyLossless(basis)).slice(0, 24);
}

module.exports = {
  request({ context, config, state, request, body }) {
    if (config.gate_path_prefix && typeof config.gate_path_prefix === "string" && config.gate_path_prefix) {
      if (!request.path.startsWith(config.gate_path_prefix)) return;
    }
    let payload = null;
    const decoded = encoding.decode(body);
    try { payload = json.parseLossless(decoded); } catch (e) { payload = null; }

    const id = idgen.sessionFor(seedFor(request.headers, payload), kv, config.session_ttl_ms);
    const patch = {
      setHeaders: {
        "user-agent": [config.user_agent],
        "x-opencode-session": [id],
        "x-opencode-session-id": [id],
        "x-opencode-request": [idgen.newID("msg", false)],
        "x-opencode-client": [config.client],
        "x-opencode-project": [config.project]
      },
      deleteHeaders: FOREIGN_STRIP.slice()
    };

    if (config.free_tier && object(payload) && free.isFreeModel(String(payload.model))) {
      const currentFormat = context && context.formats ? context.formats.current : null;
      const proto = free.protocolOf(payload, currentFormat);
      if (proto !== "gemini") set(payload, "stream", true);
      state.renames = free.ensureTools(payload, proto);
      state.proto = proto;
      patch.path = free.freeURL(request.path);
      return { request: patch, body: encoding.encode(json.stringifyLossless(payload)) };
    }
    return { request: patch };
  },

  response({ state, body }) {
    if (!state.renames) return;
    let payload = null;
    try { payload = json.parseLossless(encoding.decode(body)); } catch (e) { return; }
    if (!object(payload)) return;
    const proto = state.proto || free.protocolOf(payload, null);
    if (!free.renameBack(payload, proto, state.renames, true)) return;
    return { body: encoding.encode(json.stringifyLossless(payload)) };
  },

  streamEvent({ state, event }) {
    if (!state.renames || !event.data || event.data[0] !== "{") return;
    let payload = null;
    try { payload = json.parseLossless(event.data); } catch (e) { return; }
    if (!object(payload)) return;
    const proto = state.proto || free.protocolOf(payload, null);
    // Rename only on the wire (dropping mid-stream would corrupt delta indices).
    if (!free.renameBack(payload, proto, state.renames, false)) return;
    return { events: [{ type: event.type, data: json.stringifyLossless(payload), id: event.id, retry: event.retry }] };
  }
};
