"use strict";
// The ChatGPT/Codex request dialect, ported from the gateway's former compiled-in
// Go adapter. Every rule here was verified against the reference client, and the
// backend is a real subscription account, so this file deliberately mirrors the
// original rather than being "cleaned up" — the shape of the request is the
// feature.
//
// Hooks:
//   wirePrepare      shape the outbound body and headers
//   wireDiscover     say which model-manifest URL to ask, and as whom
//   wireParseModels  parse the manifest the host fetched

const crypto = require("tresor/crypto.v1");
const compress = require("tresor/compress.v1");

// Client identity the manifest endpoint only answers under. The backend gates the
// catalog on the client version, and serves a different catalog per release.
const ORIGINATOR = "codex-tui";
const FALLBACK_VERSION = "0.146.0";

// Lowercases a header map that may arrive with array values.
function lowerHeaders(request) {
  const out = {};
  if (!request || typeof request !== "object") return out;
  for (const name of Object.keys(request)) {
    const value = request[name];
    const first = Array.isArray(value) ? value[0] : value;
    if (typeof first === "string") out[name.toLowerCase()] = first;
  }
  return out;
}

// A stable client identity wins; the stable prompt prefix is the fallback. A
// random value is correlation-only and must never become a prompt cache key, or
// every turn looks like a new conversation and the backend's prefix cache misses.
function cacheKey(headers) {
  return headers["session-id"] || headers["x-client-request-id"] || "";
}

// Derives a deterministic key from the conversation's stable prefix: model,
// instructions, tool names in order, and the first user message. Those are
// identical on every turn of a conversation (a conversation only appends), and
// distinct conversations differ. A client with no stable prefix yields "" so the
// gateway never fabricates an identity it cannot distinguish.
function stableCacheKey(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return "";
  }
  if (!parsed || typeof parsed !== "object" || typeof parsed.model !== "string" || parsed.model === "") return "";

  const tools = [];
  if (Array.isArray(parsed.tools)) {
    for (const tool of parsed.tools) {
      const name = tool && typeof tool === "object" ? tool.name : tool;
      tools.push(String(name));
    }
  }

  const firstUser = firstUserText(parsed.input);
  if (firstUser === "") return "";

  const seed =
    "codex-cache-key:v1|model=" + parsed.model +
    "|instructions=" + (typeof parsed.instructions === "string" ? parsed.instructions : "") +
    "|tools=" + tools.join(",") +
    "|first_user=" + firstUser;
  return "cc_" + crypto.sha256Hex(seed).slice(0, 32);
}

// The first real user text in a Responses input array. A bare string content and
// a content-part array are both accepted, because clients send both.
function firstUserText(input) {
  if (!Array.isArray(input)) return "";
  for (const item of input) {
    if (!item || item.role !== "user") continue;
    if (typeof item.content === "string" && item.content !== "") return item.content;
    if (Array.isArray(item.content)) {
      const parts = [];
      for (const part of item.content) {
        if (part && typeof part.text === "string" && part.text !== "") parts.push(part.text);
      }
      const joined = parts.join("\n");
      if (joined !== "") return joined;
    }
  }
  return "";
}

// Adds the reference client's fields to a Responses body. Only fields the client
// did not already set are added, and a non-object body is returned unchanged.
function fingerprint(body, sessionID) {
  let obj;
  try {
    obj = JSON.parse(body);
  } catch (e) {
    return body;
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return body;

  let changed = false;
  if (!("store" in obj)) {
    obj.store = false;
    changed = true;
  }
  if ("input" in obj) {
    if (!("include" in obj)) {
      obj.include = ["reasoning.encrypted_content"];
      changed = true;
    }
    if (sessionID !== "" && !("prompt_cache_key" in obj)) {
      obj.prompt_cache_key = sessionID;
      changed = true;
    }
  }
  return changed ? JSON.stringify(obj) : body;
}

function isStream(body) {
  try {
    const obj = JSON.parse(body);
    return !!obj && obj.stream === true;
  } catch (e) {
    return false;
  }
}

function wirePrepare({ body, request }) {
  const raw = body && typeof body.data === "string" ? body.data : "";
  const headers = lowerHeaders(request);

  let sessionID = cacheKey(headers);
  if (sessionID === "") sessionID = stableCacheKey(raw);

  let correlationID = sessionID;
  if (correlationID === "") correlationID = "req-" + crypto.sha256Hex(raw).slice(0, 32);

  let out = fingerprint(raw, sessionID);
  const outHeaders = {};

  // Compression only applies to a streaming request, and only when it actually
  // shrinks the body — the backend accepts Content-Encoding: zstd on that
  // endpoint, and sending a larger body would be worse than sending none.
  let compressed = null;
  if (isStream(out)) {
    const result = compress.zstdCompress(out);
    if (result && result.byteLength > 0 && result.byteLength < compress.utf8Length(out)) {
      compressed = result;
    }
  }

  if (compressed) {
    outHeaders["Content-Encoding"] = "zstd";
    // The length now belongs to the encoded bytes, so the caller's stale value
    // must not be forwarded.
    outHeaders["Content-Length"] = "";
  }
  // Preserve a caller's beta opt-in.
  if (!headers["openai-beta"]) outHeaders["OpenAI-Beta"] = "responses=experimental";
  outHeaders["session-id"] = correlationID;
  outHeaders["x-client-request-id"] = correlationID;

  if (compressed) {
    return { body: { encoding: "base64", data: compressed.base64 }, headers: outHeaders };
  }
  return { body: { encoding: "utf8", data: out }, headers: outHeaders };
}

// The manifest is version-gated: the backend returns a different catalog per
// client release and 404s below an upstream floor.
function wireDiscover({ config }) {
  const version = (config && config.client_version) || FALLBACK_VERSION;
  return {
    path: "/models",
    query: { client_version: version },
    headers: {
      Originator: ORIGINATOR,
      Version: version,
      "User-Agent": "codex-tui/" + version + " (Ubuntu 22.4.0; x86_64) xterm-256color",
      Accept: "application/json",
    },
  };
}

// The manifest is a Codex envelope; the model id lives under "slug". "id" is a
// fallback in case the shape drifts. Duplicates are collapsed and order is kept.
function wireParseModels({ response }) {
  const status = response && typeof response.status === "number" ? response.status : 0;
  const body = response ? response.body : undefined;
  if (status === 401 || status === 403) {
    throw new Error(
      "codex backend rejected the token while listing models (HTTP " + status +
        ") — the login may have expired, reconnect in the Downstreams tab"
    );
  }
  if (status !== 200) {
    throw new Error("codex models endpoint returned HTTP " + status);
  }
  let envelope;
  try {
    envelope = typeof body === "string" ? JSON.parse(body) : body;
  } catch (e) {
    throw new Error("parse codex models response: invalid JSON");
  }
  const entries = envelope && Array.isArray(envelope.models) ? envelope.models : [];
  const models = [];
  const seen = {};
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") continue;
    let id = typeof entry.slug === "string" && entry.slug !== "" ? entry.slug : entry.id;
    if (typeof id !== "string") continue;
    id = id.trim();
    if (id === "" || seen[id]) continue;
    seen[id] = true;
    models.push(id);
  }
  if (models.length === 0) throw new Error("codex models endpoint returned no models");
  return { models: models };
}

module.exports = {
  wirePrepare: wirePrepare,
  wireDiscover: wireDiscover,
  wireParseModels: wireParseModels,
};
