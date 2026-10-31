"use strict";
// OpenCode Zen free-tier handling, ported from magpie's
// internal/provider/opencode_client.go (OpenCodeFree/Tools/ToolSchemas) and
// opencode_endpoints.go (OpenCodeFreeURL). A free model must be asked streamed,
// offering lowercase "bash" and "read" tools each with at least one parameter;
// missing ones are injected as stubs that say they are not callable. Client tools
// named Bash/Read (any case) are renamed to lowercase upstream and back on the
// reply; stub calls are dropped from buffered replies.

const json = require("tresor/json.v1");

const STUB = "Not available in this session. Never call this tool.";
// Exact schemas OpenCode 1.19.0 gives bash and read (they must each carry a
// parameter; an empty-properties object draws a 403 FreeTierError).
const BASH_SCHEMA = { type: "object", properties: { command: { type: "string", description: "The command to execute" }, timeout: { type: "integer", description: "Optional timeout in milliseconds" }, workdir: { type: "string", description: "The working directory to run the command in" } }, required: ["command"] };
const READ_SCHEMA = { type: "object", properties: { filePath: { type: "string", description: "The absolute path to the file or directory to read" }, offset: { type: "integer", description: "The line number to start reading from (1-indexed)" }, limit: { type: "integer", description: "The maximum number of lines to read" } }, required: ["filePath"] };
const SCHEMAS = { bash: BASH_SCHEMA, read: READ_SCHEMA };
const STUB_NAMES = { bash: true, read: true };
// Free models whose ids do not end in "-free".
const FREE_IDS = { "big-pickle": true, "grok-code": true };

function isFreeModel(model) {
  if (typeof model !== "string") return false;
  return model.endsWith("-free") || FREE_IDS[model] === true;
}

// freeURL rewrites a Zen path to the inference API (the free tier answers a free
// model at /zen with 403 but the same request at /inference with 200). Go paths
// (/zen/go) are left alone. The plugin cannot see the request Host (protected),
// so this is path-only; rule scoping selects the OpenCode downstream.
function freeURL(path) {
  if (path === "/zen") return "/inference";
  if (path.startsWith("/zen/") && !path.startsWith("/zen/go")) return "/inference" + path.slice(4);
  return path;
}

// protocolOf reads the wire format from the body shape Tresor will send (after
// auto-conversion), falling back to the downstream format literal.
function protocolOf(payload, format) {
  if (payload && typeof payload === "object") {
    if (Object.prototype.hasOwnProperty.call(payload, "contents")) return "gemini";
    if (Object.prototype.hasOwnProperty.call(payload, "input")) return "responses";
    if (Object.prototype.hasOwnProperty.call(payload, "system") && Object.prototype.hasOwnProperty.call(payload, "messages")) return "anthropic";
    if (Object.prototype.hasOwnProperty.call(payload, "messages")) return "chat";
  }
  if (format === "gemini") return "gemini";
  if (format === "openai_responses") return "responses";
  if (format === "anthropic") return "anthropic";
  return "chat";
}

function toolNameOf(t) {
  if (t && t.function && typeof t.function.name === "string") return t.function.name; // chat
  if (t && typeof t.name === "string") return t.name; // responses / anthropic
  return null;
}
function setToolName(t, name) {
  if (t && t.function && typeof t.function.name === "string") { t.function.name = name; return; }
  if (t && typeof t.name === "string") t.name = name;
}
function toolList(payload) {
  if (!payload || typeof payload !== "object") return null;
  if (Array.isArray(payload.tools)) return payload.tools;
  return null;
}

function stubTool(name, proto) {
  const schema = SCHEMAS[name];
  if (proto === "chat") return { type: "function", function: { name: name, description: STUB, parameters: schema } };
  if (proto === "responses") return { type: "function", name: name, description: STUB, parameters: schema };
  return { name: name, description: STUB, input_schema: schema }; // anthropic
}

// ensureTools renames client bash/read (any case) to lowercase and injects stubs
// for any that are missing. Returns a rename map {lower: originalName} plus the
// set of stub names injected, so the reply can be restored.
function ensureTools(payload, proto) {
  const renames = { map: {}, stubs: {} };
  if (proto === "gemini") return renames; // gemini free tier = headers only
  const tools = toolList(payload);
  if (tools) {
    for (const t of tools) {
      const n = toolNameOf(t);
      if (typeof n !== "string") continue;
      const lower = n.toLowerCase();
      if (STUB_NAMES[lower] && n !== lower) {
        setToolName(t, lower);
        renames.map[lower] = n;
      }
    }
    const present = {};
    for (const t of tools) { const n = toolNameOf(t); if (typeof n === "string") present[n.toLowerCase()] = true; }
    for (const name of Object.keys(STUB_NAMES)) {
      if (!present[name]) {
        tools.push(stubTool(name, proto));
        renames.stubs[name] = true;
      }
    }
  } else {
    const list = [];
    for (const name of Object.keys(STUB_NAMES)) { list.push(stubTool(name, proto)); renames.stubs[name] = true; }
    payload.tools = list;
  }
  return renames;
}

function toolCallsOf(choice, proto) {
  if (proto === "chat") {
    const m = choice && choice.message;
    return m && Array.isArray(m.tool_calls) ? m.tool_calls : null;
  }
  return null;
}

// renameBack walks a reply and renames lowercase tool calls back to the client's
// original names; when dropStubs is set, calls of injected stubs are removed
// entirely. Returns true when the reply was changed. Handles chat (buffered and
// one SSE delta chunk), responses (output function_call), and anthropic (tool_use).
function renameBack(reply, proto, renames, dropStubs) {
  if (!renames || proto === "gemini") return false;
  const map = renames.map || {};
  const stubs = renames.stubs || {};
  let changed = false;

  const handleCall = (call) => {
    const n = toolNameOf(call);
    if (typeof n !== "string") return false;
    const lower = n.toLowerCase();
    if (stubs[lower]) return true; // drop
    if (map[lower]) { setToolName(call, map[lower]); return "changed"; }
    return false;
  };

  if (proto === "chat") {
    const choices = Array.isArray(reply.choices) ? reply.choices : (reply.choices ? [reply.choices] : []);
    for (const c of choices) {
      if (!c) continue;
      // Buffered: message.tool_calls. Streaming delta: delta.tool_calls.
      for (const holder of [c.message, c.delta]) {
        if (!holder || !Array.isArray(holder.tool_calls)) continue;
        const keep = [];
        for (const call of holder.tool_calls) {
          const r = handleCall(call);
          if (r === true) { changed = true; continue; }
          if (r === "changed") changed = true;
          keep.push(call);
        }
        holder.tool_calls = keep;
      }
    }
    return changed;
  }
  if (proto === "responses") {
    const items = Array.isArray(reply.output) ? reply.output : [];
    const keep = [];
    for (const it of items) {
      if (it && it.type === "function_call") {
        const r = handleCall(it);
        if (r === true) { changed = true; continue; }
        if (r === "changed") changed = true;
      }
      keep.push(it);
    }
    reply.output = keep;
    return changed;
  }
  if (proto === "anthropic") {
    // Buffered content blocks, or a streaming content_block_delta is handled
    // conservatively (rename only) by the caller via streamEvent.
    const content = Array.isArray(reply.content) ? reply.content : [];
    const keep = [];
    for (const blk of content) {
      if (blk && blk.type === "tool_use") {
        const r = handleCall(blk);
        if (r === true) { changed = true; continue; }
        if (r === "changed") changed = true;
      }
      keep.push(blk);
    }
    reply.content = keep;
    return changed;
  }
  return false;
}

module.exports = { STUB: STUB, isFreeModel: isFreeModel, freeURL: freeURL, protocolOf: protocolOf, ensureTools: ensureTools, renameBack: renameBack, SCHEMAS: SCHEMAS };
