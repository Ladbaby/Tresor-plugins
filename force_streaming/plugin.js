"use strict";
const json = require("tresor/json.v1");
const encoding = require("tresor/encoding.v1");
const query = require("tresor/query.v1");
const collectors = require("./collectors");
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const object = v => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof json.NumberToken);
function set(o, k, v) { Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true }); }

module.exports = {
  request({ context, request, body }) {
    if (context.transport.client === "streaming") return;
    const format = context.formats.current;
    let path = request.path;
    if (!["/chat/completions", "/messages", "/responses", ":generateContent", ":streamGenerateContent"].some(suffix => path.endsWith(suffix))) return;
    const payload = json.parseLossless(encoding.decode(body));
    if (!object(payload)) throw Error("force_streaming expects a JSON object");
    const patch = { setHeaders: { Accept: ["text/event-stream"] } };
    if (["openai", "anthropic", "openai_responses"].includes(format)) {
      set(payload, "stream", true);
      if (format === "openai") {
        const options = own(payload, "stream_options") && object(payload.stream_options) ? payload.stream_options : {};
        set(options, "include_usage", true);
        set(payload, "stream_options", options);
      }
    } else if (format === "gemini") {
      delete payload.stream;
      if (path.endsWith(":generateContent")) path = path.slice(0, -":generateContent".length) + ":streamGenerateContent";
      if (!path.endsWith(":streamGenerateContent")) throw Error("force_streaming: invalid Gemini generation path");
      patch.path = path;
      const entries = query.parse(request.query).filter(([key]) => key !== "alt");
      entries.push(["alt", "sse"]);
      patch.query = query.stringify(entries);
    } else throw Error("force_streaming: unsupported downstream format");
    return { body: encoding.encode(json.stringifyLossless(payload)), request: patch, transport: { upstream: "sse", delivery: "collect" } };
  },
  collectStart({ state, context }) { state.collector = collectors.start(context.formats.current); },
  collectEvent({ state, event }) { collectors.event(state.collector, event); },
  collectEnd({ state, end }) {
    const collector = state.collector;
    delete state.collector;
    if (end.reason !== "eof") return;
    return { body: encoding.encode(json.stringifyLossless(collectors.end(collector))), response: { setHeaders: { "Content-Type": ["application/json"] } } };
  },
  finish({ state }) { delete state.collector; }
};
