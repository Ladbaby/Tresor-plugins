"use strict";
// mask-sensitive — secrets and personal data go to the provider as
// placeholders, and come back as they were.
//
// A request's body is masked: API keys, tokens, private keys, passwords, and —
// when turned on — email addresses, phone numbers, ID and card numbers and the
// other personal categories. A response's body and its stream are restored, so
// the client and the user see the real values while the provider never does.
//
// The placeholders are held in the request's own state and nowhere else, so a
// restart loses nothing and no secret is ever written to disk. The trade is that
// a value masked in one request cannot be restored in a later one; the client
// was shown the real value, so the next turn's transcript holds it again and it
// is masked again, to the same placeholder.

const options = require("./config");
const encoding = require("tresor/encoding.v1");
const payload = require("./payload");
const stream = require("./stream");

// The placeholder map and the held stream event live in the hook's state, which
// the host keeps for one attempt: a retry starts empty, which is right, because
// a retry re-sends the client's own body.
function valuesIn(state) {
  if (state.values === undefined) {
    state.values = {};
  }
  return state.values;
}

const request = function ({ body, config, state }) {
  const text = payload.bodyText(body);
  if (text === null || text === "") {
    return;
  }
  const resolved = options.resolve(config);
  const values = valuesIn(state);
  const r = payload.maskBody(text, resolved, values);
  if (!r.changed) {
    return;
  }
  return { body: encoding.encode(r.text) };
};

const response = function ({ body, state }) {
  const values = state.values;
  if (values === undefined || Object.keys(values).length === 0) {
    return;
  }
  const text = payload.bodyText(body);
  if (text === null || text === "") {
    return;
  }
  const r = payload.restoreBody(text, values);
  if (!r.changed) {
    return;
  }
  return { body: encoding.encode(r.text) };
};

const streamEvent = function ({ event, state }) {
  const values = state.values;
  if (values === undefined || Object.keys(values).length === 0) {
    return;
  }
  const r = stream.restoreEvent(event, values, state.held === undefined ? null : state.held);
  state.held = r.held;
  if (r.events.length === 1 && r.events[0] === event) {
    return;
  }
  return { events: r.events };
};

const streamEnd = function ({ state }) {
  const held = state.held;
  state.held = null;
  state.values = {};
  if (held === null || held === undefined) {
    return;
  }
  // A held event that never completed still has to reach the client: dropping it
  // would lose text.
  return { events: stream.release(held) };
};

const EXPORTS = { request: request, response: response, streamEvent: streamEvent, streamEnd: streamEnd };

module.exports = EXPORTS;
