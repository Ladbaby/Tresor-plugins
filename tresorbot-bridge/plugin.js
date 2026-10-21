"use strict";
module.exports = {
  prepare: function (input) {
    if (!input.bindings || !input.bindings.local || !input.bindings.local.binding_id) {
      throw new Error("TresorBot bridge requires its local service binding");
    }
    return {
      service: "local",
      operation: "prepare",
      payload: {
        binding_id: input.bindings.local.binding_id,
        routing: input.routing,
        execution: input.execution,
        request: input.request,
        body: input.body
      }
    };
  },
  prepared: function (input) {
    if (!input.result || !input.result.decision) {
      throw new Error("Sun returned no bridge decision");
    }
    return input.result.decision;
  }
};
