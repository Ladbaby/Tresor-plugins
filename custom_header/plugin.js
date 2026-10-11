"use strict";

module.exports = {
  request({ config: { headers } }) {
    const setHeaders = Object.create(null);
    for (const [name, value] of Object.entries(headers)) {
      const key = name.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(setHeaders, key)) {
        throw new Error("Duplicate header name: " + key);
      }
      setHeaders[key] = [value];
    }
    return { request: { setHeaders } };
  }
};
