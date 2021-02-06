"use strict";

((window) => {
  const errorMap = {};

  function registerErrorClass(errorName, className) {
    if (typeof errorMap[errorName] !== "undefined") {
      throw new TypeError(`Error class for "${errorName}" already registered`);
    }
    errorMap[errorName] = className;
  }

  function getErrorClass(errorName) {
    return errorMap[errorName];
  }

  Object.assign(window.Deno.core, {
    registerErrorClass,
    getErrorClass,
  });
})(this);
