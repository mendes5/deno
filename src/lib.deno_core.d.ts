// Copyright 2018-2021 the Deno authors. All rights reserved. MIT license.

// deno-lint-ignore-file no-explicit-any

/// <reference no-default-lib="true" />
/// <reference lib="esnext" />

declare namespace Deno {
  declare namespace core {
      /**
     * Retrieve a list of all open resources, in the form of a map that maps
     * resource id to the resource name.
     */
    function resources(): Record<string, string>;
  }
}
