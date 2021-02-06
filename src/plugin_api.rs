// Copyright 2018-2021 the Deno authors. All rights reserved. MIT license.

// This file defines the public interface for dynamically loaded plugins.

// The plugin needs to do all interaction with the CLI crate through trait
// objects and function pointers. This ensures that no concrete internal methods
// (such and the closures created by it) can end up in the plugin
// shared library itself, which would cause segfaults when the plugin is
// unloaded and all functions in the plugin library are unmapped from memory.


pub type InitFn = fn(&mut dyn Interface);

pub trait Interface {}
