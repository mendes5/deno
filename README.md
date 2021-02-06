# ~~Deno~~ Core

This is forked from [denoland/deno](https://github.com/denoland/deno), everything but the core module was stripped away, and even on the core module, most Deno specific features were removed and new APIs are being added.

Changes:
 - [x] No ops
 - [x] No global `Deno` api
 - [x] No shared queue
 - [x] No resource ids
 - [x] Add Built-in (sythetic) modules API. (See `js-synthetic-modules` example)
