// Copyright 2018-2021 the Deno authors. All rights reserved. MIT license.

use crate::JsRuntime;
use rusty_v8 as v8;
use std::cell::Cell;
use std::convert::TryFrom;
use std::io::{stdout, Write};
use std::option::Option;
use url::Url;
use v8::MapFnTo;

lazy_static! {
  pub static ref EXTERNAL_REFERENCES: v8::ExternalReferences =
    v8::ExternalReferences::new(&[
      v8::ExternalReference {
        function: print.map_fn_to()
      },
      v8::ExternalReference {
        function: set_macrotask_callback.map_fn_to()
      },
      v8::ExternalReference {
        function: eval_context.map_fn_to()
      },
      v8::ExternalReference {
        function: queue_microtask.map_fn_to()
      },
      v8::ExternalReference {
        function: get_promise_details.map_fn_to()
      },
      v8::ExternalReference {
        function: get_proxy_details.map_fn_to()
      },
    ]);
}

pub fn script_origin<'a>(
  s: &mut v8::HandleScope<'a>,
  resource_name: v8::Local<'a, v8::String>,
) -> v8::ScriptOrigin<'a> {
  let source_map_url = v8::String::new(s, "").unwrap();
  v8::ScriptOrigin::new(
    s,
    resource_name.into(),
    0,
    0,
    false,
    123,
    source_map_url.into(),
    true,
    false,
    false,
  )
}

pub fn module_origin<'a>(
  s: &mut v8::HandleScope<'a>,
  resource_name: v8::Local<'a, v8::String>,
) -> v8::ScriptOrigin<'a> {
  let source_map_url = v8::String::new(s, "").unwrap();
  v8::ScriptOrigin::new(
    s,
    resource_name.into(),
    0,
    0,
    false,
    123,
    source_map_url.into(),
    true,
    false,
    true,
  )
}

pub fn initialize_context<'s>(
  scope: &mut v8::HandleScope<'s, ()>,
) -> v8::Local<'s, v8::Context> {
  let scope = &mut v8::EscapableHandleScope::new(scope);

  let context = v8::Context::new(scope);
  let global = context.global(scope);

  let scope = &mut v8::ContextScope::new(scope, context);

  let deno_key = v8::String::new(scope, "Deno").unwrap();
  let deno_val = v8::Object::new(scope);
  global.set(scope, deno_key.into(), deno_val.into());

  let core_key = v8::String::new(scope, "core").unwrap();
  let core_val = v8::Object::new(scope);
  deno_val.set(scope, core_key.into(), core_val.into());

  let print_key = v8::String::new(scope, "print").unwrap();
  let print_tmpl = v8::FunctionTemplate::new(scope, print);
  let print_val = print_tmpl.get_function(scope).unwrap();
  core_val.set(scope, print_key.into(), print_val.into());

  let set_macrotask_callback_key =
    v8::String::new(scope, "setMacrotaskCallback").unwrap();
  let set_macrotask_callback_tmpl =
    v8::FunctionTemplate::new(scope, set_macrotask_callback);
  let set_macrotask_callback_val =
    set_macrotask_callback_tmpl.get_function(scope).unwrap();
  core_val.set(
    scope,
    set_macrotask_callback_key.into(),
    set_macrotask_callback_val.into(),
  );

  let eval_context_key = v8::String::new(scope, "evalContext").unwrap();
  let eval_context_tmpl = v8::FunctionTemplate::new(scope, eval_context);
  let eval_context_val = eval_context_tmpl.get_function(scope).unwrap();
  core_val.set(scope, eval_context_key.into(), eval_context_val.into());


  let get_promise_details_key =
    v8::String::new(scope, "getPromiseDetails").unwrap();
  let get_promise_details_tmpl =
    v8::FunctionTemplate::new(scope, get_promise_details);
  let get_promise_details_val =
    get_promise_details_tmpl.get_function(scope).unwrap();
  core_val.set(
    scope,
    get_promise_details_key.into(),
    get_promise_details_val.into(),
  );

  let get_proxy_details_key =
    v8::String::new(scope, "getProxyDetails").unwrap();
  let get_proxy_details_tmpl =
    v8::FunctionTemplate::new(scope, get_proxy_details);
  let get_proxy_details_val =
    get_proxy_details_tmpl.get_function(scope).unwrap();
  core_val.set(
    scope,
    get_proxy_details_key.into(),
    get_proxy_details_val.into(),
  );

  // Direct bindings on `window`.
  let queue_microtask_key = v8::String::new(scope, "queueMicrotask").unwrap();
  let queue_microtask_tmpl = v8::FunctionTemplate::new(scope, queue_microtask);
  let queue_microtask_val = queue_microtask_tmpl.get_function(scope).unwrap();
  global.set(
    scope,
    queue_microtask_key.into(),
    queue_microtask_val.into(),
  );

  scope.escape(context)
}

pub extern "C" fn host_import_module_dynamically_callback(
  context: v8::Local<v8::Context>,
  referrer: v8::Local<v8::ScriptOrModule>,
  specifier: v8::Local<v8::String>,
) -> *mut v8::Promise {
  let scope = &mut unsafe { v8::CallbackScope::new(context) };

  // NOTE(bartlomieju): will crash for non-UTF-8 specifier
  let specifier_str = specifier
    .to_string(scope)
    .unwrap()
    .to_rust_string_lossy(scope);
  let referrer_name = referrer.get_resource_name();
  let referrer_name_str = referrer_name
    .to_string(scope)
    .unwrap()
    .to_rust_string_lossy(scope);

  // TODO(ry) I'm not sure what HostDefinedOptions is for or if we're ever going
  // to use it. For now we check that it is not used. This check may need to be
  // changed in the future.
  let host_defined_options = referrer.get_host_defined_options();
  assert_eq!(host_defined_options.length(), 0);

  let resolver = v8::PromiseResolver::new(scope).unwrap();
  let promise = resolver.get_promise(scope);

  let resolver_handle = v8::Global::new(scope, resolver);
  {
    let state_rc = JsRuntime::state(scope);
    let mut state = state_rc.borrow_mut();
    state.dyn_import_cb(resolver_handle, &specifier_str, &referrer_name_str);
  }

  &*promise as *const _ as *mut _
}

pub extern "C" fn host_initialize_import_meta_object_callback(
  context: v8::Local<v8::Context>,
  module: v8::Local<v8::Module>,
  meta: v8::Local<v8::Object>,
) {
  let scope = &mut unsafe { v8::CallbackScope::new(context) };
  let state_rc = JsRuntime::state(scope);
  let state = state_rc.borrow();

  let module_global = v8::Global::new(scope, module);
  let info = state
    .modules
    .get_info(&module_global)
    .expect("Module not found");

  let url_key = v8::String::new(scope, "url").unwrap();
  let url_val = v8::String::new(scope, &info.name).unwrap();
  meta.create_data_property(scope, url_key.into(), url_val.into());

  let main_key = v8::String::new(scope, "main").unwrap();
  let main_val = v8::Boolean::new(scope, info.main);
  meta.create_data_property(scope, main_key.into(), main_val.into());
}

pub extern "C" fn promise_reject_callback(message: v8::PromiseRejectMessage) {
  let scope = &mut unsafe { v8::CallbackScope::new(&message) };

  let state_rc = JsRuntime::state(scope);
  let mut state = state_rc.borrow_mut();

  let promise = message.get_promise();
  let promise_global = v8::Global::new(scope, promise);

  match message.get_event() {
    v8::PromiseRejectEvent::PromiseRejectWithNoHandler => {
      let error = message.get_value().unwrap();
      let error_global = v8::Global::new(scope, error);
      state
        .pending_promise_exceptions
        .insert(promise_global, error_global);
    }
    v8::PromiseRejectEvent::PromiseHandlerAddedAfterReject => {
      state.pending_promise_exceptions.remove(&promise_global);
    }
    v8::PromiseRejectEvent::PromiseRejectAfterResolved => {}
    v8::PromiseRejectEvent::PromiseResolveAfterResolved => {
      // Should not warn. See #1272
    }
  };
}

pub(crate) unsafe fn get_backing_store_slice(
  backing_store: &v8::SharedRef<v8::BackingStore>,
  byte_offset: usize,
  byte_length: usize,
) -> &[u8] {
  let cells: *const [Cell<u8>] =
    &backing_store[byte_offset..byte_offset + byte_length];
  let bytes = cells as *const [u8];
  &*bytes
}

#[allow(clippy::mut_from_ref)]
pub(crate) unsafe fn get_backing_store_slice_mut(
  backing_store: &v8::SharedRef<v8::BackingStore>,
  byte_offset: usize,
  byte_length: usize,
) -> &mut [u8] {
  let cells: *const [Cell<u8>] =
    &backing_store[byte_offset..byte_offset + byte_length];
  let bytes = cells as *const _ as *mut [u8];
  &mut *bytes
}

fn print(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  _rv: v8::ReturnValue,
) {
  let arg_len = args.length();
  assert!((0..=2).contains(&arg_len));

  let obj = args.get(0);
  let is_err_arg = args.get(1);

  let mut is_err = false;
  if arg_len == 2 {
    let int_val = is_err_arg
      .integer_value(scope)
      .expect("Unable to convert to integer");
    is_err = int_val != 0;
  };
  let tc_scope = &mut v8::TryCatch::new(scope);
  let str_ = match obj.to_string(tc_scope) {
    Some(s) => s,
    None => v8::String::new(tc_scope, "").unwrap(),
  };
  if is_err {
    eprint!("{}", str_.to_rust_string_lossy(tc_scope));
    stdout().flush().unwrap();
  } else {
    print!("{}", str_.to_rust_string_lossy(tc_scope));
    stdout().flush().unwrap();
  }
}



fn set_macrotask_callback(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  _rv: v8::ReturnValue,
) {
  let state_rc = JsRuntime::state(scope);
  let mut state = state_rc.borrow_mut();

  let cb = match v8::Local::<v8::Function>::try_from(args.get(0)) {
    Ok(cb) => cb,
    Err(err) => return throw_type_error(scope, err.to_string()),
  };

  let slot = match &mut state.js_macrotask_cb {
    slot @ None => slot,
    _ => {
      return throw_type_error(
        scope,
        "Deno.core.setMacrotaskCallback() already called",
      );
    }
  };

  slot.replace(v8::Global::new(scope, cb));
}

fn eval_context(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  mut rv: v8::ReturnValue,
) {
  let source = match v8::Local::<v8::String>::try_from(args.get(0)) {
    Ok(s) => s,
    Err(_) => {
      let msg = v8::String::new(scope, "Invalid argument").unwrap();
      let exception = v8::Exception::type_error(scope, msg);
      scope.throw_exception(exception);
      return;
    }
  };

  let url = v8::Local::<v8::String>::try_from(args.get(1))
    .map(|n| Url::from_file_path(n.to_rust_string_lossy(scope)).unwrap());

  let output = v8::Array::new(scope, 2);
  /*
   output[0] = result
   output[1] = ErrorInfo | null
     ErrorInfo = {
       thrown: Error | any,
       isNativeError: boolean,
       isCompileError: boolean,
     }
  */
  let tc_scope = &mut v8::TryCatch::new(scope);
  let name =
    v8::String::new(tc_scope, url.as_ref().map_or("<unknown>", Url::as_str))
      .unwrap();
  let origin = script_origin(tc_scope, name);
  let maybe_script = v8::Script::compile(tc_scope, source, Some(&origin));

  if maybe_script.is_none() {
    assert!(tc_scope.has_caught());
    let exception = tc_scope.exception().unwrap();

    let js_zero = v8::Integer::new(tc_scope, 0);
    let js_null = v8::null(tc_scope);
    output.set(tc_scope, js_zero.into(), js_null.into());

    let errinfo_obj = v8::Object::new(tc_scope);

    let is_compile_error_key =
      v8::String::new(tc_scope, "isCompileError").unwrap();
    let is_compile_error_val = v8::Boolean::new(tc_scope, true);
    errinfo_obj.set(
      tc_scope,
      is_compile_error_key.into(),
      is_compile_error_val.into(),
    );

    let is_native_error_key =
      v8::String::new(tc_scope, "isNativeError").unwrap();
    let is_native_error_val =
      v8::Boolean::new(tc_scope, exception.is_native_error());
    errinfo_obj.set(
      tc_scope,
      is_native_error_key.into(),
      is_native_error_val.into(),
    );

    let thrown_key = v8::String::new(tc_scope, "thrown").unwrap();
    errinfo_obj.set(tc_scope, thrown_key.into(), exception);

    let js_one = v8::Integer::new(tc_scope, 1);
    output.set(tc_scope, js_one.into(), errinfo_obj.into());

    rv.set(output.into());
    return;
  }

  let result = maybe_script.unwrap().run(tc_scope);

  if result.is_none() {
    assert!(tc_scope.has_caught());
    let exception = tc_scope.exception().unwrap();

    let js_zero = v8::Integer::new(tc_scope, 0);
    let js_null = v8::null(tc_scope);
    output.set(tc_scope, js_zero.into(), js_null.into());

    let errinfo_obj = v8::Object::new(tc_scope);

    let is_compile_error_key =
      v8::String::new(tc_scope, "isCompileError").unwrap();
    let is_compile_error_val = v8::Boolean::new(tc_scope, false);
    errinfo_obj.set(
      tc_scope,
      is_compile_error_key.into(),
      is_compile_error_val.into(),
    );

    let is_native_error_key =
      v8::String::new(tc_scope, "isNativeError").unwrap();
    let is_native_error_val =
      v8::Boolean::new(tc_scope, exception.is_native_error());
    errinfo_obj.set(
      tc_scope,
      is_native_error_key.into(),
      is_native_error_val.into(),
    );

    let thrown_key = v8::String::new(tc_scope, "thrown").unwrap();
    errinfo_obj.set(tc_scope, thrown_key.into(), exception);

    let js_one = v8::Integer::new(tc_scope, 1);
    output.set(tc_scope, js_one.into(), errinfo_obj.into());

    rv.set(output.into());
    return;
  }

  let js_zero = v8::Integer::new(tc_scope, 0);
  let js_one = v8::Integer::new(tc_scope, 1);
  let js_null = v8::null(tc_scope);
  output.set(tc_scope, js_zero.into(), result.unwrap());
  output.set(tc_scope, js_one.into(), js_null.into());
  rv.set(output.into());
}

fn queue_microtask(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  _rv: v8::ReturnValue,
) {
  match v8::Local::<v8::Function>::try_from(args.get(0)) {
    Ok(f) => scope.enqueue_microtask(f),
    Err(_) => {
      let msg = v8::String::new(scope, "Invalid argument").unwrap();
      let exception = v8::Exception::type_error(scope, msg);
      scope.throw_exception(exception);
    }
  };
}

// Called by V8 during `Isolate::mod_instantiate`.
pub fn module_resolve_callback<'s>(
  context: v8::Local<'s, v8::Context>,
  specifier: v8::Local<'s, v8::String>,
  referrer: v8::Local<'s, v8::Module>,
) -> Option<v8::Local<'s, v8::Module>> {
  let scope = &mut unsafe { v8::CallbackScope::new(context) };

  let state_rc = JsRuntime::state(scope);
  let state = state_rc.borrow();

  let referrer_global = v8::Global::new(scope, referrer);
  let referrer_info = state
    .modules
    .get_info(&referrer_global)
    .expect("ModuleInfo not found");
  let referrer_name = referrer_info.name.to_string();

  let specifier_str = specifier.to_rust_string_lossy(scope);

  let resolved_specifier = state
    .loader
    .resolve(
      &specifier_str,
      &referrer_name,
      false,
    )
    .expect("Module should have been already resolved");

  if let Some(id) = state.modules.get_id(resolved_specifier.as_str()) {
    if let Some(handle) = state.modules.get_handle(id) {
      return Some(v8::Local::new(scope, handle));
    }
  }

  let msg = format!(
    r#"Cannot resolve module "{}" from "{}""#,
    specifier_str, referrer_name
  );
  throw_type_error(scope, msg);
  None
}

// Returns promise details or throw TypeError, if argument passed isn't a Promise.
// Promise details is a js_two elements array.
// promise_details = [State, Result]
// State = enum { Pending = 0, Fulfilled = 1, Rejected = 2}
// Result = PromiseResult<T> | PromiseError
fn get_promise_details(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  mut rv: v8::ReturnValue,
) {
  let promise = match v8::Local::<v8::Promise>::try_from(args.get(0)) {
    Ok(val) => val,
    Err(_) => {
      let msg = v8::String::new(scope, "Invalid argument").unwrap();
      let exception = v8::Exception::type_error(scope, msg);
      scope.throw_exception(exception);
      return;
    }
  };

  let promise_details = v8::Array::new(scope, 2);

  match promise.state() {
    v8::PromiseState::Pending => {
      let js_zero = v8::Integer::new(scope, 0);
      promise_details.set(scope, js_zero.into(), js_zero.into());
      rv.set(promise_details.into());
    }
    v8::PromiseState::Fulfilled => {
      let js_zero = v8::Integer::new(scope, 0);
      let js_one = v8::Integer::new(scope, 1);
      let promise_result = promise.result(scope);
      promise_details.set(scope, js_zero.into(), js_one.into());
      promise_details.set(scope, js_one.into(), promise_result);
      rv.set(promise_details.into());
    }
    v8::PromiseState::Rejected => {
      let js_zero = v8::Integer::new(scope, 0);
      let js_one = v8::Integer::new(scope, 1);
      let js_two = v8::Integer::new(scope, 2);
      let promise_result = promise.result(scope);
      promise_details.set(scope, js_zero.into(), js_two.into());
      promise_details.set(scope, js_one.into(), promise_result);
      rv.set(promise_details.into());
    }
  }
}

// Based on https://github.com/nodejs/node/blob/1e470510ff74391d7d4ec382909ea8960d2d2fbc/src/node_util.cc
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
fn get_proxy_details(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  mut rv: v8::ReturnValue,
) {
  // Return undefined if it's not a proxy.
  let proxy = match v8::Local::<v8::Proxy>::try_from(args.get(0)) {
    Ok(val) => val,
    Err(_) => {
      return;
    }
  };

  let proxy_details = v8::Array::new(scope, 2);
  let js_zero = v8::Integer::new(scope, 0);
  let js_one = v8::Integer::new(scope, 1);
  let target = proxy.get_target(scope);
  let handler = proxy.get_handler(scope);
  proxy_details.set(scope, js_zero.into(), target);
  proxy_details.set(scope, js_one.into(), handler);
  rv.set(proxy_details.into());
}

fn throw_type_error(scope: &mut v8::HandleScope, message: impl AsRef<str>) {
  let message = v8::String::new(scope, message.as_ref()).unwrap();
  let exception = v8::Exception::type_error(scope, message);
  scope.throw_exception(exception);
}
