// Copyright 2018-2021 the Deno authors. All rights reserved. MIT license.

use rusty_v8 as v8;

use crate::bindings;
use crate::error::attach_handle_to_error;
use crate::error::generic_error;
use crate::error::AnyError;
use crate::error::ErrWithV8Handle;
use crate::error::JsError;
use crate::futures::FutureExt;
use crate::module_specifier::ModuleSpecifier;
use crate::modules::LoadState;
use crate::modules::ModuleId;
use crate::modules::ModuleLoadId;
use crate::modules::ModuleLoader;
use crate::modules::ModuleSource;
use crate::modules::Modules;
use crate::modules::NoopModuleLoader;
use crate::modules::PrepareLoadFuture;
use crate::modules::RecursiveModuleLoad;
use futures::channel::mpsc;
use futures::future::poll_fn;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use futures::stream::StreamFuture;
use futures::task::AtomicWaker;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::mem::forget;
use std::option::Option;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Once;
use std::task::Context;
use std::task::Poll;
use v8::MapFnTo;

pub enum Snapshot {
  Static(&'static [u8]),
  JustCreated(v8::StartupData),
  Boxed(Box<[u8]>),
}

pub type JsErrorCreateFn = dyn Fn(JsError) -> AnyError;

pub type GetErrorClassFn = &'static dyn for<'e> Fn(&'e AnyError) -> &'static str;

/// Objects that need to live as long as the isolate
#[derive(Default)]
struct IsolateAllocations {
  near_heap_limit_callback_data: Option<(Box<RefCell<dyn Any>>, v8::NearHeapLimitCallback)>,
}

/// A single execution context of JavaScript. Corresponds roughly to the "Web
/// Worker" concept in the DOM. A JsRuntime is a Future that can be used with
/// an event loop (Tokio, async_std).
////
/// The JsRuntime future completes when there is an error or when all
/// pending ops have completed.
///
/// Ops are created in JavaScript by calling Deno.core.dispatch(), and in Rust
/// by implementing dispatcher function that takes control buffer and optional zero copy buffer
/// as arguments. An async Op corresponds exactly to a Promise in JavaScript.
pub struct JsRuntime {
  // This is an Option<OwnedIsolate> instead of just OwnedIsolate to workaround
  // an safety issue with SnapshotCreator. See JsRuntime::drop.
  v8_isolate: Option<v8::OwnedIsolate>,
  snapshot_creator: Option<v8::SnapshotCreator>,
  has_snapshotted: bool,
  allocations: IsolateAllocations,
}

struct DynImportModEvaluate {
  module_id: ModuleId,
  promise: v8::Global<v8::Promise>,
  module: v8::Global<v8::Module>,
}

struct ModEvaluate {
  promise: v8::Global<v8::Promise>,
  sender: mpsc::Sender<Result<(), AnyError>>,
}

/// Internal state for JsRuntime which is stored in one of v8::Isolate's
/// embedder slots.
pub(crate) struct JsRuntimeState {
  pub global_context: Option<v8::Global<v8::Context>>,
  pub(crate) js_macrotask_cb: Option<v8::Global<v8::Function>>,
  pub(crate) pending_promise_exceptions: HashMap<v8::Global<v8::Promise>, v8::Global<v8::Value>>,
  pending_dyn_mod_evaluate: HashMap<ModuleLoadId, DynImportModEvaluate>,
  pending_mod_evaluate: Option<ModEvaluate>,
  pub(crate) js_error_create_fn: Rc<JsErrorCreateFn>,
  pub loader: Rc<dyn ModuleLoader>,
  pub modules: Modules,
  pub(crate) dyn_import_map: HashMap<ModuleLoadId, v8::Global<v8::PromiseResolver>>,
  preparing_dyn_imports: FuturesUnordered<Pin<Box<PrepareLoadFuture>>>,
  pending_dyn_imports: FuturesUnordered<StreamFuture<RecursiveModuleLoad>>,
  waker: AtomicWaker,
}

impl Drop for JsRuntime {
  fn drop(&mut self) {
    if let Some(creator) = self.snapshot_creator.take() {
      // TODO(ry): in rusty_v8, `SnapShotCreator::get_owned_isolate()` returns
      // a `struct OwnedIsolate` which is not actually owned, hence the need
      // here to leak the `OwnedIsolate` in order to avoid a double free and
      // the segfault that it causes.
      let v8_isolate = self.v8_isolate.take().unwrap();
      forget(v8_isolate);

      // TODO(ry) V8 has a strange assert which prevents a SnapshotCreator from
      // being deallocated if it hasn't created a snapshot yet.
      // https://github.com/v8/v8/blob/73212783fbd534fac76cc4b66aac899c13f71fc8/src/api.cc#L603
      // If that assert is removed, this if guard could be removed.
      // WARNING: There may be false positive LSAN errors here.
      if self.has_snapshotted {
        drop(creator);
      }
    }
  }
}

#[allow(clippy::missing_safety_doc)]
pub unsafe fn v8_init() {
  let platform = v8::new_default_platform().unwrap();
  v8::V8::initialize_platform(platform);
  v8::V8::initialize();
  let argv = vec![
    "".to_string(),
    "--wasm-test-streaming".to_string(),
    // TODO(ry) This makes WASM compile synchronously. Eventually we should
    // remove this to make it work asynchronously too. But that requires getting
    // PumpMessageLoop and RunMicrotasks setup correctly.
    // See https://github.com/denoland/deno/issues/2544
    "--no-wasm-async-compilation".to_string(),
    "--harmony-top-level-await".to_string(),
    "--no-validate-asm".to_string(),
  ];
  v8::V8::set_flags_from_command_line(argv);
}

#[derive(Default)]
pub struct RuntimeOptions {
  /// Allows a callback to be set whenever a V8 exception is made. This allows
  /// the caller to wrap the JsError into an error. By default this callback
  /// is set to `JsError::create()`.
  pub js_error_create_fn: Option<Rc<JsErrorCreateFn>>,

  /// Allows to map error type to a string "class" used to represent
  /// error in JavaScript.
  pub get_error_class_fn: Option<GetErrorClassFn>,

  /// Implementation of `ModuleLoader` which will be
  /// called when V8 requests to load ES modules.
  ///
  /// If not provided runtime will error if code being
  /// executed tries to load modules.
  pub module_loader: Option<Rc<dyn ModuleLoader>>,

  /// V8 snapshot that should be loaded on startup.
  ///
  /// Currently can't be used with `will_snapshot`.
  pub startup_snapshot: Option<Snapshot>,

  /// Prepare runtime to take snapshot of loaded code.
  ///
  /// Currently can't be used with `startup_snapshot`.
  pub will_snapshot: bool,

  /// Isolate creation parameters.
  pub create_params: Option<v8::CreateParams>,
}

impl JsRuntime {
  /// Only constructor, configuration is done through `options`.
  pub fn new(mut options: RuntimeOptions) -> Self {
    static DENO_INIT: Once = Once::new();
    DENO_INIT.call_once(|| {
      unsafe { v8_init() };
    });

    let global_context;
    let (mut isolate, maybe_snapshot_creator) = if options.will_snapshot {
      // TODO(ry) Support loading snapshots before snapshotting.
      assert!(options.startup_snapshot.is_none());
      let mut creator = v8::SnapshotCreator::new(Some(&bindings::EXTERNAL_REFERENCES));
      let isolate = unsafe { creator.get_owned_isolate() };
      let mut isolate = JsRuntime::setup_isolate(isolate);
      {
        let scope = &mut v8::HandleScope::new(&mut isolate);
        let context = bindings::initialize_context(scope);
        global_context = v8::Global::new(scope, context);
        creator.set_default_context(context);
      }
      (isolate, Some(creator))
    } else {
      let mut params = options
        .create_params
        .take()
        .unwrap_or_else(v8::Isolate::create_params)
        .external_references(&**bindings::EXTERNAL_REFERENCES);
      let snapshot_loaded = if let Some(snapshot) = options.startup_snapshot {
        params = match snapshot {
          Snapshot::Static(data) => params.snapshot_blob(data),
          Snapshot::JustCreated(data) => params.snapshot_blob(data),
          Snapshot::Boxed(data) => params.snapshot_blob(data),
        };
        true
      } else {
        false
      };

      let isolate = v8::Isolate::new(params);
      let mut isolate = JsRuntime::setup_isolate(isolate);
      {
        let scope = &mut v8::HandleScope::new(&mut isolate);
        let context = if snapshot_loaded {
          v8::Context::new(scope)
        } else {
          // If no snapshot is provided, we initialize the context with empty
          // main source code and source maps.
          bindings::initialize_context(scope)
        };
        global_context = v8::Global::new(scope, context);
      }
      (isolate, None)
    };

    let loader = options
      .module_loader
      .unwrap_or_else(|| Rc::new(NoopModuleLoader));

    let js_error_create_fn = options
      .js_error_create_fn
      .unwrap_or_else(|| Rc::new(JsError::create));

    isolate.set_slot(Rc::new(RefCell::new(JsRuntimeState {
      global_context: Some(global_context),
      pending_promise_exceptions: HashMap::new(),
      pending_dyn_mod_evaluate: HashMap::new(),
      pending_mod_evaluate: None,
      js_macrotask_cb: None,
      js_error_create_fn,
      modules: Modules::new(),
      loader,
      dyn_import_map: HashMap::new(),
      preparing_dyn_imports: FuturesUnordered::new(),
      pending_dyn_imports: FuturesUnordered::new(),
      waker: AtomicWaker::new(),
    })));

    Self {
      v8_isolate: Some(isolate),
      snapshot_creator: maybe_snapshot_creator,
      has_snapshotted: false,
      allocations: IsolateAllocations::default(),
    }
  }

  pub fn global_context(&mut self) -> v8::Global<v8::Context> {
    let state = Self::state(self.v8_isolate());
    let state = state.borrow();
    state.global_context.clone().unwrap()
  }

  pub fn v8_isolate(&mut self) -> &mut v8::OwnedIsolate {
    self.v8_isolate.as_mut().unwrap()
  }

  fn setup_isolate(mut isolate: v8::OwnedIsolate) -> v8::OwnedIsolate {
    isolate.set_capture_stack_trace_for_uncaught_exceptions(true, 10);
    isolate.set_promise_reject_callback(bindings::promise_reject_callback);
    isolate.set_host_initialize_import_meta_object_callback(
      bindings::host_initialize_import_meta_object_callback,
    );
    isolate.set_host_import_module_dynamically_callback(
      bindings::host_import_module_dynamically_callback,
    );
    isolate
  }

  pub(crate) fn state(isolate: &v8::Isolate) -> Rc<RefCell<JsRuntimeState>> {
    let s = isolate.get_slot::<Rc<RefCell<JsRuntimeState>>>().unwrap();
    s.clone()
  }

  /// Executes traditional JavaScript code (traditional = not ES modules)
  ///
  /// The execution takes place on the current global context, so it is possible
  /// to maintain local JS state and invoke this method multiple times.
  ///
  /// `AnyError` can be downcast to a type that exposes additional information
  /// about the V8 exception. By default this type is `JsError`, however it may
  /// be a different type if `RuntimeOptions::js_error_create_fn` has been set.
  pub fn execute(&mut self, js_filename: &str, js_source: &str) -> Result<(), AnyError> {
    let context = self.global_context();

    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let source = v8::String::new(scope, js_source).unwrap();
    let name = v8::String::new(scope, js_filename).unwrap();
    let origin = bindings::script_origin(scope, name);

    let tc_scope = &mut v8::TryCatch::new(scope);

    let script = match v8::Script::compile(tc_scope, source, Some(&origin)) {
      Some(script) => script,
      None => {
        let exception = tc_scope.exception().unwrap();
        return exception_to_err_result(tc_scope, exception, false);
      }
    };

    match script.run(tc_scope) {
      Some(_) => Ok(()),
      None => {
        assert!(tc_scope.has_caught());
        let exception = tc_scope.exception().unwrap();
        exception_to_err_result(tc_scope, exception, false)
      }
    }
  }

  /// Takes a snapshot. The isolate should have been created with will_snapshot
  /// set to true.
  ///
  /// `AnyError` can be downcast to a type that exposes additional information
  /// about the V8 exception. By default this type is `JsError`, however it may
  /// be a different type if `RuntimeOptions::js_error_create_fn` has been set.
  pub fn snapshot(&mut self) -> v8::StartupData {
    assert!(self.snapshot_creator.is_some());
    let state = Self::state(self.v8_isolate());

    // Note: create_blob() method must not be called from within a HandleScope.
    // TODO(piscisaureus): The rusty_v8 type system should enforce this.
    state.borrow_mut().global_context.take();

    std::mem::take(&mut state.borrow_mut().modules);

    let snapshot_creator = self.snapshot_creator.as_mut().unwrap();
    let snapshot = snapshot_creator
      .create_blob(v8::FunctionCodeHandling::Keep)
      .unwrap();
    self.has_snapshotted = true;

    snapshot
  }

  /// Registers a callback on the isolate when the memory limits are approached.
  /// Use this to prevent V8 from crashing the process when reaching the limit.
  ///
  /// Calls the closure with the current heap limit and the initial heap limit.
  /// The return value of the closure is set as the new limit.
  pub fn add_near_heap_limit_callback<C>(&mut self, cb: C)
  where
    C: FnMut(usize, usize) -> usize + 'static,
  {
    let boxed_cb = Box::new(RefCell::new(cb));
    let data = boxed_cb.as_ptr() as *mut c_void;

    let prev = self
      .allocations
      .near_heap_limit_callback_data
      .replace((boxed_cb, near_heap_limit_callback::<C>));
    if let Some((_, prev_cb)) = prev {
      self
        .v8_isolate()
        .remove_near_heap_limit_callback(prev_cb, 0);
    }

    self
      .v8_isolate()
      .add_near_heap_limit_callback(near_heap_limit_callback::<C>, data);
  }

  pub fn remove_near_heap_limit_callback(&mut self, heap_limit: usize) {
    if let Some((_, cb)) = self.allocations.near_heap_limit_callback_data.take() {
      self
        .v8_isolate()
        .remove_near_heap_limit_callback(cb, heap_limit);
    }
  }

  /// Runs event loop to completion
  ///
  /// This future resolves when:
  ///  - there are no more pending dynamic imports
  ///  - there are no more pending ops
  pub async fn run_event_loop(&mut self) -> Result<(), AnyError> {
    poll_fn(|cx| self.poll_event_loop(cx)).await
  }

  /// Runs a single tick of event loop
  pub fn poll_event_loop(&mut self, cx: &mut Context) -> Poll<Result<(), AnyError>> {
    let state_rc = Self::state(self.v8_isolate());
    {
      let state = state_rc.borrow();
      state.waker.register(cx.waker());
    }

    // Ops
    {
      self.drain_macrotasks()?;
      self.check_promise_exceptions()?;
    }

    // Dynamic module loading - ie. modules loaded using "import()"
    {
      let poll_imports = self.prepare_dyn_imports(cx)?;
      assert!(poll_imports.is_ready());

      let poll_imports = self.poll_dyn_imports(cx)?;
      assert!(poll_imports.is_ready());

      self.evaluate_dyn_imports();

      self.check_promise_exceptions()?;
    }

    // Top level module
    self.evaluate_pending_module();

    let state = state_rc.borrow();

    let has_pending_dyn_imports =
      !{ state.preparing_dyn_imports.is_empty() && state.pending_dyn_imports.is_empty() };
    let has_pending_dyn_module_evaluation = !state.pending_dyn_mod_evaluate.is_empty();
    let has_pending_module_evaluation = state.pending_mod_evaluate.is_some();

    if !has_pending_dyn_imports
      && !has_pending_dyn_module_evaluation
      && !has_pending_module_evaluation
    {
      return Poll::Ready(Ok(()));
    }

    if has_pending_module_evaluation {
      if has_pending_dyn_imports || has_pending_dyn_module_evaluation {
        // pass, will be polled again
      } else {
        let msg = "Module evaluation is still pending but there are no pending ops or dynamic imports. This situation is often caused by unresolved promise.";
        return Poll::Ready(Err(generic_error(msg)));
      }
    }

    if has_pending_dyn_module_evaluation {
      if has_pending_dyn_imports {
        // pass, will be polled again
      } else {
        let msg = "Dynamically imported module evaluation is still pending but there are no pending ops. This situation is often caused by unresolved promise.";
        return Poll::Ready(Err(generic_error(msg)));
      }
    }

    Poll::Pending
  }
}

extern "C" fn near_heap_limit_callback<F>(
  data: *mut c_void,
  current_heap_limit: usize,
  initial_heap_limit: usize,
) -> usize
where
  F: FnMut(usize, usize) -> usize,
{
  let callback = unsafe { &mut *(data as *mut F) };
  callback(current_heap_limit, initial_heap_limit)
}

impl JsRuntimeState {
  // Called by V8 during `Isolate::mod_instantiate`.
  pub fn dyn_import_cb(
    &mut self,
    resolver_handle: v8::Global<v8::PromiseResolver>,
    specifier: &str,
    referrer: &str,
  ) {
    debug!("dyn_import specifier {} referrer {} ", specifier, referrer);

    let load = RecursiveModuleLoad::dynamic_import(specifier, referrer, self.loader.clone());
    self.dyn_import_map.insert(load.id, resolver_handle);
    self.waker.wake();
    let fut = load.prepare().boxed_local();
    self.preparing_dyn_imports.push(fut);
  }
}

pub(crate) fn exception_to_err_result<'s, T>(
  scope: &mut v8::HandleScope<'s>,
  exception: v8::Local<v8::Value>,
  in_promise: bool,
) -> Result<T, AnyError> {
  let is_terminating_exception = scope.is_execution_terminating();
  let mut exception = exception;

  if is_terminating_exception {
    // TerminateExecution was called. Cancel exception termination so that the
    // exception can be created..
    scope.cancel_terminate_execution();

    // Maybe make a new exception object.
    if exception.is_null_or_undefined() {
      let message = v8::String::new(scope, "execution terminated").unwrap();
      exception = v8::Exception::error(scope, message);
    }
  }

  let mut js_error = JsError::from_v8_exception(scope, exception);
  if in_promise {
    js_error.message = format!(
      "Uncaught (in promise) {}",
      js_error.message.trim_start_matches("Uncaught ")
    );
  }

  let state_rc = JsRuntime::state(scope);
  let state = state_rc.borrow();
  let js_error = (state.js_error_create_fn)(js_error);

  if is_terminating_exception {
    // Re-enable exception termination.
    scope.terminate_execution();
  }

  Err(js_error)
}

// Related to module loading
impl JsRuntime {
  /// Low-level module creation.
  ///
  /// Called during module loading or dynamic import loading.
  fn mod_new(&mut self, main: bool, name: &str, source: &str) -> Result<ModuleId, AnyError> {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();
    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let name_str = v8::String::new(scope, name).unwrap();
    let source_str = v8::String::new(scope, source).unwrap();

    let origin = bindings::module_origin(scope, name_str);
    let source = v8::script_compiler::Source::new(source_str, &origin);

    let tc_scope = &mut v8::TryCatch::new(scope);

    let maybe_module = v8::script_compiler::compile_module(tc_scope, source);

    if tc_scope.has_caught() {
      assert!(maybe_module.is_none());
      let e = tc_scope.exception().unwrap();
      return exception_to_err_result(tc_scope, e, false);
    }

    let module = maybe_module.unwrap();

    let mut import_specifiers: Vec<ModuleSpecifier> = vec![];
    for i in 0..module.get_module_requests_length() {
      let import_specifier = module.get_module_request(i).to_rust_string_lossy(tc_scope);
      let state = state_rc.borrow();
      let module_specifier = state.loader.resolve(&import_specifier, name, false)?;
      import_specifiers.push(module_specifier);
    }

    let id = state_rc.borrow_mut().modules.register(
      name,
      main,
      v8::Global::<v8::Module>::new(tc_scope, module),
      import_specifiers,
    );

    Ok(id)
  }

  /// Registers a synthetic module
  ///
  /// Synthetic modules are just like normal JS modules, but they don't contain any 
  /// JS source code, their contents are set using the V8 API and are mostly
  /// functions from native code, objects and other values.
  pub fn register_synthetic_module<'a>(
    &mut self,
    name: &str,
    exports: Vec<&str>,
    evaluator: impl MapFnTo<v8::SyntheticModuleEvaluationSteps<'a>>,
  ) {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();
    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let export_names = exports
      .iter()
      .map(|name| v8::String::new(scope, name).unwrap())
      .collect::<Vec<v8::Local<v8::String>>>();

    let module_name = v8::String::new(scope, "synthetic module").unwrap();
    let module = v8::Module::create_synthetic_module(scope, module_name, &export_names, evaluator);

    let tc_scope = &mut v8::TryCatch::new(scope);

    state_rc.borrow_mut().modules.register(
      name,
      true,
      v8::Global::<v8::Module>::new(tc_scope, module),
      vec![],
    );
  }

  /// Instantiates a ES module
  ///
  /// `AnyError` can be downcast to a type that exposes additional information
  /// about the V8 exception. By default this type is `JsError`, however it may
  /// be a different type if `RuntimeOptions::js_error_create_fn` has been set.
  fn mod_instantiate(&mut self, id: ModuleId) -> Result<(), AnyError> {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();

    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);
    let tc_scope = &mut v8::TryCatch::new(scope);

    let module = state_rc
      .borrow()
      .modules
      .get_handle(id)
      .map(|handle| v8::Local::new(tc_scope, handle))
      .expect("ModuleInfo not found");

    if module.get_status() == v8::ModuleStatus::Errored {
      exception_to_err_result(tc_scope, module.get_exception(), false)?
    }

    let result = module.instantiate_module(tc_scope, bindings::module_resolve_callback);
    match result {
      Some(_) => Ok(()),
      None => {
        let exception = tc_scope.exception().unwrap();
        exception_to_err_result(tc_scope, exception, false)
      }
    }
  }

  /// Evaluates an already instantiated ES module.
  ///
  /// `AnyError` can be downcast to a type that exposes additional information
  /// about the V8 exception. By default this type is `JsError`, however it may
  /// be a different type if `RuntimeOptions::js_error_create_fn` has been set.
  pub fn dyn_mod_evaluate(&mut self, load_id: ModuleLoadId, id: ModuleId) -> Result<(), AnyError> {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();
    let context1 = self.global_context();

    let module_handle = state_rc
      .borrow()
      .modules
      .get_handle(id)
      .expect("ModuleInfo not found");

    let status = {
      let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);
      let module = module_handle.get(scope);
      module.get_status()
    };

    if status == v8::ModuleStatus::Instantiated {
      // IMPORTANT: Top-level-await is enabled, which means that return value
      // of module evaluation is a promise.
      //
      // Because that promise is created internally by V8, when error occurs during
      // module evaluation the promise is rejected, and since the promise has no rejection
      // handler it will result in call to `bindings::promise_reject_callback` adding
      // the promise to pending promise rejection table - meaning JsRuntime will return
      // error on next poll().
      //
      // This situation is not desirable as we want to manually return error at the
      // end of this function to handle it further. It means we need to manually
      // remove this promise from pending promise rejection table.
      //
      // For more details see:
      // https://github.com/denoland/deno/issues/4908
      // https://v8.dev/features/top-level-await#module-execution-order
      let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context1);
      let module = v8::Local::new(scope, &module_handle);
      let maybe_value = module.evaluate(scope);

      // Update status after evaluating.
      let status = module.get_status();

      if let Some(value) = maybe_value {
        assert!(status == v8::ModuleStatus::Evaluated || status == v8::ModuleStatus::Errored);
        let promise = v8::Local::<v8::Promise>::try_from(value)
          .expect("Expected to get promise as module evaluation result");
        let promise_global = v8::Global::new(scope, promise);
        let mut state = state_rc.borrow_mut();
        state.pending_promise_exceptions.remove(&promise_global);
        let promise_global = v8::Global::new(scope, promise);
        let module_global = v8::Global::new(scope, module);

        let dyn_import_mod_evaluate = DynImportModEvaluate {
          module_id: id,
          promise: promise_global,
          module: module_global,
        };

        state
          .pending_dyn_mod_evaluate
          .insert(load_id, dyn_import_mod_evaluate);
      } else {
        assert!(status == v8::ModuleStatus::Errored);
      }
    }

    if status == v8::ModuleStatus::Evaluated {
      self.dyn_import_done(load_id, id);
    }

    Ok(())
  }

  /// Evaluates an already instantiated ES module.
  ///
  /// `AnyError` can be downcast to a type that exposes additional information
  /// about the V8 exception. By default this type is `JsError`, however it may
  /// be a different type if `RuntimeOptions::js_error_create_fn` has been set.
  fn mod_evaluate_inner(&mut self, id: ModuleId) -> mpsc::Receiver<Result<(), AnyError>> {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();

    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let module = state_rc
      .borrow()
      .modules
      .get_handle(id)
      .map(|handle| v8::Local::new(scope, handle))
      .expect("ModuleInfo not found");
    let mut status = module.get_status();

    let (sender, receiver) = mpsc::channel(1);

    if status == v8::ModuleStatus::Instantiated {
      // IMPORTANT: Top-level-await is enabled, which means that return value
      // of module evaluation is a promise.
      //
      // Because that promise is created internally by V8, when error occurs during
      // module evaluation the promise is rejected, and since the promise has no rejection
      // handler it will result in call to `bindings::promise_reject_callback` adding
      // the promise to pending promise rejection table - meaning JsRuntime will return
      // error on next poll().
      //
      // This situation is not desirable as we want to manually return error at the
      // end of this function to handle it further. It means we need to manually
      // remove this promise from pending promise rejection table.
      //
      // For more details see:
      // https://github.com/denoland/deno/issues/4908
      // https://v8.dev/features/top-level-await#module-execution-order
      let maybe_value = module.evaluate(scope);

      // Update status after evaluating.
      status = module.get_status();

      if let Some(value) = maybe_value {
        assert!(status == v8::ModuleStatus::Evaluated || status == v8::ModuleStatus::Errored);
        let promise = v8::Local::<v8::Promise>::try_from(value)
          .expect("Expected to get promise as module evaluation result");
        let promise_global = v8::Global::new(scope, promise);
        let mut state = state_rc.borrow_mut();
        state.pending_promise_exceptions.remove(&promise_global);
        let promise_global = v8::Global::new(scope, promise);
        assert!(
          state.pending_mod_evaluate.is_none(),
          "There is already pending top level module evaluation"
        );

        state.pending_mod_evaluate = Some(ModEvaluate {
          promise: promise_global,
          sender,
        });
        scope.perform_microtask_checkpoint();
      } else {
        assert!(status == v8::ModuleStatus::Errored);
      }
    }

    receiver
  }

  pub async fn mod_evaluate(&mut self, id: ModuleId) -> Result<(), AnyError> {
    let mut receiver = self.mod_evaluate_inner(id);

    poll_fn(|cx| {
      if let Poll::Ready(maybe_result) = receiver.poll_next_unpin(cx) {
        debug!("received module evaluate {:#?}", maybe_result);
        // If `None` is returned it means that runtime was destroyed before
        // evaluation was complete. This can happen in Web Worker when `self.close()`
        // is called at top level.
        let result = maybe_result.unwrap_or(Ok(()));
        return Poll::Ready(result);
      }
      let _r = self.poll_event_loop(cx)?;
      Poll::Pending
    })
    .await
  }

  fn dyn_import_error(&mut self, id: ModuleLoadId, err: AnyError) {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();

    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let resolver_handle = state_rc
      .borrow_mut()
      .dyn_import_map
      .remove(&id)
      .expect("Invalid dyn import id");
    let resolver = resolver_handle.get(scope);

    let exception = err
      .downcast_ref::<ErrWithV8Handle>()
      .map(|err| err.get_handle(scope))
      .unwrap_or_else(|| {
        let message = err.to_string();
        let message = v8::String::new(scope, &message).unwrap();
        v8::Exception::type_error(scope, message)
      });

    resolver.reject(scope, exception).unwrap();
    scope.perform_microtask_checkpoint();
  }

  fn dyn_import_done(&mut self, id: ModuleLoadId, mod_id: ModuleId) {
    let state_rc = Self::state(self.v8_isolate());
    let context = self.global_context();

    debug!("dyn_import_done {} {:?}", id, mod_id);
    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let resolver_handle = state_rc
      .borrow_mut()
      .dyn_import_map
      .remove(&id)
      .expect("Invalid dyn import id");
    let resolver = resolver_handle.get(scope);

    let module = {
      let state = state_rc.borrow();
      state
        .modules
        .get_handle(mod_id)
        .map(|handle| v8::Local::new(scope, handle))
        .expect("Dyn import module info not found")
    };
    // Resolution success
    assert_eq!(module.get_status(), v8::ModuleStatus::Evaluated);

    let module_namespace = module.get_module_namespace();
    resolver.resolve(scope, module_namespace).unwrap();
    scope.perform_microtask_checkpoint();
  }

  fn prepare_dyn_imports(&mut self, cx: &mut Context) -> Poll<Result<(), AnyError>> {
    let state_rc = Self::state(self.v8_isolate());

    if state_rc.borrow().preparing_dyn_imports.is_empty() {
      return Poll::Ready(Ok(()));
    }

    loop {
      let r = {
        let mut state = state_rc.borrow_mut();
        state.preparing_dyn_imports.poll_next_unpin(cx)
      };
      match r {
        Poll::Pending | Poll::Ready(None) => {
          // There are no active dynamic import loaders, or none are ready.
          return Poll::Ready(Ok(()));
        }
        Poll::Ready(Some(prepare_poll)) => {
          let dyn_import_id = prepare_poll.0;
          let prepare_result = prepare_poll.1;

          match prepare_result {
            Ok(load) => {
              let state = state_rc.borrow_mut();
              state.pending_dyn_imports.push(load.into_future());
            }
            Err(err) => {
              self.dyn_import_error(dyn_import_id, err);
            }
          }
        }
      }
    }
  }

  fn poll_dyn_imports(&mut self, cx: &mut Context) -> Poll<Result<(), AnyError>> {
    let state_rc = Self::state(self.v8_isolate());

    if state_rc.borrow().pending_dyn_imports.is_empty() {
      return Poll::Ready(Ok(()));
    }

    loop {
      let poll_result = {
        let mut state = state_rc.borrow_mut();
        state.pending_dyn_imports.poll_next_unpin(cx)
      };

      match poll_result {
        Poll::Pending | Poll::Ready(None) => {
          // There are no active dynamic import loaders, or none are ready.
          return Poll::Ready(Ok(()));
        }
        Poll::Ready(Some(load_stream_poll)) => {
          let maybe_result = load_stream_poll.0;
          let mut load = load_stream_poll.1;
          let dyn_import_id = load.id;

          if let Some(load_stream_result) = maybe_result {
            match load_stream_result {
              Ok(info) => {
                // A module (not necessarily the one dynamically imported) has been
                // fetched. Create and register it, and if successful, poll for the
                // next recursive-load event related to this dynamic import.
                match self.register_during_load(info, &mut load) {
                  Ok(()) => {
                    // Keep importing until it's fully drained
                    let state = state_rc.borrow_mut();
                    state.pending_dyn_imports.push(load.into_future());
                  }
                  Err(err) => self.dyn_import_error(dyn_import_id, err),
                }
              }
              Err(err) => {
                // A non-javascript error occurred; this could be due to a an invalid
                // module specifier, or a problem with the source map, or a failure
                // to fetch the module source code.
                self.dyn_import_error(dyn_import_id, err)
              }
            }
          } else {
            // The top-level module from a dynamic import has been instantiated.
            // Load is done.
            let module_id = load.root_module_id.unwrap();
            self.mod_instantiate(module_id)?;
            self.dyn_mod_evaluate(dyn_import_id, module_id)?;
          }
        }
      }
    }
  }

  /// "core" runs V8 with "--harmony-top-level-await"
  /// flag on - it means that each module evaluation returns a promise
  /// from V8.
  ///
  /// This promise resolves after all dependent modules have also
  /// resolved. Each dependent module may perform calls to "import()" and APIs
  /// using async ops will add futures to the runtime's event loop.
  /// It means that the promise returned from module evaluation will
  /// resolve only after all futures in the event loop are done.
  ///
  /// Thus during turn of event loop we need to check if V8 has
  /// resolved or rejected the promise. If the promise is still pending
  /// then another turn of event loop must be performed.
  fn evaluate_pending_module(&mut self) {
    let state_rc = Self::state(self.v8_isolate());

    let context = self.global_context();
    {
      let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

      let mut state = state_rc.borrow_mut();

      if let Some(module_evaluation) = state.pending_mod_evaluate.as_ref() {
        let promise = module_evaluation.promise.get(scope);
        let mut sender = module_evaluation.sender.clone();
        let promise_state = promise.state();

        match promise_state {
          v8::PromiseState::Pending => {
            // pass, poll_event_loop will decide if
            // runtime would be woken soon
          }
          v8::PromiseState::Fulfilled => {
            state.pending_mod_evaluate.take();
            scope.perform_microtask_checkpoint();
            sender.try_send(Ok(())).unwrap();
          }
          v8::PromiseState::Rejected => {
            let exception = promise.result(scope);
            state.pending_mod_evaluate.take();
            drop(state);
            scope.perform_microtask_checkpoint();
            let err1 = exception_to_err_result::<()>(scope, exception, false)
              .map_err(|err| attach_handle_to_error(scope, err, exception))
              .unwrap_err();
            sender.try_send(Err(err1)).unwrap();
          }
        }
      }
    };
  }

  fn evaluate_dyn_imports(&mut self) {
    let state_rc = Self::state(self.v8_isolate());

    loop {
      let context = self.global_context();
      let maybe_result = {
        let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

        let mut state = state_rc.borrow_mut();
        if let Some(&dyn_import_id) = state.pending_dyn_mod_evaluate.keys().next() {
          let handle = state
            .pending_dyn_mod_evaluate
            .remove(&dyn_import_id)
            .unwrap();
          drop(state);

          let module_id = handle.module_id;
          let promise = handle.promise.get(scope);
          let _module = handle.module.get(scope);

          let promise_state = promise.state();

          match promise_state {
            v8::PromiseState::Pending => {
              state_rc
                .borrow_mut()
                .pending_dyn_mod_evaluate
                .insert(dyn_import_id, handle);
              None
            }
            v8::PromiseState::Fulfilled => Some(Ok((dyn_import_id, module_id))),
            v8::PromiseState::Rejected => {
              let exception = promise.result(scope);
              let err1 = exception_to_err_result::<()>(scope, exception, false)
                .map_err(|err| attach_handle_to_error(scope, err, exception))
                .unwrap_err();
              Some(Err((dyn_import_id, err1)))
            }
          }
        } else {
          None
        }
      };

      if let Some(result) = maybe_result {
        match result {
          Ok((dyn_import_id, module_id)) => {
            self.dyn_import_done(dyn_import_id, module_id);
          }
          Err((dyn_import_id, err1)) => {
            self.dyn_import_error(dyn_import_id, err1);
          }
        }
      } else {
        break;
      }
    }
  }

  fn register_during_load(
    &mut self,
    info: ModuleSource,
    load: &mut RecursiveModuleLoad,
  ) -> Result<(), AnyError> {
    let ModuleSource {
      code,
      module_url_specified,
      module_url_found,
    } = info;

    let is_main = load.state == LoadState::LoadingRoot && !load.is_dynamic_import();
    let referrer_specifier = ModuleSpecifier::resolve_url(&module_url_found).unwrap();

    let state_rc = Self::state(self.v8_isolate());
    // #A There are 3 cases to handle at this moment:
    // 1. Source code resolved result have the same module name as requested
    //    and is not yet registered
    //     -> register
    // 2. Source code resolved result have a different name as requested:
    //   2a. The module with resolved module name has been registered
    //     -> alias
    //   2b. The module with resolved module name has not yet been registered
    //     -> register & alias

    // If necessary, register an alias.
    if module_url_specified != module_url_found {
      let mut state = state_rc.borrow_mut();
      state
        .modules
        .alias(&module_url_specified, &module_url_found);
    }

    let maybe_mod_id = {
      let state = state_rc.borrow();
      state.modules.get_id(&module_url_found)
    };

    let module_id = match maybe_mod_id {
      Some(id) => {
        // Module has already been registered.
        debug!(
          "Already-registered module fetched again: {}",
          module_url_found
        );
        id
      }
      // Module not registered yet, do it now.
      None => self.mod_new(is_main, &module_url_found, &code)?,
    };

    // Now we must iterate over all imports of the module and load them.
    let imports = {
      let state_rc = Self::state(self.v8_isolate());
      let state = state_rc.borrow();
      state.modules.get_children(module_id).unwrap().clone()
    };

    for module_specifier in imports {
      let is_registered = {
        let state_rc = Self::state(self.v8_isolate());
        let state = state_rc.borrow();
        state.modules.is_registered(&module_specifier)
      };
      if !is_registered {
        load.add_import(module_specifier.to_owned(), referrer_specifier.clone());
      }
    }

    // If we just finished loading the root module, store the root module id.
    if load.state == LoadState::LoadingRoot {
      load.root_module_id = Some(module_id);
      load.state = LoadState::LoadingImports;
    }

    if load.pending.is_empty() {
      load.state = LoadState::Done;
    }

    Ok(())
  }

  /// Asynchronously load specified module and all of its dependencies
  ///
  /// User must call `JsRuntime::mod_evaluate` with returned `ModuleId`
  /// manually after load is finished.
  pub async fn load_module(
    &mut self,
    specifier: &ModuleSpecifier,
    code: Option<String>,
  ) -> Result<ModuleId, AnyError> {
    let loader = {
      let state_rc = Self::state(self.v8_isolate());
      let state = state_rc.borrow();
      state.loader.clone()
    };

    let load = RecursiveModuleLoad::main(&specifier.to_string(), code, loader);
    let (_load_id, prepare_result) = load.prepare().await;

    let mut load = prepare_result?;

    while let Some(info_result) = load.next().await {
      let info = info_result?;
      self.register_during_load(info, &mut load)?;
    }

    let root_id = load.root_module_id.expect("Root module id empty");
    self.mod_instantiate(root_id).map(|_| root_id)
  }

  fn check_promise_exceptions(&mut self) -> Result<(), AnyError> {
    let state_rc = Self::state(self.v8_isolate());
    let mut state = state_rc.borrow_mut();

    if state.pending_promise_exceptions.is_empty() {
      return Ok(());
    }

    let key = {
      state
        .pending_promise_exceptions
        .keys()
        .next()
        .unwrap()
        .clone()
    };
    let handle = state.pending_promise_exceptions.remove(&key).unwrap();
    drop(state);

    let context = self.global_context();
    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);

    let exception = v8::Local::new(scope, handle);
    exception_to_err_result(scope, exception, true)
  }

  fn drain_macrotasks(&mut self) -> Result<(), AnyError> {
    let js_macrotask_cb_handle = match &Self::state(self.v8_isolate()).borrow().js_macrotask_cb {
      Some(handle) => handle.clone(),
      None => return Ok(()),
    };

    let context = self.global_context();
    let scope = &mut v8::HandleScope::with_context(self.v8_isolate(), context);
    let context = scope.get_current_context();
    let global: v8::Local<v8::Value> = context.global(scope).into();
    let js_macrotask_cb = js_macrotask_cb_handle.get(scope);

    // Repeatedly invoke macrotask callback until it returns true (done),
    // such that ready microtasks would be automatically run before
    // next macrotask is processed.
    let tc_scope = &mut v8::TryCatch::new(scope);

    loop {
      let is_done = js_macrotask_cb.call(tc_scope, global, &[]);

      if let Some(exception) = tc_scope.exception() {
        return exception_to_err_result(tc_scope, exception, false);
      }

      let is_done = is_done.unwrap();
      if is_done.is_true() {
        break;
      }
    }

    Ok(())
  }
}

#[cfg(test)]
pub mod tests {
  use super::*;
  use crate::modules::ModuleSourceFuture;
  use futures::future::lazy;
  use futures::FutureExt;
  use std::io;
  use std::ops::FnOnce;
  use std::rc::Rc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Arc;

  pub fn run_in_task<F>(f: F)
  where
    F: FnOnce(&mut Context) + Send + 'static,
  {
    futures::executor::block_on(lazy(move |cx| f(cx)));
  }

  #[test]
  fn syntax_error() {
    let mut runtime = JsRuntime::new(Default::default());
    let src = "hocuspocus(";
    let r = runtime.execute("i.js", src);
    let e = r.unwrap_err();
    let js_error = e.downcast::<JsError>().unwrap();
    assert_eq!(js_error.end_column, Some(11));
  }

  #[test]
  fn will_snapshot() {
    let snapshot = {
      let mut runtime = JsRuntime::new(RuntimeOptions {
        will_snapshot: true,
        ..Default::default()
      });
      runtime.execute("a.js", "a = 1 + 2").unwrap();
      runtime.snapshot()
    };

    let snapshot = Snapshot::JustCreated(snapshot);
    let mut runtime2 = JsRuntime::new(RuntimeOptions {
      startup_snapshot: Some(snapshot),
      ..Default::default()
    });
    runtime2
      .execute("check.js", "if (a != 3) throw Error('x')")
      .unwrap();
  }

  #[test]
  fn test_from_boxed_snapshot() {
    let snapshot = {
      let mut runtime = JsRuntime::new(RuntimeOptions {
        will_snapshot: true,
        ..Default::default()
      });
      runtime.execute("a.js", "a = 1 + 2").unwrap();
      let snap: &[u8] = &*runtime.snapshot();
      Vec::from(snap).into_boxed_slice()
    };

    let snapshot = Snapshot::Boxed(snapshot);
    let mut runtime2 = JsRuntime::new(RuntimeOptions {
      startup_snapshot: Some(snapshot),
      ..Default::default()
    });
    runtime2
      .execute("check.js", "if (a != 3) throw Error('x')")
      .unwrap();
  }

  #[test]
  fn test_heap_limits() {
    let create_params = v8::Isolate::create_params().heap_limits(0, 20 * 1024);
    let mut runtime = JsRuntime::new(RuntimeOptions {
      create_params: Some(create_params),
      ..Default::default()
    });
    let cb_handle = runtime.v8_isolate().thread_safe_handle();

    let callback_invoke_count = Rc::new(AtomicUsize::default());
    let inner_invoke_count = Rc::clone(&callback_invoke_count);

    runtime.add_near_heap_limit_callback(move |current_limit, _initial_limit| {
      inner_invoke_count.fetch_add(1, Ordering::SeqCst);
      cb_handle.terminate_execution();
      current_limit * 2
    });
    let err = runtime
      .execute(
        "script name",
        r#"let s = ""; while(true) { s += "Hello"; }"#,
      )
      .expect_err("script should fail");
    assert_eq!(
      "Uncaught Error: execution terminated",
      err.downcast::<JsError>().unwrap().message
    );
    assert!(callback_invoke_count.load(Ordering::SeqCst) > 0)
  }

  #[test]
  fn test_heap_limit_cb_remove() {
    let mut runtime = JsRuntime::new(Default::default());

    runtime.add_near_heap_limit_callback(|current_limit, _initial_limit| current_limit * 2);
    runtime.remove_near_heap_limit_callback(20 * 1024);
    assert!(runtime.allocations.near_heap_limit_callback_data.is_none());
  }

  #[test]
  fn test_heap_limit_cb_multiple() {
    let create_params = v8::Isolate::create_params().heap_limits(0, 20 * 1024);
    let mut runtime = JsRuntime::new(RuntimeOptions {
      create_params: Some(create_params),
      ..Default::default()
    });
    let cb_handle = runtime.v8_isolate().thread_safe_handle();

    let callback_invoke_count_first = Rc::new(AtomicUsize::default());
    let inner_invoke_count_first = Rc::clone(&callback_invoke_count_first);
    runtime.add_near_heap_limit_callback(move |current_limit, _initial_limit| {
      inner_invoke_count_first.fetch_add(1, Ordering::SeqCst);
      current_limit * 2
    });

    let callback_invoke_count_second = Rc::new(AtomicUsize::default());
    let inner_invoke_count_second = Rc::clone(&callback_invoke_count_second);
    runtime.add_near_heap_limit_callback(move |current_limit, _initial_limit| {
      inner_invoke_count_second.fetch_add(1, Ordering::SeqCst);
      cb_handle.terminate_execution();
      current_limit * 2
    });

    let err = runtime
      .execute(
        "script name",
        r#"let s = ""; while(true) { s += "Hello"; }"#,
      )
      .expect_err("script should fail");
    assert_eq!(
      "Uncaught Error: execution terminated",
      err.downcast::<JsError>().unwrap().message
    );
    assert_eq!(0, callback_invoke_count_first.load(Ordering::SeqCst));
    assert!(callback_invoke_count_second.load(Ordering::SeqCst) > 0);
  }

  #[test]
  fn dyn_import_err() {
    #[derive(Clone, Default)]
    struct DynImportErrLoader {
      pub count: Arc<AtomicUsize>,
    }

    impl ModuleLoader for DynImportErrLoader {
      fn resolve(
        &self,
        specifier: &str,
        referrer: &str,
        _is_main: bool,
      ) -> Result<ModuleSpecifier, AnyError> {
        self.count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(specifier, "/foo.js");
        assert_eq!(referrer, "file:///dyn_import2.js");
        let s = ModuleSpecifier::resolve_import(specifier, referrer).unwrap();
        Ok(s)
      }

      fn load(
        &self,
        _module_specifier: &ModuleSpecifier,
        _maybe_referrer: Option<ModuleSpecifier>,
        _is_dyn_import: bool,
      ) -> Pin<Box<ModuleSourceFuture>> {
        async { Err(io::Error::from(io::ErrorKind::NotFound).into()) }.boxed()
      }
    }

    // Test an erroneous dynamic import where the specified module isn't found.
    run_in_task(|cx| {
      let loader = Rc::new(DynImportErrLoader::default());
      let count = loader.count.clone();
      let mut runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(loader),
        ..Default::default()
      });

      runtime
        .execute(
          "file:///dyn_import2.js",
          r#"
        (async () => {
          await import("/foo.js");
        })();
        "#,
        )
        .unwrap();

      assert_eq!(count.load(Ordering::Relaxed), 0);
      // We should get an error here.
      let result = runtime.poll_event_loop(cx);
      if let Poll::Ready(Ok(_)) = result {
        unreachable!();
      }
      assert_eq!(count.load(Ordering::Relaxed), 2);
    })
  }

  #[derive(Clone, Default)]
  struct DynImportOkLoader {
    pub prepare_load_count: Arc<AtomicUsize>,
    pub resolve_count: Arc<AtomicUsize>,
    pub load_count: Arc<AtomicUsize>,
  }

  impl ModuleLoader for DynImportOkLoader {
    fn resolve(
      &self,
      specifier: &str,
      referrer: &str,
      _is_main: bool,
    ) -> Result<ModuleSpecifier, AnyError> {
      let c = self.resolve_count.fetch_add(1, Ordering::Relaxed);
      assert!(c < 4);
      assert_eq!(specifier, "./b.js");
      assert_eq!(referrer, "file:///dyn_import3.js");
      let s = ModuleSpecifier::resolve_import(specifier, referrer).unwrap();
      Ok(s)
    }

    fn load(
      &self,
      specifier: &ModuleSpecifier,
      _maybe_referrer: Option<ModuleSpecifier>,
      _is_dyn_import: bool,
    ) -> Pin<Box<ModuleSourceFuture>> {
      self.load_count.fetch_add(1, Ordering::Relaxed);
      let info = ModuleSource {
        module_url_specified: specifier.to_string(),
        module_url_found: specifier.to_string(),
        code: "export function b() { return 'b' }".to_owned(),
      };
      async move { Ok(info) }.boxed()
    }

    fn prepare_load(
      &self,
      _load_id: ModuleLoadId,
      _module_specifier: &ModuleSpecifier,
      _maybe_referrer: Option<String>,
      _is_dyn_import: bool,
    ) -> Pin<Box<dyn futures::Future<Output = Result<(), AnyError>>>> {
      self.prepare_load_count.fetch_add(1, Ordering::Relaxed);
      async { Ok(()) }.boxed_local()
    }
  }

  #[test]
  fn dyn_import_ok() {
    run_in_task(|cx| {
      let loader = Rc::new(DynImportOkLoader::default());
      let prepare_load_count = loader.prepare_load_count.clone();
      let resolve_count = loader.resolve_count.clone();
      let load_count = loader.load_count.clone();
      let mut runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(loader),
        ..Default::default()
      });

      // Dynamically import mod_b
      runtime
        .execute(
          "file:///dyn_import3.js",
          r#"
          (async () => {
            let mod = await import("./b.js");
            if (mod.b() !== 'b') {
              throw Error("bad1");
            }
            // And again!
            mod = await import("./b.js");
            if (mod.b() !== 'b') {
              throw Error("bad2");
            }
          })();
          "#,
        )
        .unwrap();

      // First poll runs `prepare_load` hook.
      assert!(matches!(runtime.poll_event_loop(cx), Poll::Pending));
      assert_eq!(prepare_load_count.load(Ordering::Relaxed), 1);

      // Second poll actually loads modules into the isolate.
      assert!(matches!(runtime.poll_event_loop(cx), Poll::Ready(Ok(_))));
      assert_eq!(resolve_count.load(Ordering::Relaxed), 4);
      assert_eq!(load_count.load(Ordering::Relaxed), 2);
      assert!(matches!(runtime.poll_event_loop(cx), Poll::Ready(Ok(_))));
      assert_eq!(resolve_count.load(Ordering::Relaxed), 4);
      assert_eq!(load_count.load(Ordering::Relaxed), 2);
    })
  }

  #[test]
  fn dyn_import_borrow_mut_error() {
    // https://github.com/denoland/deno/issues/6054
    run_in_task(|cx| {
      let loader = Rc::new(DynImportOkLoader::default());
      let prepare_load_count = loader.prepare_load_count.clone();
      let mut runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(loader),
        ..Default::default()
      });
      runtime
        .execute(
          "file:///dyn_import3.js",
          r#"
          (async () => {
            let mod = await import("./b.js");
            if (mod.b() !== 'b') {
              throw Error("bad");
            }
            // Now do any op
            Deno.core.ops();
          })();
          "#,
        )
        .unwrap();
      // First poll runs `prepare_load` hook.
      let _ = runtime.poll_event_loop(cx);
      assert_eq!(prepare_load_count.load(Ordering::Relaxed), 1);
      // Second poll triggers error
      let _ = runtime.poll_event_loop(cx);
    })
  }

  #[test]
  fn es_snapshot() {
    #[derive(Default)]
    struct ModsLoader;

    impl ModuleLoader for ModsLoader {
      fn resolve(
        &self,
        specifier: &str,
        referrer: &str,
        _is_main: bool,
      ) -> Result<ModuleSpecifier, AnyError> {
        assert_eq!(specifier, "file:///main.js");
        assert_eq!(referrer, ".");
        let s = ModuleSpecifier::resolve_import(specifier, referrer).unwrap();
        Ok(s)
      }

      fn load(
        &self,
        _module_specifier: &ModuleSpecifier,
        _maybe_referrer: Option<ModuleSpecifier>,
        _is_dyn_import: bool,
      ) -> Pin<Box<ModuleSourceFuture>> {
        unreachable!()
      }
    }

    let loader = std::rc::Rc::new(ModsLoader::default());
    let mut runtime = JsRuntime::new(RuntimeOptions {
      module_loader: Some(loader),
      will_snapshot: true,
      ..Default::default()
    });

    let specifier = ModuleSpecifier::resolve_url("file:///main.js").unwrap();
    let source_code = "Deno.core.print('hello\\n')".to_string();

    let module_id =
      futures::executor::block_on(runtime.load_module(&specifier, Some(source_code))).unwrap();

    futures::executor::block_on(runtime.mod_evaluate(module_id)).unwrap();

    let _snapshot = runtime.snapshot();
  }

  #[test]
  fn test_error_without_stack() {
    let mut runtime = JsRuntime::new(RuntimeOptions::default());
    // SyntaxError
    let result = runtime.execute(
      "error_without_stack.js",
      r#"
function main() {
  console.log("asdf);
}

main();
"#,
    );
    let expected_error = r#"Uncaught SyntaxError: Invalid or unexpected token
    at error_without_stack.js:3:14"#;
    assert_eq!(result.unwrap_err().to_string(), expected_error);
  }

  #[test]
  fn test_error_stack() {
    let mut runtime = JsRuntime::new(RuntimeOptions::default());
    let result = runtime.execute(
      "error_stack.js",
      r#"
function assert(cond) {
  if (!cond) {
    throw Error("assert");
  }
}

function main() {
  assert(false);
}

main();
        "#,
    );
    let expected_error = r#"Error: assert
    at assert (error_stack.js:4:11)
    at main (error_stack.js:9:3)
    at error_stack.js:12:1"#;
    assert_eq!(result.unwrap_err().to_string(), expected_error);
  }

  #[test]
  fn test_error_async_stack() {
    run_in_task(|cx| {
      let mut runtime = JsRuntime::new(RuntimeOptions::default());
      runtime
        .execute(
          "error_async_stack.js",
          r#"
(async () => {
  const p = (async () => {
    await Promise.resolve().then(() => {
      throw new Error("async");
    });
  })();

  try {
    await p;
  } catch (error) {
    console.log(error.stack);
    throw error;
  }
})();"#,
        )
        .unwrap();
      let expected_error = r#"Error: async
    at error_async_stack.js:5:13
    at async error_async_stack.js:4:5
    at async error_async_stack.js:10:5"#;

      match runtime.poll_event_loop(cx) {
        Poll::Ready(Err(e)) => {
          assert_eq!(e.to_string(), expected_error);
        }
        _ => panic!(),
      };
    })
  }
}
