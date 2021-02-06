use core::JsRuntime;
use core::ModuleSpecifier;
use core::RuntimeOptions;
use futures;
use rusty_v8 as v8;
use std::path::Path;
use std::convert::TryFrom;

fn add(
  scope: &mut v8::HandleScope,
  args: v8::FunctionCallbackArguments,
  mut rv: v8::ReturnValue,
) {
  let first = match v8::Local::<v8::Number>::try_from(args.get(0)) {
    Ok(s) => s.value(),
    Err(_) => {
      let msg = v8::String::new(scope, "Invalid 1st argument, expected number").unwrap();
      let exception = v8::Exception::type_error(scope, msg);
      scope.throw_exception(exception);
      return;
    }
  };
  let second = match v8::Local::<v8::Number>::try_from(args.get(1)) {
    Ok(s) => s.value(),
    Err(_) => {
      let msg = v8::String::new(scope, "Invalid 2nd argument, expected number").unwrap();
      let exception = v8::Exception::type_error(scope, msg);
      scope.throw_exception(exception);
      return;
    }
  };

  let result = v8::Number::new(scope, first + second);
  rv.set(result.into())
}


fn main() {
  let mut runtime = JsRuntime::new(RuntimeOptions {
    module_loader: Some(std::rc::Rc::new(core::FsModuleLoader)),
    ..Default::default()
  });

  runtime.register_synthetic_module(
    "file:///home/cold/engine_rs/deno/examples/core",
    vec!["a", "b"],
    |context: v8::Local<'static, v8::Context>,
     module: v8::Local<v8::Module>|
     -> Option<v8::Local<'static, v8::Value>> {
      let scope = &mut unsafe { v8::CallbackScope::new(context) };

      {
        let name = v8::String::new(scope, "a").unwrap();
        let value = v8::Number::new(scope, 4.0).into();
        module
          .set_synthetic_module_export(scope, name, value)
          .unwrap();
      }

      {
        let name = v8::String::new(scope, "b").unwrap();
        let value = v8::Number::new(scope, 4.0).into();
        module
          .set_synthetic_module_export(scope, name, value)
          .unwrap();
      }

      Some(v8::undefined(scope).into())
    },
  );

  runtime.register_synthetic_module(
    "file:///home/cold/engine_rs/deno/examples/math",
    vec!["default"],
    |context: v8::Local<'static, v8::Context>,
     module: v8::Local<v8::Module>|
     -> Option<v8::Local<'static, v8::Value>> {
      let scope = &mut unsafe { v8::CallbackScope::new(context) };

      {
        let name = v8::String::new(scope, "default").unwrap();

        let add_tmpl = v8::FunctionTemplate::new(scope, add);
        let add_val = add_tmpl.get_function(scope).unwrap();

        module
          .set_synthetic_module_export(scope, name, add_val.into())
          .unwrap();
      }

      Some(v8::undefined(scope).into())
    },
  );

  let js_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/index.js");
  let main_module = ModuleSpecifier::resolve_url_or_path(&js_path.to_string_lossy())
    .expect("Module path not found");
  let mod_id =
    futures::executor::block_on(runtime.load_module(&main_module, None)).expect("Failed to load");
  futures::executor::block_on(runtime.mod_evaluate(mod_id)).unwrap();
}
