use paperclip::v2::{
    self,
    codegen::{DefaultEmitter, Emitter, EmitterState},
    models::{ResolvableApi, DefaultSchema},
};

use std::env;
use std::fs::File;

fn main() {
    let fd = File::open("./src/lapi_swagger.yaml").expect("schema?");
    let raw: ResolvableApi<DefaultSchema> = v2::from_reader(fd).expect("deserializing spec");
    let schema = raw.resolve().expect("resolution");

    let out_dir = env::var("OUT_DIR").unwrap();
    let mut state = EmitterState::default();
    // set prefix for using generated code inside `codegen` module (see main.rs).
    state.mod_prefix = "crate::codegen::";
    state.working_dir = out_dir.into();

    let emitter = DefaultEmitter::from(state);
    emitter.generate(&schema).expect("codegen");
}
