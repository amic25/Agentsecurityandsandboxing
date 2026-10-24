//! Fuzz the whole policy pipeline: parse, merge over defaults, resolve,
//! compile, decide. Any panic is a bug.
#![no_main]

use std::path::{Path, PathBuf};

use agentkeep_policy::decide::{Compiled, Request};
use agentkeep_policy::discover::defaults_layer;
use agentkeep_policy::merge::{merge, Layer, Source};
use agentkeep_policy::resolved::{Context, Policy};
use agentkeep_policy::parse_str;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(file) = parse_str(text, "fuzz") else { return };
    let layers = [
        defaults_layer(),
        Layer { source: Source::Project(PathBuf::from("/p/agentkeep.toml")), base_dir: Some(PathBuf::from("/p")), file },
    ];
    let (merged, _warnings) = merge(&layers);
    let ctx = Context { home: PathBuf::from("/home/u"), base_dir: PathBuf::from("/p") };
    let Ok(policy) = Policy::resolve(&merged, &ctx) else { return };
    let compiled = Compiled::new(&policy);
    let argv = vec!["git".to_string(), "push".to_string()];
    let _ = compiled.decide(&Request::Command { argv: &argv });
    let _ = compiled.decide(&Request::Domain { host: "api.example.com", port: 443 });
    let _ = compiled.decide(&Request::Path { path: Path::new("/home/u/.ssh/id_ed25519"), write: false });
    let _ = compiled.decide(&Request::Env { name: "HOME" });
});
