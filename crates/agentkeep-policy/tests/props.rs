//! Property tests for the policy engine.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use agentkeep_policy::decide::{Compiled, Decision, Request};
use agentkeep_policy::merge::{merge, Layer, Source};
use agentkeep_policy::resolved::{Context, Policy};
use agentkeep_policy::schema::{CommandsSection, FilesystemSection, NetworkSection, PolicyFile};
use agentkeep_policy::{defaults, parse_str};
use proptest::prelude::*;

fn ctx() -> Context {
    Context {
        home: PathBuf::from("/home/u"),
        base_dir: PathBuf::from("/home/u/proj"),
    }
}

fn layer(source: Source, file: PolicyFile) -> Layer {
    Layer {
        source,
        base_dir: Some(PathBuf::from("/home/u/proj")),
        file,
    }
}

fn defaults_file() -> PolicyFile {
    parse_str(defaults::DEFAULT_POLICY, "<defaults>").unwrap()
}

fn host() -> impl Strategy<Value = String> {
    "[a-z]([a-z0-9-]{0,6}[a-z0-9])?(\\.[a-z]([a-z0-9-]{0,6}[a-z0-9])?){1,3}"
}

fn host_pattern() -> impl Strategy<Value = String> {
    prop_oneof![host(), host().prop_map(|h| format!("*.{h}"))]
}

fn cmd_pattern() -> impl Strategy<Value = String> {
    "[a-z]{1,6}( [a-z*-]{1,6}){0,3}\\*?"
}

fn path_str() -> impl Strategy<Value = String> {
    "(~|/[a-z]{1,5})(/[a-z.]{1,6}){0,4}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Deny and hidden lists only ever grow when lower layers are followed by
    /// a non-project layer, whatever that layer contains.
    #[test]
    fn merge_never_shrinks_deny_or_hidden(
        extra_hidden in prop::collection::vec(path_str(), 0..4),
        extra_deny in prop::collection::vec(host_pattern(), 0..4),
        extra_cmd_deny in prop::collection::vec(cmd_pattern(), 0..4),
        unhide in prop::collection::vec(path_str(), 0..3),
    ) {
        let base = defaults_file();
        let base_hidden = base.filesystem.clone().unwrap().hidden;
        let base_net_deny = base.network.clone().unwrap().deny;
        let base_cmd_deny = base.commands.clone().unwrap().deny;

        let mut upper = PolicyFile { schema: Some(1), ..PolicyFile::default() };
        upper.filesystem = Some(FilesystemSection { hidden: extra_hidden.clone(), ..Default::default() });
        upper.network = Some(NetworkSection { deny: extra_deny.clone(), ..Default::default() });
        upper.commands = Some(CommandsSection { deny: extra_cmd_deny.clone(), ..Default::default() });
        // An override from a non-project layer must be ignored.
        upper.r#override = Some(agentkeep_policy::schema::OverrideSection {
            acknowledge: Some(true), unhide, ..Default::default()
        });

        let (merged, _warnings) = merge(&[
            layer(Source::Defaults, base),
            layer(Source::Global(PathBuf::from("/g")), upper),
        ]);
        let hidden = merged.filesystem.unwrap().hidden;
        let net_deny = merged.network.unwrap().deny;
        let cmd_deny = merged.commands.unwrap().deny;
        for h in base_hidden.iter().chain(extra_hidden.iter()) { prop_assert!(hidden.contains(h)); }
        for d in base_net_deny.iter().chain(extra_deny.iter()) { prop_assert!(net_deny.contains(d)); }
        for d in base_cmd_deny.iter().chain(extra_cmd_deny.iter()) { prop_assert!(cmd_deny.contains(d)); }
    }

    /// A host in `deny` is denied regardless of what `allow` and `ask` say.
    #[test]
    fn deny_beats_ask_beats_allow(h in host(), port in 1u16..) {
        let mk = |allow: Vec<String>, ask: Vec<String>, deny: Vec<String>| {
            let f = PolicyFile {
                schema: Some(1),
                network: Some(NetworkSection { allow, ask, deny, ..Default::default() }),
                ..PolicyFile::default()
            };
            Compiled::new(&Policy::resolve(&f, &ctx()).unwrap())
        };
        let req = Request::Domain { host: &h, port };
        let all = matches!(mk(vec![h.clone()], vec![h.clone()], vec![h.clone()]).decide(&req), Decision::Deny { .. });
        let no_deny = matches!(mk(vec![h.clone()], vec![h.clone()], vec![]).decide(&req), Decision::Ask { .. });
        let only_allow = matches!(mk(vec![h.clone()], vec![], vec![]).decide(&req), Decision::Allow { .. });
        let nothing = matches!(mk(vec![], vec![], vec![]).decide(&req), Decision::Deny { .. });
        prop_assert!(all, "deny must win");
        prop_assert!(no_deny, "ask must beat allow");
        prop_assert!(only_allow, "allow alone allows");
        prop_assert!(nothing, "default is deny");
    }

    /// Hidden paths are hidden even when a parent is read-write.
    #[test]
    fn hidden_beats_read_write(sub in "[a-z]{1,6}(/[a-z]{1,6}){0,3}") {
        let f = PolicyFile {
            schema: Some(1),
            filesystem: Some(FilesystemSection {
                read_write: vec!["~/data".into()],
                hidden: vec!["~/data/secret".into()],
                ..Default::default()
            }),
            ..PolicyFile::default()
        };
        let c = Compiled::new(&Policy::resolve(&f, &ctx()).unwrap());
        let p = PathBuf::from(format!("/home/u/data/secret/{sub}"));
        let hidden = matches!(c.decide(&Request::Path { path: &p, write: false }), Decision::Deny { .. });
        prop_assert!(hidden, "hidden path must be denied");
        let q = PathBuf::from(format!("/home/u/data/{sub}"));
        let writable = c.decide(&Request::Path { path: &q, write: true }).is_allow();
        prop_assert!(writable, "read_write path must be allowed");
    }

    /// Decisions are a pure function of (policy, request).
    #[test]
    fn decide_is_deterministic(argv in prop::collection::vec("[a-z/ .-]{1,8}", 1..5)) {
        let f = defaults_file();
        let c = Compiled::new(&Policy::resolve(&f, &ctx()).unwrap());
        let a = c.decide(&Request::Command { argv: &argv });
        let b = c.decide(&Request::Command { argv: &argv });
        prop_assert_eq!(a, b);
    }

    /// Serialising a file and parsing it back is lossless.
    #[test]
    fn toml_roundtrip(
        allow in prop::collection::vec(host_pattern(), 0..4),
        ro in prop::collection::vec(path_str(), 0..4),
        pids in prop::option::of(1u32..),
    ) {
        let f = PolicyFile {
            schema: Some(1),
            network: Some(NetworkSection { allow, ..Default::default() }),
            filesystem: Some(FilesystemSection { read_only: ro, ..Default::default() }),
            limits: Some(agentkeep_policy::schema::LimitsSection { pids, ..Default::default() }),
            ..PolicyFile::default()
        };
        let text = toml::to_string(&f).unwrap();
        let back = parse_str(&text, "rt").unwrap();
        prop_assert_eq!(f, back);
    }

    /// The parser never panics on arbitrary input.
    #[test]
    fn parser_never_panics(text in "\\PC{0,200}") {
        let _ = parse_str(&text, "fuzz");
    }
}
