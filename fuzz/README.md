# Fuzz targets

Requires nightly and `cargo install cargo-fuzz`.

```sh
cd fuzz
cargo +nightly fuzz run policy_parse -- -max_total_time=60
```

Targets:

- `policy_parse`: parse → merge → resolve → compile → decide. Planned: `proxy_http` (Phase 2), `scan_rules` (Phase 3), `mcp_frame` (Phase 4).
