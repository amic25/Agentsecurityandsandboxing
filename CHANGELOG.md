# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Phase 0: Cargo workspace with the nine planned crates, CLI command surface
  (`run`, `policy`, `mcp-gateway`, `scan`, `log`, `report`, `approve`,
  `version`), cross-platform CI, cargo-deny and cargo-audit, OpenSSF Scorecard,
  DCO check, pinned GitHub Actions, community files and the threat model.
  No sandboxing is implemented yet; every command except `version` exits with
  status 70.

[Unreleased]: https://github.com/amic25/Agentsecurityandsandboxing/commits/main
