//! `builtin: ci_agent_token_exposure`: a GitHub Actions job that lets
//! people outside the project steer an AI agent holding a token that can
//! write to the repository.
//!
//! A job is reported when all of these hold (SPEC section 5):
//!
//! 1. The workflow runs on an event that untrusted users control:
//!    `pull_request_target`, `issue_comment`, `issues`, `discussion`,
//!    `discussion_comment`, `pull_request_review_comment` or
//!    `pull_request_review`, with `on` in string, list or map form.
//! 2. The job has an agent step: `uses:` of a known agent action
//!    (`anthropics/claude-code-action`, `anthropics/claude-code-base-action`,
//!    `openai/codex-action`, `google-github-actions/run-gemini-cli`,
//!    `sst/opencode`) or of any repository whose name contains `claude`,
//!    `codex`, `gemini`, `copilot`, `opencode`, `aider`, `goose` or `cline`
//!    followed by `-action` or `-cli`; or a `run:` whose pipeline stages
//!    invoke `claude`, `codex`, `gemini`, `opencode`, `aider` or `goose`
//!    (`goose run|session|recipe`, so the database migration tool of the
//!    same name stays quiet), directly or through `npx`, `bunx`, `pnpm dlx`,
//!    `uvx` or `pipx run` of their packages.
//! 3. Untrusted text reaches the job: an expression with
//!    `github.event.(comment|issue|pull_request|review|discussion|head_commit).(body|title|message)`
//!    (dot or bracket syntax), `github.head_ref`,
//!    `github.event.pull_request.head.ref`, `github.event.commits` or
//!    `toJSON(github.event...)` inside `${{ }}` in any step's `with:`,
//!    `env:` or `run:`, or in the job's or workflow's `env:`. `if:` is not
//!    looked at: a condition that reads the comment is not the comment
//!    reaching the agent. Or the agent is an action (it reads the event
//!    itself), the trigger is a comment-like event (`issue_comment`,
//!    `pull_request_review_comment`, `pull_request_review`,
//!    `discussion_comment`, `issues`, `discussion`) and the step has no
//!    allowed-users input (`allowed_users`, `allow-users`,
//!    `allowed_actors`, ... with a value other than `*`).
//! 4. The job's token can write: `permissions: write-all`, or `write` for
//!    `contents`, `pull-requests`, `issues`, `actions`, `packages` or
//!    `id-token`, at job level or, when the job has no `permissions`, at
//!    workflow level; or no `permissions` anywhere, in which case the token
//!    gets the repository default, which may be write.
//!
//! A job, or an agent step, whose `if:` checks `author_association` against
//! OWNER, MEMBER or COLLABORATOR (with `==` or `contains(...)`, not `!=` or
//! `!contains`), or compares `github.actor`, `github.triggering_actor` or a
//! `user.login`/`sender.login` with a fixed name, or admits only pull
//! requests from the same repository (`head.repo.full_name ==
//! github.repository`, `head.repo.fork == false`), is treated as gated and
//! not reported; so is `if: false`. The expression is matched, not
//! evaluated: a gate that another `||` branch bypasses still counts.
//!
//! One match per job, on the agent step's `uses:` or `run:` value; the
//! message names the trigger, the agent step, how untrusted text gets in and
//! the write permission.

use std::fmt::Write as _;

use ::regex::Regex;
use serde_json::{Map, Value};

use super::builtin::{no_options, BuiltinDetector};
use super::shell::{stage_commands, StageCommand};
use super::structured::{locate, yaml_doc_starts, Step};
use super::{Input, Match};
use crate::text::escape_truncated;

/// Stop one past the engine's cap; the engine reports the truncation.
const MAX_MATCHES: usize = crate::engine::MAX_FINDINGS_PER_RULE + 1;

/// Values quoted in a message are cut to this many characters.
const MAX_QUOTED: usize = 80;

/// Events whose payload people outside the project write.
const UNTRUSTED_EVENTS: &[&str] = &[
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "pull_request_review_comment",
    "pull_request_review",
];

/// Events whose text an agent action reads by itself.
const COMMENT_EVENTS: &[&str] = &[
    "issue_comment",
    "pull_request_review_comment",
    "pull_request_review",
    "discussion_comment",
    "issues",
    "discussion",
];

const KNOWN_ACTIONS: &[&str] = &[
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "openai/codex-action",
    "google-github-actions/run-gemini-cli",
    "sst/opencode",
];

const AGENT_CLIS: &[&str] = &["claude", "codex", "gemini", "opencode", "aider", "goose"];

/// Packages that install an agent CLI, for `npx`-style launchers.
const AGENT_PACKAGES: &[(&str, &str)] = &[
    ("@anthropic-ai/claude-code", "claude"),
    ("@openai/codex", "codex"),
    ("@google/gemini-cli", "gemini"),
    ("opencode-ai", "opencode"),
    ("aider-chat", "aider"),
];

/// Token scopes whose `write` lets an agent change the repository or
/// publish from it.
const WRITE_SCOPES: &[&str] = &[
    "contents",
    "pull-requests",
    "issues",
    "actions",
    "packages",
    "id-token",
];

pub(crate) fn build(options: Option<&Value>) -> Result<Box<dyn BuiltinDetector>, String> {
    no_options(options)?;
    Ok(Box::new(CiAgentTokenExposure::new()?))
}

#[derive(Debug)]
struct CiAgentTokenExposure {
    /// `${{ ... }}`.
    expression: Regex,
    /// Untrusted event text, inside an expression.
    untrusted: Regex,
    /// Repository names of agent actions.
    agent_repo: Regex,
    /// A quoted trusted association.
    association: Regex,
    /// An actor or login compared with a fixed name.
    actor_gate: Regex,
    /// `with:` inputs that restrict who may trigger the action.
    user_gate_input: Regex,
}

fn re(pattern: &str) -> Result<Regex, String> {
    super::regex::compile(pattern, false).map_err(|e| format!("internal pattern: {e}"))
}

impl CiAgentTokenExposure {
    fn new() -> Result<Self, String> {
        Ok(Self {
            expression: re(r"(?s)\$\{\{(.*?)\}\}")?,
            untrusted: re(concat!(
                r"(?i)\bgithub\s*\.\s*head_ref\b",
                r#"|\bgithub\s*\.\s*event\s*(?:\.\s*|\[\s*['"])(?:comment|issue|pull_request|review|discussion|head_commit)(?:['"]\s*\])?\s*(?:\.\s*|\[\s*['"])(?:body|title|message)\b"#,
                r"|\bgithub\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.\s*(?:ref|label)\b",
                r"|\bgithub\s*\.\s*event\s*\.\s*commits\b",
                r"|\btojson\s*\(\s*github\s*\.\s*event\s*(?:\.\s*(?:comment|issue|pull_request|review|discussion|head_commit)\s*)?\)",
            ))?,
            agent_repo: re(
                r"(?i)(?:claude|codex|gemini|copilot|opencode|aider|goose|cline)[a-z0-9._-]*?-(?:action|cli)(?:$|[-_.])",
            )?,
            association: re(r#"(?i)['"](?:owner|member|collaborator)['"]"#)?,
            actor_gate: re(concat!(
                r#"(?i)\bgithub\s*\.\s*(?:actor|triggering_actor)\s*==\s*['"]"#,
                r#"|['"]\s*==\s*github\s*\.\s*(?:actor|triggering_actor)\b"#,
                r#"|\.\s*(?:user|sender)\s*\.\s*login\s*==\s*['"]"#,
                r"|\bcontains\s*\(\s*fromjson\s*\([^)]*\)\s*,\s*github\s*\.\s*(?:actor|triggering_actor)\b",
                // Same-repository pull requests only: fork authors are out.
                r"|\bhead\s*\.\s*repo\s*\.\s*full_name\s*==\s*github\s*\.\s*repository\b",
                r"|\bgithub\s*\.\s*repository\s*==\s*github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.\s*repo\s*\.\s*full_name\b",
                r"|\bhead\s*\.\s*repo\s*\.\s*fork\s*==\s*false\b",
            ))?,
            user_gate_input: re(
                r"(?i)^allow(?:ed)?[-_](?:users|actors|authors|logins|usernames|associations|author[-_]associations|teams)$",
            )?,
        })
    }
}

impl BuiltinDetector for CiAgentTokenExposure {
    fn detect(&self, input: &Input<'_>) -> Vec<Match> {
        let Ok(docs) = input.yaml() else {
            return Vec::new();
        };
        let starts = yaml_doc_starts(input.text, docs.len());
        let mut out = Vec::new();
        for (doc, start) in docs.iter().zip(starts) {
            for (steps, detail) in self.workflow(doc) {
                if out.len() >= MAX_MATCHES {
                    break;
                }
                let range = locate(input.text, start, doc, &steps);
                out.push(Match::with_detail(range, detail));
            }
        }
        out.sort_by_key(|m| (m.range.start, m.range.end));
        out
    }
}

/// An agent step found in a job.
struct AgentStep {
    index: usize,
    /// `uses` or `run`.
    key: &'static str,
    /// What it runs, for the message.
    label: String,
    /// `uses:` of an agent action (reads the event payload itself).
    action: bool,
    /// Has an input that limits who can trigger it.
    user_gated: bool,
    /// Sets `allowed_non_write_users`.
    opened: bool,
}

/// How untrusted text gets into a job.
enum Reach {
    Expression { expr: String, place: String },
    ActionReadsEvent { events: Vec<String>, opened: bool },
}

/// What the job's token can do.
enum Token {
    Write(Vec<String>, &'static str),
    Default,
    ReadOnly,
}

impl CiAgentTokenExposure {
    /// The reported jobs of one workflow document: where to point and what
    /// to say.
    fn workflow(&self, doc: &Value) -> Vec<(Vec<Step>, String)> {
        let mut out = Vec::new();
        let Some(wf) = doc.as_object() else {
            return out;
        };
        let events = untrusted_events(wf.get("on"));
        if events.is_empty() {
            return out;
        }
        let Some(jobs) = wf.get("jobs").and_then(Value::as_object) else {
            return out;
        };
        for (job_id, job) in jobs {
            let Some(job) = job.as_object() else {
                continue;
            };
            if self.is_gate(job.get("if")) {
                continue;
            }
            let agents: Vec<AgentStep> = job
                .get("steps")
                .and_then(Value::as_array)
                .map(|steps| {
                    steps
                        .iter()
                        .enumerate()
                        .filter_map(|(i, s)| self.agent_step(i, s.as_object()?))
                        .collect()
                })
                .unwrap_or_default();
            let Some((agent, reach)) = self.reach(job, wf, &events, &agents) else {
                continue;
            };
            let token = token(job.get("permissions"), wf.get("permissions"));
            if matches!(token, Token::ReadOnly) {
                continue;
            }
            let steps = vec![
                Step::Key("jobs".into()),
                Step::Key(job_id.clone()),
                Step::Key("steps".into()),
                Step::Index(agent.index),
                Step::Key(agent.key.into()),
            ];
            out.push((steps, message(job_id, &events, agent, &reach, &token)));
        }
        out
    }

    /// The agent step to report and how untrusted text reaches it.
    fn reach<'a>(
        &self,
        job: &Map<String, Value>,
        wf: &Map<String, Value>,
        events: &[String],
        agents: &'a [AgentStep],
    ) -> Option<(&'a AgentStep, Reach)> {
        let first = agents.first()?;
        if let Some((expr, place)) = self.untrusted_expression(job, wf) {
            return Some((first, Reach::Expression { expr, place }));
        }
        let comment_events: Vec<String> = events
            .iter()
            .filter(|e| COMMENT_EVENTS.contains(&e.as_str()))
            .cloned()
            .collect();
        if comment_events.is_empty() {
            return None;
        }
        let agent = agents.iter().find(|a| a.action && !a.user_gated)?;
        Some((
            agent,
            Reach::ActionReadsEvent {
                events: comment_events,
                opened: agent.opened,
            },
        ))
    }

    fn agent_step(&self, index: usize, step: &Map<String, Value>) -> Option<AgentStep> {
        if self.is_gate(step.get("if")) {
            return None;
        }
        if let Some(uses) = step.get("uses").and_then(Value::as_str) {
            if !self.is_agent_action(uses) {
                return None;
            }
            let with = step.get("with").and_then(Value::as_object);
            let user_gated = with.is_some_and(|w| {
                w.iter().any(|(k, v)| {
                    let v = value_text(v);
                    self.user_gate_input.is_match(k) && !v.trim().is_empty() && v.trim() != "*"
                })
            });
            let opened = with.is_some_and(|w| {
                w.get("allowed_non_write_users")
                    .is_some_and(|v| !value_text(v).trim().is_empty())
            });
            return Some(AgentStep {
                index,
                key: "uses",
                label: escape_truncated(uses.trim(), MAX_QUOTED),
                action: true,
                user_gated,
                opened,
            });
        }
        let run = step.get("run").and_then(Value::as_str)?;
        let cli = stage_commands(run).iter().find_map(agent_command)?;
        Some(AgentStep {
            index,
            key: "run",
            label: format!("the `{cli}` CLI"),
            action: false,
            user_gated: false,
            opened: false,
        })
    }

    fn is_agent_action(&self, uses: &str) -> bool {
        let uses = uses.trim();
        if uses.starts_with("docker://") || uses.starts_with('.') {
            return false;
        }
        let path = uses.split('@').next().unwrap_or(uses).to_ascii_lowercase();
        let mut parts = path.split('/');
        let (Some(owner), Some(repo)) = (parts.next(), parts.next()) else {
            return false;
        };
        KNOWN_ACTIONS.contains(&format!("{owner}/{repo}").as_str())
            || self.agent_repo.is_match(repo)
    }

    /// Does this `if:` limit the job or step to trusted people?
    fn is_gate(&self, cond: Option<&Value>) -> bool {
        let cond = match cond {
            // `if: false`: the job or step never runs.
            Some(Value::Bool(false)) => return true,
            Some(Value::String(cond)) => cond,
            _ => return false,
        };
        let bare = cond.trim();
        let bare = bare
            .strip_prefix("${{")
            .and_then(|b| b.strip_suffix("}}"))
            .unwrap_or(bare)
            .trim();
        bare == "false" || self.is_association_gate(cond) || self.actor_gate.is_match(cond)
    }

    /// `author_association` compared positively with OWNER, MEMBER or
    /// COLLABORATOR. A literal next to `!=`, or inside `!contains(`, does
    /// not count.
    fn is_association_gate(&self, cond: &str) -> bool {
        let lower = cond.to_ascii_lowercase();
        if !lower.contains("author_association") {
            return false;
        }
        let negated_contains = lower.match_indices("!contains").any(|(i, _)| {
            lower
                .get(i..)
                .is_some_and(|r| r.contains("author_association"))
        });
        if negated_contains {
            return false;
        }
        self.association.find_iter(cond).any(|m| {
            let before = cond.get(..m.start()).unwrap_or("").trim_end();
            let after = cond.get(m.end()..).unwrap_or("").trim_start();
            !before.ends_with("!=") && !after.starts_with("!=")
        })
    }

    /// The first untrusted expression in a step's `with`, `env` or `run`,
    /// or in the job's or workflow's `env`.
    fn untrusted_expression(
        &self,
        job: &Map<String, Value>,
        wf: &Map<String, Value>,
    ) -> Option<(String, String)> {
        let steps = job.get("steps").and_then(Value::as_array);
        for (i, step) in steps.into_iter().flatten().enumerate() {
            let Some(step) = step.as_object() else {
                continue;
            };
            for key in ["with", "env", "run"] {
                if let Some(expr) = step.get(key).and_then(|v| self.find_untrusted(v)) {
                    return Some((expr, format!("step {} `{key}`", i + 1)));
                }
            }
        }
        if let Some(expr) = job.get("env").and_then(|v| self.find_untrusted(v)) {
            return Some((expr, "the job's `env`".into()));
        }
        let expr = wf.get("env").and_then(|v| self.find_untrusted(v))?;
        Some((expr, "the workflow's `env`".into()))
    }

    fn find_untrusted(&self, value: &Value) -> Option<String> {
        let mut stack = vec![value];
        while let Some(v) = stack.pop() {
            match v {
                Value::String(s) => {
                    for caps in self.expression.captures_iter(s) {
                        let (Some(all), Some(inner)) = (caps.get(0), caps.get(1)) else {
                            continue;
                        };
                        if self.untrusted.is_match(inner.as_str()) {
                            return Some(all.as_str().to_owned());
                        }
                    }
                }
                Value::Array(items) => stack.extend(items.iter().rev()),
                Value::Object(map) => stack.extend(map.values().rev()),
                _ => {}
            }
        }
        None
    }
}

/// The untrusted events in `on`, in the order written.
fn untrusted_events(on: Option<&Value>) -> Vec<String> {
    let names: Vec<&str> = match on {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        Some(Value::Object(map)) => map.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim();
        if UNTRUSTED_EVENTS.contains(&name) && !out.iter().any(|e| e == name) {
            out.push(name.to_owned());
        }
    }
    out
}

/// A scalar as text (`true`, `5`), empty for null, maps and lists.
fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null | Value::Array(_) | Value::Object(_) => String::new(),
    }
}

/// The agent CLI a pipeline stage runs, if any.
fn agent_command(cmd: &StageCommand) -> Option<&'static str> {
    let non_flags = || {
        cmd.args
            .iter()
            .map(String::as_str)
            .filter(|a| !a.starts_with('-'))
    };
    if let Some(&cli) = AGENT_CLIS.iter().find(|c| **c == cmd.name) {
        if cli == "goose" && !matches!(non_flags().next(), Some("run" | "session" | "recipe")) {
            return None;
        }
        return Some(cli);
    }
    let mut args = non_flags();
    match cmd.name.as_str() {
        "npx" | "bunx" | "pnpx" | "uvx" => {}
        "pnpm" | "yarn" | "bun" => {
            if !matches!(args.next(), Some("dlx" | "x" | "exec")) {
                return None;
            }
        }
        "npm" => {
            if !matches!(args.next(), Some("exec" | "x")) {
                return None;
            }
        }
        "pipx" => {
            if args.next() != Some("run") {
                return None;
            }
        }
        "uv" => {
            if (args.next(), args.next()) != (Some("tool"), Some("run")) {
                return None;
            }
        }
        _ => return None,
    }
    let package = package_name(args.next()?);
    AGENT_PACKAGES
        .iter()
        .find(|(p, _)| *p == package)
        .map(|(_, cli)| *cli)
}

/// `@scope/pkg@1.2` -> `@scope/pkg`, `pkg==1.0` -> `pkg`.
fn package_name(spec: &str) -> &str {
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(rest) => (1, rest),
        None => (0, spec),
    };
    let end = rest
        .find(['@', '=', '<', '>', '~', '['])
        .unwrap_or(rest.len());
    spec.get(..scope + end).unwrap_or(spec)
}

fn token(job: Option<&Value>, workflow: Option<&Value>) -> Token {
    let (perms, level) = match (job, workflow) {
        (Some(p), _) => (p, "job"),
        (None, Some(p)) => (p, "workflow"),
        (None, None) => return Token::Default,
    };
    match perms {
        Value::String(s) if s.trim().eq_ignore_ascii_case("write-all") => {
            Token::Write(vec!["write-all".into()], level)
        }
        Value::Object(map) => {
            let writes: Vec<String> = WRITE_SCOPES
                .iter()
                .filter(|scope| {
                    map.get(**scope)
                        .and_then(Value::as_str)
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("write"))
                })
                .map(|scope| format!("{scope}: write"))
                .collect();
            if writes.is_empty() {
                Token::ReadOnly
            } else {
                Token::Write(writes, level)
            }
        }
        _ => Token::ReadOnly,
    }
}

fn message(
    job_id: &str,
    events: &[String],
    agent: &AgentStep,
    reach: &Reach,
    token: &Token,
) -> String {
    let mut out = String::new();
    let triggers = match reach {
        Reach::ActionReadsEvent {
            events: comment_events,
            ..
        } => comment_events.join(", "),
        Reach::Expression { .. } => events.join(", "),
    };
    // Writing to a String cannot fail.
    let _ = write!(
        out,
        "job `{}` runs on {triggers}; step {} runs {}; ",
        escape_truncated(job_id, MAX_QUOTED),
        agent.index + 1,
        agent.label
    );
    match reach {
        Reach::Expression { expr, place } => {
            let _ = write!(
                out,
                "untrusted text reaches the job through `{}` in {place}; ",
                escape_truncated(expr, MAX_QUOTED)
            );
        }
        Reach::ActionReadsEvent { opened, .. } => {
            out.push_str(
                "the action reads the triggering text itself and no author_association \
                 check or allowed-users input limits who can trigger it",
            );
            if *opened {
                out.push_str(" (allowed_non_write_users is set)");
            }
            out.push_str("; ");
        }
    }
    match token {
        Token::Write(scopes, level) => {
            let _ = write!(
                out,
                "the token can write ({}, {level} level)",
                scopes.join(", ")
            );
        }
        Token::Default | Token::ReadOnly => out.push_str(
            "no permissions block at job or workflow level, so the GITHUB_TOKEN gets the \
             repository default, which may be write",
        ),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Vec<(String, String)> {
        let d = CiAgentTokenExposure::new().unwrap();
        d.detect(&Input::new(".github/workflows/agent.yml", text))
            .into_iter()
            .map(|m| (text[m.range].to_owned(), m.detail.unwrap_or_default()))
            .collect()
    }

    fn assert_quiet(text: &str) {
        let m = run(text);
        assert!(m.is_empty(), "unexpected match: {m:?}\n{text}");
    }

    const COMMENT_AGENT: &str = "\
name: Claude
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  pull-requests: write
jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
";

    #[test]
    fn comment_triggered_action_with_write_token() {
        let m = run(COMMENT_AGENT);
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!(m[0].0, "anthropics/claude-code-action@v1");
        assert_eq!(
            m[0].1,
            "job `claude` runs on issue_comment; step 2 runs anthropics/claude-code-action@v1; \
             the action reads the triggering text itself and no author_association check or \
             allowed-users input limits who can trigger it; the token can write \
             (contents: write, pull-requests: write, workflow level)"
        );
    }

    #[test]
    fn untrusted_expression_on_pull_request_target() {
        let text = "\
on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - name: Review
        run: |
          npx -y @anthropic-ai/claude-code@latest -p \"Review: ${{ github.event.pull_request.title }}\"
";
        let m = run(text);
        assert_eq!(m.len(), 1, "{m:?}");
        assert!(
            m[0].0.starts_with("npx -y @anthropic-ai/claude-code"),
            "{}",
            m[0].0
        );
        assert_eq!(
            m[0].1,
            "job `review` runs on pull_request_target; step 2 runs the `claude` CLI; untrusted \
             text reaches the job through `${{ github.event.pull_request.title }}` in step 2 \
             `run`; the token can write (write-all, job level)"
        );
    }

    #[test]
    fn trigger_forms() {
        for on in [
            "on: issues",
            "on: [push, issues]",
            "on:\n  push:\n  issues:\n    types: [opened]",
            "\"on\": {issues: {}}",
        ] {
            let text =
                format!("{on}\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@main\n");
            let m = run(&text);
            assert_eq!(m.len(), 1, "{on}: {m:?}");
            assert!(m[0].1.contains("runs on issues"), "{}", m[0].1);
            // No permissions anywhere: the default token.
            assert!(
                m[0].1.contains("repository default, which may be write"),
                "{}",
                m[0].1
            );
        }
    }

    #[test]
    fn agent_steps_by_uses_and_run() {
        let step = |s: &str| {
            format!(
                "on: issue_comment\npermissions: {{contents: write}}\njobs:\n  a:\n    steps:\n      - {s}\n        env:\n          BODY: ${{{{ github.event.comment.body }}}}\n"
            )
        };
        for s in [
            "uses: anthropics/claude-code-base-action@beta",
            "uses: google-github-actions/run-gemini-cli@v0",
            "uses: sst/opencode/github@latest",
            "uses: some-org/my-aider-action@v2",
            "uses: acme/copilot-cli@1.0.0",
            "uses: Anthropics/Claude-Code-Action/subdir@0123456789abcdef0123456789abcdef01234567",
            "run: claude -p \"$BODY\"",
            "run: codex exec --full-auto \"$BODY\"",
            "run: gemini -p \"$BODY\" | tee out.txt",
            "run: sudo -E opencode run \"$BODY\"",
            "run: aider --message \"$BODY\"",
            "run: goose run -t \"$BODY\"",
            "run: npx @google/gemini-cli -p \"$BODY\"",
            "run: pnpm dlx @openai/codex@0.40 exec \"$BODY\"",
            "run: pipx run aider-chat==0.86 --message \"$BODY\"",
            "run: uv tool run aider-chat --message \"$BODY\"",
        ] {
            assert_eq!(run(&step(s)).len(), 1, "{s}");
        }
        for s in [
            "uses: actions/checkout@v4",
            "uses: docker://claude-code-action:latest",
            "uses: ./.github/actions/claude-action",
            "uses: acme/claude-tools@v1",
            "run: echo \"ask claude about $BODY\"",
            "run: npm install -g @anthropic-ai/claude-code",
            "run: goose -dir migrations postgres \"$DB\" up",
            "run: goose up",
            "run: npx prettier --check .",
        ] {
            assert!(run(&step(s)).is_empty(), "{s}");
        }
    }

    #[test]
    fn expression_forms() {
        let job = |expr: &str, place: &str| {
            let (step_env, job_env, wf_env) = match place {
                "step" => (
                    format!("        env:\n          X: {expr}\n"),
                    String::new(),
                    String::new(),
                ),
                "job" => (
                    String::new(),
                    format!("    env:\n      X: {expr}\n"),
                    String::new(),
                ),
                _ => (String::new(), String::new(), format!("env:\n  X: {expr}\n")),
            };
            format!(
                "on: pull_request_target\n{wf_env}permissions:\n  pull-requests: write\njobs:\n  a:\n{job_env}    steps:\n      - run: claude -p \"$X\"\n{step_env}"
            )
        };
        for expr in [
            "${{ github.event.comment.body }}",
            "${{github.event.issue.title}}",
            "${{ github.event['pull_request']['body'] }}",
            "${{ github.event.review.body }}",
            "${{ github.event.discussion.title }}",
            "${{ github.event.head_commit.message }}",
            "${{ github.head_ref }}",
            "${{ github.event.pull_request.head.ref }}",
            "${{ toJSON(github.event) }}",
            "${{ toJson(github.event.comment) }}",
            "\"Fix: ${{ github.event.issue.body }}\"",
        ] {
            for place in ["step", "job", "workflow"] {
                let m = run(&job(expr, place));
                assert_eq!(m.len(), 1, "{expr} in {place}");
            }
        }
        for expr in [
            "${{ github.event.pull_request.number }}",
            "${{ github.event.issue.user.login }}",
            "${{ github.sha }}",
            "github.event.comment.body",
            "${{ github.event.pull_request.base.ref }}",
        ] {
            assert!(run(&job(expr, "step")).is_empty(), "{expr}");
        }
    }

    #[test]
    fn untrusted_trigger_without_agent_step_is_quiet() {
        assert_quiet(
            "\
on: pull_request_target
permissions: write-all
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
      - run: echo \"${{ github.event.pull_request.title }}\"
",
        );
    }

    #[test]
    fn agent_on_push_only_is_quiet() {
        assert_quiet(
            "\
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
permissions:
  contents: write
jobs:
  claude:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: ${{ github.event.head_commit.message }}
",
        );
    }

    #[test]
    fn author_association_gates() {
        for cond in [
            "github.event.comment.author_association == 'OWNER'",
            "${{ github.event.comment.author_association == 'MEMBER' || github.event.comment.author_association == 'OWNER' }}",
            "contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.comment.author_association)",
            "contains(github.event.comment.body, '@claude') && github.event.comment.author_association == \"COLLABORATOR\"",
            "github.actor == 'maintainer-name'",
            "github.event.comment.user.login == 'maintainer-name'",
            "contains(fromJSON('[\"alice\",\"bob\"]'), github.actor)",
            "github.event.pull_request.head.repo.full_name == github.repository",
            "${{ github.event.pull_request.head.repo.fork == false }}",
            "false",
            "${{ false }}",
        ] {
            let job_gated =
                COMMENT_AGENT.replace("contains(github.event.comment.body, '@claude')", cond);
            assert!(job_gated.contains(cond), "{cond}");
            assert_quiet(&job_gated);
        }
        // Not gates: negations and checks that let everyone through.
        for cond in [
            "github.event.comment.author_association != 'OWNER'",
            "${{ 'OWNER' != github.event.comment.author_association }}",
            "${{ !contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association) }}",
            "github.event.comment.author_association != 'NONE'",
            "github.actor != 'dependabot[bot]'",
        ] {
            let text = COMMENT_AGENT.replace("contains(github.event.comment.body, '@claude')", cond);
            assert_eq!(run(&text).len(), 1, "{cond}");
        }
    }

    #[test]
    fn step_level_gate_and_allowed_users_inputs() {
        let gated_step = COMMENT_AGENT.replace(
            "      - uses: anthropics/claude-code-action@v1\n",
            "      - if: github.event.comment.author_association == 'OWNER'\n        uses: anthropics/claude-code-action@v1\n",
        );
        assert_quiet(&gated_step);
        let with_input = |input: &str| {
            COMMENT_AGENT.replace(
                "          anthropic_api_key:",
                &format!("          {input}\n          anthropic_api_key:"),
            )
        };
        assert_quiet(&with_input("allowed_users: \"alice,bob\""));
        assert_quiet(&with_input("allow-users: alice"));
        // A wildcard is no gate; allowed_non_write_users opens the action.
        assert_eq!(run(&with_input("allowed_users: \"*\"")).len(), 1);
        let m = run(&with_input("allowed_non_write_users: \"*\""));
        assert!(m[0].1.contains("(allowed_non_write_users is set)"), "{m:?}");
        // An allowed-users input does not help when the text is passed in
        // explicitly.
        let explicit =
            with_input("allowed_users: alice\n          prompt: ${{ github.event.issue.body }}");
        assert_eq!(run(&explicit).len(), 1);
    }

    #[test]
    fn permissions() {
        let with_perms = |wf: &str, job: &str| {
            format!(
                "on: issue_comment\n{wf}jobs:\n  a:\n{job}    steps:\n      - uses: anthropics/claude-code-action@v1\n"
            )
        };
        // Read-only tokens are not reported.
        for (wf, job) in [
            ("permissions: read-all\n", ""),
            ("permissions: {}\n", ""),
            (
                "permissions:\n  contents: read\n  pull-requests: read\n",
                "",
            ),
            (
                "permissions: write-all\n",
                "    permissions:\n      contents: read\n",
            ),
            (
                "",
                "    permissions:\n      contents: read\n      statuses: write\n",
            ),
        ] {
            assert!(run(&with_perms(wf, job)).is_empty(), "{wf} {job}");
        }
        for (wf, job, want) in [
            (
                "permissions: write-all\n",
                "",
                "(write-all, workflow level)",
            ),
            (
                "",
                "    permissions:\n      id-token: write\n",
                "(id-token: write, job level)",
            ),
            (
                "permissions:\n  contents: read\n",
                "    permissions:\n      issues: write\n      packages: write\n",
                "(issues: write, packages: write, job level)",
            ),
            ("", "", "repository default"),
        ] {
            let m = run(&with_perms(wf, job));
            assert_eq!(m.len(), 1, "{wf} {job}");
            assert!(m[0].1.contains(want), "{}", m[0].1);
        }
    }

    #[test]
    fn several_jobs_and_documents() {
        let text = "\
on: [issue_comment, pull_request_review_comment]
jobs:
  lint:
    steps:
      - run: cargo clippy
  agent-one:
    steps:
      - uses: anthropics/claude-code-action@v1
  agent-two:
    if: github.event.comment.author_association == 'MEMBER'
    steps:
      - uses: anthropics/claude-code-action@v1
  agent-three:
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
";
        let m = run(text);
        assert_eq!(m.len(), 2, "{m:?}");
        assert!(m[0].1.starts_with(
            "job `agent-one` runs on issue_comment, pull_request_review_comment; step 1"
        ));
        assert!(m[1].1.starts_with("job `agent-three`"), "{}", m[1].1);
        // Each points at its own step.
        let text_lines: Vec<&str> = text.lines().collect();
        let d = CiAgentTokenExposure::new().unwrap();
        let input = Input::new("w.yml", text);
        let ranges: Vec<usize> = d
            .detect(&input)
            .iter()
            .map(|m| input.lines().line_of(m.range.start))
            .collect();
        assert_eq!(
            text_lines[ranges[0]],
            "      - uses: anthropics/claude-code-action@v1"
        );
        assert_eq!(ranges, vec![7, 15]);
    }

    #[test]
    fn unparseable_and_odd_shapes_are_quiet() {
        for text in [
            "on: issue_comment\njobs: [\n",
            "",
            "- a\n- b\n",
            "on: issue_comment\njobs: 5\n",
            "on: issue_comment\njobs:\n  a: 1\n  b:\n    steps: {x: 1}\n  c:\n    steps: [1, null, {uses: 7}]\n",
            "on: {issue_comment: null}\njobs:\n  a:\n    uses: org/repo/.github/workflows/claude.yml@main\n",
        ] {
            assert_quiet(text);
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(package_name("@openai/codex@0.40"), "@openai/codex");
        assert_eq!(package_name("aider-chat==0.86"), "aider-chat");
        assert_eq!(package_name("opencode-ai"), "opencode-ai");
        assert_eq!(package_name("@"), "@");
        let ev = untrusted_events(Some(&serde_json::json!([
            "push",
            "issues",
            "issues",
            " issue_comment "
        ])));
        assert_eq!(ev, vec!["issues", "issue_comment"]);
        assert!(untrusted_events(Some(&serde_json::json!(5))).is_empty());
    }

    #[test]
    fn options_are_rejected() {
        assert!(build(None).is_ok());
        assert!(build(Some(&serde_json::json!({"actions": []}))).is_err());
    }
}
