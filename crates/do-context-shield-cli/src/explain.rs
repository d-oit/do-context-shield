//! CLI flow and stable output for policy simulation.

use crate::cli::ExplainPolicyArgs;
use crate::config::{self, CliSelection};
use crate::pipeline::build_policy_planner;
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct ExplainOutput {
    simulation: bool,
    policy: String,
    blocked: bool,
    entities: Vec<ExplainEntity>,
}

#[derive(Serialize)]
struct ExplainEntity {
    kind: String,
    start: usize,
    end: usize,
    action: &'static str,
    reason_code: &'static str,
    matched_rule: Option<usize>,
    used_default: bool,
}

/// Run a value-free policy simulation over stdin.
///
/// This resolves the ordinary one-shot config precedence, but deliberately
/// builds only detector, judge, and policy plugins.
///
/// # Errors
///
/// Returns an error when configuration, plugin construction, detection,
/// policy validation, serialization, stdin, or stdout fails.
pub(crate) fn run(
    args: ExplainPolicyArgs,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = config::resolve(
        &CliSelection {
            detector: args.detector,
            pipeline: crate::cli::PipelineSelection {
                judge: args.policy.judge,
                policy: args.policy.policy,
                transformer: None,
            },
            process: args.process,
            context: args.context,
            ..CliSelection::default()
        },
        config,
    );
    let planner = build_policy_planner(&resolved)?;
    let input = crate::input::read_stdin()?;
    let decisions = planner.explain(&input, &resolved.to_context())?;
    let blocked = decisions
        .iter()
        .any(|decision| decision.action == do_context_shield_plugin_api::Action::Block);
    let output = ExplainOutput {
        simulation: true,
        policy: resolved.policy,
        blocked,
        entities: decisions
            .into_iter()
            .map(|decision| ExplainEntity {
                kind: decision.kind,
                start: decision.start,
                end: decision.end,
                action: decision.action.as_str(),
                reason_code: decision.reason_code.as_str(),
                matched_rule: decision.matched_rule,
                used_default: decision.used_default,
            })
            .collect(),
    };
    if args.format == "json" {
        serde_json::to_writer_pretty(io::stdout(), &output)?;
        println!();
    } else {
        println!("policy simulation (no sanitization, vault, or audit writes)");
        println!("policy: {}", output.policy);
        println!("blocked: {}", output.blocked);
        for entity in &output.entities {
            let rule = entity
                .matched_rule
                .map_or_else(|| "none".to_owned(), |index| index.to_string());
            println!(
                "{} {}..{} -> {} reason={} matched_rule={} used_default={}",
                entity.kind,
                entity.start,
                entity.end,
                entity.action,
                entity.reason_code,
                rule,
                entity.used_default,
            );
        }
    }
    io::stdout().flush()?;
    Ok(())
}
