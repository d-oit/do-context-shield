//! Environment metadata emitted alongside Criterion measurements.

use std::process::Command;

use crate::corpus::{CORPUS_REVISION, Case};

/// Print toolchain, platform, feature, thread, and exact corpus-size metadata.
pub fn print_header(stage: &str, cases: &[Case]) {
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || "unknown".to_owned(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        );
    let parallelism = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    eprintln!(
        "benchmark metadata: stage={stage} corpus={CORPUS_REVISION} rustc={rustc} os={} arch={} logical_threads={parallelism} gliner2_feature={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(feature = "gliner2")
    );
    if let Some(cpu) = cpu_model() {
        eprintln!("benchmark metadata: cpu={cpu}");
    }
    for case in cases {
        eprintln!(
            "benchmark input: name={} bytes={} entities={}",
            case.name,
            case.text.len(),
            case.entities.len()
        );
    }
}

fn cpu_model() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model name").then(|| value.trim().to_owned())
    })
}

/// Validate a caller-supplied, stable identity for a local model artifact.
///
/// # Errors
///
/// Returns an error when the identity is absent, empty, or contains whitespace
/// or control characters that would make benchmark metadata ambiguous.
pub fn model_identity(value: Option<String>) -> Result<String, &'static str> {
    let Some(value) = value else {
        return Err("set a stable model identity for the supplied local export");
    };
    let identity = value.trim();
    if identity.is_empty()
        || identity
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(
            "model identity must be non-empty and contain no whitespace or control characters",
        );
    }
    Ok(identity.to_owned())
}

#[cfg(test)]
mod tests {
    use super::model_identity;

    #[test]
    fn model_identity_requires_stable_nonempty_metadata() {
        assert!(model_identity(None).is_err());
        assert!(model_identity(Some(String::new())).is_err());
        assert!(model_identity(Some("model with spaces".to_owned())).is_err());
        assert!(model_identity(Some("model\nrevision".to_owned())).is_err());
        assert_eq!(
            model_identity(Some("org/model@revision".to_owned())),
            Ok("org/model@revision".to_owned())
        );
    }
}
