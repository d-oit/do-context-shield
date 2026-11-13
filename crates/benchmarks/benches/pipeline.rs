use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use do_context_shield_benchmarks::corpus::{pseudonymization_plan, standard_cases};
use do_context_shield_benchmarks::metadata::print_header;
use do_context_shield_detector_hybrid::HybridDetector;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::{
    Detector, Policy, ProcessingContext, ScopeId, Transformer, Vault,
};
use do_context_shield_plugin_process::{ProcessCommand, ProcessConfig, ProcessDetector};
use do_context_shield_policy_default::DefaultPolicy;
use do_context_shield_transformer_mask::MaskingTransformer;
use do_context_shield_transformer_pseudonymize::PseudonymizingTransformer;
use do_context_shield_vault_json::JsonVault;
use do_context_shield_vault_memory::MemoryVault;

fn regex_and_hybrid(c: &mut Criterion) {
    let cases = standard_cases();
    print_header("regex-and-hybrid-detection", &cases);
    let regex = RegexDetector;
    let hybrid = HybridDetector::new(Box::new(RegexDetector), Box::new(RegexDetector));
    let mut group = c.benchmark_group("detection");
    for case in &cases {
        group.throughput(Throughput::Bytes(case.text.len() as u64));
        group.bench_with_input(BenchmarkId::new("regex", case.name), case, |b, input| {
            b.iter(|| match regex.detect(black_box(&input.text)) {
                Ok(entities) => black_box(entities),
                Err(error) => panic!("regex benchmark failed: {error}"),
            });
        });
        group.bench_with_input(
            BenchmarkId::new("hybrid-regex-regex", case.name),
            case,
            |b, input| {
                b.iter(|| match hybrid.detect(black_box(&input.text)) {
                    Ok(entities) => black_box(entities),
                    Err(error) => panic!("hybrid benchmark failed: {error}"),
                });
            },
        );
    }
    group.finish();
}

fn policy_planning(c: &mut Criterion) {
    let cases = standard_cases();
    print_header("policy-planning", &cases);
    let policy = DefaultPolicy;
    let context = ProcessingContext::default();
    let mut group = c.benchmark_group("policy-plan");
    for case in &cases {
        group.throughput(Throughput::Elements(case.entities.len() as u64));
        group.bench_with_input(BenchmarkId::new("default", case.name), case, |b, input| {
            b.iter(
                || match policy.plan(black_box(&input.entities), &[], black_box(&context)) {
                    Ok(plan) => black_box(plan),
                    Err(error) => panic!("policy benchmark failed: {error}"),
                },
            );
        });
    }
    group.finish();
}

fn transformation_and_vault(c: &mut Criterion) {
    let cases = standard_cases();
    print_header("transformation-and-vault", &cases);
    let scope = ScopeId("synthetic-benchmark-session".to_owned());
    let pseudonymizer = PseudonymizingTransformer;
    let masker = MaskingTransformer;
    let mut memory = MemoryVault::default();
    let mut group = c.benchmark_group("transformation");
    for case in &cases {
        let plan = pseudonymization_plan(&case.entities);
        group.throughput(Throughput::Bytes(case.text.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("pseudonymize-memory-vault", case.name),
            case,
            |b, input| {
                b.iter(|| {
                    match pseudonymizer.transform(
                        black_box(&input.text),
                        black_box(&plan),
                        &scope,
                        &mut memory,
                    ) {
                        Ok(result) => black_box(result),
                        Err(error) => panic!("transform benchmark failed: {error}"),
                    }
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("mask", case.name), case, |b, input| {
            b.iter(|| {
                match masker.transform(
                    black_box(&input.text),
                    black_box(&plan),
                    &scope,
                    &mut memory,
                ) {
                    Ok(result) => black_box(result),
                    Err(error) => panic!("mask benchmark failed: {error}"),
                }
            });
        });
    }
    group.finish();

    if let Some(case) = cases.first() {
        let entity = &case.entities[0];
        let scope = ScopeId("synthetic-vault-session".to_owned());
        let mut memory = MemoryVault::default();
        let mapping = match memory.get_or_insert(&scope, &entity.kind, &entity.value) {
            Ok(mapping) => mapping,
            Err(error) => panic!("memory vault setup failed: {error}"),
        };
        c.bench_function("vault/memory-get-or-insert", |b| {
            b.iter(|| {
                match memory.get_or_insert(
                    &scope,
                    black_box(&entity.kind),
                    black_box(&entity.value),
                ) {
                    Ok(mapping) => black_box(mapping),
                    Err(error) => panic!("memory vault benchmark failed: {error}"),
                }
            });
        });
        c.bench_function("vault/memory-resolve", |b| {
            b.iter(|| match memory.resolve(&scope, black_box(&mapping.token)) {
                Ok(mapping) => black_box(mapping),
                Err(error) => panic!("memory vault benchmark failed: {error}"),
            });
        });

        let directory = match tempfile::tempdir() {
            Ok(directory) => directory,
            Err(error) => panic!("temporary benchmark directory unavailable: {error}"),
        };
        let path = directory.path().join("synthetic-vault.json");
        let mut json = match JsonVault::open(path) {
            Ok(vault) => vault,
            Err(error) => panic!("JSON vault setup failed: {error}"),
        };
        let json_mapping = match json.get_or_insert(&scope, &entity.kind, &entity.value) {
            Ok(mapping) => mapping,
            Err(error) => panic!("JSON vault setup failed: {error}"),
        };
        c.bench_function("vault/json-get-or-insert", |b| {
            b.iter(|| {
                match json.get_or_insert(&scope, black_box(&entity.kind), black_box(&entity.value))
                {
                    Ok(mapping) => black_box(mapping),
                    Err(error) => panic!("JSON vault benchmark failed: {error}"),
                }
            });
        });
        c.bench_function("vault/json-resolve", |b| {
            b.iter(
                || match json.resolve(&scope, black_box(&json_mapping.token)) {
                    Ok(mapping) => black_box(mapping),
                    Err(error) => panic!("JSON vault benchmark failed: {error}"),
                },
            );
        });
    }
}

#[cfg(unix)]
fn process_overhead(c: &mut Criterion) {
    let cases = standard_cases();
    print_header("process-plugin-overhead", &cases);
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../plugin-process/tests/fixtures/plugin.sh"
    );
    let plugin = ProcessDetector::new(ProcessConfig {
        command: Some(ProcessCommand::new("sh", [fixture, "detect-clean"])),
        timeout: Duration::from_secs(5),
    });
    let mut group = c.benchmark_group("process-plugin-detect-clean");
    for case in &cases {
        group.throughput(Throughput::Bytes(case.text.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("spawn-ndjson-roundtrip", case.name),
            case,
            |b, input| {
                b.iter(|| match plugin.detect(black_box(&input.text)) {
                    Ok(entities) => black_box(entities),
                    Err(error) => panic!("process plugin benchmark failed: {error}"),
                });
            },
        );
    }
    group.finish();
}

#[cfg(not(unix))]
fn process_overhead(_c: &mut Criterion) {}

criterion_group!(
    benches,
    regex_and_hybrid,
    policy_planning,
    transformation_and_vault,
    process_overhead
);
criterion_main!(benches);
