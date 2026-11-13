use std::hint::black_box;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use do_context_shield_benchmarks::corpus::standard_cases;
use do_context_shield_benchmarks::metadata::{model_identity, print_header};
use do_context_shield_detector_gliner2::{Gliner2Config, Gliner2Detector, probe};
use do_context_shield_detector_hybrid::HybridDetector;
use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::Detector;

const MODEL_ENV: &str = "DO_CONTEXT_SHIELD_BENCH_MODEL_DIR";
const MODEL_ID_ENV: &str = "DO_CONTEXT_SHIELD_BENCH_MODEL_ID";

fn local_model(c: &mut Criterion) {
    let Some(model_dir) = std::env::var_os(MODEL_ENV) else {
        eprintln!(
            "SKIP: GLiNER2 benchmarks are opt-in; set {MODEL_ENV} to an existing local model directory. No model is downloaded."
        );
        return;
    };
    let model_dir = PathBuf::from(model_dir);
    if !model_dir.is_dir() {
        panic!(
            "{MODEL_ENV} was explicitly set but is not an existing directory; provide a local GLiNER2 export path"
        );
    }
    if std::env::var_os("ORT_DYLIB_PATH").is_none() {
        panic!(
            "{MODEL_ENV} is set; set ORT_DYLIB_PATH to a local ONNX Runtime shared library. No runtime is downloaded."
        );
    }
    let model_id = model_identity(std::env::var(MODEL_ID_ENV).ok())
        .unwrap_or_else(|error| panic!("{MODEL_ID_ENV} {error}"));

    let config = Gliner2Config::with_model_dir(model_dir.clone()).with_limits(512, 2);
    let readiness = probe(&config);
    if !readiness.available {
        panic!(
            "local GLiNER2 model is not ready ({}): {}",
            readiness.code.as_str(),
            readiness.guidance
        );
    }

    let cases = standard_cases();
    print_header("local-gliner2-and-hybrid", &cases);
    eprintln!(
        "benchmark model: id={model_id} selection=local layout={} max_tokens={} intra_threads=2",
        readiness.layout.map_or("unknown", |layout| layout.as_str()),
        config.max_tokens
    );
    let warm_detector = Gliner2Detector::new(config.clone());
    if let Err(error) = warm_detector.detect(&cases[0].text) {
        panic!("local GLiNER2 warm-up failed: {error}");
    }
    let warm_hybrid = HybridDetector::new(
        Box::new(RegexDetector),
        Box::new(Gliner2Detector::new(config.clone())),
    );
    if let Err(error) = warm_hybrid.detect(&cases[0].text) {
        panic!("local hybrid warm-up failed: {error}");
    }

    let mut group = c.benchmark_group("local-gliner2");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    for case in &cases {
        group.throughput(Throughput::Bytes(case.text.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("cold-first-detect", case.name),
            case,
            |b, input| {
                b.iter(|| {
                    let detector = Gliner2Detector::new(config.clone());
                    match detector.detect(black_box(&input.text)) {
                        Ok(entities) => black_box(entities),
                        Err(error) => panic!("local GLiNER2 cold inference failed: {error}"),
                    }
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("warm-detect", case.name),
            case,
            |b, input| {
                b.iter(|| match warm_detector.detect(black_box(&input.text)) {
                    Ok(entities) => black_box(entities),
                    Err(error) => panic!("local GLiNER2 warm inference failed: {error}"),
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("warm-hybrid-regex-gliner2", case.name),
            case,
            |b, input| {
                b.iter(|| match warm_hybrid.detect(black_box(&input.text)) {
                    Ok(entities) => black_box(entities),
                    Err(error) => panic!("local hybrid inference failed: {error}"),
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, local_model);
criterion_main!(benches);
