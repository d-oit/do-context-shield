#![no_main]

use do_context_shield_detector_regex::RegexDetector;
use do_context_shield_plugin_api::Detector;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Arbitrary byte slice conversion attempt to &str.
    // We fuzz valid UTF-8 strings as well as lossy UTF-8 representations.
    let lossy_input;
    let input: &str = match std::str::from_utf8(data) {
        Ok(valid_utf8) => valid_utf8,
        Err(_) => {
            lossy_input = String::from_utf8_lossy(data);
            &lossy_input
        }
    };

    let detector = RegexDetector;
    if let Ok(entities) = detector.detect(input) {
        for entity in entities {
            // Assert matched byte ranges are within input bounds
            assert!(
                entity.start <= input.len(),
                "start offset {} exceeds input length {}",
                entity.start,
                input.len()
            );
            assert!(
                entity.end <= input.len(),
                "end offset {} exceeds input length {}",
                entity.end,
                input.len()
            );
            assert!(
                entity.start <= entity.end,
                "start offset {} > end offset {}",
                entity.start,
                entity.end
            );

            // Assert matched byte ranges fall on valid UTF-8 character boundaries
            assert!(
                input.is_char_boundary(entity.start),
                "start offset {} is not a UTF-8 char boundary in `{}`",
                entity.start,
                input
            );
            assert!(
                input.is_char_boundary(entity.end),
                "end offset {} is not a UTF-8 char boundary in `{}`",
                entity.end,
                input
            );

            // Assert entity value equals input substring at span
            assert_eq!(
                &input[entity.start..entity.end],
                entity.value,
                "entity value mismatch at span {}..{}",
                entity.start,
                entity.end
            );
        }
    }
});
