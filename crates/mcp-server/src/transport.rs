//! Bounded newline-delimited frame transport for the MCP stdio adapter.
//!
//! The wire format is one JSON-RPC message per line. Reads are bounded by
//! [`crate::DEFAULT_MAX_REQUEST_BYTES`]: a frame is buffered up to the limit
//! plus one detection byte, never more, so an untrusted client cannot make the
//! long-lived server grow its input buffer without bound.
//!
//! Failure contract:
//!
//! - A frame longer than the limit produces one `null`-id invalid-request
//!   error and ends the session. The oversized frame cannot be parsed, so no
//!   id can be recovered safely, and draining an attacker-controlled stream
//!   would itself be unbounded. None of the frame reaches
//!   [`crate::handle::handle_request`], so it cannot reach a plugin, the vault,
//!   or the audit sink.
//! - A final frame with no newline at EOF produces one `null`-id parse error
//!   and ends the session; it is never parsed as if it were complete.
//! - A complete bounded frame that is not valid UTF-8 is answered with one
//!   `null`-id parse error and skipped: the frame boundary was found inside the
//!   limit, so continuing cannot grow the buffer, and the bytes are never
//!   echoed or lossily converted.

use std::io::{BufRead, Write};

use do_context_shield_core::PrivacyPipeline;
use do_context_shield_plugin_api::ProcessingContext;
use serde_json::Value;

use crate::ToolSet;
use crate::handle::{handle_request, unusable_frame_response};

/// Outcome of one bounded frame read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameOutcome {
    /// End of input before any byte of a frame.
    Eof,
    /// A newline-terminated frame of at most `limit` bytes is in the buffer.
    Line,
    /// The frame exceeded `limit` bytes before its newline.
    TooLarge,
    /// End of input inside a frame that never saw a newline.
    Unterminated,
}

/// Read one newline-terminated frame into `buf`, at most `limit + 1` bytes.
///
/// The extra byte distinguishes a frame of exactly `limit` bytes from an
/// oversized one. The newline itself is consumed but not stored, and no byte
/// past the newline is consumed, so a following frame is not disturbed.
fn read_frame<R: BufRead>(
    reader: &mut R,
    limit: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<FrameOutcome> {
    buf.clear();
    let capacity = limit.saturating_add(1);
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if buf.is_empty() {
                FrameOutcome::Eof
            } else {
                FrameOutcome::Unterminated
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(available.len()).min(capacity - buf.len());
        buf.extend_from_slice(&available[..take]);
        if let Some(index) = newline
            && take == index
        {
            // Consume the newline as well: leaving it would make the next read
            // see an empty frame and spin without end.
            reader.consume(take + 1);
            return Ok(if buf.len() > limit {
                FrameOutcome::TooLarge
            } else {
                FrameOutcome::Line
            });
        }
        reader.consume(take);
        if buf.len() >= capacity {
            return Ok(FrameOutcome::TooLarge);
        }
    }
}

/// Serve newline-delimited JSON-RPC frames until EOF or a terminating failure.
///
/// # Errors
///
/// Returns an error when reading stdin or writing a response fails. Protocol
/// failures are `Ok` values carrying a JSON-RPC error.
pub(crate) fn serve<R: BufRead, W: Write>(
    pipeline: &mut PrivacyPipeline,
    tools: ToolSet,
    default_context: &ProcessingContext,
    input: &mut R,
    output: &mut W,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    loop {
        match read_frame(input, limit, &mut buf)? {
            FrameOutcome::Eof => return Ok(()),
            FrameOutcome::Line => {
                if buf.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&buf) else {
                    write_response(
                        output,
                        &unusable_frame_response(-32700, "request frame is not valid UTF-8"),
                    )?;
                    continue;
                };
                if let Some(response) = handle_request(pipeline, tools, default_context, text)? {
                    write_response(output, &response)?;
                }
            }
            FrameOutcome::TooLarge => {
                write_response(
                    output,
                    &unusable_frame_response(
                        -32600,
                        &format!("request frame exceeds the {limit}-byte limit"),
                    ),
                )?;
                return Ok(());
            }
            FrameOutcome::Unterminated => {
                write_response(
                    output,
                    &unusable_frame_response(-32700, "request frame is not newline-terminated"),
                )?;
                return Ok(());
            }
        }
    }
}

/// Write one JSON-RPC message followed by the framing newline, and flush so a
/// client waiting on a reply is not held by buffering.
fn write_response<W: Write>(output: &mut W, response: &Value) -> std::io::Result<()> {
    serde_json::to_writer(&mut *output, response)?;
    output.write_all(b"\n")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use do_context_shield_plugin_api::{Detector, DetectorError, Entity};

    use super::*;

    /// Counts `detect` calls: a rejected request must never reach a plugin.
    struct CountingDetector(Arc<AtomicUsize>);

    impl Detector for CountingDetector {
        fn detect(&self, _input: &str) -> Result<Vec<Entity>, DetectorError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    fn counting_pipeline() -> (PrivacyPipeline, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let policy = match do_context_shield_plugin_registry::policy("default") {
            Ok(policy) => policy,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let transformer = match do_context_shield_plugin_registry::transformer("pseudonymize") {
            Ok(transformer) => transformer,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let vault = match do_context_shield_plugin_registry::vault("memory") {
            Ok(vault) => vault,
            Err(error) => panic!("unexpected error: {error}"),
        };
        let pipeline = PrivacyPipeline::new(
            Box::new(CountingDetector(Arc::clone(&calls))),
            policy,
            transformer,
            vault,
        );
        (pipeline, calls)
    }

    const VALID: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"context.sanitize","arguments":{"text":"alice@example.com","recipient":"local"}}}"#;

    /// Unwrap a frame read: the tests assert on the outcome, and an I/O error
    /// is a test failure rather than an expected value.
    fn frame<R: BufRead>(reader: &mut R, limit: usize, buf: &mut Vec<u8>) -> FrameOutcome {
        match read_frame(reader, limit, buf) {
            Ok(outcome) => outcome,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    fn parsed_responses(output: &[u8]) -> Vec<Value> {
        String::from_utf8_lossy(output)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| match serde_json::from_str(line) {
                Ok(value) => value,
                Err(error) => panic!("invalid response line: {error}"),
            })
            .collect()
    }

    fn serve_text(input: &str, limit: usize) -> (Vec<u8>, usize) {
        let (mut pipeline, calls) = counting_pipeline();
        let mut output = Vec::new();
        if let Err(error) = serve(
            &mut pipeline,
            ToolSet::all(),
            &ProcessingContext::default(),
            &mut Cursor::new(input.as_bytes()),
            &mut output,
            limit,
        ) {
            panic!("unexpected error: {error}");
        }
        (output, calls.load(Ordering::SeqCst))
    }

    #[test]
    fn frames_at_the_limit_are_accepted_and_one_byte_over_is_rejected() {
        let exact = b"12345678\nnext\n";
        let mut buf = Vec::new();
        let mut reader = Cursor::new(exact);
        assert_eq!(frame(&mut reader, 8, &mut buf), FrameOutcome::Line);
        assert_eq!(buf, b"12345678");
        // The newline belongs to the frame: the next read must see the next
        // frame, not an empty one (a leftover newline would spin forever).
        assert_eq!(frame(&mut reader, 8, &mut buf), FrameOutcome::Line);
        assert_eq!(buf, b"next");
        assert_eq!(frame(&mut reader, 8, &mut buf), FrameOutcome::Eof);
        assert_eq!(
            frame(&mut Cursor::new(exact), 7, &mut buf),
            FrameOutcome::TooLarge
        );
        // The too-large frame stopped after limit + 1 bytes; the buffer never
        // grows past that bound.
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn multibyte_utf8_is_measured_in_bytes_not_characters() {
        // Three two-byte characters: six bytes, three characters.
        let bytes = "ééé\n";
        let mut buf = Vec::new();
        assert_eq!(
            frame(&mut Cursor::new(bytes.as_bytes()), 6, &mut buf),
            FrameOutcome::Line
        );
        assert_eq!(
            frame(&mut Cursor::new(bytes.as_bytes()), 5, &mut buf),
            FrameOutcome::TooLarge
        );
    }

    #[test]
    fn unterminated_and_empty_inputs_are_distinguished() {
        let mut buf = Vec::new();
        assert_eq!(frame(&mut Cursor::new(b""), 8, &mut buf), FrameOutcome::Eof);
        assert_eq!(
            frame(&mut Cursor::new(b"{\"jsonrpc\""), 16, &mut buf),
            FrameOutcome::Unterminated
        );
        // A frame that hits the limit without a newline is oversized, not
        // truncated-but-complete.
        assert_eq!(
            frame(&mut Cursor::new(b"{\"jsonrpc\""), 8, &mut buf),
            FrameOutcome::TooLarge
        );
    }

    #[test]
    fn oversized_frame_never_reaches_the_pipeline() {
        // The frame would be a valid sanitize call if it were parsed; it is
        // padded past the limit with whitespace so only the size rejects it.
        let oversized = format!("{VALID}{}\n", " ".repeat(300));
        let (output, calls) = serve_text(&oversized, 64);
        let parsed = parsed_responses(&output);
        assert_eq!(parsed.len(), 1, "{parsed:?}");
        let error = &parsed[0];
        assert_eq!(error.get("id"), Some(&Value::Null), "{error}");
        assert_eq!(
            error.pointer("/error/code").and_then(Value::as_i64),
            Some(-32600),
            "{error}"
        );
        assert_eq!(calls, 0, "oversized input reached the detector");
        // Termination is deterministic: a valid frame after the oversized one
        // is not processed, because the session ended.
        let (output, calls) = serve_text(&format!("{oversized}{VALID}\n"), 64);
        assert_eq!(parsed_responses(&output).len(), 1);
        assert_eq!(calls, 0);
    }

    #[test]
    fn invalid_utf8_frame_is_rejected_and_the_session_continues() {
        let mut input = Vec::new();
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\"}\xff\n");
        input.extend_from_slice(VALID.as_bytes());
        input.push(b'\n');
        let (mut pipeline, calls) = counting_pipeline();
        let mut output = Vec::new();
        if let Err(error) = serve(
            &mut pipeline,
            ToolSet::all(),
            &ProcessingContext::default(),
            &mut Cursor::new(input),
            &mut output,
            4096,
        ) {
            panic!("unexpected error: {error}");
        }
        let parsed = parsed_responses(&output);
        assert_eq!(parsed.len(), 2, "{parsed:?}");
        assert_eq!(
            parsed[0].pointer("/error/code").and_then(Value::as_i64),
            Some(-32700)
        );
        assert_eq!(parsed[1].get("id").and_then(Value::as_i64), Some(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The raw frame bytes are never echoed.
        let rendered = String::from_utf8_lossy(&output);
        assert!(!rendered.contains('\u{fffd}'), "{rendered}");
    }

    #[test]
    fn exactly_at_the_limit_dispatches_and_blank_lines_are_skipped() {
        let (output, calls) = serve_text(&format!("\n  \n{VALID}\n"), VALID.len());
        assert_eq!(calls, 1);
        let parsed = parsed_responses(&output);
        assert_eq!(parsed.len(), 1, "{parsed:?}");
        assert_eq!(parsed[0].get("id").and_then(Value::as_i64), Some(1));
    }

    #[test]
    fn unterminated_trailing_frame_is_an_error_and_is_not_parsed() {
        let (output, calls) = serve_text(VALID, 4096);
        assert_eq!(calls, 0, "an unterminated frame reached the detector");
        let parsed = parsed_responses(&output);
        assert_eq!(parsed.len(), 1, "{parsed:?}");
        assert_eq!(
            parsed[0].pointer("/error/code").and_then(Value::as_i64),
            Some(-32700)
        );
    }
}
