//! Shared wire types for the newline-delimited JSON protocol.

use serde::Serialize;

/// One detected entity as sent to a child process.
#[derive(Serialize)]
pub(crate) struct WireEntity<'a> {
    pub(crate) kind: &'a str,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) value: &'a str,
    pub(crate) confidence: f32,
}
