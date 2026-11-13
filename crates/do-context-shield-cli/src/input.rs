//! Shared input handling for one-shot commands.

use std::io::{self, Read};

/// Read the complete stdin payload used by one-shot text commands.
///
/// # Errors
///
/// Returns an I/O error when stdin cannot be read as UTF-8 text.
pub(crate) fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}
