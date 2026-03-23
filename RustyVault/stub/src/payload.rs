use std::env;
use std::fs::File;
use std::io::Read;
use crate::config::{MAGIC_DELIMITER, PARTIAL_KEY};

pub fn extract_and_decrypt(corrupted_mode: bool) -> Option<Vec<u8>> {
    let current_exe = env::current_exe().ok()?;
    let mut file = File::open(current_exe).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;

    let pos = buffer.windows(MAGIC_DELIMITER.len()).rposition(|w| w == MAGIC_DELIMITER)?;
    let encrypted_data = &buffer[pos + MAGIC_DELIMITER.len()..];
    
    let final_key = if corrupted_mode { PARTIAL_KEY ^ 0xFF } else { PARTIAL_KEY };
    Some(encrypted_data.iter().map(|&b| b ^ final_key).collect())
}
