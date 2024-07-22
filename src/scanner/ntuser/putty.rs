use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
    let mut results: Vec<String> = Vec::new();
    let key_path = "Software\\SimonTatham\\PuTTY";

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let mut last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
                    results.push(format!("putty\tPuTTY has been used by this user\t{}\t{}\t{}", target, key_path, last_key_write_timestamp));

                    match key.get_sub_key_by_path(parser, "SshHostKeys") {
                        Some(subkey) => {
                            last_key_write_timestamp = get_date_time_from_filetime(subkey.detail.last_key_written_date_and_time());
                            for v in subkey.value_iter() {
                                results.push(format!("putty\tSshHostKeys: {} -> {}\t{}\t{}\t{}", v.detail.value_name(), v.get_content().0, target, key_path, last_key_write_timestamp));
                            }
                        },
                        None => {}
                    }

                    if results.len() != 0 {
                        Some(results.join("\n"))
                    } else {
                        None
                    }
                },
                None => None
            }
        },
        Err(_e) => None
    }
}