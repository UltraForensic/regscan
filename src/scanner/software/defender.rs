use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Microsoft\\Windows Defender";

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let mut results: Vec<String> = Vec::new();

                    match key.get_sub_key_by_path(parser, "Exclusions") {
                        Some(mut sub_key) => {
                            let subsub_keys = sub_key.read_sub_keys(parser);
                            for ssk in subsub_keys {
                                let last_key_write_timestamp = get_date_time_from_filetime(ssk.detail.last_key_written_date_and_time());
                                for v in ssk.value_iter() {
                                    results.push(format!("defender\tWindows Defender {} exclusion setting found -> {}\t{}\t{}\t{}", ssk.key_name, v.detail.value_name(), target, key_path, last_key_write_timestamp));
                                }
                            }
                        },
                        None => {}
                    }

                    if results.len() != 0 {
                        Some(results.join("\n"))
                    } else {
                        None
                    }
                }
                None => None
            }
        },
        Err(_e) => None
    }
}