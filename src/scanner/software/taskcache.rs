use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let sub_keys = key.read_sub_keys(parser);
                    let mut results: Vec<String> = Vec::new();

                    for skey in sub_keys {
                        let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());
                        results.push(format!("taskcache\tTaskCache {} found\t{}\t{}\\{}\t{}", skey.key_name, target, key_path, skey.key_name, last_key_write_timestamp));
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