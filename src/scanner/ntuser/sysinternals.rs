use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Software\\SysInternals";
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let sub_keys = key.read_sub_keys(parser);
                    let mut results: Vec<String> = Vec::new();

                    for skey in sub_keys {
                        let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());

                        results.push(format!("sysinternals\tSysInternals {} use has been detected\t{}\t{}\t{}", skey.key_name, target, key_path, last_key_write_timestamp));
                    }

                    Some(results.join("\n"))
                }
                None => None
            }
        },
        Err(_e) => None
    }
}