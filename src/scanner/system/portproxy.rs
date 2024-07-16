use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String, controlset: u32) ->  Option<String> {
    let key_path = format!("ControlSet00{}\\Services\\PortProxy\\v4tov4\\tcp", controlset);
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(key) => {
                    let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());

                    let mut results: Vec<String> = Vec::new();
                    for value in key.value_iter() {
                        results.push(format!("portproxy\tPackets to {} will be transferred to {}\t{}\t{}\t{}", value.detail.value_name(), value.get_content().0, target, key_path, last_key_write_timestamp));
                    }
                    Some(results.join("\n"))
                }
                None => None
            }
        },
        Err(_e) => None
    }
}