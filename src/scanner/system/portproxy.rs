use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn get_portproxy(parser: &mut Parser, controlset: u32) ->  Option<String> {
    let key_path = format!("ControlSet00{}\\Services\\PortProxy\\v4tov4\\tcp", controlset);
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(key) => {
                    let mut results: Vec<String> = Vec::new();
                    for value in key.value_iter() {
                        results.push(format!("portproxy\t\"{}\" -> \"{}\"", value.detail.value_name(), value.get_content().0));
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

pub fn generate_timeline(parser: &mut Parser, target: &String, controlset: u32) ->  Option<String> {
    let key_path = format!("ControlSet00{}\\Services\\PortProxy\\v4tov4\\tcp", controlset);
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(key) => {
                    let mut e = false;
                    for _v in key.value_iter() { e = true; }
                    if e {
                        let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
                        Some(String::from(format!("portproxy\tLast write timestamp of PortProxy setting\t{}\t{}\t{}", target, key_path, last_key_write_timestamp)))
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