use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup";
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let sub_keys = key.read_sub_keys(parser);
                    let mut results: Vec<String> = Vec::new();

                    for mut skey in sub_keys {
                        let sub_keys2 = skey.read_sub_keys(parser);
                        for skey2 in sub_keys2 {
                            let parameters = skey2.get_value("Parameters").unwrap().get_content().0;
                            let script = skey2.get_value("Script").unwrap().get_content().0;
                            let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());

                            results.push(format!("startupscripts\tStartup Script of \"{}\" has been configured (Parameters: \"{}\")\t{}\t{}\t{}", script, parameters, target, skey2.path, last_key_write_timestamp));
                        }
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

pub fn get_asep(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Microsoft\\Windows\\CurrentVersion\\Group Policy\\Scripts\\Startup";
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let sub_keys = key.read_sub_keys(parser);
                    let mut results: Vec<String> = Vec::new();

                    for mut skey in sub_keys {
                        let sub_keys2 = skey.read_sub_keys(parser);
                        for skey2 in sub_keys2 {
                            let parameters = skey2.get_value("Parameters").unwrap().get_content().0;
                            let script = skey2.get_value("Script").unwrap().get_content().0;
                            let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());

                            results.push(format!("startupscripts\t{}\t{}\t{}\t{}\t{}\tParameters: \"{}\"", script, target, skey2.path, "*", last_key_write_timestamp, parameters));
                        }
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