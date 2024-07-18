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
                        match skey.get_value("Id") {
                            Some(v) => {
                                match parser.get_key(&format!("Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{}", v.get_content().0), false) {
                                    Ok(r2) => {
                                        match r2 {
                                            Some(key2) => {
                                                let mut result_str = format!("taskcache\tTaskCache {} found (GUID: \"{}\", ", skey.key_name, v.get_content().0);
                                                match key2.get_value("Path") {
                                                    Some(path) => {
                                                        result_str = format!("{}Path = \"{}\", ", result_str, path.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("Date") {
                                                    Some(path) => {
                                                        result_str = format!("{}Date = \"{}\", ", result_str, path.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("Author") {
                                                    Some(path) => {
                                                        result_str = format!("{}Author = \"{}\", ", result_str, path.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("URI") {
                                                    Some(path) => {
                                                        result_str = format!("{}URI = \"{}\"", result_str, path.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                results.push(format!("{})\t{}\t{}\\{}\t{}", result_str, target, key_path, skey.key_name, last_key_write_timestamp));
                                                continue;
                                            },
                                            None => {}
                                        }
                                    },
                                    Err(_e) => {}
                                }
                                results.push(format!("taskcache\tTaskCache {} found (GUID: \"{}\")\t{}\t{}\\{}\t{}", skey.key_name, v.get_content().0, target, key_path, skey.key_name, last_key_write_timestamp));
                            },
                            None => {}
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