use chrono::Utc;
use notatin::{parser::Parser, cell_value::CellValue, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
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
                                        let mut path_val = String::new();
                                        let mut author_val = String::new();
                                        let mut uri_val = String::new();
                                        let mut c_ts = Utc::now();
                                        let mut l_ts = Utc::now();
                                        let mut d_ts = Utc::now();
                                        match r2 {
                                            Some(key2) => {
                                                match key2.get_value("Path") {
                                                    Some(path) => {
                                                        path_val = format!("{}", path.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("DynamicInfo") {
                                                    Some(dyninfo) => {
                                                        match dyninfo.get_content().0 {
                                                            CellValue::Binary(d) => {
                                                                c_ts = get_date_time_from_filetime(u64::from_le_bytes(d[4..12].try_into().unwrap()));
                                                                l_ts = get_date_time_from_filetime(u64::from_le_bytes(d[12..20].try_into().unwrap()));
                                                                d_ts = get_date_time_from_filetime(u64::from_le_bytes(d[28..36].try_into().unwrap()));
                                                            },
                                                            _ => {}
                                                        }
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("Author") {
                                                    Some(author) => {
                                                        author_val = format!("{}", author.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                match key2.get_value("URI") {
                                                    Some(uri) => {
                                                        uri_val = format!("{}", uri.get_content().0);
                                                    },
                                                    None => {}
                                                }
                                                results.push(format!("taskcache\tCreation timestamp of task \"{}\" (GUID: \"{}\", Path = \"{}\", Author = \"{}\", URI = \"{}\")\t{}\t{}\\{}\t{}", skey.key_name, v.get_content().0, path_val, author_val, uri_val, target, key_path, skey.key_name, c_ts));
                                                results.push(format!("taskcache\tLast execution timestamp of task \"{}\" (GUID: \"{}\", Path = \"{}\", CreationDate = \"{}\", Author = \"{}\", URI = \"{}\")\t{}\t{}\\{}\t{}", skey.key_name, v.get_content().0, path_val, c_ts, author_val, uri_val, target, key_path, skey.key_name, l_ts));
                                                results.push(format!("taskcache\tLast completion timestamp of task \"{}\" (GUID: \"{}\", Path = \"{}\", CreationDate = \"{}\", Author = \"{}\", URI = \"{}\")\t{}\t{}\\{}\t{}", skey.key_name, v.get_content().0, path_val, c_ts, author_val, uri_val, target, key_path, skey.key_name, d_ts));
                                                continue;
                                            },
                                            None => {}
                                        }
                                    },
                                    Err(_e) => {}
                                }
                                results.push(format!("taskcache\tLast execution timestamp of task \"{}\" (GUID: \"{}\", DELETED: Possible Immediate Task)\t{}\t{}\\{}\t{}", skey.key_name, v.get_content().0, target, key_path, skey.key_name, last_key_write_timestamp));
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