use notatin::{parser::Parser, cell_value::CellValue, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let mut results: Vec<String> = Vec::new();
    let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(key) => {
                    for v in key.value_iter() {
                        println!("{:?}", v.get_content().0);
                        if v.detail.value_name() != "MRUList".to_string() {
                            match v.get_content().0 {
                                CellValue::String(s) => {
                                    let mut chars = s.chars();
                                    chars.next_back();
                                    chars.next_back();
                                    let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
                                    results.push(format!("runmru\tRunMRU record found: \"{}\"\t{}\t{}\t{}", chars.as_str(), target, key_path, last_key_write_timestamp));
                                },
                                _ => {
                                    println!("[-] Weird value inside RunMRU record: {:?}", v.get_content().0);
                                }
                            }
                        }
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