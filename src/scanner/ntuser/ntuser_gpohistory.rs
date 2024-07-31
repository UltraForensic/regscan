use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History";
    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let sub_keys = key.read_sub_keys(parser);
                    let mut results: Vec<String> = Vec::new();

                    for mut skey in sub_keys {
                        let sub_keys2 = skey.read_sub_keys(parser);
                        for skey2 in sub_keys2 {
                            let displayname = skey2.get_value("DisplayName").unwrap().get_content().0;
                            let filesyspath = skey2.get_value("FileSysPath").unwrap().get_content().0;
                            let link = skey2.get_value("Link").unwrap().get_content().0;
                            let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());

                            results.push(format!("ntuser_gpohistory\tGPO history of \"{}\" has been generated (FileSysPath: \"{}\", Link: \"{}\")\t{}\t{}\t{}", displayname, filesyspath, link, target, skey2.path, last_key_write_timestamp));
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