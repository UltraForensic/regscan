use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path_list = ["Software\\7-Zip", "Software\\Wow6432Node\\7-Zip"];
    let mut results: Vec<String> = Vec::new();

    for key_path in key_path_list {
        match parser.get_key(&key_path, false).unwrap() {
            Some(key) => {
                let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());

                match key.get_value("Path") {
                    None => {},
                    Some(k) => {
                        results.push(format!("sevenzip\t7-Zip is installed at {}\t{}\t{}\t{}", k.get_content().0, target, key_path, last_key_write_timestamp));
                    }
                }
                match key.get_value("Path64") {
                    None => {},
                    Some(k) => {
                        results.push(format!("sevenzip\t7-Zip is installed at {} (64-bit)\t{}\t{}\t{}", k.get_content().0, target, key_path, last_key_write_timestamp));
                    }
                }
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