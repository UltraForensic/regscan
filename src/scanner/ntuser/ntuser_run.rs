use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let mut results: Vec<String> = Vec::new();

    let key_paths = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ];

    for kpath in key_paths {
        match parser.get_key(kpath, false).unwrap() {
            Some(key) => {
                let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
                for v in key.value_iter() {
                    results.push(format!("ntuser_run\tRun key entry found (Name: \"{}\", Path: \"{}\")\t{}\t{}\t{}", v.detail.value_name(), v.get_content().0, target, kpath, last_key_write_timestamp));
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