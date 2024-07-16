use notatin::{parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String) ->  Option<String> {
    let mut results: Vec<String> = Vec::new();

    let key_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ];

    for kpath in key_paths {
        let key = parser.get_key(kpath, false).unwrap().unwrap();
        let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
        for v in key.value_iter() {
            results.push(format!("software_run\tRun key entry found (Name: \"{}\", Path: \"{}\")\t{}\t{}\t{}", v.detail.value_name(), v.get_content().0, target, kpath, last_key_write_timestamp));
        }
    }

    if results.len() != 0 {
        Some(results.join("\n"))
    } else {
        None
    }
}