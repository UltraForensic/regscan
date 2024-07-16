use notatin::{parser::Parser, cell_value::CellValue, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String, controlset: u32) ->  Option<String> {
    let key_path = format!("ControlSet00{}\\Control\\SecurityProviders\\WDigest", controlset);
    let key = parser.get_key(&key_path, false).unwrap().unwrap();
    let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());

    match key.get_value("UseLogonCredential") {
        None => None,
        Some(k) => {
            match k.get_content().0 {
                CellValue::U32(v) => {
                    // Alerts even if data of value `UseLogonCredential` is other than 1
                    Some(format!("wdigest\tUseLogonCredential = {}\t{}\t{}\t{}", v, target, key_path, last_key_write_timestamp))
                },
                _ => None
            }
        }
    }
}