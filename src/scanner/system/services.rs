use notatin::{cell_value::CellValue, parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String, controlset: u32, noisy: bool) ->  Option<String> {
    let mut results: Vec<String> = Vec::new();
    let key_path = format!("ControlSet00{}\\Services", controlset);

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    for skey in key.read_sub_keys(parser) {
                        let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());
                        let imagepath = match skey.get_value("ImagePath") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::String(s) => &s.clone(),
                                    _ => "Unknown"
                                }
                            },
                            None => "Unknown"
                        };
                        let servicetype = match skey.get_value("Type") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::U32(i) => {
                                        match i {
                                            4 => "Adapter",
                                            2 => "FileSystemDriver",
                                            80 => "UserService | Win32OwnProcess",
                                            208 => "UserService | UserserviceInstance | Win32OwnProcess",
                                            256 => "InteractiveProcess",
                                            272 => "Win32OwnProcess | InteractiveProcess",
                                            1 => "KernelDriver",
                                            8 => "RecognizerDriver",
                                            16 => "Win32OwnProcess",
                                            32 => "Win32ShareProcess",
                                            _ => &i.to_string()
                                        }
                                    },
                                    _ => "Unknown"
                                }
                            },
                            None => "Unknown"
                        };
                        let starttype = match skey.get_value("Start") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::U32(i) => {
                                        match i {
                                            2 => "Automatic",
                                            0 => "Boot",
                                            4 => "Disabled",
                                            3 => "Manual",
                                            1 => "System",
                                            _ => &i.to_string()
                                        }
                                    },
                                    _ => "Unknown"
                                }
                            },
                            None => "Unknown"
                        };
                        if noisy || servicetype.contains("Win32OwnProcess") {
                            results.push(format!("services\tService \"{}\" has been created or updated (Type: \"{}\", Start: \"{}\", ImagePath: \"{}\")\t{}\t{}\\{}\t{}", skey.key_name, servicetype, starttype, imagepath, target, key_path, skey.key_name, last_key_write_timestamp));
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