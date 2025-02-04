use notatin::{cell_value::CellValue, parser::Parser, util::get_date_time_from_filetime};

pub fn scan(parser: &mut Parser, target: &String, controlset: u32, noisy: bool) ->  Option<(String, String, String)> {
    let mut timeline_results: Vec<String> = Vec::new();
    let mut asep_results: Vec<String> = Vec::new();
    let mut systeminfo_results: Vec<String> = Vec::new();

    let key_path = format!("ControlSet00{}\\Services", controlset);

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    for mut skey in key.read_sub_keys(parser) {
                        let last_key_write_timestamp = get_date_time_from_filetime(skey.detail.last_key_written_date_and_time());
                        let servicetype = match skey.get_value("Type") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::U32(i) => {
                                        match i {
                                            4 => "Adapter",
                                            2 => "FileSystemDriver",
                                            80 => "UserService | Win32OwnProcess",
                                            96 => "UserService | Win32ShareProcess",
                                            208 => "UserService | UserserviceInstance | Win32OwnProcess",
                                            224 => "UserService | UserserviceInstance | Win32ShareProcess",
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
                        let description = match skey.get_value("Description") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::String(s) => {
                                        &s.clone()
                                    },
                                    _ => "Unknown"
                                }
                            },
                            None => "Unknown"
                        };
                        let servicedll = match skey.get_sub_key_by_path(parser, "Parameters") {
                            Some(pk) => {
                                match pk.get_value("ServiceDll") {
                                    Some(v) => {
                                        match v.get_content().0 {
                                            CellValue::String(s) => {
                                                &s.clone()
                                            },
                                            _ => "None"
                                        }
                                    },
                                    None => "None"
                                }
                            },
                            None => "None"
                        };
                        let imagepath = match skey.get_value("ImagePath") {
                            Some(v) => {
                                match v.get_content().0 {
                                    CellValue::String(s) => &s.clone(),
                                    _ => "Unknown"
                                }
                            },
                            None => "Unknown"
                        };
                        if noisy || servicetype.contains("Win32OwnProcess") {
                            timeline_results.push(format!("services\tService \"{}\" has been modified\t{}\t{}\\{}\t{}", skey.key_name, target, key_path, skey.key_name, last_key_write_timestamp));
                        }
                        if (noisy || servicetype.contains("Win32OwnProcess")) && starttype == "Automatic" {
                            asep_results.push(format!("services\t{}\t{}\t{}\\{}\tImagePath\t{}\tType: \"{}\", Start: \"{}\", Description: \"{}\", ServiceDll: \"{}\"", imagepath, target, key_path, skey.key_name, last_key_write_timestamp, servicetype, starttype, description, servicedll));
                        }
                    }

                    Some((timeline_results.join("\n"), asep_results.join("\n"), systeminfo_results.join("\n")))
                },
                None => None
            }
        },
        Err(_e) => None
    }
}