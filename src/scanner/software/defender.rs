use notatin::{parser::Parser, cell_value::CellValue, util::get_date_time_from_filetime};

pub fn generate_timeline(parser: &mut Parser, target: &String) ->  Option<String> {
    let key_path = "Microsoft\\Windows Defender";

    match parser.get_key(&key_path, false) {
        Ok(r) => {
            match r {
                Some(mut key) => {
                    let mut results: Vec<String> = Vec::new();

                    match key.get_sub_key_by_path(parser, "Exclusions") {
                        Some(mut sub_key) => {
                            let subsub_keys = sub_key.read_sub_keys(parser);
                            for ssk in subsub_keys {
                                let last_key_write_timestamp = get_date_time_from_filetime(ssk.detail.last_key_written_date_and_time());
                                for v in ssk.value_iter() {
                                    results.push(format!("defender\tWindows Defender {} exclusion setting is set: \"{}\"\t{}\t{}\t{}", ssk.key_name, v.detail.value_name(), target, key_path, last_key_write_timestamp));
                                }
                            }
                        },
                        None => {}
                    }

                    match key.get_sub_key_by_path(parser, "Features") {
                        Some(sub_key) => {
                            let last_key_write_timestamp = get_date_time_from_filetime(sub_key.detail.last_key_written_date_and_time());
                            match sub_key.get_value("TamperProtection") {
                                Some(v) => {
                                    match v.get_content().0 {
                                        CellValue::U32(0) => { results.push(format!("defender\tWindows Defender Tamper Protection has been disabled (TamperProtection={})\t{}\t{}\t{}", v.get_content().0, target, key_path, last_key_write_timestamp)); },
                                        CellValue::U32(4) => { results.push(format!("defender\tWindows Defender Tamper Protection and Cloud Protection have been disabled (TamperProtection={})\t{}\t{}\t{}", v.get_content().0, target, key_path, last_key_write_timestamp)); }
                                        _ => {}
                                    }
                                },
                                None => {}
                            }
                        },
                        None => {}
                    }

                    match key.get_sub_key_by_path(parser, "Features\\Controls") {
                        Some(sub_key) => {
                            let mut cnt = 0;
                            let last_key_write_timestamp = get_date_time_from_filetime(sub_key.detail.last_key_written_date_and_time());
                            for _v in sub_key.value_iter() { cnt += 1; }
                            if cnt == 0 {
                                results.push(format!("defender\tSignature may have been removed from Windows Defender\t{}\t{}\t{}", target, key_path, last_key_write_timestamp));
                            }
                        },
                        None => {}
                    }

                    let policy_paths = ["Microsoft\\Windows Defender", "Policies\\Microsoft\\Windows Defender"];
                    let values = ["DisableAntiSpyware", "DisableAntiVirus"];
                    for pp in policy_paths {
                        match parser.get_key(pp, false) {
                            Ok(ockn) => {
                                match ockn {
                                    Some(pkey) => {
                                        let last_key_write_timestamp = get_date_time_from_filetime(pkey.detail.last_key_written_date_and_time());
                                        for sv in values {
                                            match pkey.get_value(sv) {
                                                Some(v) => {
                                                    match v.get_content().0 {
                                                        CellValue::U32(i) => {
                                                            if i != 0 {
                                                                results.push(format!("defender\t{} is set to {}\t{}\t{}\t{}", sv, i, target, pp, last_key_write_timestamp));
                                                            }
                                                        },
                                                        _ => {}
                                                    }
                                                },
                                                None => {}
                                            }
                                        }
                                    },
                                    None => {}
                                }
                            },
                            Err(_e) => {}
                        }
                    }

                    let rtprotection_path = "Microsoft\\Windows Defender\\Real-Time Protection";
                    match parser.get_key(rtprotection_path, false) {
                        Ok(ockn) => {
                            match ockn {
                                Some(key) => {
                                    let last_key_write_timestamp = get_date_time_from_filetime(key.detail.last_key_written_date_and_time());
                                    match key.get_value("DisableRealtimeMonitoring") {
                                        Some(v) => {
                                            if v.get_content().0 == CellValue::U32(1) {
                                                results.push(format!("defender\tReal-Time Protection is disabled\t{}\t{}\t{}", target, rtprotection_path, last_key_write_timestamp));
                                            } else {
                                                results.push(format!("defender\tDisableRealtimeMonitoring is set to {} (Real-Time Protection may have been disabled previously)\t{}\t{}\t{}", v.get_content().0, target, rtprotection_path, last_key_write_timestamp));
                                            }
                                        },
                                        None => {}
                                    }
                                },
                                None => {}
                            }
                        },
                        Err(_e) => {}
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