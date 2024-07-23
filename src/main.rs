mod scanner;
mod util;

use chrono::Utc;
use clap::Parser;
use hex;
use std::fs;
use std::fs::File;
use std::io::Write;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Args {
    #[arg(short, long, help = "Target directory containing registry hive and transaction log files to process.")]
    target: String,
    #[arg(short, long, help = "Output directory to save TSV formatted timeline_results to.")]
    outdir: String,
    #[arg(short, long, help = "Disable automatic filter on some rule (eg. services) and output all timeline_results")]
    noisy: bool,
    #[arg(short, long, help = "Recover deleted entry and analyze (this option might need extra time to process).")]
    recover: bool
}

fn main() {
    let args = Args::parse();

    // Results
    let mut timeline_results: Vec<String> = Vec::new();
    let mut asep_results: Vec<String> = Vec::new();
    let mut systeminfo: Vec<String> = Vec::new();
    let mut localaccounts: Vec<String> = Vec::new();

    let mut bootkey: [u8; 16] = Default::default();
    let mut sam_hive_path = String::from("");

    println!("[!] regscan v{} started", VERSION);
    let timestamp_str = Utc::now().format("%Y%m%d%H%M%S%Z").to_string();

    timeline_results.push(String::from("Rule name\tDetail\tHive\tKey\tTimestamp"));
    asep_results.push(String::from("Rule name\tPath\tHive\tKey\tValue\tLast write timestamp of the key\tRemarks"));
    localaccounts.push(String::from("RID\tUsername\tFull Name\tComment\tUser Comment\tNTLM Hash"));

    let target_files = fs::read_dir(args.target).unwrap();
    for entry in target_files {
        let f = entry.unwrap().path().into_os_string().into_string().unwrap();

        if !(f.contains(".LOG") || fs::metadata(&f).unwrap().is_dir()) {
            match util::generate_hive_parser(&f, args.recover) {
                Ok(mut parser) => {
                    if f.contains("SYSTEM") {
                        println!("[*] Loaded {} as a SYSTEM hive", f);

                        let basic_info = scanner::system::initial::get_basic_info(&mut parser);
                        systeminfo.push(format!("ComputerName\t{}", basic_info[0]));
                        systeminfo.push(format!("TimeZoneKeyName\t{}", basic_info[1]));

                        match scanner::system::initial::get_bootkey(&mut parser, &f) {
                            Some(b) => {
                                bootkey = b;
                                systeminfo.push(format!("Boot Key\t{}", hex::encode(bootkey)));
                            },
                            None => {}
                        }

                        let mut controlsets = Vec::new();
                        match parser.get_key("ControlSet001", false).unwrap() {
                            Some(_t) => {
                                controlsets.push(1);
                            },
                            None => {}
                        }
                        match parser.get_key("ControlSet002", false).unwrap() {
                            Some(_t) => {
                                controlsets.push(2);
                            },
                            None => {}
                        }

                        let timeline_scanners = [
                            scanner::system::wdigest::generate_timeline,
                            scanner::system::portproxy::generate_timeline
                        ];
        
                        for controlset in controlsets {
                            for s in timeline_scanners {
                                match s(&mut parser, &f, controlset) {
                                    Some(t) => { timeline_results.push(t); },
                                    None => {}
                                }
                            }
                            match scanner::system::services::generate_timeline(&mut parser, &f, controlset, args.noisy) {
                                Some(t) => { timeline_results.push(t); },
                                None => {}
                            }
                            match scanner::system::services::get_asep(&mut parser, &f, controlset, args.noisy) {
                                Some(t) => { asep_results.push(t); },
                                None => {}
                            }
                            match scanner::system::portproxy::get_portproxy(&mut parser, controlset) {
                                Some(t) => { systeminfo.push(t); },
                                None => {}
                            }
                        }
                    } else if f.contains("SOFTWARE") {
                        println!("[*] Loaded {} as a SOFTWARE hive", f);

                        let basic_info = scanner::software::initial::get_basic_info(&mut parser);
                        systeminfo.push(format!("ProductName\t{}", basic_info[0]));
                        systeminfo.push(format!("DisplayVersion\t{}", basic_info[1]));
                        systeminfo.push(format!("Version\t{}.{}.{}", basic_info[2], basic_info[3], basic_info[4]));
                        systeminfo.push(format!("BuildLabEx\t{}", basic_info[5]));
                        systeminfo.push(format!("RegisteredOrganization\t{}", basic_info[6]));
                        systeminfo.push(format!("RegisteredOwner\t{}", basic_info[7]));
                        
                        let timeline_scanners = [
                            scanner::software::software_gpohistory::generate_timeline,
                            scanner::software::defender::generate_timeline,
                            scanner::software::taskcache::generate_timeline,
                            scanner::software::startupscripts::generate_timeline
                        ];
                        let asep_scanners = [
                            scanner::software::software_run::get_asep,
                            scanner::software::startupscripts::get_asep
                        ];

                        for s in timeline_scanners {
                            match s(&mut parser, &f) {
                                Some(t) => { timeline_results.push(t); },
                                None => {}
                            }
                        }
                        for s in asep_scanners {
                            match s(&mut parser, &f) {
                                Some(t) => { asep_results.push(t); },
                                None => {}
                            }
                        }
                    } else if f.contains("Amcache") {
                        println!("[*] Loaded {} as a Amcache hive", f);
                    } else if f.contains("SAM") {
                        sam_hive_path = f.clone();
                    } else if f.contains("SECURITY") {
                        println!("[*] Loaded {} as a SECURITY hive", f);
                    } else if f.contains("DEFAULT") {
                        println!("[*] Loaded {} as a DEFAULT hive", f);
                    } else if f.contains("NTUSER") {
                        println!("[*] Loaded {} as a NTUSER hive", f);

                        let timeline_scanners = [
                            scanner::ntuser::sysinternals::generate_timeline,
                            scanner::ntuser::sevenzip::generate_timeline, 
                            scanner::ntuser::ntuser_gpohistory::generate_timeline,
                            scanner::ntuser::putty::generate_timeline,
                            scanner::ntuser::logonscripts::generate_timeline
                        ];
                        let asep_scanners = [
                            scanner::ntuser::ntuser_run::get_asep,
                            scanner::ntuser::logonscripts::get_asep
                        ];

                        for s in timeline_scanners {
                            match s(&mut parser, &f) {
                                Some(t) => { timeline_results.push(t); },
                                None => {}
                            }
                        }
                        for s in asep_scanners {
                            match s(&mut parser, &f) {
                                Some(t) => { asep_results.push(t); },
                                None => {}
                            }
                        }
                    } else if f.contains("UsrClass") {
                        println!("[*] Loaded {} as a UsrClass hive", f);
                    } else {
                        println!("[-] Failed to load {}", f);
                        println!("[-] Unknown registry hive type");
                    }
                },
                Err(e) => {
                    println!("[-] Failed to load {}", f);
                    println!("[-] {}", e);
                }
            }
        }
    }

    if sam_hive_path.len() != 0 {
        match util::generate_hive_parser(&sam_hive_path, args.recover) {
            Ok(mut parser) => {
                println!("[*] Loaded {} as a SAM hive", sam_hive_path);
                let rids = scanner::sam::get_rids(&mut parser);

                match scanner::sam::get_syskey(&mut parser, bootkey) {
                    Some(syskey) => {
                        systeminfo.push(format!("SysKey\t{}", hex::encode(syskey)));
                        for rid in rids {
                            match scanner::sam::get_account_info(&mut parser, rid) {
                                Some(t) => { localaccounts.push(t); },
                                None => {}
                            }
                        }
                    },
                    None => {
                        println!("[-] Failed to obtain syskey! Something is wrong :(");
                    }
                }
            },
            Err(e) => {
                println!("[-] Failed to load {}", sam_hive_path);
                println!("[-] {}", e);
            }
        }
    }

    // Output results under specified directory
    match fs::create_dir_all(&args.outdir) {
        Ok(_r) => {
            let timeline_path = format!("{}/{}_regscan_Timeline.tsv", &args.outdir, timestamp_str);
            match File::create(&timeline_path) {
                Ok(mut f) => {
                    match writeln!(f, "{}", timeline_results.join("\n")) {
                        Ok(_t) => {
                            println!("[+] Successfully saved timeline to {}", timeline_path);
                        },
                        Err(u) => {
                            println!("[-] Failed to write timeline to {}", timeline_path);
                            println!("[-] {}", u)
                        }
                    }
                },
                Err(e) => {
                    println!("[-] Failed to open file {}", timeline_path);
                    println!("[-] {}", e)
                }
            }
            let asep_path = format!("{}/{}_regscan_ASEPs.tsv", &args.outdir, timestamp_str);
            match File::create(&asep_path) {
                Ok(mut f) => {
                    match writeln!(f, "{}", asep_results.join("\n")) {
                        Ok(_t) => {
                            println!("[+] Successfully saved ASEPs to {}", asep_path);
                        },
                        Err(u) => {
                            println!("[-] Failed to write ASEPs to {}", asep_path);
                            println!("[-] {}", u)
                        }
                    }
                },
                Err(e) => {
                    println!("[-] Failed to open file {}", asep_path);
                    println!("[-] {}", e)
                }
            }
            let systeminfo_path = format!("{}/{}_regscan_SystemInfo.tsv", &args.outdir, timestamp_str);
            match File::create(&systeminfo_path) {
                Ok(mut f) => {
                    match writeln!(f, "{}", systeminfo.join("\n")) {
                        Ok(_t) => {
                            println!("[+] Successfully saved system information to {}", systeminfo_path);
                        },
                        Err(u) => {
                            println!("[-] Failed to write system information to {}", systeminfo_path);
                            println!("[-] {}", u)
                        }
                    }
                },
                Err(e) => {
                    println!("[-] Failed to open file {}", systeminfo_path);
                    println!("[-] {}", e)
                }
            }
            let localaccounts_path = format!("{}/{}_regscan_LocalAccounts.tsv", &args.outdir, timestamp_str);
            match File::create(&localaccounts_path) {
                Ok(mut f) => {
                    match writeln!(f, "{}", localaccounts.join("\n")) {
                        Ok(_t) => {
                            println!("[+] Successfully saved local accounts information to {}", localaccounts_path);
                        },
                        Err(u) => {
                            println!("[-] Failed to write local accounts information to {}", localaccounts_path);
                            println!("[-] {}", u)
                        }
                    }
                },
                Err(e) => {
                    println!("[-] Failed to open file {}", localaccounts_path);
                    println!("[-] {}", e)
                }
            }
        },
        Err(e) => {
            println!("[-] Failed to create directory on {}", args.outdir);
            println!("[-] {}", e)
        }
    }
}
