mod scanner;
mod util;

use clap::Parser;
use std::fs;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Parser)]
struct Args {
    #[arg(short = 'd', long = "dir", help = "Target directory containing registry hive and transaction log files to process.")]
    target: String,
    #[arg(short, long, help = "File name to save CSV formatted results to.")]
    csv: String,
    #[arg(short, long, help = "Recover deleted entry and analyze (this option might need extra time to process).")]
    recover: bool,
    #[arg(short, long, help = "Output the results also to the standard output.")]
    stdout: bool,
}

fn main() {
    let args = Args::parse();
    let mut results: Vec<String> = Vec::new();

    results.push(String::from("Rule name,Detail,Hive,Key,Last write timestamp of the key"));

    let target_files = fs::read_dir(args.target).unwrap();
    for entry in target_files {
        let f = entry.unwrap().path().into_os_string().into_string().unwrap();

        if !(f.contains(".LOG") || fs::metadata(&f).unwrap().is_dir()) {
            match util::generate_hive_parser(&f, args.recover) {
                Ok(mut parser) => {
                    if f.contains("SYSTEM") {
                        println!("[*] Loaded {} as a SYSTEM hive", f);

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
        
                        for controlset in controlsets {
                            match scanner::system::wdigest::scan(&mut parser, &f, controlset) {
                                Some(t) => { results.push(t); },
                                None => {}
                            }
                            match scanner::system::portproxy::scan(&mut parser, &f, controlset) {
                                Some(t) => { results.push(t); },
                                None => {}
                            }
                        }
                    } else if f.contains("SOFTWARE") {
                        println!("[*] Loaded {} as a SOFTWARE hive", f);

                        let basic_info = scanner::software::initial::get_basic_info(&mut parser);
                        println!("[!] ProductName: {}", basic_info[0]);
                        println!("[!] DisplayVersion: {}", basic_info[1]);
                        println!("[!] Version: {}.{}.{}", basic_info[2], basic_info[3], basic_info[4]);
                        println!("[!] BuildLabEx: {}", basic_info[5]);
                        println!("[!] RegisteredOrganization: {}", basic_info[6]);
                        println!("[!] RegisteredOwner: {}", basic_info[7]);
                        
                        match scanner::software::gpo_history::scan(&mut parser, &f) {
                            Some(t) => { results.push(t); },
                            None => {}
                        }
                    } else if f.contains("Amcache") {
                        println!("[*] Loaded {} as a Amcache hive", f);
                    } else if f.contains("SAM") {
                        println!("[*] Loaded {} as a SAM hive", f);
                    } else if f.contains("SECURITY") {
                        println!("[*] Loaded {} as a SECURITY hive", f);
                    } else if f.contains("DEFAULT") {
                        println!("[*] Loaded {} as a DEFAULT hive", f);
                    } else if f.contains("NTUSER") {
                        println!("[*] Loaded {} as a NTUSER hive", f);

                        let scanners = [
                            scanner::ntuser::sysinternals::scan,
                            scanner::ntuser::sevenzip::scan, 
                            scanner::ntuser::gpo_history::scan,
                            scanner::ntuser::putty::scan
                        ];

                        for s in scanners {
                            match s(&mut parser, &f) {
                                Some(t) => { results.push(t); },
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

    match File::create(&args.csv) {
        Ok(mut f) => {
            match writeln!(f, "{}", results.join("\n")) {
                Ok(_t) => {
                    println!("[+] Successfully analyzed registry hive files and saved results to {}", args.csv);
                },
                Err(u) => {
                    println!("[-] Failed to write results to {}", args.csv);
                    println!("[-] {}", u)
                }
            }
        },
        Err(e) => {
            println!("[-] Failed to open file {}", args.csv);
            println!("[-] {}", e)
        }
    }

    if args.stdout {
        println!("[*] Results:");
        println!("{}", results.join("\n"));
    }
}
