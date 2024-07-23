use hex;
use notatin::parser::Parser;
use std::fs;

// ref: https://github.com/MichaelGrafnetter/DSInternals/blob/39ee8a69bbdc1cfd12c9afdd7513b4788c4895d4/Src/DSInternals.DataStore/Cryptography/BootKeyRetriever.cs
const KEY_PERMUTATION: [u8; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

pub fn get_basic_info(parser: &mut Parser) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();

    let key_paths = [
        "ControlSet001\\Control\\ComputerName\\ComputerName",
        "ControlSet001\\Control\\TimeZoneInformation"
    ];
    let value_names = [
        "ComputerName",
        "TimeZoneKeyName"
    ];

    for i in 0..key_paths.len() {
        let key = parser.get_key(key_paths[i], false).unwrap().unwrap();
        results.push(format!("{}", key.get_value(value_names[i]).unwrap().get_content().0));
    }

    results
}

pub fn get_bootkey(parser: &mut Parser, target: &String) -> Option<[u8; 16]> {
    let mut key = parser.get_key("ControlSet001\\Control\\Lsa", false).unwrap().unwrap();

    let subkeys = ["JD", "Skew1", "GBG", "Data"];

    let mut collected_values: String = String::new();
    let mut bootkey: [u8; 16] = Default::default();

    for i in 0..4 {
        match key.get_sub_key_by_path(parser, subkeys[i]) {
            Some(subkey) => {
                let class_name_start_offset = 4096 + 4 + subkey.detail.class_name_offset_relative();
                let class_name_end_offset = class_name_start_offset + subkey.detail.class_name_size() as i32;
                let class_name: Vec<u8> = fs::read(target).unwrap()[class_name_start_offset as usize..class_name_end_offset as usize].to_vec();
                let class_name_packets = class_name
                    .chunks(2)
                    .map(|e| u16::from_le_bytes(e.try_into().unwrap()))
                    .collect::<Vec<_>>();
                collected_values = format!("{}{}", collected_values, String::from_utf16_lossy(&class_name_packets));
            },
            None => { return None; }
        }
    }
    
    let cv = hex::decode(collected_values.as_str()).unwrap();
    for i in 0..16 {
        bootkey[i] = cv[usize::from(KEY_PERMUTATION[i])];
    }
    
    Some(bootkey)
}