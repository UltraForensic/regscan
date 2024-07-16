use notatin::parser::Parser;

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