use notatin::parser::Parser;

pub fn get_basic_info(parser: &mut Parser) -> Vec<String> {
    let values = ["ProductName", "DisplayVersion", "CurrentMajorVersionNumber", "CurrentMinorVersionNumber", "CurrentBuild", "BuildLabEx", "RegisteredOrganization", "RegisteredOwner"];

    let mut results: Vec<String> = Vec::new();
    let key = parser.get_key("Microsoft\\Windows NT\\CurrentVersion", false).unwrap().unwrap();

    for v in values {
        results.push(format!("{}", key.get_value(v).unwrap().get_content().0));
    }

    results
}