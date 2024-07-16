use notatin::{
    err::Error,
    {parser::Parser, parser_builder::ParserBuilder},
};
use std::fs::metadata;

pub fn generate_hive_parser(target: &String, recover_deleted: bool) -> Result<Parser, Error> {
    let targethive = target.clone();
    let targetlogone = format!("{}.LOG1", target);
    let targetlogtwo = format!("{}.LOG2", target);

    let mut builder = ParserBuilder::from_path(targethive);
    
    builder.recover_deleted(recover_deleted);

    if metadata(targetlogone.clone()).is_ok() {
        builder.with_transaction_log(targetlogone);
    }
    if metadata(targetlogtwo.clone()).is_ok() {
        builder.with_transaction_log(targetlogtwo);
    }
    let parser = builder.build()?;
    Ok(parser)
}