use crate::config::Config;
use crate::util::spacetime_dns;
use clap::Arg;
use clap::ArgMatches;

pub fn cli() -> clap::Command<'static> {
    clap::Command::new("call")
        .about("Invokes a reducer function in a database")
        .arg(Arg::new("database").required(true))
        .arg(Arg::new("function_name").required(true))
        .arg(Arg::new("arguments").required(true).help("arguments as a JSON array"))
        .after_help("Run `spacetime help call` for more detailed information.\n")
}

pub async fn exec(config: Config, args: &ArgMatches) -> Result<(), anyhow::Error> {
    let database = args.value_of("database").unwrap();
    let address = if let Ok(address) = spacetime_dns(&config, database).await {
        address
    } else {
        database.to_string()
    };

    let function_name = args.value_of("function_name").unwrap();
    let arg_json = args.value_of("arg_json").unwrap_or("{}");

    let client = reqwest::Client::new();
    let res = client
        .post(format!(
            "http://{}/database/call/{}/{}",
            config.host, address, function_name
        ))
        .body(arg_json.to_owned())
        .send()
        .await?;

    res.error_for_status()?;

    Ok(())
}
