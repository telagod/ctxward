use std::{env, path::PathBuf};

#[tokio::main]
async fn main() {
    let config_path = parse_config_path();
    if let Err(err) = context_gurd::app::run(config_path).await {
        eprintln!("fatal: {err}");
        std::process::exit(1);
    }
}

fn parse_config_path() -> PathBuf {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config"
            && let Some(path) = args.next()
        {
            return PathBuf::from(path);
        }
    }
    env::var("CONTEXT_GURD_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/example.yaml"))
}
