#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use aget_rs::app::core::{http::HttpHandler, indexd::SignResponse};
use aget_rs::features::{args::Args, running::Runnable};
use log::{error, LevelFilter};
use log4rs;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use regex::Regex;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::{thread, time::Duration};
use structopt::StructOpt;

fn init_logger(tag_name: &str, level: LevelFilter) -> Result<log4rs::Handle, String> {
  let stdout = ConsoleAppender::builder()
    .encoder(Box::new(PatternEncoder::new(
      &(format!("[{}]", tag_name) + " {d} - {h({l} - {t} - {m}{n})}"),
    )))
    .build();

  let config = Config::builder()
    .appender(Appender::builder().build("stdout", Box::new(stdout)))
    .logger(
      Logger::builder()
        .appender("stdout")
        .additive(false)
        .build("stdout", level),
    )
    .build(Root::builder().appender("stdout").build(level))
    .unwrap();

  log4rs::init_config(config).map_err(|e| {
    format!(
      "couldn't initialize log configuration. Reason: {}",
      e.description()
    )
  })
}

/// An Index Engine for Omics Data Files.
#[derive(Debug, PartialEq, StructOpt)]
#[structopt(setting=structopt::clap::AppSettings::ColoredHelp, name="Biominer Aget", author="Jingcheng Yang <yjcyxky@163.com>")]
struct Opt {
  /// Activate debug mode
  /// short and long flags (-D, --debug) will be deduced from the field's name
  #[structopt(name = "debug", short = "D", long = "debug")]
  debug: bool,

  /// Where to find the biominer api server
  #[structopt(name = "api-server", short = "a", long = "api-server")]
  api_server: Option<String>,

  /// Which file you want to download
  #[structopt(name = "guid", short = "g", long = "guid")]
  guid: String,

  // Output directory
  #[structopt(
    name = "output-dir",
    short = "o",
    long = "output-dir",
    default_value = "./"
  )]
  output_dir: String,

  /// Username for the biominer-indexd api server
  #[structopt(
    name = "username",
    short = "u",
    long = "username",
    default_value = "anonymous"
  )]
  username: String,

  /// Password for the biominer api server
  #[structopt(
    name = "password",
    short = "p",
    long = "password",
    default_value = "anonymous"
  )]
  password: String,

  #[structopt(
    name = "concurrency",
    long = "concurrency",
    help = "The number of concurrency request [default: 10]"
  )]
  pub concurrency: Option<u64>,

  #[structopt(
    name = "chunk_size",
    short = "k",
    long = "chunk_size",
    help = "The number ofinterval length of each concurrent request [default: '50m']"
  )]
  pub chunk_size: Option<String>,

  #[structopt(
    name = "timeout",
    short = "t",
    long = "timeout",
    help = "Timeout(seconds) of request [default: 60]"
  )]
  pub timeout: Option<u64>,

  #[structopt(
    name = "dns-timeout",
    long = "dns-timeout",
    help = "DNS Timeout(seconds) of request [default: 10]"
  )]
  pub dns_timeout: Option<u64>,

  #[structopt(
    name = "retries",
    long = "retries",
    help = "The maximum times of retring [default: 5]"
  )]
  pub retries: Option<u64>,

  #[structopt(
    name = "retry-wait",
    long = "retry-wait",
    help = "The seconds between retries [default: 0]"
  )]
  pub retry_wait: Option<u64>,
}

lazy_static! {
  static ref REGEX_LISTS: HashMap<&'static str, Regex> = {
    let mut m = HashMap::new();
    m.insert("guid", Regex::new(r"^biominer.[0-9a-z\-_]{5,16}/[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$").unwrap());
    m
  };
}

fn validate_regex(regex_name: &str, value: &str) -> Result<(), Box<dyn Error>> {
  if !REGEX_LISTS.get(regex_name).unwrap().is_match(value) {
    return Err(format!("{} is not a valid biominer-indexd {}. e.g.: biominer.fudan-pgx/cdf6b997-1e13-49b4-83ea-7bbddbdba0da", 
                       value, regex_name).into());
  }
  Ok(())
}

fn main() {
  let args = Opt::from_args();

  let log_result = if args.debug {
    init_logger("biominer-aget", LevelFilter::Debug)
  } else {
    init_logger("biominer-aget", LevelFilter::Info)
  };

  if let Err(log) = log_result {
    error!("Log initialization error, {}", log);
    std::process::exit(1);
  };

  validate_regex("guid", &args.guid).unwrap_or_else(|e| {
    error!("{}", e);
    std::process::exit(1);
  });

  let api_server = if args.api_server.is_none() {
    "https://api.3steps.cn/biominer-indexd".to_string()
    // "http://localhost:3000".to_string()
  } else {
    args.api_server.unwrap()
  };

  let sign_resp = SignResponse::new(&api_server, &args.guid);
  trace!("Signed Response: {:?}", sign_resp);

  let output_dir = Path::new(&args.output_dir);
  let output_file = output_dir.join(&sign_resp.filename);
  let rc_aget_file = output_dir.join(&format!("{}{}", sign_resp.filename, ".rc.aget"));
  if output_file.exists() && !rc_aget_file.exists() {
    warn!(
      "{} exists, please remove it and retry!",
      &output_file.to_str().unwrap()
    );
    std::process::exit(1);
  } else {
    info!(
      "{} exists, but continue transferring from breakpoint.",
      &output_file.to_str().unwrap()
    );
  }

  let args = sign_resp.into_args(
    args.concurrency,
    args.chunk_size,
    args.timeout,
    args.dns_timeout,
    args.retries,
    args.retry_wait,
    args.debug,
    &output_dir,
  );

  for i in 0..args.retries() + 1 {
    if i != 0 {
      println!("Retry {}", i);
    }

    let httphandler = HttpHandler::new(&args).unwrap();
    let result = httphandler.run();

    if let Err(err) = result {
      error!("Error: {}", err);
      // Retry
      let retrywait = args.retry_wait();
      thread::sleep(Duration::from_secs(retrywait));
      continue;
    } else {
      // Success
      return;
    }
  }

  // All retries fail
  std::process::exit(1);
}
