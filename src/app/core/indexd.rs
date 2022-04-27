use crate::common::{
  character::escape_nonascii,
  errors::Error,
  liberal::ParseLiteralNumber,
  net::{Method, Uri},
  tasks::TaskType,
};
use crate::features::args::Args;
use log::error;
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
  fmt,
  path::{Path, PathBuf},
  time::Duration,
};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Default)]
pub struct Hash {
  pub id: u64,
  pub hash_type: String, // Max 16 characters, md5, sha1, sha256, sha512, crc32, crc64, etag, etc
  pub hash: String,      // Max 128 characters
  pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignData {
  pub header: Vec<String>, // ["Content-Type: application/json"] or ["Content-Type: application/x-www-form-urlencoded"]
  pub data: Vec<String>,   // ["username=admin", "password=admin"]
  pub baseurl: String,     // "http://localhost:8080"
  pub method: String,      // "GET" or "POST"
  pub params: Vec<String>, // ["AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE", "Signature=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SignResponse {
  pub sign: SignData,
  pub size: u64,
  // At least one of the hashes exists.
  pub hashes: Vec<Hash>,
  pub filename: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndexdCmdArgs {
  pub header: Vec<String>,
  pub data: String,
  pub method: String,
  pub params: Vec<String>,
  pub baseurl: String,
  pub concurrency: Option<u64>,
  pub chunk_size: Option<String>,
  pub timeout: Option<u64>,
  pub dns_timeout: Option<u64>,
  pub retries: Option<u64>,
  pub retry_wait: Option<u64>,
  pub size: u64,
  pub debug: bool,
  // At least one of the hashes exists.
  pub hashes: Vec<Hash>,
  pub filename: String,
}

impl SignResponse {
  pub fn new(api_server: &str, guid: &str, which_repo: &str) -> SignResponse {
    let query_guid = guid.split("/").collect::<Vec<&str>>()[1];
    let endpoint = format!("{}/{}/{}?which_repo={}", api_server, "api/v1/files", query_guid, which_repo);
    let client = reqwest::blocking::Client::new();
    let body = match client.post(&endpoint).send() {
      Ok(resp) => {
        let status = resp.status();
        let content = resp.text().unwrap();
        if status != reqwest::StatusCode::CREATED {
          error!("Error: not found the guid {}, Reason: {}", guid, content);
          std::process::exit(1);
        } else {
          let sign_response: SignResponse = serde_json::from_str(&content).unwrap();
          sign_response
        }
      }
      Err(e) => {
        error!("Failed to get file from {}. Reason: {}", &endpoint, e);
        std::process::exit(1);
      }
    };

    return body;
  }

  pub fn data(&self) -> String {
    self.sign.data.join("&")
  }

  pub fn into_args(
    &self,
    concurrency: Option<u64>,
    chunk_size: Option<String>,
    timeout: Option<u64>,
    dns_timeout: Option<u64>,
    retries: Option<u64>,
    retry_wait: Option<u64>,
    debug: bool,
    output_dir: &Path,
  ) -> IndexdCmdArgs {
    IndexdCmdArgs {
      header: self.sign.header.clone(),
      data: self.data(),
      method: self.sign.method.clone(),
      params: self.sign.params.clone(),
      baseurl: self.sign.baseurl.clone(),
      concurrency: concurrency,
      chunk_size: chunk_size,
      timeout: timeout,
      dns_timeout: dns_timeout,
      retries: retries,
      retry_wait: retry_wait,
      size: self.size,
      debug: debug,
      hashes: self.hashes.clone(),
      filename: output_dir
        .join(&self.filename.clone())
        .to_str()
        .unwrap()
        .to_string(),
    }
  }
}

impl Args for IndexdCmdArgs {
  /// Path of output
  fn output(&self) -> PathBuf {
    Path::new(&self.filename).to_path_buf()
  }

  /// Request method for http
  fn method(&self) -> Method {
    match self.method.to_uppercase().as_str() {
      "GET" => Method::GET,
      "POST" => Method::POST,
      _ => panic!("{:?}", Error::UnsupportedMethod(self.method.to_string())),
    }
  }

  /// The uri of a task
  fn uri(&self) -> Uri {
    escape_nonascii(&self.baseurl)
      .parse()
      .expect("URL is unvalidable")
  }

  /// The data for http post request
  fn data(&self) -> Option<&str> {
    if self.data.len() > 0 {
      Some(self.data.as_str())
    } else {
      None
    }
  }

  /// Request headers
  fn headers(&self) -> Vec<(&str, &str)> {
    let mut headers = Vec::new();
    for item in &self.header {
      let mut header = item.split(":");
      let key = header.next().unwrap().trim();
      let value = header.next().unwrap().trim();
      headers.push((key, value));
    }

    headers
  }

  fn proxy(&self) -> Option<&str> {
    None
  }

  // Set request timeout
  //
  // Request timeout is the total time before a response must be received.
  // Default value is 60 seconds.
  fn timeout(&self) -> Duration {
    match self.timeout {
      Some(timeout) => Duration::from_secs(timeout),
      None => Duration::from_secs(60),
    }
  }

  fn dns_timeout(&self) -> Duration {
    match self.dns_timeout {
      Some(timeout) => Duration::from_secs(timeout),
      None => Duration::from_secs(60),
    }
  }

  fn keep_alive(&self) -> Duration {
    Duration::from_secs(60)
  }

  fn lifetime(&self) -> Duration {
    Duration::from_secs(0)
  }

  // Always return `true`
  fn disable_redirects(&self) -> bool {
    true
  }

  /// The number of concurrency
  fn concurrency(&self) -> u64 {
    match self.concurrency {
      Some(concurrency) => concurrency,
      None => 10,
    }
  }

  /// The chunk size of each concurrency for http task
  fn chunk_size(&self) -> u64 {
    self
      .chunk_size
      .as_deref()
      .map(|i| i.literal_number().unwrap())
      .unwrap_or_else(|| {
        self
          .chunk_size
          .as_ref()
          .map(|i| i.as_str().literal_number().unwrap())
          .unwrap_or(1024 * 1024 * 50)
      }) // 50m
  }

  /// The number of retry of a task, default is 5
  fn retries(&self) -> u64 {
    self.retries.unwrap_or_else(|| self.retries.unwrap_or(0))
  }

  /// The internal of each retry, default is zero
  fn retry_wait(&self) -> u64 {
    self
      .retry_wait
      .unwrap_or_else(|| self.retry_wait.unwrap_or(0))
  }

  /// Task type
  fn task_type(&self) -> TaskType {
    TaskType::HTTP
  }

  /// To debug mode, if it returns true
  fn debug(&self) -> bool {
    self.debug
  }

  /// To quiet mode, if it return true
  fn quiet(&self) -> bool {
    false
  }
}
