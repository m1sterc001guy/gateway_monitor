use std::{cmp::min, time::Duration};

use chrono::{DateTime, Local};
use clap::Parser;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio::time;
use url::Url;

#[derive(Parser, Debug)]
struct GatewayMonitorOpts {
    /// Gateway HTTP Address
    #[arg(long = "gateway-addr", env = "GATEWAY_ADDRESS")]
    gateway_addr: Url,

    /// Gateway Password
    #[arg(long = "password", env = "GATEWAY_PASSWORD")]
    password: String,

    /// Gateway Password
    #[arg(long = "interval", default_value_t = 300)]
    interval: u64,

    /// Telegram Bot token
    #[arg(long = "bot-token", env = "BOT_TOKEN")]
    bot_token: String,

    /// Telegram Chat ID
    #[arg(long = "chat-id", env = "CHAT_ID")]
    chat_id: String,
}

#[tokio::main]
async fn main() {
    let opts = GatewayMonitorOpts::parse();
    let client = GatewayRpcClient::new(
        opts.gateway_addr,
        opts.password,
        opts.bot_token,
        opts.chat_id,
    );
    const FAILURE_THRESHOLD: u32 = 10;

    let mut curr_failures = 0;
    let mut curr_failure_delay = 10;
    loop {
        let delay = match client.get_info().await {
            Ok(info) => {
                if let Some(state) = info.get("gateway_state") {
                    let state = state.as_str().expect("Could not parse state");
                    if state == "Running" {
                        let now: DateTime<Local> = Local::now();
                        println!(
                            "Validated: {} Waiting 5 minutes before validating gateway again...",
                            now.format("%Y-%m-%d %H:%M:%S")
                        );
                        curr_failures = 0;
                        curr_failure_delay = 10;
                        opts.interval
                    } else {
                        eprintln!("Error contacting gateway curr_failures={curr_failures} curr_failure_delay={curr_failure_delay} state={state}");
                        curr_failure_delay
                    }
                } else {
                    eprintln!("Error contacting gateway curr_failures={curr_failures} curr_failure_delay={curr_failure_delay} State does not exist");
                    curr_failure_delay
                }
            }
            Err(e) => {
                curr_failures += 1;
                eprintln!("Error contacting gateway curr_failures={curr_failures} curr_failure_delay={curr_failure_delay} error={e:?}");
                curr_failure_delay
            }
        };

        if curr_failures > FAILURE_THRESHOLD {
            eprintln!("Send telegram message");
            client.send_telegram_message(format!("Gateway is offline. curr_failures={curr_failures} curr_failure_delay={curr_failure_delay}")).await;
            let new_failure_delay = curr_failure_delay * 5;
            // Cap failure delay at 1 hour.
            curr_failure_delay = min(new_failure_delay, 3600);
            curr_failures = 0;
        }

        time::sleep(Duration::from_secs(delay)).await;
    }
}

pub struct GatewayRpcClient {
    /// Base URL to gateway web server
    base_url: Url,
    /// A request client
    client: reqwest::Client,
    /// OGateway password
    password: String,
    /// Telegram Bot Token
    bot_token: String,
    /// Telegram Chat ID
    chat_id: String,
}

impl GatewayRpcClient {
    pub fn new(base_url: Url, password: String, bot_token: String, chat_id: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
            password,
            bot_token,
            chat_id,
        }
    }

    pub async fn get_info(&self) -> Result<Value, reqwest::Error> {
        let url = self.base_url.join("/info").expect("invalid base url");
        self.call_get(url).await
    }

    pub async fn send_telegram_message(&self, message: String) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.bot_token);

        let res = self
            .client
            .post(&url)
            .json(&json!({
                "chat_id": self.chat_id,
                "text": message,
            }))
            .send()
            .await;

        match res {
            Ok(response) => {
                println!(
                    "Successfully sent Telegram message! Response: {:?}",
                    response
                );
            }
            Err(err) => {
                eprintln!("Error sending message: {}", err);
            }
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
    ) -> Result<T, reqwest::Error> {
        let mut builder = self.client.request(method, url);
        builder = builder.bearer_auth(self.password.clone());
        let response = builder.send().await?;
        response.json::<T>().await
    }

    async fn call_get<T: DeserializeOwned>(&self, url: Url) -> Result<T, reqwest::Error> {
        self.call(Method::GET, url).await
    }
}
