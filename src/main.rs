use std::{
    fs::{self, File},
    io::Write,
    time::{Duration, Instant},
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, Deserialize, Serialize)]
struct AuthorizationRequest {
    client_id: String,
    audience: String,
    scope: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
    verification_uri_complete: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenRequest {
    client_id: String,
    device_code: String,
    grant_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    id_token: String,
    scope: String,
    expires_in: u32,
    token_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExchangeResponse {
    error: String,
    error_description: String,
}
#[derive(Debug, Deserialize, Serialize)]
enum TokenRequestResponse {
    Success(TokenResponse),
    Error(ExchangeResponse),
}

fn authorization_request(
    base_url: &str,
    client_id: &str,
    audience: &str,
    scope: &str,
) -> Result<AuthorizationResponse, reqwest::Error> {
    let client = Client::new();
    let params = [
        ("client_id", client_id),
        ("audience", audience),
        ("scope", scope),
    ];
    let response = client
        .post(&format!("{}/oauth/device/code", base_url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()?
        .json()?;
    Ok(response)
}

fn token_request(base_url: &str, token_request: &TokenRequest) -> Result<String, reqwest::Error> {
    let client = Client::new();
    let params = [
        ("client_id", token_request.client_id.to_string()),
        ("device_code", token_request.device_code.to_string()),
        ("grant_type", token_request.grant_type.to_string()),
    ];
    let response = client
        .post(&*format!("{}/oauth/token", base_url).trim_matches('"'))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()?;
    let response_body = response.text()?;
    Ok(response_body)
}

#[derive(Debug, Deserialize, Serialize)]
struct UserInfoResponse {
    sub: String,
    nickname: String,
    name: String,
    picture: String,
    updated_at: String,
}
fn user_info_request(
    base_url: &str,
    access_token: &str,
) -> Result<UserInfoResponse, reqwest::Error> {
    let client = Client::new();
    let userinfo_response = client
        .get(&*format!("{}/userinfo", base_url).trim_matches('"'))
        .header(
            "Authorization",
            format!("Bearer {}", access_token.to_string().trim_matches('"')),
        )
        .send()?
        .json()?;

    Ok(userinfo_response)
}
struct Timer {
    start: Instant,
    duration: Duration,
}

impl Timer {
    fn new(seconds: u64) -> Timer {
        Timer {
            start: Instant::now(),
            duration: Duration::from_secs(seconds),
        }
    }

    fn has_expired(&self) -> bool {
        Instant::now().duration_since(self.start) >= self.duration
    }

    fn is_prompt_time(&self) -> bool {
        Instant::now().duration_since(self.start).as_secs() % 60 == 0
    }

    fn remaining_duration(&self) -> Duration {
        self.duration - Instant::now().duration_since(self.start)
    }
}


fn main() {
    let base_url = "https://acme-demo.auth0.com";
    let client_id = "nZ8JDrV8Hklf3JumewRl2ke3ovPZn5Ho";
    let audience = "urn:my-videos";
    let scope = "offline_access openid profile";
    let grant_type = "urn:ietf:params:oauth:grant-type:device_code";
    let acme_demo_home_dir = home::home_dir()
        .map(|dir| dir.join(".auth0/acme-demo"))
        .unwrap_or_default()
        .display()
        .to_string();
    if !fs::metadata(&acme_demo_home_dir).is_ok() {
        let _ = fs::create_dir_all(&acme_demo_home_dir);
    }
    let acme_demo_token_path = format!("{}/token.json", acme_demo_home_dir);

    if let Ok(_metadata) = fs::metadata(&acme_demo_token_path) {
        // Token file exists, proceed with userinfo request       
        let token_file = File::open(&acme_demo_token_path).unwrap();
        let token_response: TokenResponse = serde_json::from_reader(token_file).unwrap();
        match user_info_request(base_url, &token_response.access_token) {
            Ok(userinfo_response) => {
                println!("Welcome, {} to the ACME Demo App!!", userinfo_response.nickname);
                println!("You have successfully logged in");
                let expires_in_formatted = format!(
                    "{}",
                    [
                        (token_response.expires_in / (60 * 60 * 24), "day"),
                        ((token_response.expires_in / (60 * 60)) % 24, "hour"),
                        ((token_response.expires_in / 60) % 60, "minute"),
                        (token_response.expires_in % 60, "second"),
                    ]
                    .iter()
                    .filter(|(value, _)| *value > 0)
                    .map(|(value, unit)| format!(
                        "{} {}{}",
                        value,
                        unit,
                        if *value > 1 { "s" } else { "" }
                    ))
                    .collect::<Vec<String>>()
                    .join(", ")
                );
                println!("Your token expires in: {}", expires_in_formatted);
            }
            Err(err) => {
                eprintln!("Failed to fetch userinfo: {}", err);
            }
        }
    } else  {
        match authorization_request(base_url, client_id, audience, scope) {
            Ok(authorization_response) => {
                println!("Welcome to the ACME Demo App!");
                println!("Please log in to continue");
                println!(
                    "On your computer or mobile device, go to: {:?}",
                    authorization_response.verification_uri
                );
                println!(
                    "Enter the following code: {:?}",
                    authorization_response.user_code
                );
                println!(
                    "For convenience, you can use the following link: {:?}",
                    authorization_response.verification_uri_complete
                );
                println!("or scan the QR code below");
                qr2term::print_qr(&authorization_response.verification_uri_complete).unwrap();
                let token_request_payload = TokenRequest {
                    client_id: client_id.to_string(),
                    device_code: authorization_response.device_code,
                    grant_type: grant_type.to_string(),
                };
                let expiry_counter = Timer::new(authorization_response.expires_in);
                let token_response = loop {
                    let token_request_response = token_request(base_url, &token_request_payload);
                    let token_request_response_bytes = token_request_response.unwrap().into_bytes();
                    let token_request_response: TokenResponse = match serde_json::from_slice::<
                        ExchangeResponse,
                    >(
                        &token_request_response_bytes
                    ) {
                        Ok(exchange_response) => {
                            if expiry_counter.has_expired() {
                                println!("Login link has now expired, please try again and activate within {}", authorization_response.expires_in);
                                std::process::exit(1);
                            } else if exchange_response.error == "authorization_pending" {
                                if expiry_counter.is_prompt_time() {
                                    println!("You have {} minutes to complete the process", (expiry_counter.remaining_duration().as_secs() + 1) / 60);
                                }
                                std::thread::sleep(std::time::Duration::from_secs(
                                    authorization_response.interval as u64,
                                ));
                                continue;
                            } else {
                                println!(
                                    "Unable to marshall Exchange Response: {:?}",
                                    exchange_response
                                );
                                std::process::exit(1);
                            }
                        }
                        _ => {
                            match serde_json::from_slice::<TokenResponse>(&token_request_response_bytes)
                            {
                                Ok(token_response) => token_response,
                                token_response => {
                                    println!("Unable to marshall token_response: {:?}", token_response);
                                    std::process::exit(1);
                                }
                            }
                        }
                    };
    
                    break token_request_response;
                };
                // return token_response
                match user_info_request(base_url, &token_response.access_token) {
                    Ok(userinfo_response) => {
                        // Step 4 - Activation Complete
                        println!("Welcome, {} to the ACME Demo App!!", userinfo_response.nickname);
                        println!("You have successfully logged in");
                        let expires_in_formatted = format!(
                            "{}",
                            [
                                (token_response.expires_in / (60 * 60 * 24), "day"),
                                ((token_response.expires_in / (60 * 60)) % 24, "hour"),
                                ((token_response.expires_in / 60) % 60, "minute"),
                                (token_response.expires_in % 60, "second"),
                            ]
                            .iter()
                            .filter(|(value, _)| *value > 0)
                            .map(|(value, unit)| format!(
                                "{} {}{}",
                                value,
                                unit,
                                if *value > 1 { "s" } else { "" }
                            ))
                            .collect::<Vec<String>>()
                            .join(", ")
                        );
                        println!("Your token expires in: {}", expires_in_formatted);
    
                        // write the token to a json file
                        let mut file = File::create(&acme_demo_token_path).unwrap();
                        let token_json = serde_json::to_string_pretty(&token_response).unwrap();
                        file.write_all(token_json.as_bytes()).unwrap();
                        println!("Token written to {}", &acme_demo_token_path);
                    }
                    Err(err) => {
                        eprintln!("Failed to fetch userinfo: {}", err);
                    }
                }
            }
            Err(err) => {
                eprintln!("Failed to exchange device code for access token: {}", err);
            }
        };
    }
    

}
