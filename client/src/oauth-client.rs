use std::fs;
use std::error::Error;
use std::path::Path;
use std::collections::HashMap;
use std::io::{self, Write};

use reqwest::blocking::Client;
use reqwest::Certificate;
use serde::Deserialize;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};

#[derive(Deserialize, Debug, Clone)]
struct OpenIDConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize, Debug, Clone)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize, Debug, Clone)]
struct JwkKey {
    kid: String,
    n: String,
    e: String,
    // other fields ignored
}

#[derive(Deserialize, Debug, Clone)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(Deserialize, Debug)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
    name: Option<String>,
}

struct OAuthClientApp {
    client: Client,
    client_no_redirect: Client,
    base_url: String,
    config: Option<OpenIDConfiguration>,
    token_response: Option<TokenResponse>,
    jwks: Option<JwksResponse>,
    auth_code: Option<String>,
}

impl OAuthClientApp {
    fn new() -> Result<Self, Box<dyn Error>> {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let ca_path = Path::new(manifest_dir).join("../server/CAs/tls-chain/root/root.crt");
        let ca_pem = fs::read(&ca_path)?;
        let ca_cert = Certificate::from_pem(&ca_pem)?;

        let client = Client::builder()
            .add_root_certificate(ca_cert.clone())
            .danger_accept_invalid_certs(true)
            .build()?;

        let client_no_redirect = Client::builder()
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            client,
            client_no_redirect,
            base_url: "https://localhost:8443".to_string(),
            config: None,
            token_response: None,
            jwks: None,
            auth_code: None,
        })
    }

    fn discovery(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 1. Discovery ---");
        let discovery_url = format!("{}/.well-known/openid-configuration", self.base_url);
        let config: OpenIDConfiguration = self.client.get(&discovery_url).send()?.json()?;
        println!("Config: {:#?}", config);
        self.config = Some(config);
        Ok(())
    }

    fn authorize(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 2. Authorize ---");
        let config = self.config.as_ref().ok_or("Config not loaded. Run discovery first.")?;

        let auth_url = format!("{}?response_type=code&client_id=client-1&redirect_uri=http://localhost:3000/callback&state=xyz", config.authorization_endpoint);
        println!("Requesting Auth: {}", auth_url);
        
        let resp = self.client_no_redirect.get(&auth_url).send()?;
        println!("Auth Status: {}", resp.status());

        let location = resp.headers().get("location").ok_or("No Location header")?.to_str()?;
        println!("Redirect Location: {}", location);

        let url_parsed = reqwest::Url::parse(location)?;
        let pairs: HashMap<_, _> = url_parsed.query_pairs().into_owned().collect();
        let code = pairs.get("code").ok_or("No code in redirect")?.to_string();
        println!("Got Code: {}", code);
        
        self.auth_code = Some(code);
        Ok(())
    }

    fn token_exchange(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 3. Token Exchange ---");
        let config = self.config.as_ref().ok_or("Config not loaded. Run discovery first.")?;
        let code = self.auth_code.as_ref().ok_or("Auth code not found. Run authorize first.")?;

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", "client-1"),
            ("redirect_uri", "http://localhost:3000/callback"),
        ];

        let token_resp: TokenResponse = self.client.post(&config.token_endpoint)
            .form(&params)
            .send()?
            .json()?;
        
        println!("Got Tokens: {:#?}", token_resp);
        self.token_response = Some(token_resp);
        Ok(())
    }

    fn get_jwks(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 4. Get JWKS ---");
        let config = self.config.as_ref().ok_or("Config not loaded. Run discovery first.")?;
        
        let jwks: JwksResponse = self.client.get(&config.jwks_uri).send()?.json()?;
        println!("JWKS: {:#?}", jwks);
        self.jwks = Some(jwks);
        Ok(())
    }

    fn verify_token(&self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 5. Verify ID Token ---");
        let token_resp = self.token_response.as_ref().ok_or("Tokens not found. Run token exchange first.")?;
        let jwks = self.jwks.as_ref().ok_or("JWKS not loaded. Run get_jwks first.")?;

        let header = decode_header(&token_resp.id_token)?;
        let kid = header.kid.ok_or("No kid in header")?;
        println!("Token kid: {}", kid);

        let jwk = jwks.keys.iter().find(|k| k.kid == kid).ok_or("Key not found in JWKS")?;

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["client-1"]);
        validation.set_issuer(&["https://127.0.0.1:8443"]);

        let token_data = decode::<Claims>(&token_resp.id_token, &decoding_key, &validation)?;
        println!(" Token Verified!");
        println!("Claims: {:#?}", token_data.claims);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut app = OAuthClientApp::new()?;

    loop {
        println!("\n=== OAuth Client Interactive Mode ===");
        println!("1. Discovery (Get Config)");
        println!("2. Authorize (Get Code)");
        println!("3. Token Exchange (Get Tokens)");
        println!("4. Get JWKS");
        println!("5. Verify ID Token");
        println!("0. Exit");
        print!("Select an option: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                if let Err(e) = app.discovery() {
                    eprintln!("Error: {}", e);
                }
            }
            "2" => {
                if let Err(e) = app.authorize() {
                    eprintln!("Error: {}", e);
                }
            }
            "3" => {
                if let Err(e) = app.token_exchange() {
                    eprintln!("Error: {}", e);
                }
            }
            "4" => {
                if let Err(e) = app.get_jwks() {
                    eprintln!("Error: {}", e);
                }
            }
            "5" => {
                if let Err(e) = app.verify_token() {
                    eprintln!("Error: {}", e);
                }
            }
            "0" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option, please try again."),
        }
    }

    Ok(())
}
