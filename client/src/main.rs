use std::error::Error;

use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use base64::prelude::*;

use sha2::{Sha256, Digest};

use json_commit::ast::Node;
use json_commit::commit::path_tree;
use json_commit::commit::generator::GeneratorBuilder;
use json_commit::commit::commitment::Commitment;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::OsRng;

// HTTP header fields
#[derive(Deserialize, Debug, Clone)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize, Debug, Clone)]
struct JwkKey {
    kid: String,
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

struct JCommitClientApp {
    client: Client,
    base_url: String,
    json_data: Option<String>,
    response_headers: Option<HeaderMap>,
    jwks: Option<JwksResponse>,
    tau: Option<Vec<u8>>,          // τ = z·h, compressed RistrettoPoint
    computed_commitment: Option<Vec<u8>>,
}

impl JCommitClientApp {
    fn new() -> Result<Self, Box<dyn Error>> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            client,
            base_url: "http://127.0.0.1:8443".to_string(),
            json_data: None,
            response_headers: None,
            jwks: None,
            tau: None,
            computed_commitment: None,
        })
    }

    fn fetch_jwks(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- Fetch JWKS ---");
        let url = format!("{}/.well-known/jwks.json", self.base_url);
        let jwks: JwksResponse = self.client.get(&url).send()?.json()?;
        println!("JWKS: {:#?}", jwks);
        self.jwks = Some(jwks);
        Ok(())
    }

    fn request_data(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 1. Request Data ---");
        let url = format!("{}/users/1", self.base_url);
        println!("Requesting: {}", url);

        let response = self.client.get(&url).send()?;
        println!("Status: {}", response.status());
        self.response_headers = Some(response.headers().clone());

        // Server returns {"JSON": {...}}
        let body_text = response.text()?;;
        let body_json: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|_| "Failed to parse response JSON")?;
        let attr_json = body_json["JSON"].clone();
        let attr_text = serde_json::to_string(&attr_json)
            .map_err(|_| "Failed to serialize JSON attributes")?;
        println!("Received {} attributes", attr_json.as_object().map_or(0, |m| m.len()));
        self.json_data = Some(attr_text);
        Ok(())
    }

    fn compute_commitment(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 2. Compute Commitment ---");
        let json_str = self.json_data.as_ref().ok_or("No body. Run request_data first.")?;

        // Client samples random scalar z
        let z = Scalar::random(&mut OsRng);
        // Compute τ = z·h  (h is the Ristretto255 base point)
        let tau_point = z * RISTRETTO_BASEPOINT_POINT;
        let tau_bytes = tau_point.compress().to_bytes();
        self.tau = Some(tau_bytes.to_vec());
        println!("τ = h^z: {}", hex::encode(&tau_bytes));

        let ast = Node::parse_str(json_str).map_err(|_| "Failed to parse JSON")?;
        let (path_hash_strings, leaf_values, _) = path_tree::extract_paths_and_values(&ast, b"init_vector");
        let generators = GeneratorBuilder::build_from_hashes(&path_hash_strings)?;

        // C = τ + Σ H(v_i)·g_i
        let commitment = Commitment::compute_vector_commitment_with_z(&generators, &leaf_values, &z)?;
        let commit_bytes = commitment.compress().to_bytes();
        self.computed_commitment = Some(commit_bytes.to_vec());
        println!(" Computed Commitment C: {}", hex::encode(&commit_bytes));
        Ok(())
    }

    fn submit_commitment_for_signature(&self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 3. Submit C + τ for Signature ---");
        let commit_bytes = self.computed_commitment.as_ref().ok_or("No commitment computed.")?;
        let tau_bytes    = self.tau.as_ref().ok_or("No tau computed.")?;

        let url        = format!("{}/sign-commitment", self.base_url);
        let commit_hex = hex::encode(commit_bytes);
        let tau_hex    = hex::encode(tau_bytes);

        let response = self.client.post(&url)
            .header("JDC-commit",   commit_hex.clone())
            .header("JSON-Commit",  tau_hex.clone())   // τ in JSON-Commit header
            .send()?;;

        let headers = response.headers();
        let server_sig = get_header_str(headers, "JDC").unwrap_or("");
        if server_sig.is_empty() {
            println!(" JDC signature missing from response headers.");
            return Ok(());
        }

        println!(" Received JWS (Commitment Signature):
{}", server_sig);

        println!("\n--- 4. Parse JWS ---");
        let parts: Vec<&str> = server_sig.split('.').collect();
        if parts.len() == 3 {
            println!(" JWS structure: Header.Payload.Signature");
            if let Ok(header_bytes) = BASE64_URL_SAFE_NO_PAD.decode(parts[0]) {
                if let Ok(header_json) = String::from_utf8(header_bytes) {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&header_json) {
                        println!("[JWS Header]:\n{}", serde_json::to_string_pretty(&parsed).unwrap());
                    }
                }
            }
        } else {
            println!(" Invalid JWS format (expected 3 parts, got {})", parts.len());
        }
        Ok(())
    }

    fn run_benchmark(&mut self, iterations: u128) -> Result<(), Box<dyn Error>> {
        println!("\n--- Running Performance Benchmark ({} iterations) ---", iterations);
        use std::time::Instant;

        let mut sum_req_ns: u128 = 0;
        let mut sum_commit_ns: u128 = 0;
        let mut sum_submit_ns: u128 = 0;
        let mut sum_total_ns: u128 = 0;

        let mut sample_json_len = 0;
        let mut sample_commit_len = 0;
        let mut sample_jws_len = 0;
        let mut sample_rfc_len = 0;

        for _ in 0..iterations {
            let start_total = Instant::now();

            // 1. Fetch JSON data
            let start_req = Instant::now();
            let url = format!("{}/users/1", self.base_url);
            let response = self.client.get(&url).send()?;
            let body_text = response.text()?;
            let body_json: serde_json::Value = serde_json::from_str(&body_text)
                .map_err(|_| "Failed to parse response JSON")?;
            let attr_json = body_json["JSON"].clone();
            let attr_text = serde_json::to_string(&attr_json)
                .map_err(|_| "Failed to serialize JSON attributes")?;
            sample_json_len = attr_text.len();
            self.json_data = Some(attr_text.clone());
            let req_ns = start_req.elapsed().as_nanos();

            // 2. Client samples z, computes τ = z·h and C = τ + Σ H(v_i)·g_i
            let start_commit = Instant::now();
            let z = Scalar::random(&mut OsRng);
            let tau_point = z * RISTRETTO_BASEPOINT_POINT;
            let tau_bytes_arr = tau_point.compress().to_bytes();
            let attr_text_ref = self.json_data.as_ref().unwrap();
            let ast = Node::parse_str(attr_text_ref).map_err(|_| "Failed to parse JSON")?;
            let (path_hash_strings, leaf_values, _) = path_tree::extract_paths_and_values(&ast, b"init_vector");
            let generators = GeneratorBuilder::build_from_hashes(&path_hash_strings)?;
            let commitment = Commitment::compute_vector_commitment_with_z(&generators, &leaf_values, &z)?;
            let commit_bytes = commitment.compress().to_bytes().to_vec();
            sample_commit_len = commit_bytes.len();
            self.computed_commitment = Some(commit_bytes.clone());
            let commit_ns = start_commit.elapsed().as_nanos();

            // 3. Submit C and τ, obtain the server signature over C
            let start_submit = Instant::now();
            let post_url = format!("{}/sign-commitment", self.base_url);
            let commit_hex = hex::encode(&commit_bytes);
            let tau_hex    = hex::encode(tau_bytes_arr);
            let res2 = self.client.post(&post_url)
                .header("JDC-commit",  commit_hex.clone())
                .header("JSON-Commit", tau_hex.clone())  // τ
                .send()?;;
            let h2 = res2.headers();

            let rfc_sig_input = get_header_str(h2, "Signature-Input").unwrap_or("");
            let rfc_signature = get_header_str(h2, "Signature").unwrap_or("");
            let server_sig    = get_header_str(h2, "JDC").unwrap_or("");

            let header_commit_hex = get_header_str(h2, "JSON-Commit")
                .ok_or("Missing JSON-Commit header in response")?;
            if header_commit_hex != commit_hex {
                return Err("Commitment mismatch in JSON-Commit header".into());
            }

            sample_rfc_len = rfc_sig_input.len() + rfc_signature.len();
            sample_jws_len = server_sig.len();

            let parts: Vec<&str> = server_sig.split('.').collect();
            if parts.len() != 3 {
                return Err("Invalid JWS format".into());
            }
            let _sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[2])?;

            let submit_ns = start_submit.elapsed().as_nanos();
            let total_ns = start_total.elapsed().as_nanos();

            sum_req_ns += req_ns;
            sum_commit_ns += commit_ns;
            sum_submit_ns += submit_ns;
            sum_total_ns += total_ns;
        }

        println!("\n\n✅ Single-Pass Benchmark Completed!");
        println!("---------------------------------------------------");
        println!("[ STORAGE COSTS & SIZES ]");
        println!("JSON Payload (100 values) : {} bytes", sample_json_len);
        println!("Client Commitment         : {} bytes", sample_commit_len);
        println!("JWS Size (in Header)      : {} bytes", sample_jws_len);
        println!("RFC9421 Headers Size      : {} bytes", sample_rfc_len);
        println!("---------------------------------------------------");
        println!("[ PERFORMANCE (1 iteration) ]");
        println!("Phase 1 (Network Latency & JSON fetch)   : {} ns (avg)", sum_req_ns / iterations);
        println!("Phase 2 (Local Commitment Computation)   : {} ns (avg)", sum_commit_ns / iterations);
        println!("Phase 3 (Sig Issuance & Verification)    : {} ns (avg)", sum_submit_ns / iterations);
        println!("---------------------------------------------------");
        println!("Total Credential Issuance Time           : {} ns (avg)", sum_total_ns / iterations);
        println!("---------------------------------------------------\n");

        Ok(())
    }
}

fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse command-line argument: --iterations=N or --iterations N
    let args: Vec<String> = std::env::args().collect();
    let iterations: u128 = args.windows(2)
        .find_map(|w| {
            if w[0] == "--iterations" { w[1].parse().ok() } else { None }
        })
        .or_else(|| {
            args.iter()
                .find_map(|a| a.strip_prefix("--iterations=").and_then(|v| v.parse().ok()))
        })
        .unwrap_or(100);

    let mut app = JCommitClientApp::new()?;

    // Fetch JWKS on startup
    if let Err(e) = app.fetch_jwks() {
        eprintln!("Failed to fetch JWKS: {}", e);
    }

    if let Err(e) = app.run_benchmark(iterations) {
        eprintln!("Benchmark Error: {}", e);
    }

    Ok(())
}
