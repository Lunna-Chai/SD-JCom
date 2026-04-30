use std::error::Error;
use std::io::{self, Write};

use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use base64::prelude::*;

use json_commit::ast::Node;
use json_commit::commit::path_tree;
use json_commit::commit::generator::GeneratorBuilder;
use json_commit::commit::commitment::Commitment;

// ES256K signature verfication（secp256k1 / k256）
use k256::ecdsa::{VerifyingKey, Signature as EcdsaSignature, signature::Verifier};

// Ristretto255 using for commitment（curve25519-dalek）
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::OsRng;

// HTTP header constants
const HEADER_JDC_COMMIT: &str  = "JDC-commit";   // commitment C (hex)
const HEADER_JSON_COMMIT: &str = "JSON-Commit";  // τ = z·h (hex), carried in Phase 2→3
const HEADER_JDC: &str         = "JDC";          // JWS returned by the server

// Data structures
#[derive(Deserialize, Debug, Clone)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// EC public key from JWKS (secp256k1, used to verify the server JWS signature)
#[derive(Deserialize, Debug, Clone)]
struct JwkKey {
    kid: String,
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

// Application struct

struct JCommitClientApp {
    client:              Client,
    base_url:            String,
    /// Serialized JSON attribute string (used for commitment computation)
    json_data:           Option<String>,
    jwks:                Option<JwksResponse>,
    /// τ = z·h, compressed Ristretto255 point (32 bytes)
    tau:                 Option<Vec<u8>>,
    /// Commitment C = τ + Σ H(v_i)·g_i, compressed Ristretto255 point (32 bytes)
    computed_commitment: Option<Vec<u8>>,
}

impl JCommitClientApp {
    fn new() -> Result<Self, Box<dyn Error>> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            client,
            base_url:            "http://127.0.0.1:8443".to_string(),
            json_data:           None,
            jwks:                None,
            tau:                 None,
            computed_commitment: None,
        })
    }

    //  Step 0: Fetch the server JWKS public key 
    fn fetch_jwks(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- Fetch JWKS ---");
        let url = format!("{}/.well-known/jwks.json", self.base_url);
        let jwks: JwksResponse = self.client.get(&url).send()?.json()?;
        println!("JWKS: {:#?}", jwks);
        self.jwks = Some(jwks);
        Ok(())
    }

    //   Step 1 [ONLINE]: Request JSON attribute set from server 
    //
    //   The server returns {"JSON": {...100 attributes...}} without generating z
    //   or signing z.  The client extracts the attribute string for local
    //   commitment computation.

    fn request_data(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 1. [ONLINE] Request JSON Attributes ---");
        let url = format!("{}/users/1", self.base_url);
        println!("GET {}", url);

        let response = self.client.get(&url).send()?;
        println!("Status: {}", response.status());

        let body_text = response.text()?;
        let body_json: serde_json::Value = serde_json::from_str(&body_text)
            .map_err(|_| "Failed to parse server response as JSON")?;

        let attr_json = body_json["JSON"].clone();
        let attr_text = serde_json::to_string(&attr_json)
            .map_err(|_| "Failed to serialize JSON attributes")?;

        println!("Received {} attributes", attr_json.as_object().map_or(0, |m| m.len()));
        self.json_data = Some(attr_text);
        Ok(())
    }

    // Step 2 [OFFLINE]: Client samples z, computes τ and commitment C 
    //
    //   τ = z · h              (h = Ristretto255 base point, RISTRETTO_BASEPOINT_POINT)
    //   C = τ + Σ H(v_i)·g_i  (Pedersen vector commitment; g_i deterministically
    //                           derived from path hashes)
    //
    //   This step requires no network and can be precomputed offline.

    fn compute_commitment(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 2. [OFFLINE] Compute Commitment (Ristretto255 / Curve25519) ---");
        let json_str = self.json_data.as_ref()
            .ok_or("No JSON data. Run request_data first.")?;

        // Sample random scalar z
        let z = Scalar::random(&mut OsRng);

        // τ = z · h  (h is the Ristretto255 base point)
        let tau_point = z * RISTRETTO_BASEPOINT_POINT;
        let tau_bytes = tau_point.compress().to_bytes();
        self.tau = Some(tau_bytes.to_vec());
        println!("τ = z·h : {}", hex::encode(&tau_bytes));

        // Build generators and compute C = τ + Σ H(v_i)·g_i
        let ast = Node::parse_str(json_str).map_err(|_| "Failed to parse JSON")?;
        let (path_hash_strings, leaf_values, _) =
            path_tree::extract_paths_and_values(&ast, b"init_vector");
        let generators = GeneratorBuilder::build_from_hashes(&path_hash_strings)?;
        let commitment =
            Commitment::compute_vector_commitment_with_z(&generators, &leaf_values, &z)?;
        let commit_bytes = commitment.compress().to_bytes();

        self.computed_commitment = Some(commit_bytes.to_vec());
        println!("C = τ + Σ H(v_i)·g_i : {}", hex::encode(&commit_bytes));
        println!("✅ Commitment computed ({} bytes, Ristretto255 compressed point)", commit_bytes.len());
        Ok(())
    }

    //  Step 3 [ONLINE]: Submit C and τ, obtain the server signature over C
    //
    //   Server-side flow:
    //     1. Read τ from JSON-Commit header and C from JDC-commit header
    //     2. Rebuild g_i generators from the stored JSON
    //     3. Compute C' = τ + Σ H(v_i)·g_i
    //     4. Verify C == C'; reject if they differ
    //     5. Sign C with the ECDSA ES256K private key; write JWS into the JDC
    //        response header.  Echo C_hex back via JSON-Commit for the client.

    fn submit_commitment_for_signature(&self) -> Result<(), Box<dyn Error>> {
        println!("\n--- 3. [ONLINE] Submit C + τ for Server Verification & Signing ---");
        let commit_bytes = self.computed_commitment.as_ref()
            .ok_or("No commitment. Run compute_commitment first.")?;
        let tau_bytes = self.tau.as_ref()
            .ok_or("No τ. Run compute_commitment first.")?;

        let url        = format!("{}/sign-commitment", self.base_url);
        let commit_hex = hex::encode(commit_bytes);
        let tau_hex    = hex::encode(tau_bytes);

        println!("POST {}", url);
        println!("  {} (C)  : {}", HEADER_JDC_COMMIT,  commit_hex);
        println!("  {} (τ) : {}", HEADER_JSON_COMMIT, tau_hex);

        let response = self.client
            .post(&url)
            .header(HEADER_JDC_COMMIT,  commit_hex.clone())
            .header(HEADER_JSON_COMMIT, tau_hex)
            .send()?;

        let headers = response.headers();

        // Verify that the C_hex echoed back by the server matches the local value
        let resp_commit_hex = get_header_str(headers, HEADER_JSON_COMMIT)
            .ok_or("Missing JSON-Commit header in response")?;
        if resp_commit_hex != commit_hex {
            return Err("Commitment mismatch: server returned different C_hex".into());
        }
        println!("Server echoed back C_hex matches local commitment");

        // Extract the JWS (ECDSA ES256K signature over C issued by the server)
        let jws = get_header_str(headers, HEADER_JDC).unwrap_or("");
        if jws.is_empty() {
            println!("❌ JDC header missing — server did not issue a signature.");
            return Ok(());
        }
        println!(" Received JWS (server signature over Ristretto255 commitment C):\n{}", jws);

        // Parse and verify JWS structure (Header.Payload.Signature)
        println!("\n--- 4. Verify JWS Signature (ES256K / secp256k1) ---");
        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() != 3 {
            println!(" Invalid JWS: expected 3 dot-separated parts, got {}", parts.len());
            return Ok(());
        }
        println!(" JWS structure valid (Header.Payload.Signature)");

        // Display the JWS Protected Header
        if let Ok(hdr_bytes) = BASE64_URL_SAFE_NO_PAD.decode(parts[0]) {
            if let Ok(hdr_str) = String::from_utf8(hdr_bytes) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&hdr_str) {
                    println!("[JWS Protected Header]:\n{}",
                        serde_json::to_string_pretty(&parsed).unwrap());
                }
            }
        }

        // Cryptographic verification using the JWKS public key (ES256K: SHA-256 + ECDSA)
        match self.verify_jws_signature(parts[0], parts[1], parts[2]) {
            Ok(())  => println!(" JWS ES256K signature verified against JWKS public key"),
            Err(e)  => println!(" JWS signature verification FAILED: {}", e),
        }
        println!("[JWS Signature (Base64Url)]:\n{}", parts[2]);

        Ok(())
    }

    // JWS signature verification: ES256K via secp256k1 public key from JWKS 
    //
    //   Server signing: signing_key.sign(sign_input.as_bytes())
    //   where sign_input = "{header_b64}.{payload_b64}" (SHA-256 hashed internally).
    //   Here we symmetrically call VerifyingKey::verify() to reproduce the same
    //   hash-then-verify flow.

    fn verify_jws_signature(
        &self,
        header_b64:  &str,
        payload_b64: &str,
        sig_b64:     &str,
    ) -> Result<(), Box<dyn Error>> {
        let jwks = self.jwks.as_ref()
            .ok_or("No JWKS. Run fetch_jwks first (or restart client).")?;

        // Locate the secp256k1 public key in JWKS
        let key = jwks.keys.iter()
            .find(|k| k.kty == "EC" && k.crv.as_deref() == Some("secp256k1"))
            .ok_or("No secp256k1 key found in JWKS")?;
        let x_b64 = key.x.as_deref().ok_or("Missing x coordinate in JWK")?;
        let y_b64 = key.y.as_deref().ok_or("Missing y coordinate in JWK")?;

        let x_bytes = BASE64_URL_SAFE_NO_PAD.decode(x_b64)
            .map_err(|e| format!("JWK x decode error: {}", e))?;
        let y_bytes = BASE64_URL_SAFE_NO_PAD.decode(y_b64)
            .map_err(|e| format!("JWK y decode error: {}", e))?;
        if x_bytes.len() != 32 || y_bytes.len() != 32 {
            return Err("JWK x/y must each be 32 bytes for secp256k1".into());
        }

        // Build uncompressed SEC1 point: 0x04 || x(32B) || y(32B)
        let mut point_bytes = [0u8; 65];
        point_bytes[0] = 0x04;
        point_bytes[1..33].copy_from_slice(&x_bytes);
        point_bytes[33..65].copy_from_slice(&y_bytes);
        let encoded_point = k256::EncodedPoint::from_bytes(&point_bytes)
            .map_err(|_| "Failed to construct SEC1 encoded point")?;
        let vk = VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|_| "Failed to construct VerifyingKey from JWK")?;

        // Decode signature bytes (r‖s, fixed 64 bytes)
        let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(sig_b64)
            .map_err(|e| format!("Signature base64 decode error: {}", e))?;
        let sig = EcdsaSignature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid signature bytes: {}", e))?;

        // Verify: message = "{header_b64}.{payload_b64}" (SHA-256 applied internally)
        let sign_input = format!("{}.{}", header_b64, payload_b64);
        vk.verify(sign_input.as_bytes(), &sig)
            .map_err(|e| format!("ES256K verification failed: {}", e).into())
    }

    //  Interactive benchmark (20 iterations) 

    fn run_benchmark(&mut self) -> Result<(), Box<dyn Error>> {
        println!("\n--- Running Benchmark (20 iterations) ---");
        use std::time::Instant;

        let iterations: u128 = 20;
        let (mut sum1, mut sum2, mut sum3, mut sum_total) = (0u128, 0, 0, 0);
        let mut sample_json_len = 0usize;
        let mut sample_commit_len = 0usize;
        let mut sample_jws_len = 0usize;

        for _ in 0..iterations {
            let t_total = Instant::now();

            // Phase 1 [ONLINE]: GET /users/1
            let t1 = Instant::now();
            let url = format!("{}/users/1", self.base_url);
            let resp = self.client.get(&url).send()?;
            let body_text = resp.text()?;
            let body_json: serde_json::Value = serde_json::from_str(&body_text)
                .map_err(|_| "JSON parse error")?;
            let attr_text = serde_json::to_string(&body_json["JSON"])
                .map_err(|_| "Serialize error")?;
            sample_json_len = attr_text.len();
            self.json_data = Some(attr_text.clone());
            let ns1 = t1.elapsed().as_nanos();

            // Phase 2 [OFFLINE]: compute τ = z·h and C = τ + Σ H(v_i)·g_i (pure CPU)
            let t2 = Instant::now();
            let z = Scalar::random(&mut OsRng);
            let tau_point = z * RISTRETTO_BASEPOINT_POINT;
            let tau_bytes = tau_point.compress().to_bytes();
            let ast = Node::parse_str(&attr_text).map_err(|_| "JSON parse error")?;
            let (path_hash_strings, leaf_values, _) =
                path_tree::extract_paths_and_values(&ast, b"init_vector");
            let generators = GeneratorBuilder::build_from_hashes(&path_hash_strings)?;
            let commitment =
                Commitment::compute_vector_commitment_with_z(&generators, &leaf_values, &z)?;
            let commit_bytes = commitment.compress().to_bytes().to_vec();
            sample_commit_len = commit_bytes.len();
            self.computed_commitment = Some(commit_bytes.clone());
            self.tau = Some(tau_bytes.to_vec());
            let ns2 = t2.elapsed().as_nanos();

            // Phase 3 [ONLINE]: POST /sign-commitment — server verifies C'==C and signs
            let t3 = Instant::now();
            let post_url   = format!("{}/sign-commitment", self.base_url);
            let commit_hex = hex::encode(&commit_bytes);
            let tau_hex    = hex::encode(tau_bytes);
            let res2 = self.client.post(&post_url)
                .header(HEADER_JDC_COMMIT,  commit_hex.clone())
                .header(HEADER_JSON_COMMIT, tau_hex)
                .send()?;
            let h2 = res2.headers();
            let resp_commit = get_header_str(h2, HEADER_JSON_COMMIT)
                .ok_or("Missing JSON-Commit in response")?;
            if resp_commit != commit_hex {
                return Err("Commitment mismatch in benchmark".into());
            }
            let jws = get_header_str(h2, HEADER_JDC).unwrap_or("");
            sample_jws_len = jws.len();
            let parts: Vec<&str> = jws.split('.').collect();
            if parts.len() != 3 {
                return Err("Invalid JWS format in benchmark".into());
            }
            let _sig = BASE64_URL_SAFE_NO_PAD.decode(parts[2])?;
            let ns3 = t3.elapsed().as_nanos();

            sum1     += ns1;
            sum2     += ns2;
            sum3     += ns3;
            sum_total += t_total.elapsed().as_nanos();
        }

        println!("\n✅ Benchmark Completed ({} iterations avg)", iterations);
        println!("─────────────────────────────────────────────────────────");
        println!("[ STORAGE ]");
        println!("  JSON Payload (100 attrs)              : {} bytes", sample_json_len);
        println!("  Commitment C (Ristretto255 compressed): {} bytes", sample_commit_len);
        println!("  JWS in JDC header                     : {} bytes", sample_jws_len);
        println!("─────────────────────────────────────────────────────────");
        println!("[ LATENCY (avg per iteration) ]");
        println!("  Phase 1 [ONLINE]  JSON fetch           : {} ns", sum1     / iterations);
        println!("  Phase 2 [OFFLINE] Commitment compute   : {} ns", sum2     / iterations);
        println!("  Phase 3 [ONLINE]  Submit + Sign        : {} ns", sum3     / iterations);
        println!("  Total                                  : {} ns", sum_total / iterations);
        println!("─────────────────────────────────────────────────────────");
        Ok(())
    }
}

//  Utility functions 

fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}


fn main() -> Result<(), Box<dyn Error>> {
    let mut app = JCommitClientApp::new()?;

    if let Err(e) = app.fetch_jwks() {
        eprintln!("Failed to fetch JWKS: {}", e);
    }

    loop {
        println!("\n=== SD-JCom Interactive Client (Ristretto255 / Curve25519) ===");
        println!("1. [ONLINE]  Request JSON attributes from server");
        println!("2. [OFFLINE] Compute commitment C and blinding τ (local, no network)");
        println!("3. [ONLINE]  Submit C + τ for server verification & signing");
        println!("4.           Run benchmark (20 iterations)");
        println!("0.           Exit");
        print!("Select: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => { if let Err(e) = app.request_data()                    { eprintln!("Error: {}", e); } }
            "2" => { if let Err(e) = app.compute_commitment()              { eprintln!("Error: {}", e); } }
            "3" => { if let Err(e) = app.submit_commitment_for_signature() { eprintln!("Error: {}", e); } }
            "4" => { if let Err(e) = app.run_benchmark()                   { eprintln!("Error: {}", e); } }
            "0" => { println!("Exiting."); break; }
            _   => println!("Invalid option."),
        }
    }

    Ok(())
}
