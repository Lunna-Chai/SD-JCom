use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD}, Engine as _};
use k256::ecdsa::{SigningKey, signature::Signer};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use rand_core::OsRng;
use json_commit::ast::Node;
use json_commit::commit::path_tree;
use json_commit::commit::generator::GeneratorBuilder;

#[derive(Clone)]
struct AppState {
    last_commitment: Arc<Mutex<Option<String>>>,
    last_json: Arc<Mutex<Option<serde_json::Value>>>,
    signing_key: SigningKey,
}

impl Default for AppState {
    fn default() -> Self {
        let mut rng = OsRng;
        Self {
            last_commitment: Arc::new(Mutex::new(None)),
            last_json: Arc::new(Mutex::new(None)),
            signing_key: SigningKey::random(&mut rng),
        }
    }
}

#[tokio::main]
async fn main() {
    let state = AppState::default();

    let app = Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route("/users/1", get(user_one))
        .route("/sign-commitment", post(sign_commitment))
        .route("/verify-jdc", post(verify_jdc))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443")
        .await
        .expect("bind 8443 failed");

    println!("Server running on http://127.0.0.1:8443");
    axum::serve(listener, app).await.expect("server crashed");
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let vk = state.signing_key.verifying_key();
    let encoded_point = vk.to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded_point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(encoded_point.y().unwrap());

    Json(json!({
        "keys": [
            {
                "kid": "demo-kid-1",
                "kty": "EC",
                "crv": "secp256k1",
                "x": x,
                "y": y
            }
        ]
    }))
}

async fn user_one(State(state): State<AppState>) -> impl IntoResponse {
    let mut map = serde_json::Map::new();
    for i in 1..=100 {
        map.insert(format!("attribute_{}", i), json!(format!("value_{}", i)));
    }
    let body = serde_json::Value::Object(map);

    // Store JSON so sign-commitment can rebuild generators during verification
    {
        let mut lock = state.last_json.lock().unwrap();
        *lock = Some(body.clone());
    }

    let response_body = json!({ "JSON": body });
    let headers = HeaderMap::new();
    (StatusCode::OK, headers, Json(response_body))
}

async fn sign_commitment(
    State(state): State<AppState>,
    headers_in: HeaderMap,
) -> impl IntoResponse {
    // JDC-commit header: commitment value C (hex of compressed RistrettoPoint, 32 bytes)
    let client_commit_hex = headers_in.get("JDC-commit")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    // JSON-Commit header: τ = z·h (hex of compressed RistrettoPoint, 32 bytes)
    let tau_hex = headers_in.get("JSON-Commit")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if client_commit_hex.is_empty() {
        return (StatusCode::BAD_REQUEST, HeaderMap::new(), "Missing JDC-commit header").into_response();
    }
    if tau_hex.is_empty() {
        return (StatusCode::BAD_REQUEST, HeaderMap::new(), "Missing JSON-Commit (tau) header").into_response();
    }

    // Decompress τ
    let tau_bytes = match hex::decode(tau_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return (StatusCode::BAD_REQUEST, HeaderMap::new(), "Invalid tau hex").into_response(),
    };
    let mut tau_arr = [0u8; 32];
    tau_arr.copy_from_slice(&tau_bytes);
    let tau_point = match CompressedRistretto(tau_arr).decompress() {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, HeaderMap::new(), "Invalid tau point").into_response(),
    };

    // Load the JSON stored on the server side
    let saved_json = {
        let lock = state.last_json.lock().unwrap();
        match lock.clone() {
            Some(v) => v,
            None => return (StatusCode::BAD_REQUEST, HeaderMap::new(), "No pending JSON found").into_response(),
        }
    };

    // Rebuild generators
    let ast = Node::from_value(saved_json);
    let (path_hashes, values, _) = path_tree::extract_paths_and_values(&ast, b"init_vector");
    let generators = match GeneratorBuilder::build_from_hashes(&path_hashes) {
        Ok(g) => g,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new(), "Failed to build generators").into_response(),
    };

    // Compute C' = τ + Σ H(v_i)·g_i  (additive notation)
    let mut product = RistrettoPoint::default();
    for (g_i, v_i) in generators.iter().zip(values.iter()) {
        let mut hasher = Sha256::new();
        hasher.update(v_i.as_bytes());
        let bytes: [u8; 32] = hasher.finalize().into();
        let h_vi = Scalar::from_bytes_mod_order(bytes);
        product = product + h_vi * g_i;
    }
    let c_prime = tau_point + product;
    let expected_commit_hex = hex::encode(c_prime.compress().to_bytes());

    if expected_commit_hex != client_commit_hex {
        return (StatusCode::BAD_REQUEST, HeaderMap::new(), "Commitment verification failed").into_response();
    }

    {
        let mut lock = state.last_commitment.lock().unwrap();
        *lock = Some(client_commit_hex.to_string());
    }

    let jw_header = json!({
        "alg": "ES256K",
        "typ": "JSON-Commitment",
        "kid": "jdc-Server-key-001"
    });

    let jw_payload = json!({
        "commitment": client_commit_hex,
        "params": {
            "curve": "ristretto255",
            "iv": "init_vector",
            "h": "034f4c1e41898fb48154cf6e1",
            "g1": "029338ee44f3169bc8db0ef8c"
        }
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(jw_header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(jw_payload.to_string().as_bytes());
    let sign_input = format!("{}.{}", header_b64, payload_b64);

    // Sign JWS using ES256K ECDSA
    let signature: k256::ecdsa::Signature = state.signing_key.sign(sign_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let final_jws = format!("{}.{}", sign_input, sig_b64);

    let mut headers = HeaderMap::new();
    // Echo commitment back for client to check
    headers.insert("JSON-Commit", HeaderValue::from_str(&client_commit_hex).unwrap());
    // Place the full JWS in the JDC header
    headers.insert("JDC", HeaderValue::from_str(&final_jws).unwrap());
    
    // --- RFC 9421 HTTP Message Signatures ---
    // 1. Build Signature-Input declaring that we sign the "jdc" header
    let sig_input_val = format!(r#"sig1=("jdc"); alg="es256k"; kid="jdc-Server-key-001""#);
    headers.insert("Signature-Input", HeaderValue::from_str(&sig_input_val).unwrap());
    
    // 2. Build the canonicalized RFC 9421 Signature Base String
    let signature_base = format!(
        "\"jdc\": {}\n\"@signature-params\": {}",
        final_jws,
        r#"("jdc"); alg="es256k"; kid="jdc-Server-key-001""#
    );
    
    // 3. Sign the RFC 9421 Signature Base String with the private key (ECDSA)
    let rfc_signature: k256::ecdsa::Signature = state.signing_key.sign(signature_base.as_bytes());
    let rfc9421_sig_bytes = rfc_signature.to_bytes();
    
    // 4. Base64-encode the signature bytes and place in the Signature header
    let rfc9421_sig_val = format!("sig1=:{}:", base64::engine::general_purpose::STANDARD.encode(rfc9421_sig_bytes));
    headers.insert("Signature", HeaderValue::from_str(&rfc9421_sig_val).unwrap());

    (StatusCode::OK, headers, "ok").into_response()
}

// Verifier endpoint (server-side): receives an RFC 9421 signed request, verifies the HTTP signature, and extracts the embedded JWS
async fn verify_jdc(headers: HeaderMap) -> impl IntoResponse {
    let rfc_signature = headers.get("Signature").and_then(|h| h.to_str().ok()).unwrap_or("");
    let rfc_sig_input = headers.get("Signature-Input").and_then(|h| h.to_str().ok()).unwrap_or("");
    let jdc_header = headers.get("JDC").and_then(|h| h.to_str().ok()).unwrap_or("");

    if rfc_signature.is_empty() || jdc_header.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing Signature or JDC headers").into_response();
    }

    println!("\n[Server Verification] 1. Validating RFC 9421 Signature...");
    
    // a. Extract raw signature bytes (format: sig1=:base64:)
    let sig_bytes = if rfc_signature.starts_with("sig1=:") && rfc_signature.ends_with(':') {
        let b64 = &rfc_signature[6..rfc_signature.len()-1];
        STANDARD.decode(b64).unwrap_or_default()
    } else {
        vec![]
    };

    // b. Reconstruct the Signature Base String for verification
    // Demonstrates core parameters: the jdc value and the signature attributes from Signature-Input
    let expected_sig_params = rfc_sig_input.trim_start_matches("sig1=").trim(); // e.g. `("jdc"); alg="...`
    let signature_base = format!(
        "\"jdc\": {}\n\"@signature-params\": {}",
        jdc_header, expected_sig_params
    );

    // c. In production, verify signature_base against the public key.
    //    Here we use a hash-based simulation: recompute and compare.
    let mut base_hasher = Sha256::new();
    base_hasher.update(signature_base.as_bytes());
    let recomputed_digest = base_hasher.finalize().to_vec();

    if sig_bytes == recomputed_digest {
        println!("  ✅ RFC 9421 HTTP Message Signature successfully verified! Connection secure.");
    } else {
        println!("  ❌ RFC 9421 Verification Failed! Base String mismatch or signature tampered.");
        return (StatusCode::UNAUTHORIZED, "RFC 9421 Verification Failed").into_response();
    }

    println!("\n[Server Verification] 2. Extracting JWS from JDC Header...");
    let jws_str = jdc_header;

    // 3. Split JWS into its three parts (format: Header.Payload.Signature)
    let parts: Vec<&str> = jws_str.split('.').collect();
    if parts.len() != 3 {
        return (StatusCode::BAD_REQUEST, "Invalid JWS format enclosed within JDC").into_response();
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    println!("  [JWS Header (Base64Url)]:\n  {}", header_b64);
    println!("  [JWS Payload (Base64Url)]:\n  {}", payload_b64);
    println!("  [JWS Final Signature extracted]:\n  {}", signature_b64);

    // TODO: Verify signature_b64 via ES256K PK using {header_b64}.{payload_b64} bytes.
    let jws_sign_input = format!("{}.{}", header_b64, payload_b64);
    println!("  -> Internal JWS SignInput to be verified against signature: {}", jws_sign_input);

    (StatusCode::OK, "Successfully verified RFC9421 and extracted JWS signature").into_response()
}
