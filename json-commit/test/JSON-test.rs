//! json_tests: helpers and tests for building sample JSON payloads

use serde_json::{json, Value};

/// Build a sample "personal info" JSON payload.
///
/// Shape (example):
/// {
///   "identity": { "id": 1, "name": "Alice" },
///   "contact": { "email": "alice@example.com", "phone": "+1-202-555-0188" },
///   "balance": { "CNY": 100, "USD": 200 },
///   "tags": ["vip", "beta"],
///   "active": true,
///   "created_at": "2025-11-05T12:00:00Z"
/// }
/// The sample example reprsent below from RFC 9901
/// Not including any information of authors
pub fn sample_person_simple_json() -> Value {
    json!({
      "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
      "given_name": "太郎",
      "family_name": "山田",
      "email": "\"unusual email address\"@example.jp",
      "phone_number": "+81-80-1234-5678",
      "address": {
        "street_address": "東京都港区芝公園４丁目２−８",
        "locality": "東京都",
        "region": "港区",
        "country": "JP"
      },
      "birthdate": "1940-01-01"
    })
}
/// Pretty-printed JSON string of the sample personal info payload
pub fn sample_person_json_string() -> String {
    serde_json::to_string_pretty(&sample_person_simple_json()).expect("serialize sample person json")
}

/// Build a richer sample JSON for a "personal detailed asset proof (bank)" scenario.
/// Amounts that need arithmetic have a parallel *_cents integer to avoid float issues.
pub fn sample_person_asset_proof_complex_json() -> Value {
    json!({
        "version": 1,
        "statement_period": {
            "from": "2025-10-01",
            "to": "2025-10-31"
        },
        "bank": {
            "name": "Example Bank",
            "branch": "001",
            "swift": "EXAMPUS3M"
        },
        "identity": {
            "customer_id": "CUST-0001",
            "name": "Alice Doe",
            "national_id": "ID1234567890",
            "dob": "1992-03-14",
            "residency_country": "US"
        },
        "kyc": {
            "status": "verified",
            "verified_at": "2025-11-01T10:00:00Z",
            "checks": {
                "id_document": true,
                "address": true,
                "liveness": true
            }
        },
        "accounts": [
            {
                "account_id": "CHK-001",
                "type": "checking",
                "currency": "USD",
                "balance_cents": 523475,
                "as_of": "2025-10-31T23:59:59Z",
                "available_cents": 523475,
                "transactions": [
                    {"date": "2025-10-25", "desc": "Payroll", "amount_cents": 350000, "type": "credit", "balance_after_cents": 523475},
                    {"date": "2025-10-20", "desc": "Groceries", "amount_cents": -12345, "type": "debit", "balance_after_cents": 173475}
                ]
            },
            {
                "account_id": "SAV-001",
                "type": "savings",
                "currency": "CNY",
                "balance_cents": 8800000,
                "as_of": "2025-10-31T23:59:59+08:00",
                "available_cents": 8800000,
                "transactions": [
                    {"date": "2025-10-11", "desc": "Interest", "amount_cents": 5000, "type": "credit", "balance_after_cents": 8800000}
                ]
            },
            {
                "account_id": "BRK-001",
                "type": "brokerage",
                "currency": "USD",
                "cash_balance_cents": 120000,
                "as_of": "2025-10-31T23:59:59Z",
                "holdings": [
                    {"symbol": "AAPL", "quantity": 10, "avg_cost_cents": 15000, "mark_price_cents": 17000, "market_value_cents": 170000},
                    {"symbol": "MSFT", "quantity": 20, "avg_cost_cents": 20000, "mark_price_cents": 25000, "market_value_cents": 500000},
                    {"symbol": "SPY",  "quantity": 30, "avg_cost_cents": 40000, "mark_price_cents": 61000, "market_value_cents": 1830000}
                ]
            }
        ],
        "loans": [
            {
                "loan_id": "MTG-001",
                "type": "mortgage",
                "currency": "USD",
                "outstanding_principal_cents": 2000000,
                "interest_rate_percent": 4.25,
                "monthly_payment_cents": 152345,
                "next_due_date": "2025-11-15"
            }
        ],
        "credit_cards": [
            {
                "card_id": "CC-001",
                "currency": "USD",
                "credit_limit_cents": 1000000,
                "statement_balance_cents": 125055,
                "minimum_due_cents": 25000,
                "due_date": "2025-11-10",
                "apr_percent": 19.99
            }
        ],
        "proofs": {
            "bank_signature_hex": "deadbeefcafebabe",
            "statement_hashes": [
                "b1946ac92492d2347c6235b4d2611184",
                "e2fc714c4727ee9395f324cd2e7f331f"
            ]
        },
        "totals": {
            // deposits only include checking/savings balances per currency
            "total_deposits_by_currency": {
                "USD_cents": 523475,
                "CNY_cents": 8800000
            },
            // investments in USD: brokerage holdings + cash
            "total_investments_usd_cents": 2620000,
            // liabilities in USD: loans + credit cards
            "total_liabilities_usd_cents": 2125055,
            // net worth (USD scope) = USD deposits + USD investments - USD liabilities
            "net_worth_usd_cents": 1018420
        },
        "loans1": [
            {
                "loan_id1": "MTG-001",
                "type1": "mortgage",
                "currency1": "USD",
                "outstanding_principal_cents1": 2000000,
                "interest_rate_percent1": 4.25,
                "monthly_payment_cents1": 152345,
                "next_due_date1": "2025-11-15"
            }
        ],
         "loans2": [
            {
                "loan_id12": "MTG-001",
                "type12": "mortgage",
                "currency12": "USD",
                "outstanding_principal_cents12": 2000000,
                "interest_rate_percent12": 4.25,
                "monthly_payment_cents12": 152345,
                "next_due_date12": "2025-11-15"
            }
        ],
        "address2":{
            "street_address2": "東京都港区芝公園４丁目２−８",
            "locality2": "東京都"
        }
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use json_commit::ast::Node;
    use json_commit::commit::path_tree;
    use json_commit::commit::generator::GeneratorBuilder;
    use json_commit::commit::commitment::Commitment;
    use json_commit::proof::{Prover, Verifier};
    use std::time::Instant; 

    #[test]
    fn test_simple_json_path_tree_to_proof() {
        println!("==== Simple JSON Proof Benchmarks ====");
        
        let total_start = Instant::now();

        // 1. AST parsing
        let step_start = Instant::now();
        let json_val = sample_person_simple_json();
        let ast = Node::from_value(json_val);
        println!("1. AST Parsing Time: {:?}", step_start.elapsed());

        // 2. Path-Tree & Hashes Extraction
        let step_start = Instant::now();
        let iv = b"test_init_vector";
        let (hash_strings, values, readable_paths) = path_tree::extract_paths_and_values(&ast, iv);
        println!("2. Path-Tree & Hashes Extraction Time: {:?}", step_start.elapsed());
        for (i, h) in hash_strings.iter().enumerate() {
            println!("   Path [{}]: {}", i, h);
        }

        // 3. Mapping to Elliptic Curve Generators
        let step_start = Instant::now();
        let generators = GeneratorBuilder::build_from_hashes(&hash_strings)
            .expect("Failed to build generators from hashes");
        println!("3. Curve Generators Build Time: {:?}", step_start.elapsed());
        for (i, g) in generators.iter().enumerate() {
            let affine = g.compress();
            println!("   Generator [{}]: {:?}", i, affine);
        }

        // 4. Compute Pedersen Commitment
        let step_start = Instant::now();
        let (commitment, z) = Commitment::compute_vector_commitment(&generators, &values)
            .expect("Failed to compute vector commitment");
        println!("4. Vector Commitment Time: {:?}", step_start.elapsed());
        println!("   Commitment point: {:?}", commitment.compress());
        println!("   Blinding factor z: {:?}", z);

        // 5. Generate Zero-Knowledge Proof
        let step_start = Instant::now();
        let mut prover = Prover::new(generators.clone(), values.clone(), hash_strings.clone(), readable_paths.clone(), commitment, z);
        let mut verifier = Verifier::new(commitment);
        let sc_indices = vec![0, 2, 3]; // Select attributes to disclose
        println!("   Disclosed attributes indices: {:?}", sc_indices);

        let alpha = prover.commit();
        let e = verifier.challenge(alpha, sc_indices.clone());
        println!("   Random Challenge e: {:?}", e);
        
        let (beta, opened_items) = prover.prove(&sc_indices, &e)
            .expect("Failed to generate proof");
        println!("   Generated Proof pi = {{");
        println!("      beta: {:?}", beta.compress());
        for (i, (val, _p, read_p, g)) in opened_items.iter().enumerate() {
            println!("      item[{}]: value='{}', path={:?}, generator={:?}", sc_indices[i], val, read_p, g.compress());
        }
        println!("   }}");
        println!("5. Proof Generation Time: {:?}", step_start.elapsed());

        // 6. Verify Proof
        let step_start = Instant::now();
        let valid = verifier.verify(beta, &opened_items).expect("Verification logic error");
        println!("6. Proof Verification Time: {:?}", step_start.elapsed());

        println!(">> Total Execution Time: {:?}", total_start.elapsed());
        assert!(valid, "Proof verification failed!");
        println!("==== Simple JSON Proof Benchmarks Completed ====\n");
    }

    #[test]
    fn test_complex_json_path_tree_to_proof() {
        println!("==== Complex JSON (Asset Proof) Benchmarks ====");
        
        let total_start = Instant::now();

        // 1. AST parsing
        let step_start = Instant::now();
        let json_val = sample_person_asset_proof_complex_json();
        let ast = Node::from_value(json_val);
        println!("1. AST Parsing Time: {:?}", step_start.elapsed());

        // 2. Path-Tree & Hashes Extraction
        let step_start = Instant::now();
        let iv = b"test_init_vector";
        let (hash_strings, values, readable_paths) = path_tree::extract_paths_and_values(&ast, iv);
        println!("2. Path-Tree & Hashes Extraction Time: {:?}", step_start.elapsed());
        for (i, h) in hash_strings.iter().enumerate() {
            println!("   Path [{}]: {}", i, h);
        }

        // 3. Mapping to Elliptic Curve Generators
        let step_start = Instant::now();
        let generators = GeneratorBuilder::build_from_hashes(&hash_strings)
            .expect("Failed to build generators from hashes");
        println!("3. Curve Generators Build Time ({:?} items): {:?}", generators.len(), step_start.elapsed());
        for (i, g) in generators.iter().enumerate() {
            let affine = g.compress();
            println!("   Generator [{}]: {:?}", i, affine);
        }

        // 4. Compute Pedersen Commitment
        let step_start = Instant::now();
        let (commitment, z) = Commitment::compute_vector_commitment(&generators, &values)
            .expect("Failed to compute vector commitment");
        println!("4. Vector Commitment Time: {:?}", step_start.elapsed());
        println!("   Commitment point: {:?}", commitment.compress());
        println!("   Blinding factor z: {:?}", z);

        // 5. Generate Zero-Knowledge Proof
        let step_start = Instant::now();
        let mut prover = Prover::new(generators.clone(), values.clone(), hash_strings.clone(), readable_paths.clone(), commitment, z);
        let mut verifier = Verifier::new(commitment);
        let sc_indices: Vec<usize> = (0..100).collect(); // For complex proofs, selectively disclose 100 attributes
        println!("   Disclosed attributes indices: {:?}", sc_indices);

        let alpha = prover.commit();
        let e = verifier.challenge(alpha, sc_indices.clone());
        println!("   Random Challenge e: {:?}", e);

        let (beta, opened_items) = prover.prove(&sc_indices, &e)
            .expect("Failed to generate proof");
        println!("   Generated Proof pi = {{");
        println!("      beta: {:?}", beta.compress());
        for (i, (val, _p, read_p, g)) in opened_items.iter().enumerate() {
            println!("      item[{}]: value='{}', path={:?}, generator={:?}", sc_indices[i], val, read_p, g.compress());
        }
        println!("   }}");
        println!("5. Proof Generation Time (Disclosing {:?} items): {:?}", opened_items.len(), step_start.elapsed());

        // 5.5 Calculate and print proof size
        let mut size_bytes = 32 + 32 + 32; // Commitment C, alpha, beta occupy space (each 32 bytes, Ristretto255 compressed format)
        for (_v_node, _path_hash, readable_path, _g_node) in &opened_items {
            for p in readable_path {
                size_bytes += p.len();
            }
        }
        println!("   >> Proof Size: {} bytes (approx {:.2} KB)", size_bytes, size_bytes as f64 / 1024.0);

        // 6. Verify Proof
        let step_start = Instant::now();
        let valid = verifier.verify(beta, &opened_items).expect("Verification logic error");
        println!("6. Proof Verification Time: {:?}", step_start.elapsed());

        println!(">> Total Execution Time: {:?}", total_start.elapsed());
        assert!(valid, "Proof verification failed!");
        println!("==== Complex JSON Benchmarks Completed ====\n");
    }

    #[test]
    fn test_scaling_benchmarks() {
        use std::time::Instant;
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};
        use std::collections::HashMap;
        
        println!("==== Scaling Benchmarks Start ====");
        
        let sizes = vec![0, 50, 100, 150, 200, 300, 400, 500];
        let depths = vec![2, 3, 5, 10];
        
        // 1. WARM UP phase: Wake up CPU frequency and preheat the system allocator
        println!("Warming up CPU and allocator...");
        for _ in 0..5 {
            let mut wrapper = serde_json::Map::new();
            for i in 0..200 {
                wrapper.insert(format!("attr_{}", i), serde_json::json!(i));
            }
            let ast = Node::from_value(serde_json::Value::Object(wrapper));
            let (hash_strings, values, _) = path_tree::extract_paths_and_values(&ast, b"iv");
            let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
            let _ = Commitment::compute_vector_commitment(&generators, &values).unwrap();
        }
        
        // 2. Multi-epoch sampling: Multiple rounds of sampling to smooth out random fluctuations
        let epochs = 5;
        let mut results: HashMap<(i32, usize), Vec<f64>> = HashMap::new();
        
        for _epoch in 0..epochs {
            for size in &sizes {
                for depth in &depths {
                    let mut current_val = serde_json::Value::Object(serde_json::Map::new());
                    if let serde_json::Value::Object(ref mut map) = current_val {
                        for i in 0..*size {
                            map.insert(format!("attr_{}", i), serde_json::json!(format!("val_{}", i)));
                        }
                    }
                    
                    for d in 0..(*depth - 1) {
                        let mut wrapper = serde_json::Map::new();
                        wrapper.insert(format!("level_{}", depth - d), current_val);
                        current_val = serde_json::Value::Object(wrapper);
                    }
                    
                    // Start timing from JSON parsing (AST construction), including path extraction, generator creation, and vector commitment computation
                    let start = Instant::now();
                    let ast = Node::from_value(current_val);
                    let iv = b"benchmark_iv";
                    let (hash_strings, values, _) = path_tree::extract_paths_and_values(&ast, iv);
                    
                    let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
                    let (_commitment, _z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();
                    let total_time = start.elapsed().as_secs_f64() * 1000.0;
                    
                    results.entry((*depth, *size)).or_insert_with(Vec::new).push(total_time);
                }
            }
        }
        
        // 3. Print Averaged Results
        for depth in &depths {
            for size in &sizes {
                let times = results.get(&(*depth, *size)).unwrap();
                // Exclude two extreme values (optional), or directly average
                let mut t = times.clone(); t.sort_by(|a, b| a.partial_cmp(b).unwrap()); let avg = t[t.len() / 2];
                
                println!("BENCHMARK_CSV:{},{},{}", depth, size, avg);
            }
        }
    }

    #[test]
    fn test_verify_benchmarks() {
        use std::time::Instant;
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};
        use json_commit::proof::{Prover, Verifier};
        use std::collections::HashMap;
        
        println!("==== Verification Benchmarks Start ====");
        
        let total_size = 200;
        let opened_sizes = vec![0, 20, 40, 60, 80, 100, 120, 140, 160, 180, 200];
        let depths = vec![2, 3, 5, 10];
        
        println!("Warming up CPU...");
        for _ in 0..5 {
            let mut wrapper = serde_json::Map::new();
            for i in 0..50 {
                wrapper.insert(format!("attr_{}", i), serde_json::json!(i));
            }
            let ast = Node::from_value(serde_json::Value::Object(wrapper));
            let (hash_strings, values, readable) = path_tree::extract_paths_and_values(&ast, b"iv");
            let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
            let (c, z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();
            let mut prover = Prover::new(generators, values, hash_strings, readable, c, z);
            let mut verifier = Verifier::new(c);
            let alpha = prover.commit();
            let e = verifier.challenge(alpha, vec![0, 1, 2]);
            let (beta, opened) = prover.prove(&vec![0, 1, 2], &e).unwrap();
            let _ = verifier.verify(beta, &opened).unwrap();
        }
        
        let epochs = 5;
        let mut results: HashMap<(i32, usize), Vec<f64>> = HashMap::new();
        
        for _epoch in 0..epochs {
            for opened_size in &opened_sizes {
                for depth in &depths {
                    let mut current_val = serde_json::Value::Object(serde_json::Map::new());
                    if let serde_json::Value::Object(ref mut map) = current_val {
                        for i in 0..total_size {
                            map.insert(format!("attr_{}", i), serde_json::json!(format!("val_{}", i)));
                        }
                    }
                    
                    for d in 0..(*depth - 1) {
                        let mut wrapper = serde_json::Map::new();
                        wrapper.insert(format!("level_{}", depth - d), current_val);
                        current_val = serde_json::Value::Object(wrapper);
                    }
                    
                    let ast = Node::from_value(current_val);
                    let iv = b"benchmark_iv";
                    let (hash_strings, values, readable) = path_tree::extract_paths_and_values(&ast, iv);
                    let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
                    let (commitment, z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();
                    
                    let mut prover = Prover::new(generators.clone(), values.clone(), hash_strings.clone(), readable.clone(), commitment, z);
                    let mut verifier = Verifier::new(commitment);
                    
                    let sc_indices: Vec<usize> = (0..*opened_size).collect();
                    let alpha = prover.commit();
                    let e = verifier.challenge(alpha, sc_indices.clone());
                    let (beta, opened_items) = prover.prove(&sc_indices, &e).unwrap();
                    
                    let inner_iters = 10;
                    let start = Instant::now();
                    let mut valid = true;
                    for _ in 0..inner_iters {
                        valid = verifier.verify(beta, &opened_items).unwrap();
                    }
                    let verify_time = (start.elapsed().as_secs_f64() * 1000.0) / (inner_iters as f64);
                    assert!(valid);
                    
                    results.entry((*depth, *opened_size)).or_insert_with(Vec::new).push(verify_time);
                }
            }
        }
        
        for depth in &depths {
            for opened_size in &opened_sizes {
                let times = results.get(&(*depth, *opened_size)).unwrap();
                let mut t = times.clone(); t.sort_by(|a, b| a.partial_cmp(b).unwrap()); let avg = t[t.len() / 2];
                
                println!("VERIFY_BENCHMARK_CSV:{},{},{}", depth, opened_size, avg);
            }
        }
    }

    #[test]
    fn test_proof_size_benchmarks() {
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};
        use json_commit::proof::{Prover, Verifier};
        
        println!("==== Proof Size Benchmarks Start ====");
        
        let total_size = 200;
        let opened_sizes = vec![0, 20, 40, 60, 80, 100, 120, 140, 160, 180, 200];
        let depths = vec![2, 3, 5, 10];
        
        for opened_size in &opened_sizes {
            for depth in &depths {
                let mut current_val = serde_json::Value::Object(serde_json::Map::new());
                if let serde_json::Value::Object(ref mut map) = current_val {
                    for i in 0..total_size {
                        map.insert(format!("attr_{}", i), serde_json::json!(format!("val_{}", i)));
                    }
                }
                
                for d in 0..(*depth - 1) {
                    let mut wrapper = serde_json::Map::new();
                    wrapper.insert(format!("level_{}", depth - d), current_val);
                    current_val = serde_json::Value::Object(wrapper);
                }
                
                let ast = Node::from_value(current_val);
                let iv = b"benchmark_iv";
                let (hash_strings, values, readable) = path_tree::extract_paths_and_values(&ast, iv);
                let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
                let (c, z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();
                
                let sc_indices: Vec<usize> = (0..*opened_size).collect();
                let mut prover = Prover::new(generators, values, hash_strings, readable, c, z);
                let mut verifier = Verifier::new(c);
                let alpha = prover.commit();
                let e = verifier.challenge(alpha, sc_indices.clone());
                let (_beta, opened) = prover.prove(&sc_indices, &e).unwrap();
                
                // Proof size calculation: Commitment C, alpha, beta (each 32 bytes, Ristretto255 compressed), plus paths.
                let mut size_bytes = 32 + 32 + 32; // C, alpha, beta points
                for (_v_node, _path_hash, readable_path, _g_node) in &opened {
                    for p in readable_path {
                        size_bytes += p.len();
                    }
                }
                
                println!("PROOF_SIZE_CSV:{},{},{}", depth, opened_size, size_bytes);
            }
        }
    }

    #[test]
    fn test_proof_gen_benchmarks() {
        use std::time::Instant;
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};
        use json_commit::proof::{Prover, Verifier};
        
        println!("==== Proof Generation Benchmarks Start ====");
        
        let total_size = 200;
        let opened_sizes = vec![0, 20, 40, 60, 80, 100];
        
        let mut wrapper = serde_json::Map::new();
        for i in 0..total_size {
            wrapper.insert(format!("attr_{}", i), serde_json::json!(format!("val_{}", i)));
        }
        let ast = Node::from_value(serde_json::Value::Object(wrapper));
        let (hash_strings, values, readable) = path_tree::extract_paths_and_values(&ast, b"benchmark_iv");
        let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
        let (commitment, z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();
        
        let epochs = 1000;
        let warmup_iters = 50;
        
        for opened_size in &opened_sizes {
            let sc_indices: Vec<usize> = (0..*opened_size).collect();
            
            // Warm-up phase (heavier to stabilize CPU frequency & caches)
            for _ in 0..warmup_iters {
                let mut prover_w = Prover::new(generators.clone(), values.clone(), hash_strings.clone(), readable.clone(), commitment, z.clone());
                let mut verifier_w = Verifier::new(commitment);
                let alpha_w = prover_w.commit();
                let e_w = verifier_w.challenge(alpha_w, sc_indices.clone());
                let _ = prover_w.prove(&sc_indices, &e_w).unwrap();
            }
            
            let mut samples: Vec<f64> = Vec::with_capacity(epochs);
            for _ in 0..epochs {
                // Testing ONLY the proof building operations
                let mut prover = Prover::new(generators.clone(), values.clone(), hash_strings.clone(), readable.clone(), commitment, z.clone());
                let mut verifier = Verifier::new(commitment);
                
                let start = Instant::now();
                let alpha = prover.commit();
                let e = verifier.challenge(alpha, sc_indices.clone());
                let _ = prover.prove(&sc_indices, &e).unwrap();
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            
            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p1 = samples[samples.len() / 100];
            println!("PROOF_GEN_CSV:{},{}", opened_size, p1);
        }
    }

    #[test]
    fn test_sdjwt_proof_gen_benchmarks() {
        use std::time::Instant;
        use sd_jwt_rs::{SDJWTIssuer, SDJWTHolder, ClaimsForSelectiveDisclosureStrategy, SDJWTSerializationFormat};
        use jsonwebtoken::EncodingKey;
        use serde_json::{json, Map, Value};
        
        println!("==== SD-JWT Proof Generation Benchmarks Start ====");
        
        // use the same test parameters as our scheme: 100 attributes, disclosure count from 0 to 100
        let total_size = 200;
        let opened_sizes: Vec<usize> = vec![0, 20, 40, 60, 80, 100];
        
        // sd-jwt-rust internal test EC private key
        const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
        
        // Construct the test payload identical to our scheme
        let mut user_claims_map = Map::new();
        user_claims_map.insert("iss".to_string(), Value::String("https://example.com/issuer".to_string()));
        user_claims_map.insert("iat".to_string(), json!(1683000000));
        user_claims_map.insert("exp".to_string(), json!(1883000000));
        for i in 0..total_size {
            user_claims_map.insert(format!("attr_{}", i), Value::String(format!("val_{}", i)));
        }
        let user_claims = Value::Object(user_claims_map.clone());
        
        // Issuer first issues an SD-JWT containing all selectively disclosable fields (this part is not timed, corresponding to our scheme's pre-commit work)
        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let mut issuer = SDJWTIssuer::new(issuer_key, None);
        let sd_jwt = issuer.issue_sd_jwt(
            user_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        ).unwrap();
        
        let epochs = 1000;
        
        for opened_size in &opened_sizes {
            // Construct the fields to be disclosed: the first opened_size attributes
            let mut claims_to_disclose = Map::new();
            for i in 0..*opened_size {
                claims_to_disclose.insert(format!("attr_{}", i), Value::String(format!("val_{}", i)));
            }
            
            // Warm-up phase (heavier)
            for _ in 0..50 {
                let mut holder = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
                let _ = holder.create_presentation(claims_to_disclose.clone(), None, None, None, None).unwrap();
            }
            
            let mut samples: Vec<f64> = Vec::with_capacity(epochs);
            for _ in 0..epochs {
                // Only measure the time for the Holder to generate the Presentation in the SD-JWT (corresponding to our scheme's prover.prove)
                let mut holder = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
                let start = Instant::now();
                let _ = holder.create_presentation(claims_to_disclose.clone(), None, None, None, None).unwrap();
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            

            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p1 = samples[samples.len() / 100];
            let mut holder2 = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
            let presentation_size = holder2.create_presentation(claims_to_disclose.clone(), None, None, None, None).unwrap().len();
            println!("SDJWT_PROOF_SIZE_CSV:{},{}", opened_size, presentation_size);
            println!("SDJWT_PROOF_GEN_CSV:{},{}", opened_size, p1);

        }
    }

    #[test]
    fn test_bbs_proof_gen_benchmarks() {
        use std::time::Instant;
        use pairing_crypto::bbs::{
            ciphersuites::{
                bls12_381::KeyPair,
                bls12_381_g1_sha_256::{proof_gen, sign},
            },
            BbsProofGenRequest,
            BbsProofGenRevealMessageRequest,
            BbsSignRequest,
        };

        println!("==== BBS (pairing_crypto) Proof Generation Benchmarks Start ====");

        // Use the same test parameters as our scheme and SD-JWT: 100 messages, disclosure count 0..=100
        let total_size: usize = 200;
        let opened_sizes: Vec<usize> = vec![0, 20, 40, 60, 80, 100];

        const IKM: &[u8; 49] =
            b"only_for_example_not_A_random_seed_at_Allllllllll";
        const KEY_INFO: &[u8; 16] = b"example-key-info";
        let header: &[u8] = b"example-header";
        let presentation_header: &[u8] = b"example-presentation-header";

        // Construct 200 "attr_i=val_i" byte messages
        let message_strings: Vec<String> = (0..total_size)
            .map(|i| format!("attr_{}=val_{}", i, i))
            .collect();
        let messages: Vec<&[u8]> =
            message_strings.iter().map(|s| s.as_bytes()).collect();

        // Generate key pair (not timed, corresponds to issuer's setup phase)
        let (secret_key, public_key) = KeyPair::new(IKM, KEY_INFO)
            .map(|kp| (kp.secret_key.to_bytes(), kp.public_key.to_octets()))
            .expect("BBS key generation failed");

        // Sign the messages (not timed, corresponds to issuer's credential issuance)
        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(&messages),
        })
        .expect("BBS sign failed");

        let epochs = 1;

        for opened_size in &opened_sizes {
            // The first opened_size messages are disclosed, the rest are hidden
            let proof_messages: Vec<BbsProofGenRevealMessageRequest<&[u8]>> =
                messages
                    .iter()
                    .enumerate()
                    .map(|(i, m)| BbsProofGenRevealMessageRequest {
                        reveal: i < *opened_size,
                        value: *m,
                    })
                    .collect();

            // warm-up (heavier)
            for _ in 0..50 {
                let _ = proof_gen(&BbsProofGenRequest {
                    public_key: &public_key,
                    header: Some(header),
                    presentation_header: Some(presentation_header),
                    messages: Some(proof_messages.as_slice()),
                    signature: &signature,
                    verify_signature: Some(false),
                })
                .expect("BBS proof_gen warm-up failed");
            }

            let mut samples: Vec<f64> = Vec::with_capacity(epochs);
            for _ in 0..epochs {
                let start = Instant::now();
                let _ = proof_gen(&BbsProofGenRequest {
                    public_key: &public_key,
                    header: Some(header),
                    presentation_header: Some(presentation_header),
                    messages: Some(proof_messages.as_slice()),
                    signature: &signature,
                    verify_signature: Some(false),
                })
                .expect("BBS proof_gen failed");
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }


            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p1 = samples[samples.len() / 100];
            let proof_size = proof_gen(&BbsProofGenRequest {
                public_key: &public_key,
                header: Some(header),
                presentation_header: Some(presentation_header),
                messages: Some(proof_messages.as_slice()),
                signature: &signature,
                verify_signature: Some(false),
            }).unwrap().len();
            println!("BBS_PROOF_SIZE_CSV:{},{}", opened_size, proof_size);
            println!("BBS_PROOF_GEN_CSV:{},{}", opened_size, p1);

        }
    }

    // Verification benchmarks — 3 schemes, total_size = 100, x = opened size

    #[test]
    fn test_our_verify_benchmarks() {
        use std::time::Instant;
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};
        use json_commit::proof::{Prover, Verifier};

        println!("==== Our Scheme Verification Benchmarks Start ====");

        let total_size = 200;
        let opened_sizes: Vec<usize> = vec![0, 20, 40, 60, 80, 100];
        let epochs = 1000;

        // Construct a JSON with 100 attributes (flat, depth=2, consistent with proof_gen test)
        let mut wrapper = serde_json::Map::new();
        for i in 0..total_size {
            wrapper.insert(format!("attr_{}", i), serde_json::json!(format!("val_{}", i)));
        }
        let ast = Node::from_value(serde_json::Value::Object(wrapper));
        let iv = b"benchmark_iv";
        let (hash_strings, values, readable) = path_tree::extract_paths_and_values(&ast, iv);
        let generators = GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
        let (commitment, z) = Commitment::compute_vector_commitment(&generators, &values).unwrap();

        for opened_size in &opened_sizes {
            let sc_indices: Vec<usize> = (0..*opened_size).collect();

            // Reconstruct prover/verifier each time, perform commit/challenge/prove outside of timing
            let mut prover = Prover::new(
                generators.clone(),
                values.clone(),
                hash_strings.clone(),
                readable.clone(),
                commitment,
                z,
            );
            let mut verifier = Verifier::new(commitment);
            let alpha = prover.commit();
            let e = verifier.challenge(alpha, sc_indices.clone());
            let (beta, opened_items) = prover.prove(&sc_indices, &e).unwrap();

            // warm-up
            let _ = verifier.verify(beta, &opened_items).unwrap();

            let mut total_time = 0.0;
            for _ in 0..epochs {
                let start = Instant::now();
                let valid = verifier.verify(beta, &opened_items).unwrap();
                total_time += start.elapsed().as_secs_f64() * 1000.0;
                assert!(valid);
            }

            let avg_time = total_time / (epochs as f64);
            println!("OUR_VERIFY_CSV:{},{}", opened_size, avg_time);
        }
    }

    #[test]
    fn test_sdjwt_verify_benchmarks() {
        use std::time::Instant;
        use sd_jwt_rs::{
            SDJWTIssuer, SDJWTHolder, SDJWTVerifier,
            ClaimsForSelectiveDisclosureStrategy, SDJWTSerializationFormat,
        };
        use jsonwebtoken::{EncodingKey, DecodingKey};
        use serde_json::{json, Map, Value};

        println!("==== SD-JWT Verification Benchmarks Start ====");

        // Consistent with proof_gen test: total_size = 100
        let total_size = 200;
        let opened_sizes: Vec<usize> = vec![0, 20, 40, 60, 80, 100];

        const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
        const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";

        let mut user_claims_map = Map::new();
        user_claims_map.insert("iss".to_string(), Value::String("https://example.com/issuer".to_string()));
        user_claims_map.insert("iat".to_string(), json!(1683000000));
        user_claims_map.insert("exp".to_string(), json!(1883000000));
        for i in 0..total_size {
            user_claims_map.insert(format!("attr_{}", i), Value::String(format!("val_{}", i)));
        }
        let user_claims = Value::Object(user_claims_map);

        let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
        let mut issuer = SDJWTIssuer::new(issuer_key, None);
        let sd_jwt = issuer.issue_sd_jwt(
            user_claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        ).unwrap();

        let epochs = 1000;

        for opened_size in &opened_sizes {
            // Holder pre-generates the presentation (not timed)
            let mut claims_to_disclose = Map::new();
            for i in 0..*opened_size {
                claims_to_disclose.insert(format!("attr_{}", i), Value::String(format!("val_{}", i)));
            }
            let mut holder = SDJWTHolder::new(sd_jwt.clone(), SDJWTSerializationFormat::Compact).unwrap();
            let presentation = holder
                .create_presentation(claims_to_disclose, None, None, None, None)
                .unwrap();

            // warm-up
            let _ = SDJWTVerifier::new(
                presentation.clone(),
                Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
                None, None,
                SDJWTSerializationFormat::Compact,
            ).unwrap();

            let mut total_time = 0.0;
            for _ in 0..epochs {
                let start = Instant::now();
                let _ = SDJWTVerifier::new(
                    presentation.clone(),
                    Box::new(|_, _| DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes()).unwrap()),
                    None, None,
                    SDJWTSerializationFormat::Compact,
                ).unwrap();
                total_time += start.elapsed().as_secs_f64() * 1000.0;
            }

            let avg_time = total_time / (epochs as f64);
            println!("SDJWT_VERIFY_CSV:{},{}", opened_size, avg_time);
        }
    }

    #[test]
    fn test_bbs_verify_benchmarks() {
        use std::time::Instant;
        use pairing_crypto::bbs::{
            ciphersuites::{
                bls12_381::KeyPair,
                bls12_381_g1_sha_256::{proof_gen, proof_verify, sign},
            },
            BbsProofGenRequest,
            BbsProofGenRevealMessageRequest,
            BbsProofVerifyRequest,
            BbsSignRequest,
        };

        println!("==== BBS (pairing_crypto) Verification Benchmarks Start ====");

        // Consistent with proof_gen test: total_size = 100
        let total_size: usize = 200;
        let opened_sizes: Vec<usize> = vec![0, 20, 40, 60, 80, 100];

        const IKM: &[u8; 49] =
            b"only_for_example_not_A_random_seed_at_Allllllllll";
        const KEY_INFO: &[u8; 16] = b"example-key-info";
        let header: &[u8] = b"example-header";
        let presentation_header: &[u8] = b"example-presentation-header";

        let message_strings: Vec<String> = (0..total_size)
            .map(|i| format!("attr_{}=val_{}", i, i))
            .collect();
        let messages: Vec<&[u8]> =
            message_strings.iter().map(|s| s.as_bytes()).collect();

        let (secret_key, public_key) = KeyPair::new(IKM, KEY_INFO)
            .map(|kp| (kp.secret_key.to_bytes(), kp.public_key.to_octets()))
            .expect("BBS key generation failed");

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(&messages),
        })
        .expect("BBS sign failed");

        let epochs = 1000;

        for opened_size in &opened_sizes {
            let proof_messages: Vec<BbsProofGenRevealMessageRequest<&[u8]>> =
                messages
                    .iter()
                    .enumerate()
                    .map(|(i, m)| BbsProofGenRevealMessageRequest {
                        reveal: i < *opened_size,
                        value: *m,
                    })
                    .collect();

            // Pre-generate proof (not timed)
            let proof = proof_gen(&BbsProofGenRequest {
                public_key: &public_key,
                header: Some(header),
                presentation_header: Some(presentation_header),
                messages: Some(proof_messages.as_slice()),
                signature: &signature,
                verify_signature: Some(false),
            })
            .expect("BBS proof_gen failed");

            // Construct verifier-side revealed messages: &[(usize, &[u8])]
            let revealed: Vec<(usize, &[u8])> = (0..*opened_size)
                .map(|i| (i, messages[i]))
                .collect();

            // warm-up
            let _ = proof_verify(&BbsProofVerifyRequest {
                public_key: &public_key,
                header: Some(header),
                presentation_header: Some(presentation_header),
                proof: &proof,
                messages: Some(revealed.as_slice()),
            })
            .expect("BBS proof_verify warm-up failed");

            let mut total_time = 0.0;
            for _ in 0..epochs {
                let start = Instant::now();
                let ok = proof_verify(&BbsProofVerifyRequest {
                    public_key: &public_key,
                    header: Some(header),
                    presentation_header: Some(presentation_header),
                    proof: &proof,
                    messages: Some(revealed.as_slice()),
                })
                .expect("BBS proof_verify failed");
                total_time += start.elapsed().as_secs_f64() * 1000.0;
                assert!(ok);
            }

            let avg_time = total_time / (epochs as f64);
            println!("BBS_VERIFY_CSV:{},{}", opened_size, avg_time);
        }
    }

    // Commit / Issuer-side benchmarks — SD-JWT (issue) and BBS (sign)
    // x = number of attributes (same axis as our scaling benchmark)


    #[test]
    fn test_sdjwt_commit_benchmarks() {
        use std::time::Instant;
        use sd_jwt_rs::{
            SDJWTIssuer, ClaimsForSelectiveDisclosureStrategy, SDJWTSerializationFormat,
        };
        use jsonwebtoken::EncodingKey;
        use serde_json::{json, Map, Value};

        println!("==== SD-JWT Commit (issue) Benchmarks Start ====");

        let sizes: Vec<usize> = vec![0, 50, 100, 150, 200];
        let epochs = 100;

        const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

        for &size in &sizes {
            let mut user_claims_map = Map::new();
            user_claims_map.insert("iss".to_string(), Value::String("https://example.com/issuer".to_string()));
            user_claims_map.insert("iat".to_string(), json!(1683000000));
            user_claims_map.insert("exp".to_string(), json!(1883000000));
            for i in 0..size {
                user_claims_map.insert(format!("attr_{}", i), Value::String(format!("val_{}", i)));
            }
            let user_claims = Value::Object(user_claims_map);

            // warm-up
            {
                let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
                let mut issuer = SDJWTIssuer::new(issuer_key, None);
                let _ = issuer.issue_sd_jwt(
                    user_claims.clone(),
                    ClaimsForSelectiveDisclosureStrategy::AllLevels,
                    None, false,
                    SDJWTSerializationFormat::Compact,
                ).unwrap();
            }

            let mut total_time = 0.0;
            for _ in 0..epochs {
                let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap();
                let mut issuer = SDJWTIssuer::new(issuer_key, None);
                let start = Instant::now();
                let _ = issuer.issue_sd_jwt(
                    user_claims.clone(),
                    ClaimsForSelectiveDisclosureStrategy::AllLevels,
                    None, false,
                    SDJWTSerializationFormat::Compact,
                ).unwrap();
                total_time += start.elapsed().as_secs_f64() * 1000.0;
            }

            let avg_time = total_time / (epochs as f64);
            println!("SDJWT_COMMIT_CSV:{},{}", size, avg_time);
        }
    }

    #[test]
    fn test_bbs_commit_benchmarks() {
        use std::time::Instant;
        use pairing_crypto::bbs::{
            ciphersuites::{bls12_381::KeyPair, bls12_381_g1_sha_256::sign},
            BbsSignRequest,
        };

        println!("==== BBS Commit (sign) Benchmarks Start ====");

        let sizes: Vec<usize> = vec![0, 50, 100, 150, 200];
        let epochs = 100;

        const IKM: &[u8; 49] =
            b"only_for_example_not_A_random_seed_at_Allllllllll";
        const KEY_INFO: &[u8; 16] = b"example-key-info";
        let header: &[u8] = b"example-header";

        let (secret_key, public_key) = KeyPair::new(IKM, KEY_INFO)
            .map(|kp| (kp.secret_key.to_bytes(), kp.public_key.to_octets()))
            .expect("BBS key generation failed");

        for &size in &sizes {
            let message_strings: Vec<String> = (0..size)
                .map(|i| format!("attr_{}=val_{}", i, i))
                .collect();
            let messages: Vec<&[u8]> =
                message_strings.iter().map(|s| s.as_bytes()).collect();

            // warm-up
            let _ = sign(&BbsSignRequest {
                secret_key: &secret_key,
                public_key: &public_key,
                header: Some(header),
                messages: Some(&messages),
            }).expect("BBS sign warm-up failed");

            let mut total_time = 0.0;
            for _ in 0..epochs {
                let start = Instant::now();
                let _ = sign(&BbsSignRequest {
                    secret_key: &secret_key,
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(&messages),
                }).expect("BBS sign failed");
                total_time += start.elapsed().as_secs_f64() * 1000.0;
            }

            let avg_time = total_time / (epochs as f64);
            println!("BBS_COMMIT_CSV:{},{}", size, avg_time);
        }
    }

    /// Commitment generation benchmark (Ristretto255):
    /// Construct JSON → Extract paths → Generate generator → Compute Pedersen vector commitment
    /// Using the actual Commitment::compute_vector_commitment (curve25519-dalek)
    #[test]
    fn test_our_commit_benchmarks() {
        use std::time::Instant;
        use json_commit::ast::Node;
        use json_commit::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};

        println!("==== Our Commit Benchmarks (Ristretto255) Start ====");

        let sizes: Vec<usize> = vec![0, 50, 100, 150, 200];
        let depths: Vec<usize> = vec![2, 10];
        let epochs = 20;

        // Warm-up
        for _ in 0..5 {
            let mut wrapper = serde_json::Map::new();
            for i in 0..200 {
                wrapper.insert(format!("attr_{}", i), serde_json::json!(i));
            }
            let ast = Node::from_value(serde_json::Value::Object(wrapper));
            let (hs, vs, _) = path_tree::extract_paths_and_values(&ast, b"iv");
            let gens = GeneratorBuilder::build_from_hashes(&hs).unwrap();
            let _ = Commitment::compute_vector_commitment(&gens, &vs).unwrap();
        }

        for &depth in &depths {
        for &size in &sizes {
            let mut samples = Vec::with_capacity(epochs);

            for _ in 0..epochs {
                // Construct nested JSON
                let mut current_val = serde_json::Value::Object(serde_json::Map::new());
                if let serde_json::Value::Object(ref mut map) = current_val {
                    for i in 0..size {
                        map.insert(
                            format!("attr_{}", i),
                            serde_json::json!(format!("val_{}", i)),
                        );
                    }
                }
                for d in 0..(depth - 1) {
                    let mut wrapper = serde_json::Map::new();
                    wrapper.insert(format!("level_{}", depth - d), current_val);
                    current_val = serde_json::Value::Object(wrapper);
                }

                let start = Instant::now();

                // Complete commitment generation process (Ristretto255)
                let ast = Node::from_value(current_val);
                let iv = b"benchmark_iv";
                let (hash_strings, values, _) =
                    path_tree::extract_paths_and_values(&ast, iv);
                let generators =
                    GeneratorBuilder::build_from_hashes(&hash_strings).unwrap();
                let _ = Commitment::compute_vector_commitment(&generators, &values).unwrap();

                let t_ms = start.elapsed().as_secs_f64() * 1000.0;
                samples.push(t_ms);
            }

            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = samples[samples.len() / 2];
            println!("OUR_PIPPENGER_COMMIT_CSV:{},{},{}", depth, size, median);
        }
        }

        println!("==== Our Commit Benchmarks (Ristretto255) Done ====");
    }

    #[test]
    fn test_msm_optimization_comparison() {
        use ark_ec::{CurveGroup, Group, VariableBaseMSM};
        use ark_ff::UniformRand;
        use ark_std::Zero;
        use std::time::Instant;

        // MSM sizes: aligned with proof_gen benchmark (total messages = 100)
        let sizes: Vec<usize> = vec![10, 50, 100, 200];
        let epochs_per_size = 200;

        let mut rng = ark_std::test_rng();

        println!("\n==== MSM Optimization Comparison ====");
        println!("epochs per sample: {}", epochs_per_size);

        // Curve25519 / Ristretto255 (the curve used by SD-JCom, curve25519-dalek)
        //   (1) Serial naive: scalar-multiply each point then accumulate
        //   (2) Pippenger: curve25519-dalek vartime_multiscalar_mul (Pippenger algorithm)
        {
            use curve25519_dalek::ristretto::RistrettoPoint;
            use curve25519_dalek::scalar::Scalar;
            use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
            use rand_core::OsRng;

            println!("\n---- Curve: Curve25519 / Ristretto255 (SD-JCom) ----");
            println!("n,serial_naive_ms,pippenger_ms,speedup");

            for &n in &sizes {
                let points: Vec<RistrettoPoint> =
                    (0..n).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
                let scalars: Vec<Scalar> =
                    (0..n).map(|_| Scalar::random(&mut OsRng)).collect();

                // warm-up
                let _ = scalars.iter().zip(points.iter())
                    .map(|(s, p)| s * p)
                    .fold(RistrettoPoint::identity(), |acc, x| acc + x);

                // (1) Serial naive
                let t = Instant::now();
                for _ in 0..epochs_per_size {
                    let _acc = scalars.iter().zip(points.iter())
                        .map(|(s, p)| s * p)
                        .fold(RistrettoPoint::identity(), |acc, x| acc + x);
                }
                let serial_ms =
                    t.elapsed().as_secs_f64() * 1000.0 / epochs_per_size as f64;

                // (2) Pippenger: curve25519-dalek vartime_multiscalar_mul
                let t = Instant::now();
                for _ in 0..epochs_per_size {
                    let _acc = RistrettoPoint::vartime_multiscalar_mul(&scalars, &points);
                }
                let pip_ms =
                    t.elapsed().as_secs_f64() * 1000.0 / epochs_per_size as f64;

                println!(
                    "{},{:.4},{:.4},{:.2}x",
                    n,
                    serial_ms,
                    pip_ms,
                    serial_ms / pip_ms
                );
            }
        }

        // BLS12-381 G1 (curve used by BBS; pairing_crypto internally uses blstrs serial MSM)
        {
            use ark_bls12_381::{Fr, G1Projective};

            println!("\n---- Curve: BLS12-381 G1 ----");
            println!("n,serial_naive_ms,pippenger_ms,speedup");

            for &n in &sizes {
                let points: Vec<G1Projective> =
                    (0..n).map(|_| G1Projective::rand(&mut rng)).collect();
                let points_aff: Vec<_> =
                    points.iter().map(|p| p.into_affine()).collect();
                let scalars: Vec<Fr> =
                    (0..n).map(|_| Fr::rand(&mut rng)).collect();

                // warm-up
                let _ = points.iter().zip(scalars.iter()).fold(
                    G1Projective::zero(),
                    |acc, (p, s)| acc + *p * *s,
                );

                // (1) Serial naive
                let t = Instant::now();
                for _ in 0..epochs_per_size {
                    let _acc = points.iter().zip(scalars.iter()).fold(
                        G1Projective::zero(),
                        |acc, (p, s)| acc + *p * *s,
                    );
                }
                let serial_ms =
                    t.elapsed().as_secs_f64() * 1000.0 / epochs_per_size as f64;

                // (2) Pippenger (arkworks VariableBaseMSM)
                let t = Instant::now();
                for _ in 0..epochs_per_size {
                    let _acc =
                        G1Projective::msm(&points_aff, &scalars).unwrap();
                }
                let pip_ms =
                    t.elapsed().as_secs_f64() * 1000.0 / epochs_per_size as f64;

                println!(
                    "{},{:.4},{:.4},{:.2}x",
                    n,
                    serial_ms,
                    pip_ms,
                    serial_ms / pip_ms
                );
            }
        }

        println!("\n==== MSM Comparison Done ====\n");
    }
}
