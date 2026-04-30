use serde_json::Value;
use tokio::task::{self, JoinSet};
use tokio::sync::mpsc;
use std::collections::VecDeque;

use crate::ast::Node;
use crate::commit::{self, commitment};
use crate::commit::generator::PrimitiveEntry;


use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use crate::errors::JcError;

pub struct Commitment;

impl Commitment {
    /// compute Pedersen Vector Commitment: C = h^z * Prod(g_i ^ H(v_i))
    ///
    ///
    /// - `generators`: Array of elliptic curve group elements [g_1, ... g_n] derived from the path-tree
    /// - `values`: Array of strings corresponding to the values of each leaf node [v_1, ... v_n]
    pub fn compute_vector_commitment(
        generators: &[RistrettoPoint],
        values: &[String],
    ) -> Result<(RistrettoPoint, Scalar), JcError> {
        if generators.len() != values.len() {
            return Err(JcError::Other(
                "The number of generators must match the number of values".to_string(),
            ));
        }

        // I. Select a random scalar z <- F (Ristretto255 scalar field)
        let z = Scalar::random(&mut OsRng);

        // Get the base point h: Ristretto255 standard base point
        let h = RISTRETTO_BASEPOINT_POINT;

        // Compute the first part: C_base = z * h
        let mut commitment = z * h;

        // II. Compute the product part (elliptic curve point addition): accumulate sum(g_i * H(v_i))
        for (g_i, v_i) in generators.iter().zip(values.iter()) {
            let mut hasher = Sha256::new();
            hasher.update(v_i.as_bytes());
            let bytes: [u8; 32] = hasher.finalize().into();
            let h_vi_scalar = Scalar::from_bytes_mod_order(bytes);
            let term = h_vi_scalar * g_i;
            commitment = commitment + term;
        }

        // Return the final commitment C and the witness random scalar z (if the prover needs to keep z)
        Ok((commitment, z))
    }

    /// Compute Pedersen Vector Commitment using a given random scalar z
    pub fn compute_vector_commitment_with_z(
        generators: &[RistrettoPoint],
        values: &[String],
        z: &Scalar,
    ) -> Result<RistrettoPoint, JcError> {
        if generators.len() != values.len() {
            return Err(JcError::Other(
                "The number of generators must match the number of values".to_string(),
            ));
        }

        let h = RISTRETTO_BASEPOINT_POINT;
        let mut commitment = z * h;

        for (g_i, v_i) in generators.iter().zip(values.iter()) {
            let mut hasher = Sha256::new();
            hasher.update(v_i.as_bytes());
            let bytes: [u8; 32] = hasher.finalize().into();
            let h_vi_scalar = Scalar::from_bytes_mod_order(bytes);
            let term = h_vi_scalar * g_i;
            commitment = commitment + term;
        }

        Ok(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Node;
    use crate::commit::path_tree;
    use crate::commit::generator::GeneratorBuilder;

    #[test]
    fn test_full_commitment_pipeline() {
        // 1. Input JSON string
        let json_str = r#"{"identity": {"id": 1, "name": "Alice"}, "balance": {"CNY": 200,"USD": 150,"JNY": 100},"company":"SJTU"}"#;
        let ast = Node::parse_str(json_str).unwrap();
        let iv = b"init_vector";
        
        // 2. Extract paths and values
        println!("\n========== STEP 1: Extract Paths from Path-Tree ==========");
        let (path_hash_strings, leaf_values, _) = path_tree::extract_paths_and_values(&ast, iv);
        
        println!("Total leaf nodes: {}", path_hash_strings.len());
        for (i, (path, value)) in path_hash_strings.iter().zip(leaf_values.iter()).enumerate() {
            println!("Path{}: hash={}", i + 1, &path[..16.min(path.len())]);
            println!("  └─ Value: {}", value);
        }
        
        // 3. Generate generators (using path hash strings)
        println!("\n========== STEP 2: Generate Curve Points from Paths ==========");
        let generators_result = GeneratorBuilder::build_from_hashes(&path_hash_strings);
        assert!(generators_result.is_ok(), "Failed to build generators");
        let generators = generators_result.unwrap();
        
        println!("Generated {} generators:", generators.len());
        for (i, g) in generators.iter().enumerate() {
            println!("g{}: {:?}", i + 1, g);
        }
        
        // 4. Compute Pedersen Vector Commitment
        println!("\n========== STEP 3: Compute Pedersen Vector Commitment ==========");
        let commitment_result = Commitment::compute_vector_commitment(&generators, &leaf_values);
        assert!(commitment_result.is_ok(), "Failed to compute commitment");
        
        let (commitment, z) = commitment_result.unwrap();
        println!("Random mask z: {:?}", z);
        println!("Final Commitment C: {:?}", commitment);
        
        // 5. Summary output
        println!("\n========== SUMMARY ==========");
        println!("✓ Successfully computed Pedersen Vector Commitment");
        println!("  - Input JSON: {}", json_str);
        println!("  - Leaf nodes processed: {}", leaf_values.len());
        println!("  - Commitment value computed with {} generators", generators.len());
    }
}