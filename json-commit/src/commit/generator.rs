use crate::ast::Node;
use crate::errors::JcError;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::{self, JoinSet};
use std::collections::VecDeque;


use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Sha512;

#[derive(Debug, Clone)]
pub struct PrimitiveEntry {
    /// path，like [("obj", "key"), ("arr", "0")]
    pub path: Vec<(String, String)>,
    pub value: Value,
}

impl PrimitiveEntry {
    /// a simple async function
    pub async fn func(&self) {
        println!("Processing primitive at {:?}", self.path);
    }
}

// define a global unique public domain separation tag
pub const CREDENTIAL_GENERATOR_DST: &[u8] = b"JSON_CREDENTIAL_GENERATOR_DST_V1";

pub struct GeneratorBuilder;

impl GeneratorBuilder {
    /// Map an array of precomputed hash strings to Ristretto255 group generators
    pub fn build_from_hashes(
        hash_strings: &[String],
    ) -> Result<Vec<RistrettoPoint>, JcError> {
        let dst = CREDENTIAL_GENERATOR_DST;
        let generators = hash_strings
            .iter()
            .map(|hash_str| {
                // Hash the concatenation of DST and message to the Ristretto255 group
                let msg = hash_str.as_bytes();
                let mut input = Vec::with_capacity(dst.len() + msg.len());
                input.extend_from_slice(dst);
                input.extend_from_slice(msg);
                RistrettoPoint::hash_from_bytes::<Sha512>(&input)
            })
            .collect();
        Ok(generators)
    }
}


#[cfg(test)]
mod tests {
    use super::GeneratorBuilder;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use sha2::Sha512;

    #[test]
    fn func() {
        let dst = b"MY_APP_DOMAIN_SEPARATION_TAG";
        let msg = b"Hello, world!";
        let mut input = Vec::new();
        input.extend_from_slice(dst);
        input.extend_from_slice(msg);
        let point = RistrettoPoint::hash_from_bytes::<Sha512>(&input);
        println!("Hashed Point: {:?}", point.compress());
    }

    #[test]
    fn test_generator_builder() {
        let hash1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        let hash2 = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92".to_string();
        let hash_results = vec![hash1, hash2];

        let generators = GeneratorBuilder::build_from_hashes(&hash_results);
        assert!(generators.is_ok(), "Failed to build generators");

        let points = generators.unwrap();
        assert_eq!(points.len(), 2, "Incorrect number of generators");

        println!("Generator based on the first hash: {:?}", points[0].compress());
        println!("Generator based on the second hash: {:?}", points[1].compress());
    }
}
