use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use rand_core::OsRng;
use sha2::{Sha256, Digest};
use crate::errors::JcError;

/// Hash a string value to a scalar on the curve
pub fn hash_value_to_scalar(value: &str) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    Scalar::from_bytes_mod_order(bytes)
}

/// prover
pub struct Prover {
    generators: Vec<RistrettoPoint>,
    values: Vec<String>,
    paths: Vec<String>,
    readable_paths: Vec<Vec<String>>,
    commitment: RistrettoPoint,
    z: Scalar,
    r: Option<Scalar>,
}

impl Prover {
    pub fn new(
        generators: Vec<RistrettoPoint>,
        values: Vec<String>,
        paths: Vec<String>,
        readable_paths: Vec<Vec<String>>,
        commitment: RistrettoPoint,
        z: Scalar,
    ) -> Self {
        Self {
            generators,
            values,
            paths,
            readable_paths,
            commitment,
            z,
            r: None,
        }
    }

    ///  Step 1: Prover P generates a random number r and computes alpha = r * h
    pub fn commit(&mut self) -> RistrettoPoint {
        let r = Scalar::random(&mut OsRng);
        self.r = Some(r);
        &r * &RISTRETTO_BASEPOINT_POINT
    }

    ///  Step 3: Prover P receives the challenge and generates the proof beta and opened values
    pub fn prove(
        &self,
        sc_indices: &[usize],
        e: &Scalar,
    ) -> Result<(RistrettoPoint, Vec<(String, String, Vec<String>, RistrettoPoint)>), JcError> {
        let r = self.r.as_ref().ok_or_else(|| JcError::Other("Prover commit step missed".into()))?;
        let h = RISTRETTO_BASEPOINT_POINT;

        // Boundary check (maintain original semantics)
        for &i in sc_indices {
            if i >= self.generators.len() || i >= self.values.len() {
                return Err(JcError::Other(format!("Index {} out of bounds", i)));
            }
        }

        // Serial multi-scalar multiplication: compute h_vi * g_i for each i and accumulate
        let sum_opened: RistrettoPoint = sc_indices
            .iter()
            .map(|&i| {
                let h_vi = hash_value_to_scalar(&self.values[i]);
                &h_vi * &self.generators[i]
            })
            .fold(RistrettoPoint::identity(), |a, b| a + b);

        let term_sc = self.z * h + sum_opened;
        let c_prime = self.commitment - term_sc;

        let ze = self.z * *e;
        let ze_plus_r = ze + r;
        let part1 = ze_plus_r * h;
        let part2 = *e * c_prime;
        let beta = part1 + part2;

        let opened_items = sc_indices.iter().map(|&i| {
            (self.values[i].clone(), self.paths[i].clone(), self.readable_paths[i].clone(), self.generators[i].clone())
        }).collect();

        Ok((beta, opened_items))
    }
}

/// verifier
pub struct Verifier {
    commitment: RistrettoPoint,
    sc_indices: Vec<usize>,
    e: Option<Scalar>,
    alpha: Option<RistrettoPoint>,
}

impl Verifier {
    pub fn new(commitment: RistrettoPoint) -> Self {
        Self {
            commitment,
            sc_indices: Vec::new(),
            e: None,
            alpha: None,
        }
    }

    ///  Step 2: Verifier V receives alpha, selects the indices SC to be revealed by the prover, and provides a random challenge e
    pub fn challenge(&mut self, alpha: RistrettoPoint, sc_indices: Vec<usize>) -> Scalar {
        self.alpha = Some(alpha);
        self.sc_indices = sc_indices;
        
        let e = Scalar::random(&mut OsRng); // Generate a random scalar in the field
        self.e = Some(e);
        e
    }

    ///  Step 4: Verifier V receives the proof pi={beta, values}, and verifies the equation: 
    /// beta * (Prod_{i in SC} g_i^{H(v_i)})^e == C^e * alpha
    pub fn verify(&self, beta: RistrettoPoint, opened_items: &[(String, String, Vec<String>, RistrettoPoint)]) -> Result<bool, JcError> {
        let e = self.e.as_ref().ok_or_else(|| JcError::Other("Challenge e not found".into()))?;
        let alpha = self.alpha.as_ref().ok_or_else(|| JcError::Other("Commit alpha not found".into()))?;

        if opened_items.len() != self.sc_indices.len() {
            return Err(JcError::Other("Mismatch in opened items length".into()));
        }

        // Batch rebuild all g_i at once to avoid calling hash-to-curve individually in the loop
        let all_paths: Vec<String> = opened_items.iter().map(|(_, path_i, _, _)| path_i.clone()).collect();
        let expected_generators = crate::commit::generator::GeneratorBuilder::build_from_hashes(&all_paths)?;

        if expected_generators.len() != opened_items.len() {
            return Err(JcError::Other("Generator count mismatch".into()));
        }

        // Serially verify generator validity and accumulate scalar multiplications
        let mut sum_sc = RistrettoPoint::identity();
        for ((v_i, _, _, g_i), expected_g_i) in opened_items.iter().zip(expected_generators.iter()) {
            if expected_g_i != g_i {
                return Ok(false);
            }
            let h_vi = hash_value_to_scalar(v_i);
            sum_sc = sum_sc + &h_vi * g_i;
        }

        let lhs = beta + *e * sum_sc;
        let rhs = *e * self.commitment + *alpha;

        Ok(lhs == rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Node;
    use crate::commit::{commitment::Commitment, generator::GeneratorBuilder, path_tree};

    #[test]
    fn test_select_open_protocol() {
        // --- [Preparation Phase] Build commitments and generators from JSON ---
        let json_str = r#"{"identity": {"id": 1, "name": "Alice"}, "balance": {"CNY": 200,"USD": 150,"JNY": 100},"company":"SJTU"}"#;
        let ast = Node::parse_str(json_str).unwrap();
        let iv = b"init_vector";
        
        // Get paths and leaf values
        let (path_hash_strings, leaf_values, readable_paths) = path_tree::extract_paths_and_values(&ast, iv);
        
        // Compute the corresponding generators g_i
        let generators = GeneratorBuilder::build_from_hashes(&path_hash_strings).unwrap();
        
        // Compute the original zero-knowledge commitment C and the corresponding scalar z
        let (c, z) = Commitment::compute_vector_commitment(&generators, &leaf_values).unwrap();
        
        println!("\n=========== Original commitment generated ===========");
        println!("Total leaf nodes: {}", leaf_values.len());

        // --- [ZK Interaction Phase] ---
        
        let mut prover = Prover::new(generators.clone(), leaf_values.clone(), path_hash_strings.clone(), readable_paths.clone(), c, z);
        let mut verifier = Verifier::new(c);

        // Assume we only want to selectively disclose the fields at indices 0 ("name": "Alice") and 2 ("city": "Shanghai")
        let sc_indices = vec![0, 2];

        // 1. P generates alpha and sends it to V
        let alpha = prover.commit();
        println!("(1) P -> V :  alpha sent");

        // 2. V determines the disclosure indices SC, generates a random challenge e, and sends it to P
        let e = verifier.challenge(alpha, sc_indices.clone());
        println!("(2) V -> P :  Disclosure indices {:?}, challenge scalar e sent", sc_indices);

        // 3. P computes and constructs the zero-knowledge proof, including beta and the specific plaintext values, and sends it to V
        let (beta, opened_items) = prover.prove(&sc_indices, &e).unwrap();
        println!("(3) P -> V :  Sending proof pi = {{");
        println!("      beta: {:?}", beta);
        for (idx, (v, p, read_p, g)) in opened_items.iter().enumerate() {
            println!("      item[{}]: value='{}', path='{:?}', generator={:?}", idx, v, read_p, g);
        }
        println!("  }}");

        // 4. V verifies the correctness of the equation upon receiving the proof
        let result = verifier.verify(beta, &opened_items).unwrap();
        println!("(4) V local verification result: {}", if result { "Passed" } else { "Failed" });

        assert!(result, "The SelectOpen protocol verification should succeed!");
    }
}