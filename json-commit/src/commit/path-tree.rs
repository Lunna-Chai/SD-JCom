use crate::ast::Node;
use sha2::{Sha256, Digest};

/// path field: represent path segment, indicating the position of the current node in the previous layer (object key or array index)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Key(String),
    Index(usize),
}

/// path tree node
#[derive(Debug, Clone)]
pub struct PathNode {
    /// path segment of the current node (e.g., Key("id") or Index(0))
    pub segment: Option<PathSegment>,
    /// path hash of the current node computed from top to bottom (corresponding to path_i in the diagram)
    pub path_hash: Vec<u8>,
    pub readable_path: Vec<String>,
    /// list of child paths or empty (if reached the leaf level of the original AST, no need to store the original value)
    pub children: PathChildren,
}

#[derive(Debug, Clone)]
pub enum PathChildren {
    /// Node containing child path branches
    Branches(Vec<PathNode>),
    /// Path endpoint (no longer carries the original JSON Value)
    Empty,
}

impl PathNode {
    /// Generate a path tree from the root-level AST node
    /// * `iv`: initial vector or initial base of the Root Hash
    pub fn from_ast(ast: &Node, iv: &[u8]) -> Self {
        // According to the diagram logic, the root can be considered as H(iv)
        let root_hash = Self::hash_function(iv);
        let root_readable = vec![String::from_utf8_lossy(iv).into_owned()];
        Self::build_tree(None, ast, &root_hash, &root_readable)
    }

    /// Internal recursive function to build the path tree (propagating parent_hash from top to bottom)
    fn build_tree(segment: Option<PathSegment>, node: &Node, parent_hash: &[u8], parent_readable: &[String]) -> Self {
        // Compute the path hash of the current node
        let current_hash = match &segment {
            Some(seg) => Self::hash_concat(parent_hash, seg),
            None => parent_hash.to_vec(), // Root node directly uses the initial Root Hash
        };
        
        let mut current_readable = parent_readable.to_vec();
        match &segment {
            Some(PathSegment::Key(k)) => current_readable.push(k.clone()),
            Some(PathSegment::Index(idx)) => current_readable.push(idx.to_string()),
            None => {}
        }

        match node {
            Node::Object(fields) => {
                let mut branches = Vec::with_capacity(fields.len());
                for (key, child_node) in fields {
                    let child_segment = Some(PathSegment::Key(key.clone()));
                    branches.push(Self::build_tree(child_segment, child_node, &current_hash, &current_readable));
                }
                PathNode {
                    segment,
                    path_hash: current_hash,
                    readable_path: current_readable.clone(),
                    children: PathChildren::Branches(branches),
                }
            }
            Node::Array(items) => {
                let mut branches = Vec::with_capacity(items.len());
                for (index, child_node) in items.iter().enumerate() {
                    let child_segment = Some(PathSegment::Index(index));
                    branches.push(Self::build_tree(child_segment, child_node, &current_hash, &current_readable));
                }
                PathNode {
                    segment,
                    path_hash: current_hash,
                    readable_path: current_readable.clone(),
                    children: PathChildren::Branches(branches),
                }
            }
            Node::Primitive(_) => {
                // Note: Since we only need to build the "path" tree, we terminate the branch when encountering a primitive data type.
                // The `path_hash` of the current node is still valid (this itself is the path_i required for the last level),
                // but there is no need to store the actual data in the child nodes.
                PathNode {
                    segment,
                    path_hash: current_hash,
                    readable_path: current_readable.clone(),
                    children: PathChildren::Empty,
                }
            }
        }
    }

    /// Example hash function: compute H(data)
     fn hash_function(data: &[u8]) -> Vec<u8> {
        // Placeholder logic: simply return the concatenation to be able to construct the full textual path
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec() 
    }

    /// Concatenation and hash logic: H(parent_hash || segment_bytes)
    fn hash_concat(parent_hash: &[u8], segment: &PathSegment) -> Vec<u8> {
        let mut prepend_data = parent_hash.to_vec();
        match segment {
            PathSegment::Key(k) => {
                prepend_data.extend_from_slice(k.as_bytes());
            }
            PathSegment::Index(idx) => {
                // Serialize the array index and include it in the hash concatenation
                prepend_data.extend_from_slice(idx.to_string().as_bytes());
            }
        }
        
        Self::hash_function(&prepend_data)
    }

    /// Traverse and extract all path_hash values that reach the terminal (Empty) nodes.
    pub fn collect_leaf_paths(&self) -> (Vec<Vec<u8>>, Vec<Vec<String>>) {
        let mut paths = Vec::new();
        let mut readables = Vec::new();
        self.collect_leaf_paths_recursive(&mut paths, &mut readables);
        (paths, readables)
    }

    /// Internal depth-first traversal to collect leaf paths
    fn collect_leaf_paths_recursive(&self, paths: &mut Vec<Vec<u8>>, readables: &mut Vec<Vec<String>>) {
        match &self.children {
            PathChildren::Empty => {
                // Current node has no successor nodes (reached the original Primitive data end), add to results
                paths.push(self.path_hash.clone());
                readables.push(self.readable_path.clone());
            }
            PathChildren::Branches(branches) => {
                for child in branches {
                    child.collect_leaf_paths_recursive(paths, readables);
                }
            }
        }
    }
}

pub fn generate_all_paths_from_ast(ast: &Node, iv: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<String>>) {
    let root = PathNode::from_ast(ast, iv);
    root.collect_leaf_paths()
}

/// Given an array of plaintext paths, return a one-dimensional array of SHA-256 hash strings
pub fn compute_path_hashes(paths: &[Vec<u8>]) -> Vec<String> {
    paths.iter()
        .map(|p| {
            let mut hasher = Sha256::new();
            hasher.update(p);
            hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
        })
        .collect()
}

/// Simultaneously collect paths and corresponding leaf node values
/// Returns (array of path hash strings, array of corresponding leaf values, array of readable paths)
pub fn extract_paths_and_values(ast: &Node, iv: &[u8]) -> (Vec<String>, Vec<String>, Vec<Vec<String>>) {
    let mut leaf_values = Vec::new();
    
    // First, compute all paths
    let (all_paths, readable_paths) = generate_all_paths_from_ast(ast, iv);
    
    // Simultaneously collect values
    collect_leaf_values_recursive(ast, &mut leaf_values);
    
    // Compute SHA-256 hash strings for the paths
    let hash_strings = compute_path_hashes(&all_paths);
    
    (hash_strings, leaf_values, readable_paths)
}

/// Recursively collect all leaf node values
fn collect_leaf_values_recursive(node: &Node, values: &mut Vec<String>) {
    match node {
        Node::Object(fields) => {
            for (_, child_node) in fields {
                collect_leaf_values_recursive(child_node, values);
            }
        }
        Node::Array(items) => {
            for child_node in items {
                collect_leaf_values_recursive(child_node, values);
            }
        }
        Node::Primitive(val) => {
            values.push(val.to_string());
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Node;

    #[test]
    fn test_extract_all_paths() {
        let json_str = r#"{"identity": {"id": 1, "name": "Alice"}, "balance": {"CNY": 200,"USD": 150,"JNY": 100},"company":"SJTU"}"#;
        let ast = Node::parse_str(json_str).unwrap();
        
        // Simulate initial IV
        let iv = b"init_vector";
        
        // Directly call the high-level function to get the array
        let (all_paths, _readable) = generate_all_paths_from_ast(&ast, iv);
        
        println!("==== Total paths found: {} ====", all_paths.len());
        for (i, p) in all_paths.iter().enumerate() {
            // Keep the output of "init_vectoridentityid" and other readable path strings before hashing
            println!("path{}: {:?}", i + 1, String::from_utf8_lossy(p));
        }
     
        let hash_string_array = compute_path_hashes(&all_paths);
            
        println!("\n==== Output 1D Hash Array: ====\n{:?}", hash_string_array);
    }
}