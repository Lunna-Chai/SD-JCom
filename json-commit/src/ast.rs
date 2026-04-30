use serde_json::{Map, Value};
use crate::errors::JcError;

/// AST node: Object / Array / Primitive
#[derive(Debug, Clone)]
pub enum Node {
    Object(Vec<(String, Node)>),
    Array(Vec<Node>),
    Primitive(Value),
}

#[derive(Debug, Clone)]
pub struct FieldMeta {
    pub name: Option<String>,   // Some(key) for object field, None for array / primitive with generated id
    pub offset: usize,
    pub len: usize,
}

impl Node {
    /// Construct AST Node from serde_json::Value
    pub fn from_value(v: Value) -> Self {
        match v {
            Value::Object(map) => {
                let mut vec = Vec::with_capacity(map.len());
                for (k, v) in map {
                    vec.push((k, Node::from_value(v)));
                }
                Node::Object(vec)
            }
            Value::Array(arr) => Node::Array(arr.into_iter().map(Node::from_value).collect()),
            prim => Node::Primitive(prim),
        }
    }

    /// Construct AST from JSON text
    pub fn parse_str(s: &str) -> Result<Self, JcError> {
        let v: Value = serde_json::from_str(s)?;
        Ok(Node::from_value(v))
    }

    /// Reconstruct serde_json::Value from Node 
    pub fn to_value(&self) -> Value {
        match self {
            Node::Object(fields) => {
                let mut map = Map::with_capacity(fields.len());
                for (k, node) in fields {
                    map.insert(k.clone(), node.to_value());
                }
                Value::Object(map)
            }
            Node::Array(items) => Value::Array(items.iter().map(|n| n.to_value()).collect()),
            Node::Primitive(v) => v.clone(),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_atomic_pieces_object() {
        let s = r#"{"b":1,"a":2,"big":[1,2]}"#;
        let ast = Node::parse_str(s).expect("parse");
        println!("ast: {:?}", ast);

        // if let Node::Object(v) = ast {
        //     let tmp_str = v[1].1.to_value().to_string();
        //     println!("{:?}", &tmp_str);
        //     println!("{tmp_str}");
        // } 
    }

    #[test]
    fn parse_array_and_primitives() {
        let s = r#"[1, {"key": ["y", "z"]}, null]"#;
        let ast = Node::parse_str(s).unwrap();
        println!("ast: {:?}", ast);
    }

    #[test]
    fn canonical_with_offsets_matches_atomic_pieces() {
        let s = r#"[{"account":{"id":1,"name":"Alice"}},{"account":{"id":2,"name":"Bob"}}]"#;
        let ast = Node::parse_str(s).expect("parse json");
        println!("ast: {:?}", ast);
    }
}



