use crate::ProtocolError;
use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

const MAX_JSON_DEPTH: usize = 32;

struct StrictSeed {
    depth: usize,
}

struct StrictVisitor {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom("JSON nesting exceeds 32"));
        }
        deserializer.deserialize_any(StrictVisitor { depth: self.depth })
    }
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("non-finite JSON number"));
        }
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key: {key}"
                )));
            }
            let value = map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(serde_json::Value::Object(values))
    }
}

pub fn from_slice_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed { depth: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_value(value).map_err(ProtocolError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_and_excessive_nesting() {
        assert!(from_slice_strict::<serde_json::Value>(br#"{"id":1,"id":2}"#).is_err());
        let deeply_nested = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(from_slice_strict::<serde_json::Value>(deeply_nested.as_bytes()).is_err());
        assert!(from_slice_strict::<serde_json::Value>(br#"{"id":1}"#).is_ok());
    }
}
