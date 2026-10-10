use serde_json::Value;

// Check the whole schema before matching values: optional fields and successful
// alternatives can otherwise hide assertions that a small test validator ignores.
pub fn assert_supported(schema: &Value, keywords: &[&str], types: &[&str], formats: &[&str]) {
    let schema = schema
        .as_object()
        .expect("test validator only supports object schemas");
    for (keyword, value) in schema {
        assert!(
            keywords.contains(&keyword.as_str())
                || matches!(
                    keyword.as_str(),
                    "description" | "default" | "title" | "examples" | "$comment"
                ),
            "unsupported schema keyword: {keyword}"
        );
        match keyword.as_str() {
            "type" => {
                let supported = |ty: &Value| ty.as_str().is_some_and(|ty| types.contains(&ty));
                assert!(
                    match value.as_array() {
                        Some(choices) => !choices.is_empty() && choices.iter().all(supported),
                        None => supported(value),
                    },
                    "unsupported schema type: {value}"
                );
            }
            "properties" => {
                for child in value
                    .as_object()
                    .expect("schema properties must be an object")
                    .values()
                {
                    assert_supported(child, keywords, types, formats);
                }
            }
            "items" => assert_supported(value, keywords, types, formats),
            "allOf" | "anyOf" | "oneOf" => {
                for child in value
                    .as_array()
                    .expect("schema alternatives must be an array")
                {
                    assert_supported(child, keywords, types, formats);
                }
            }
            "additionalProperties" => assert!(
                value.is_boolean(),
                "test validator only supports boolean additionalProperties"
            ),
            "format" => assert!(
                value
                    .as_str()
                    .is_some_and(|format| formats.contains(&format)),
                "unsupported schema format: {value}"
            ),
            "minimum" | "maximum" => assert!(
                value.is_u64(),
                "test validator only supports u64 {keyword}: {value}"
            ),
            "minLength" | "minItems" | "maxItems" => assert!(
                value
                    .as_u64()
                    .is_some_and(|bound| usize::try_from(bound).is_ok()),
                "test validator only supports usize {keyword}: {value}"
            ),
            "pattern" => {
                regex::Regex::new(value.as_str().expect("schema pattern must be a string"))
                    .expect("schema pattern must be supported by Rust regex");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unsupported_schema_branches_fail_loudly() {
        let keywords = [
            "properties",
            "items",
            "allOf",
            "anyOf",
            "oneOf",
            "additionalProperties",
            "format",
        ];
        for schema in [
            json!({"properties":{"optional":{"not":{}}}}),
            json!({"items":{"not":{}}}),
            json!({"allOf":[{}, {"not":{}}]}),
            json!({"anyOf":[{}, {"not":{}}]}),
            json!({"oneOf":[{}, {"not":{}}]}),
            json!({"additionalProperties":{"type":"string"}}),
            json!({"format":"uri"}),
            json!(false),
        ] {
            assert!(
                std::panic::catch_unwind(|| assert_supported(&schema, &keywords, &[], &[]))
                    .is_err(),
                "unsupported schema was accepted: {schema}"
            );
        }
    }

    #[test]
    fn annotations_are_not_subschemas() {
        assert_supported(
            &json!({
                "description":"Synthetic annotation fixture", "title":"Fixture", "$comment":"Metadata",
                "default":{"not":{}}, "examples":[{"const":"example data"}]
            }),
            &[],
            &[],
            &[],
        );
    }
}
