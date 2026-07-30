#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_type_is_strict_and_sniffing_remains_disabled() {
        let assessment = ContentTypeAssessment::strict(
            Some(b"text/html; charset=UTF-8"),
            b"<html></html>",
        )
        .unwrap();
        assert_eq!(assessment.classification, ContentClassification::Html);
        assert_eq!(assessment.charset, Some(Charset::Utf8));
        assert!(!assessment.sniffing_performed);
        assert!(MediaType::parse(b"text/html; charset=utf-8; charset=ascii").is_err());
    }

    #[test]
    fn compression_ratio_and_layer_accounting_are_bounded() {
        let receipt = validate_encoding_layers(vec![EncodingLayerObservation {
            encoding: ContentEncoding::Gzip,
            input_bytes: 100,
            output_bytes: 1000,
            output_sha256: "a".repeat(64),
        }])
        .unwrap();
        assert_eq!(receipt.maximum_observed_ratio, 10);
        assert!(validate_encoding_layers(vec![EncodingLayerObservation {
            encoding: ContentEncoding::Gzip,
            input_bytes: 1,
            output_bytes: 101,
            output_sha256: "a".repeat(64),
        }])
        .is_err());
    }

    #[test]
    fn html_extraction_discovers_links_and_form_parameters_without_execution() {
        let document = extract_structured(
            ContentClassification::Html,
            br#"<html><a href="/home">x</a><form action="/login" method="post"><input name="user"><input name="pass"></form></html>"#,
            ExtractionLimits::default(),
        )
        .unwrap();
        assert_eq!(document.links.len(), 2);
        assert_eq!(document.forms.len(), 1);
        assert!(document.forms[0].parameter_names.contains("user"));
        assert_eq!(document.metadata.get("script_execution").unwrap(), "disabled");
    }

    #[test]
    fn xml_doctype_and_unbalanced_json_are_rejected() {
        assert!(extract_structured(
            ContentClassification::Xml,
            b"<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]><x>&y;</x>",
            ExtractionLimits::default(),
        )
        .is_err());
        assert!(extract_structured(
            ContentClassification::Json,
            br#"{"x":[1,2}"#,
            ExtractionLimits::default(),
        )
        .is_err());
    }

    #[test]
    fn discovery_graph_marks_cross_origin_as_passive_and_deduplicates() {
        let document = StructuredDocument {
            kind: ContentClassification::Html,
            body_sha256: "a".repeat(64),
            body_bytes: 1,
            node_count: 1,
            maximum_depth: 1,
            token_count: 1,
            links: vec![
                ExtractedLink {
                    raw_target_sha256: hash_bytes(b"/a"),
                    raw_target: "/a".into(),
                    source_tag: "a".into(),
                    source_attribute: "href".into(),
                },
                ExtractedLink {
                    raw_target_sha256: hash_bytes(b"/a#x"),
                    raw_target: "/a#x".into(),
                    source_tag: "a".into(),
                    source_attribute: "href".into(),
                },
                ExtractedLink {
                    raw_target_sha256: hash_bytes(b"https://other.example/x"),
                    raw_target: "https://other.example/x".into(),
                    source_tag: "a".into(),
                    source_attribute: "href".into(),
                },
            ],
            forms: Vec::new(),
            metadata: BTreeMap::new(),
        };
        let graph = DiscoveryGraph::build(
            &Url::parse("https://app.example.com/start").unwrap(),
            &document,
        )
        .unwrap();
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.duplicate_count, 1);
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.disposition == DiscoveryDisposition::CrossOriginPassive));
    }
}
