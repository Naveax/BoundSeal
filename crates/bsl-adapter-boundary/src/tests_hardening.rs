#[test]
fn nested_scheme_cannot_hide_inside_fixture_identifier() {
    assert!(matches!(
        FixtureObject::new(
            "nested-scheme",
            "fixture://profile/http://external-host",
            FixtureObjectKind::StructuredDocument,
            hex('a'),
            16,
            BTreeMap::new(),
        ),
        Err(BoundaryError::InvalidFixture(_))
    ));
}
