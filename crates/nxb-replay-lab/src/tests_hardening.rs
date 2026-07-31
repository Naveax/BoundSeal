#[test]
fn nested_scheme_cannot_hide_inside_replay_fixture_reference() {
    assert!(matches!(
        ReplayInputRef::new(
            "nested-scheme",
            "fixture://profile/https://external-host",
            hex('a'),
            16,
        ),
        Err(ReplayError::InvalidBundle(_))
    ));
}
