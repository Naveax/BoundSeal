use std::{
    fs,
    path::{Path, PathBuf},
};

const GIT_GUARD_PATH: &str = "scripts/nxb-153-windows-immutable-source-git-output-inner.ps1";
const ENUMERATION_GUARD_PATH: &str =
    "scripts/nxb-153-windows-immutable-source-enumeration-inner.ps1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn source(path: &str) -> String {
    let full = repository_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", full.display()))
}

#[test]
fn windows_h2_nested_wrappers_execute_in_child_scope() {
    for path in [GIT_GUARD_PATH, ENUMERATION_GUARD_PATH] {
        let script = source(path);
        let child_call = "    & $innerPath @innerParameters";
        let dot_sourced_call = "    . $innerPath @innerParameters";

        assert!(
            script.contains(child_call),
            "{path}: nested immutable-source wrapper must execute in a child scope"
        );
        assert!(
            !script.contains(dot_sourced_call),
            "{path}: dot-sourcing would let nested wrapper state overwrite pinned stream/handle authority"
        );
        assert_eq!(
            script.matches(child_call).count(),
            1,
            "{path}: expected exactly one child-scope nested wrapper invocation"
        );

        let call = script
            .find(child_call)
            .expect("nested wrapper child invocation must be present");
        let final_check = script
            .find("final pinned object")
            .expect("nested wrapper must revalidate its pinned source object after execution");
        assert!(
            call < final_check,
            "{path}: final pinned-object validation must occur after child execution"
        );
    }
}
