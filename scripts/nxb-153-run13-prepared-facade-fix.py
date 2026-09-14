#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing prepared-authority facade anchor: {label}")
    return text.replace(old, new, 1)


def patch_prepared_authority() -> None:
    path = Path("crates/nxb-core/src/prepared_file_authority.rs")
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''        crate::workspace_impl::reject_path_indirections(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("prepared file has no parent"))?,
            "prepared file parent",
        )?;
        crate::workspace_impl::reject_path_indirections(path, "prepared file")?;
''',
        '''        crate::workspace::reject_path_indirections(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("prepared file has no parent"))?,
            "prepared file parent",
        )?;
        crate::workspace::reject_path_indirections(path, "prepared file")?;
''',
        "create_named admission",
    )
    text = replace_once(
        text,
        '        crate::workspace_impl::reject_path_indirections(&self.path, "prepared file")?;\n',
        '        crate::workspace::reject_path_indirections(&self.path, "prepared file")?;\n',
        "named binding admission",
    )
    text = replace_once(
        text,
        '''        crate::workspace_impl::reject_path_indirections(
            destination,
            "published prepared destination",
        )?;
''',
        '''        crate::workspace::reject_path_indirections(
            destination,
            "published prepared destination",
        )?;
''',
        "destination binding admission",
    )
    text = replace_once(
        text,
        '''        crate::workspace_impl::reject_path_indirections(
            destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("create-only destination has no parent"))?,
            "create-only destination parent",
        )?;
        crate::workspace_impl::reject_path_indirections(destination, "create-only destination")?;
''',
        '''        crate::workspace::reject_path_indirections(
            destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("create-only destination has no parent"))?,
            "create-only destination parent",
        )?;
        crate::workspace::reject_path_indirections(destination, "create-only destination")?;
''',
        "create-only destination admission",
    )

    path.write_text(text, encoding="utf-8", newline="\n")


def patch_source_contract() -> None:
    path = Path("crates/nxb-core/tests/workspace_facade_lint_source_contract.rs")
    text = path.read_text(encoding="utf-8")
    const_anchor = 'const NXB_PATH: &str = "crates/nxb-core/src/nxb.rs";\n'
    if "PREPARED_AUTHORITY_PATH" not in text:
        text = replace_once(
            text,
            const_anchor,
            const_anchor
            + 'const PREPARED_AUTHORITY_PATH: &str = "crates/nxb-core/src/prepared_file_authority.rs";\n',
            "source-contract constant",
        )

    test = r'''

#[test]
fn prepared_publication_uses_scoped_workspace_admission_for_pinned_child_paths() {
    let prepared = source(PREPARED_AUTHORITY_PATH);
    assert!(
        prepared
            .matches("crate::workspace::reject_path_indirections")
            .count()
            >= 6,
        "{PREPARED_AUTHORITY_PATH}: prepared publication must admit target-scoped /proc/self/fd or Windows pinned child paths through the workspace facade"
    );
    assert_eq!(
        prepared
            .matches("crate::workspace_impl::reject_path_indirections")
            .count(),
        1,
        "{PREPARED_AUTHORITY_PATH}: only the external trusted Linux tool path may bypass scoped workspace admission"
    );
    assert!(
        prepared.contains(
            "crate::workspace_impl::reject_path_indirections(tool, \"Linux hard-link system tool\")?;"
        ),
        "{PREPARED_AUTHORITY_PATH}: the sole unscoped admission must remain the external trusted Linux tool"
    );
}
'''
    if "prepared_publication_uses_scoped_workspace_admission_for_pinned_child_paths" not in text:
        text += test
    path.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    patch_prepared_authority()
    patch_source_contract()


if __name__ == "__main__":
    main()
