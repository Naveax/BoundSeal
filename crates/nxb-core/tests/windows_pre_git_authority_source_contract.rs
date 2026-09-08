use std::{
    fs,
    path::{Path, PathBuf},
};

const AMBIENT_GIT_GUARD_MARKERS: &[&str] = &[
    "$ambientGitAuthority = [Collections.Generic.List[string]]::new()",
    "[Environment]::GetEnvironmentVariables().Keys",
    "$name.StartsWith('GIT_', [StringComparison]::OrdinalIgnoreCase)",
    "$ambientGitAuthority.Add($name)",
    "if ($ambientGitAuthority.Count -gt 0)",
    "$orderedGitAuthority = @($ambientGitAuthority | Sort-Object { $_.ToUpperInvariant() })",
    "ambient Git authority variables are not admitted before exact-head resolution",
];

#[derive(Clone, Copy)]
struct CanonicalSurface {
    path: &'static str,
    host_git_resolution: &'static str,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(relative_path: &str) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {} as UTF-8: {error}", path.display()))
}

fn read_bytes(relative_path: &str) -> Vec<u8> {
    let path = repository_root().join(relative_path);
    fs::read(&path).unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn unique_index(text: &str, needle: &str, label: &str) -> usize {
    let mut matches = text.match_indices(needle);
    let first = matches
        .next()
        .unwrap_or_else(|| panic!("{label}: missing required source pattern: {needle}"));
    assert!(
        matches.next().is_none(),
        "{label}: required source pattern must occur exactly once: {needle}"
    );
    first.0
}

fn assert_pre_git_guard(surface: CanonicalSurface) {
    let text = read_text(surface.path);
    let host_git_index = unique_index(
        &text,
        surface.host_git_resolution,
        surface.path,
    );

    for marker in AMBIENT_GIT_GUARD_MARKERS {
        let guard_index = unique_index(&text, marker, surface.path);
        assert!(
            guard_index < host_git_index,
            "{}: ambient Git authority guard pattern occurs after host Git resolution: {}",
            surface.path,
            marker
        );
    }
}

#[test]
fn canonical_windows_surfaces_reject_ambient_git_authority_before_host_git_resolution() {
    let surfaces = [
        CanonicalSurface {
            path: "scripts/prepare-and-validate-nxb-153-windows.ps1",
            host_git_resolution:
                "$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/validate-nxb-153-windows.ps1",
            host_git_resolution:
                "$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/review-nxb-153-evidence-windows.ps1",
            host_git_resolution:
                "$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/nxb-153-windows-immutable-source.ps1",
            host_git_resolution:
                "$gitCommand = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/record-nxb-153-windows-process-lifecycle-evidence.ps1",
            host_git_resolution: "$git = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/review-nxb-153-windows-admission.ps1",
            host_git_resolution: "$git = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/review-nxb-153-windows-admission-complete.ps1",
            host_git_resolution: "$git = Get-Command git -CommandType Application -ErrorAction Stop",
        },
        CanonicalSurface {
            path: "scripts/nxb-153-windows-host-git-lifetime-probe.ps1",
            host_git_resolution: "$git = Get-Command git -CommandType Application -ErrorAction Stop",
        },
    ];

    for surface in surfaces {
        assert_pre_git_guard(surface);
    }
}

#[test]
fn canonical_windows_outer_entries_remain_byte_identical() {
    let prepare = read_bytes("scripts/prepare-and-validate-nxb-153-windows.ps1");
    for sibling in [
        "scripts/validate-nxb-153-windows.ps1",
        "scripts/review-nxb-153-evidence-windows.ps1",
    ] {
        assert_eq!(
            prepare,
            read_bytes(sibling),
            "canonical Windows outer entry drifted from the shared byte-identical authority: {sibling}"
        );
    }
}
