#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/nxb-core/src/prepared_file_authority.rs")
text = path.read_text(encoding="utf-8")

helper_anchor = '''impl PreparedFileAuthority {
'''
helper = r'''#[cfg(target_os = "linux")]
fn linux_external_process_path(path: &Path) -> Result<PathBuf> {
    let proc_self_fd = Path::new("/proc/self/fd");
    let Ok(relative) = path.strip_prefix(proc_self_fd) else {
        return Ok(path.to_path_buf());
    };
    let mut components = relative.components();
    let descriptor = components
        .next()
        .ok_or_else(|| anyhow::anyhow!("Linux stable authority path is missing its directory descriptor"))?;
    let descriptor = descriptor.as_os_str().to_str().ok_or_else(|| {
        anyhow::anyhow!("Linux stable authority descriptor is not canonical UTF-8")
    })?;
    if descriptor.is_empty() || !descriptor.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("Linux stable authority descriptor is not a canonical decimal file descriptor");
    }

    let mut qualified = PathBuf::from(format!("/proc/{}/fd/{descriptor}", std::process::id()));
    for component in components {
        qualified.push(component.as_os_str());
    }
    Ok(qualified)
}

'''
if "fn linux_external_process_path" not in text:
    if helper_anchor not in text:
        raise SystemExit("missing PreparedFileAuthority impl anchor")
    text = text.replace(helper_anchor, helper + helper_anchor, 1)

old = '''        let output = Command::new(tool)
            .arg("-L")
            .arg("--")
            .arg(&source)
            .arg(destination)
'''
new = '''        let destination_for_child = linux_external_process_path(destination)?;
        let output = Command::new(tool)
            .arg("-L")
            .arg("--")
            .arg(&source)
            .arg(&destination_for_child)
'''
if old not in text:
    raise SystemExit("missing Linux hard-link destination command anchor")
text = text.replace(old, new, 1)

linux_test_anchor = '''    #[test]
    fn prepared_authority_detects_same_permission_path_replacement() {
'''
linux_test = r'''    #[test]
    fn external_process_path_qualifies_proc_self_fd_without_rewriting_normal_paths() {
        let qualified = linux_external_process_path(Path::new("/proc/self/fd/123/example.json"))
            .unwrap();
        assert_eq!(
            qualified,
            PathBuf::from(format!(
                "/proc/{}/fd/123/example.json",
                std::process::id()
            ))
        );
        let normal = Path::new("/tmp/example.json");
        assert_eq!(linux_external_process_path(normal).unwrap(), normal);
    }

'''
if "external_process_path_qualifies_proc_self_fd_without_rewriting_normal_paths" not in text:
    if linux_test_anchor not in text:
        raise SystemExit("missing Linux prepared-authority test anchor")
    text = text.replace(linux_test_anchor, linux_test + linux_test_anchor, 1)

path.write_text(text, encoding="utf-8", newline="\n")
