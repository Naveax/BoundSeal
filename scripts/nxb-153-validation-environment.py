#!/usr/bin/env python3
"""Fail-closed ambient validation-environment authority guard for NXB-153."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Mapping, NoReturn

FORBIDDEN_EXACT = frozenset(
    {
        "AR",
        "BASH_ENV",
        "BASHOPTS",
        "BASH_COMPAT",
        "BINDGEN_EXTRA_CLANG_ARGS",
        "CARGO",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_TARGET_DIR",
        "CC",
        "CC_ENABLE_DEBUG_OUTPUT",
        "CFLAGS",
        "CL",
        "CPP",
        "CPPFLAGS",
        "CRATE_CC_NO_DEFAULTS",
        "CXX",
        "CXXFLAGS",
        "LD",
        "LDFLAGS",
        "POSIXLY_CORRECT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RANLIB",
        "RANLIBFLAGS",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "SHELLOPTS",
        "_CL_",
    }
)

# These families map directly to Git repository/object/config authority,
# Cargo/rustup configuration, Bash function/startup authority, or can substitute
# compiler/runner/profile/source/native-build behavior. Canonical Linux entrypoints
# also reject GIT_* before their first Git invocation; this audit deliberately repeats
# that fail-closed boundary before deeper children and heavy validation.
FORBIDDEN_PREFIXES = (
    "AR_",
    "BASH_FUNC_",
    "BINDGEN_EXTRA_CLANG_ARGS_",
    "CARGO_ALIAS_",
    "CARGO_BUILD_",
    "CARGO_NET_",
    "CARGO_PROFILE_",
    "CARGO_REGISTRIES_",
    "CARGO_REGISTRY_",
    "CARGO_SOURCE_",
    "CARGO_TARGET_",
    "CC_",
    "CFLAGS_",
    "CPPFLAGS_",
    "CXX_",
    "CXXFLAGS_",
    "GIT_",
    "LD_",
    "LDFLAGS_",
    "RANLIB_",
    "RUSTC_",
    "RUSTDOC_",
    "RUSTUP_",
)


class EnvironmentAuthorityError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise EnvironmentAuthorityError(message)


def authority_key(name: str) -> bool:
    canonical = name.upper()
    if canonical in FORBIDDEN_EXACT:
        return True
    return any(canonical.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)


def audit_environment(environment: Mapping[str, str]) -> dict[str, object]:
    collisions = sorted(
        {name for name in environment if authority_key(name)},
        key=lambda value: value.upper(),
    )
    if collisions:
        # Values are intentionally never printed: registry tokens or other
        # sensitive data must not leak merely because a variable name is banned.
        fail(
            "ambient Git/compiler/Cargo/Python/Bash authority variables are not admitted: "
            + ", ".join(collisions)
        )
    return {
        "ambient_variables_checked": len(environment),
        "authority_variables_present": 0,
        "policy": "nxb-153-compiler-cargo-python-authority-v2",
    }


def run_bash_startup_probe(
    bash_path: str,
    arguments: list[str],
    environment: Mapping[str, str],
    label: str,
) -> int:
    try:
        completed = subprocess.run(
            [bash_path, *arguments],
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        fail(f"Linux Bash startup self-test timed out: {label}")
    except OSError as error:
        fail(f"Linux Bash startup self-test could not execute {label}: {error}")
    return completed.returncode


def linux_bash_startup_self_test() -> None:
    if not sys.platform.startswith("linux"):
        return

    path_value = os.environ.get("PATH", "")
    bash_path = shutil.which("bash", path=path_value)
    if not bash_path or not os.path.isabs(bash_path) or not os.path.isfile(bash_path):
        fail("Linux Bash startup self-test could not resolve an absolute Bash executable")

    baseline_environment: dict[str, str] = {"PATH": path_value}
    for name in ("HOME", "LANG", "LC_ALL", "TERM", "TMPDIR"):
        value = os.environ.get(name)
        if value is not None:
            baseline_environment[name] = value

    with tempfile.TemporaryDirectory(prefix="nxb-153-bash-startup-") as root:
        startup_path = os.path.join(root, "bash-env-startup.sh")
        marker_path = os.path.join(root, "bash-env-marker")
        with open(startup_path, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                'builtin printf "%s" hostile > "${NXB153_BASH_ENV_MARKER:?}"\n'
                "export NXB153_BASH_ENV_IMPORTED=1\n"
            )

        bash_env_environment = dict(baseline_environment)
        bash_env_environment["BASH_ENV"] = startup_path
        bash_env_environment["NXB153_BASH_ENV_MARKER"] = marker_path

        nonprivileged = run_bash_startup_probe(
            bash_path,
            ["-c", '[[ "${NXB153_BASH_ENV_IMPORTED:-}" == 1 ]]'],
            bash_env_environment,
            "non-privileged BASH_ENV control",
        )
        if nonprivileged != 0 or not os.path.isfile(marker_path):
            fail("non-privileged Bash control did not consume the synthetic BASH_ENV startup file")

        os.unlink(marker_path)
        privileged = run_bash_startup_probe(
            bash_path,
            ["-p", "-c", '[[ -z "${NXB153_BASH_ENV_IMPORTED+x}" ]]'],
            bash_env_environment,
            "privileged BASH_ENV rejection",
        )
        if privileged != 0 or os.path.exists(marker_path):
            fail("privileged Bash consumed synthetic BASH_ENV startup authority")

        hostile_function_environment = dict(baseline_environment)
        hostile_function_environment["BASH_FUNC_nxb153_hostile%%"] = "() { return 23; }"
        nonprivileged_function = run_bash_startup_probe(
            bash_path,
            ["-c", "declare -F nxb153_hostile >/dev/null"],
            hostile_function_environment,
            "non-privileged exported-function control",
        )
        if nonprivileged_function != 0:
            fail("non-privileged Bash control did not import the synthetic exported function")

        privileged_function = run_bash_startup_probe(
            bash_path,
            ["-p", "-c", "! declare -F nxb153_hostile >/dev/null"],
            hostile_function_environment,
            "privileged exported-function rejection",
        )
        if privileged_function != 0:
            fail("privileged Bash imported synthetic exported-function authority")

        trusted_cp_environment = dict(baseline_environment)
        trusted_cp_environment["BASH_FUNC_cp%%"] = "() { return 37; }"
        trusted_cp = run_bash_startup_probe(
            bash_path,
            ["-c", "declare -F cp >/dev/null; cp; [[ $? -eq 37 ]]"],
            trusted_cp_environment,
            "intended non-privileged trusted-function import",
        )
        if trusted_cp != 0:
            fail("non-privileged Bash did not import the intended trusted-function control")


def self_test() -> None:
    allowed = {
        "HOME": "/tmp/nxb-home",
        "PATH": "/usr/bin:/bin",
        "HTTPS_PROXY": "http://proxy.invalid:8080",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": r"C:\Windows",
        # Visual Studio/SDK discovery remains host authority rather than an
        # operator-selectable compiler override in this contract.
        "INCLUDE": r"C:\sdk\include",
        "LIB": r"C:\sdk\lib",
        "LIBPATH": r"C:\sdk\libpath",
    }
    result = audit_environment(allowed)
    if result["authority_variables_present"] != 0:
        fail("self-test allowed environment returned an invalid authority count")

    rejected_names = (
        "RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_DIST_SERVER",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_RUSTC",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
        "CARGO_PROFILE_RELEASE_LTO",
        "CARGO_REGISTRIES_CRATES_IO_INDEX",
        "CARGO_SOURCE_CRATES_IO_REPLACE_WITH",
        "CARGO_NET_OFFLINE",
        "PYTHONPATH",
        "PYTHONHOME",
        "CC",
        "CC_X86_64_UNKNOWN_LINUX_GNU",
        "CFLAGS",
        "CFLAGS_X86_64_UNKNOWN_LINUX_GNU",
        "AR",
        "AR_X86_64_UNKNOWN_LINUX_GNU",
        "CL",
        "_CL_",
        "CRATE_CC_NO_DEFAULTS",
        "BINDGEN_EXTRA_CLANG_ARGS",
        "BASH_ENV",
        "BASHOPTS",
        "BASH_COMPAT",
        "BASH_FUNC_untrusted%%",
        "POSIXLY_CORRECT",
        "SHELLOPTS",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_EXEC_PATH",
    )
    for name in rejected_names:
        try:
            audit_environment({name: "untrusted"})
        except EnvironmentAuthorityError:
            continue
        fail(f"self-test accepted forbidden ambient authority variable: {name}")

    # Matching is deliberately case-insensitive so the same policy applies on
    # Windows and does not acquire platform-specific spelling loopholes.
    try:
        audit_environment({"cflags_x86_64_pc_windows_msvc": "/DUNTRUSTED"})
    except EnvironmentAuthorityError:
        pass
    else:
        fail("self-test accepted case-variant forbidden authority variable")

    try:
        audit_environment({"bash_func_printf%%": "() { :; }"})
    except EnvironmentAuthorityError:
        pass
    else:
        fail("self-test accepted case-variant exported Bash function authority")

    try:
        audit_environment({"git_dir": "/tmp/untrusted-git-dir"})
    except EnvironmentAuthorityError:
        pass
    else:
        fail("self-test accepted case-variant Git authority variable")

    linux_bash_startup_self_test()

    print("NXB-153 validation environment authority self-test passed.")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        fail("exactly one mode is required")
    mode = argv[1]
    if mode == "self-test":
        self_test()
    elif mode == "audit":
        result = audit_environment(os.environ)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        fail(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except EnvironmentAuthorityError as error:
        print(f"NXB-153 validation environment authority failed: {error}", file=sys.stderr)
        raise SystemExit(1)
