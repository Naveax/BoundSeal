#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
evidence_directory="${2:-$repo_root/target/nxb-validation}"
expected_lock_sha256="f65a915dadc5ab8e29171ec64dc7bfdee33ccfd4204a3bc83a83a9baadee5dff"
secure_launcher="$repo_root/scripts/review-nxb-153-evidence-linux-secure.py"

fail() {
    printf 'NXB-153 guarded evidence closure failed: %s\n' "$1" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
command -v git >/dev/null 2>&1 || fail 'git is unavailable'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is unavailable'
[[ -f "$secure_launcher" ]] || fail "secure Linux evidence launcher is missing: $secure_launcher"

cd "$repo_root"
initial_head="$(git rev-parse HEAD)"
[[ "$initial_head" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD could not be resolved before evidence review'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree must be clean before evidence review'
[[ -f Cargo.lock ]] || fail 'Cargo.lock is missing before evidence review'
initial_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$initial_lock_sha256" == "$expected_lock_sha256" ]] ||
    fail "Cargo.lock SHA-256 mismatch before evidence review: expected $expected_lock_sha256, found $initial_lock_sha256"

guarded_launcher() {
    local mode="$1"
    python3 -I - "$repo_root" "$evidence_directory" "$mode" <<'PY'
from __future__ import annotations

import contextlib
import io
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import types

MAXIMUM_LAUNCHER_BYTES = 131072
LAUNCHER_PARTS = ("scripts", "review-nxb-153-evidence-linux-secure.py")


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"NXB-153 outer descriptor guard failed: {message}")


def absolute_without_resolution(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(os.fspath(path)))


def require_linux_primitives() -> None:
    if not sys.platform.startswith("linux"):
        fail("outer descriptor guard is supported only on Linux")
    for name in ("O_DIRECTORY", "O_NOFOLLOW"):
        if not hasattr(os, name):
            fail(f"required Linux primitive {name} is unavailable")


def directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def open_directory_anchored(path: pathlib.Path, label: str) -> int:
    absolute = absolute_without_resolution(path)
    parts = absolute.parts
    if not parts or parts[0] != os.path.sep:
        fail(f"{label} must be an absolute POSIX path")

    try:
        current_fd = os.open(os.path.sep, directory_flags())
    except OSError as error:
        fail(f"could not open filesystem root for {label}: {error}")

    try:
        for component in parts[1:]:
            if component in ("", ".", ".."):
                fail(f"{label} contains an invalid path component")
            try:
                next_fd = os.open(component, directory_flags(), dir_fd=current_fd)
            except OSError as error:
                fail(f"could not securely open {label} component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd
            if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                fail(f"{label} component is not a directory: {component}")
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def open_directory_relative(anchor_fd: int, parts: tuple[str, ...], label: str) -> int:
    current_fd = os.dup(anchor_fd)
    try:
        for component in parts:
            if component in ("", ".", ".."):
                fail(f"{label} contains an invalid relative component")
            try:
                next_fd = os.open(component, directory_flags(), dir_fd=current_fd)
            except OSError as error:
                fail(f"could not securely open {label} component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd
            if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                fail(f"{label} component is not a directory: {component}")
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def open_regular_relative(
    anchor_fd: int,
    parts: tuple[str, ...],
    label: str,
    maximum_bytes: int,
) -> bytes:
    current_fd = os.dup(anchor_fd)
    try:
        for component in parts[:-1]:
            try:
                next_fd = os.open(component, directory_flags(), dir_fd=current_fd)
            except OSError as error:
                fail(f"could not securely traverse {label} component {component!r}: {error}")
            os.close(current_fd)
            current_fd = next_fd

        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        except OSError as error:
            fail(f"could not securely open {label}: {error}")
    finally:
        os.close(current_fd)

    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            fail(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum_bytes:
            fail(f"{label} size is invalid")

        value = bytearray()
        while len(value) <= maximum_bytes:
            chunk = os.read(file_fd, min(1024 * 1024, maximum_bytes + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)

        after = os.fstat(file_fd)
        if len(value) != before.st_size or len(value) > maximum_bytes:
            fail(f"{label} changed size while being read")
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
            or getattr(after, "st_ctime_ns", None) != getattr(before, "st_ctime_ns", None)
        ):
            fail(f"{label} metadata changed while being read")
        return bytes(value)
    finally:
        os.close(file_fd)


def same_directory_object(first_fd: int, second_fd: int) -> bool:
    first = os.fstat(first_fd)
    second = os.fstat(second_fd)
    return (
        stat.S_ISDIR(first.st_mode)
        and stat.S_ISDIR(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )


def directory_binding_matches(path: pathlib.Path, pinned_fd: int, label: str) -> bool:
    try:
        current_fd = open_directory_anchored(path, f"{label} current namespace")
    except SystemExit:
        return False
    try:
        return same_directory_object(current_fd, pinned_fd)
    finally:
        os.close(current_fd)


def assert_directory_binding(path: pathlib.Path, pinned_fd: int, label: str) -> None:
    if not directory_binding_matches(path, pinned_fd, label):
        fail(f"{label} pathname no longer names the pinned directory object")


native_subprocess_run = subprocess.run


def run_in_directory_fd(directory_fd: int, arguments, *args, **kwargs):
    saved_fd = os.open(".", directory_flags())
    try:
        os.fchdir(directory_fd)
        kwargs = dict(kwargs)
        kwargs["cwd"] = None
        return native_subprocess_run(arguments, *args, **kwargs)
    finally:
        os.fchdir(saved_fd)
        os.close(saved_fd)


def process_anchor_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="nxb-153-outer-guard-") as temporary:
        root = pathlib.Path(temporary)
        trusted = root / "repository"
        replacement = root / "replacement"
        trusted.mkdir()
        replacement.mkdir()
        (trusted / "marker.txt").write_text("trusted\n", encoding="utf-8")
        (replacement / "marker.txt").write_text("substituted\n", encoding="utf-8")

        trusted_fd = open_directory_anchored(trusted, "outer-guard self-test repository")
        try:
            pinned_name = root / "repository-pinned"
            trusted.rename(pinned_name)
            replacement.rename(trusted)

            process = run_in_directory_fd(
                trusted_fd,
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; print(Path('marker.txt').read_text().strip())",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            if process.returncode != 0 or process.stdout.strip() != "trusted":
                fail("self-test child process was redirected by repository pathname replacement")
            if directory_binding_matches(trusted, trusted_fd, "outer-guard self-test repository"):
                fail("self-test failed to detect repository namespace replacement")
        finally:
            os.close(trusted_fd)


def load_secure_launcher(repo_fd: int, logical_path: pathlib.Path):
    raw = open_regular_relative(
        repo_fd,
        LAUNCHER_PARTS,
        "secure Linux evidence launcher",
        MAXIMUM_LAUNCHER_BYTES,
    )
    try:
        source = raw.decode("utf-8", errors="strict")
        code = compile(source, str(logical_path), "exec", dont_inherit=True)
    except (UnicodeDecodeError, SyntaxError) as error:
        fail(f"secure Linux evidence launcher could not be compiled from pinned bytes: {error}")

    module = types.ModuleType("nxb153_secure_linux_launcher")
    module.__file__ = str(logical_path)
    module.__package__ = None
    try:
        exec(code, module.__dict__)
    except Exception as error:
        fail(f"secure Linux evidence launcher could not be loaded from pinned bytes: {error}")
    return module


require_linux_primitives()
if len(sys.argv) != 4:
    fail("internal usage: <repo-root> <evidence-directory> <self-test|review>")

repo_root = absolute_without_resolution(pathlib.Path(sys.argv[1]))
evidence_directory = absolute_without_resolution(pathlib.Path(sys.argv[2]))
mode = sys.argv[3]
if mode not in ("self-test", "review"):
    fail("unknown outer descriptor-guard mode")

# The shell already changed into the repository before starting this bootstrap.
# Pin that inherited cwd object first, then prove the canonical repo pathname still
# names the same object. This avoids reopening an attacker-swapped repo path as
# the trust root for the Python review chain.
repo_fd = os.open(".", directory_flags())
evidence_fd = -1
try:
    assert_directory_binding(repo_root, repo_fd, "repository root")

    launcher_path = repo_root.joinpath(*LAUNCHER_PARTS)
    secure = load_secure_launcher(repo_fd, launcher_path)

    if mode == "self-test":
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            secure.self_test()
            process_anchor_self_test()
        assert_directory_binding(repo_root, repo_fd, "repository root")
        value = output.getvalue()
        if value:
            print(value, end="")
        raise SystemExit(0)

    try:
        relative_evidence = evidence_directory.relative_to(repo_root)
    except ValueError:
        evidence_fd = open_directory_anchored(evidence_directory, "evidence directory")
    else:
        evidence_fd = open_directory_relative(
            repo_fd,
            tuple(relative_evidence.parts),
            "evidence directory",
        )

    assert_directory_binding(evidence_directory, evidence_fd, "evidence directory")

    original_open_directory = secure.open_directory_anchored

    def pinned_open_directory(path: pathlib.Path, label: str) -> int:
        absolute = absolute_without_resolution(pathlib.Path(path))
        if absolute == repo_root:
            return os.dup(repo_fd)
        if absolute == evidence_directory:
            return os.dup(evidence_fd)
        return original_open_directory(path, label)

    secure.open_directory_anchored = pinned_open_directory

    def guarded_subprocess_run(arguments, *args, **kwargs):
        cwd = kwargs.get("cwd")
        command = arguments[0] if isinstance(arguments, (list, tuple)) and arguments else None
        if command == "git" and cwd is not None:
            requested = absolute_without_resolution(pathlib.Path(cwd))
            if requested == repo_root:
                kwargs = dict(kwargs)
                kwargs.pop("cwd", None)
                return run_in_directory_fd(
                    repo_fd,
                    arguments,
                    *args,
                    **kwargs,
                )
        return native_subprocess_run(arguments, *args, **kwargs)

    subprocess.run = guarded_subprocess_run
    try:
        assert_directory_binding(repo_root, repo_fd, "repository root")
        assert_directory_binding(evidence_directory, evidence_fd, "evidence directory")

        saved_argv = sys.argv
        output = io.StringIO()
        try:
            sys.argv = [str(launcher_path), str(repo_root), str(evidence_directory)]
            with contextlib.redirect_stdout(output):
                secure.main()
        finally:
            sys.argv = saved_argv

        # PASS output is still buffered here. A rename/replacement that detached
        # either pinned authority object makes the review fail even if the inner
        # semantic review itself completed.
        assert_directory_binding(repo_root, repo_fd, "repository root")
        assert_directory_binding(evidence_directory, evidence_fd, "evidence directory")

        value = output.getvalue()
        if value:
            print(value, end="")
    finally:
        subprocess.run = native_subprocess_run
finally:
    if evidence_fd >= 0:
        os.close(evidence_fd)
    os.close(repo_fd)
PY
}

self_test_output="$(guarded_launcher self-test)"
review_output="$(guarded_launcher review)"

final_head="$(git rev-parse HEAD)"
[[ "$final_head" == "$initial_head" ]] ||
    fail "Git HEAD changed during evidence review: initial=$initial_head final=$final_head; any newly published closure requires explicit recovery/review"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
    fail 'working tree changed during evidence review; any newly published closure requires explicit recovery/review'
final_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
[[ "$final_lock_sha256" == "$initial_lock_sha256" ]] ||
    fail 'Cargo.lock bytes changed during evidence review; any newly published closure requires explicit recovery/review'

if [[ -n "$self_test_output" ]]; then
    printf '%s\n' "$self_test_output"
fi
if [[ -n "$review_output" ]]; then
    printf '%s\n' "$review_output"
fi
printf 'NXB-153 guarded Linux closure authority remained stable.\n'
printf 'HEAD: %s\n' "$initial_head"
printf 'Cargo.lock SHA-256: %s\n' "$initial_lock_sha256"
