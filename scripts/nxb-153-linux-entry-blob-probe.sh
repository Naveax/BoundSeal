#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'NXB-153 Linux entry blob authority probe failed: %s\n' "$1" >&2
    exit 1
}

capture_blob_exact() {
    local git_path="$1" object="$2" output_name="$3"
    local payload sentinel=$'\036' captured_object
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 80
    payload="$({
        "$git_path" cat-file blob "$object" || exit $?
        printf '%s' "$sentinel"
    })" || return 81
    [[ "${payload: -1}" == "$sentinel" ]] || return 82
    payload="${payload%$sentinel}"
    [[ -n "$payload" ]] || return 83
    captured_object="$(printf '%s' "$payload" | "$git_path" hash-object --stdin)" || return 84
    [[ "$captured_object" == "$object" ]] || return 85
    printf -v "$output_name" '%s' "$payload"
}

primitive_self_test() {
    local root previous_pwd real_git fake_git normal_object nul_object captured
    previous_pwd="$PWD"
    root="$(mktemp -d)" || fail 'could not create primitive self-test root'

    real_git="$(type -P git)" || fail 'git executable is unavailable'
    "$real_git" -C "$root" init -q
    cd "$root"

    normal_object="$(printf '#!/usr/bin/env bash\nprintf trusted\\n\n' | "$real_git" hash-object -w --stdin)" ||
        fail 'could not create normal synthetic Git blob'
    captured=''
    capture_blob_exact "$real_git" "$normal_object" captured ||
        fail 'normal synthetic blob did not survive exact capture'
    [[ "$(printf '%s' "$captured" | "$real_git" hash-object --stdin)" == "$normal_object" ]] ||
        fail 'normal synthetic captured bytes lost Git object identity'

    nul_object="$(printf 'before\0after\n' | "$real_git" hash-object -w --stdin)" ||
        fail 'could not create NUL-bearing synthetic Git blob'
    captured=''
    if capture_blob_exact "$real_git" "$nul_object" captured 2>/dev/null; then
        fail 'NUL-bearing synthetic Git blob was accepted after Bash representation'
    fi

    fake_git="$root/fake-git"
    cat > "$fake_git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ge 3 && "$1" == cat-file && "$2" == blob ]]; then
    case "${NXB_FAKE_GIT_MODE:?}" in
        fail)
            printf 'partial-prefix'
            exit 17
            ;;
        truncate)
            printf 'partial-prefix'
            exit 0
            ;;
        *)
            exit 18
            ;;
    esac
fi
exec "${NXB_REAL_GIT:?}" "$@"
SH
    chmod 700 "$fake_git"
    export NXB_REAL_GIT="$real_git"

    captured=''
    export NXB_FAKE_GIT_MODE=fail
    if capture_blob_exact "$fake_git" "$normal_object" captured 2>/dev/null; then
        fail 'failed synthetic producer became a successful captured blob'
    fi

    captured=''
    export NXB_FAKE_GIT_MODE=truncate
    if capture_blob_exact "$fake_git" "$normal_object" captured 2>/dev/null; then
        fail 'successful truncated synthetic producer retained the selected Git object identity'
    fi

    unset NXB_FAKE_GIT_MODE NXB_REAL_GIT
    cd "$previous_pwd"
    rm -rf "$root"
}

for required_command in git bash mktemp chmod; do
    type -P "$required_command" >/dev/null 2>&1 || fail "$required_command executable is unavailable"
done

if [[ "${1:-}" == '--primitive-self-test' ]]; then
    [[ "$#" -eq 1 ]] || fail '--primitive-self-test accepts no additional arguments'
    primitive_self_test
    printf 'NXB-153 Linux entry blob primitive self-test passed.\n'
    exit 0
fi

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
cd "$repo_root"
git_application="$(type -P git)"
head_sha="$("$git_application" rev-parse HEAD)" || fail 'could not resolve exact Git HEAD'
[[ "$head_sha" =~ ^[0-9a-f]{40}$ ]] || fail 'exact Git HEAD is not canonical SHA-1'

primitive_self_test

probe_relative='scripts/nxb-153-linux-entry-blob-probe.sh'
probe_object="$("$git_application" rev-parse "$head_sha:$probe_relative")" || fail 'probe is not committed at exact head'
[[ "$probe_object" =~ ^[0-9a-f]{40}$ ]] || fail 'probe Git object is not canonical SHA-1'
[[ "$("$git_application" cat-file -t "$probe_object")" == blob ]] || fail 'probe exact-head object is not a blob'
probe_actual="$("$git_application" hash-object -- "$repo_root/$probe_relative")" || fail 'could not hash probe working bytes'
[[ "$probe_actual" == "$probe_object" ]] || fail 'probe working bytes differ from exact-head Git authority'

wrappers=(
    'scripts/prepare-and-validate-nxb-153-linux.sh'
    'scripts/validate-nxb-153-linux.sh'
    'scripts/review-nxb-153-evidence-linux.sh'
)

for relative in "${wrappers[@]}"; do
    object="$("$git_application" rev-parse "$head_sha:$relative")" || fail "wrapper is not committed at exact head: $relative"
    [[ "$object" =~ ^[0-9a-f]{40}$ ]] || fail "wrapper Git object is not canonical SHA-1: $relative"
    [[ "$("$git_application" cat-file -t "$object")" == blob ]] || fail "wrapper exact-head object is not a blob: $relative"
    size="$("$git_application" cat-file -s "$object")" || fail "could not resolve wrapper size: $relative"
    [[ "$size" =~ ^[0-9]+$ && "$size" -gt 0 && "$size" -le 1048576 ]] || fail "wrapper size is outside the admitted envelope: $relative"
    actual="$("$git_application" hash-object -- "$repo_root/$relative")" || fail "could not hash wrapper working bytes: $relative"
    [[ "$actual" == "$object" ]] || fail "wrapper working bytes differ from exact-head authority: $relative"

    source_text=''
    capture_blob_exact "$git_application" "$object" source_text || fail "wrapper exact-head bytes failed capture integrity: $relative"
    bash -n <(printf '%s' "$source_text") || fail "wrapper exact-head bytes failed Bash syntax validation: $relative"

    source_count=0
    while IFS= read -r line; do
        if [[ "$line" == *'source <('* ]]; then
            source_count=$((source_count + 1))
            [[ "$line" == *"source <(printf '%s'"* ]] || fail "wrapper contains noncanonical process-substitution source: $relative"
        fi
    done <<< "$source_text"
    [[ "$source_count" -eq 1 ]] || fail "wrapper must contain exactly one canonical source delegation: $relative"
    [[ "$source_text" == *'hash-object --stdin'* ]] || fail "wrapper is missing captured-byte Git object verification: $relative"
    unset source_text
done

final_head="$("$git_application" rev-parse HEAD)" || fail 'could not re-resolve final Git HEAD'
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during Linux entry blob authority probe'

printf 'NXB-153 Linux entry blob authority probe passed.\n'
printf 'HEAD: %s\n' "$head_sha"
printf 'Wrappers: %s\n' "${#wrappers[@]}"
