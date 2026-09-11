#!/usr/bin/env -S bash -p
set -euo pipefail

fail() {
    builtin printf 'NXB-153 Linux entry blob authority probe failed: %s\n' "$1" >&2
    builtin exit 1
}

[[ "$-" == *p* ]] || fail 'Linux entry blob authority probe requires privileged Bash mode (-p)'

nxb_guard_git_environment=("${!GIT_@}")
[[ "${#nxb_guard_git_environment[@]}" -eq 0 ]] ||
    fail "ambient Git authority variables are not admitted before exact-head resolution: ${nxb_guard_git_environment[*]}"
builtin unset nxb_guard_git_environment

capture_blob_exact() {
    local git_path="$1" object="$2" output_name="$3"
    local payload sentinel=$'\036' captured_object
    [[ "$output_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 80
    payload="$({
        "$git_path" cat-file blob "$object" || exit $?
        builtin printf '%s' "$sentinel"
    })" || return 81
    [[ "${payload: -1}" == "$sentinel" ]] || return 82
    payload="${payload%$sentinel}"
    [[ -n "$payload" ]] || return 83
    captured_object="$(builtin printf '%s' "$payload" | "$git_path" hash-object --stdin)" || return 84
    [[ "$captured_object" == "$object" ]] || return 85
    builtin printf -v "$output_name" '%s' "$payload"
}

primitive_self_test() {
    local root previous_pwd real_git fake_git normal_object nul_object captured
    previous_pwd="$PWD"
    root="$(mktemp -d)" || fail 'could not create primitive self-test root'

    real_git="$(type -P git)" || fail 'git executable is unavailable'
    "$real_git" -C "$root" init -q
    cd "$root"

    normal_object="$(builtin printf '#!/usr/bin/env bash\nprintf trusted\\n\n' | "$real_git" hash-object -w --stdin)" ||
        fail 'could not create normal synthetic Git blob'
    captured=''
    capture_blob_exact "$real_git" "$normal_object" captured ||
        fail 'normal synthetic blob did not survive exact capture'
    [[ "$(builtin printf '%s' "$captured" | "$real_git" hash-object --stdin)" == "$normal_object" ]] ||
        fail 'normal synthetic captured bytes lost Git object identity'

    nul_object="$(builtin printf 'before\0after\n' | "$real_git" hash-object -w --stdin)" ||
        fail 'could not create NUL-bearing synthetic Git blob'
    captured=''
    if capture_blob_exact "$real_git" "$nul_object" captured 2>/dev/null; then
        fail 'NUL-bearing synthetic Git blob was accepted after Bash representation'
    fi

    fake_git="$root/fake-git"
    cat > "$fake_git" <<'SH'
#!/usr/bin/env -S bash -p
set -euo pipefail
if [[ "$#" -ge 3 && "$1" == cat-file && "$2" == blob ]]; then
    case "${NXB_FAKE_GIT_MODE:?}" in
        fail)
            builtin printf 'partial-prefix'
            builtin exit 17
            ;;
        truncate)
            builtin printf 'partial-prefix'
            builtin exit 0
            ;;
        *)
            builtin exit 18
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

bash_application="$(type -P bash)" || fail 'bash executable could not be resolved'

if [[ "${1:-}" == '--primitive-self-test' ]]; then
    [[ "$#" -eq 1 ]] || fail '--primitive-self-test accepts no additional arguments'
    primitive_self_test
    builtin printf 'NXB-153 Linux entry blob primitive self-test passed.\n'
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
    "$bash_application" -p -n <<<"$source_text" || fail "wrapper exact-head bytes failed privileged Bash syntax validation: $relative"

    [[ "$source_text" == '#!/usr/bin/env -S bash -p'$'\n'* ]] ||
        fail "wrapper does not request privileged Bash in its direct-exec shebang: $relative"
    [[ "$source_text" == *'[[ "$-" == *p* ]]'* ]] ||
        fail "wrapper does not require privileged Bash mode at runtime: $relative"
    [[ "$source_text" == *'nxb_guard_git_environment=("${!GIT_@}")'* ]] ||
        fail "wrapper does not reject ambient Git authority before exact-head resolution: $relative"
    [[ "$source_text" == *'ambient Git authority variables are not admitted before exact-head resolution'* ]] ||
        fail "wrapper is missing the pre-Git authority rejection contract: $relative"
    [[ "$source_text" != *'source <('* ]] ||
        fail "wrapper retained process-substitution source delegation: $relative"
    [[ "$source_text" == *'hash-object --stdin'* ]] ||
        fail "wrapper is missing captured-byte Git object verification: $relative"

    eval_count=0
    while IFS= read -r line; do
        if [[ "$line" == *'builtin eval '* ]]; then
            eval_count=$((eval_count + 1))
        fi
    done <<< "$source_text"
    [[ "$eval_count" -eq 1 ]] ||
        fail "wrapper must contain exactly one builtin in-memory eval delegation: $relative"
    unset source_text
done

immutable_relative='scripts/nxb-153-linux-immutable-source.sh'
immutable_object="$("$git_application" rev-parse "$head_sha:$immutable_relative")" ||
    fail 'canonical Linux immutable-source runner is not committed at exact head'
[[ "$immutable_object" =~ ^[0-9a-f]{40}$ ]] || fail 'immutable-source runner object is not canonical SHA-1'
[[ "$("$git_application" cat-file -t "$immutable_object")" == blob ]] || fail 'immutable-source runner exact-head object is not a blob'
immutable_size="$("$git_application" cat-file -s "$immutable_object")" || fail 'could not resolve immutable-source runner size'
[[ "$immutable_size" =~ ^[0-9]+$ && "$immutable_size" -gt 0 && "$immutable_size" -le 1048576 ]] ||
    fail 'immutable-source runner size is outside the admitted envelope'
immutable_actual="$("$git_application" hash-object -- "$repo_root/$immutable_relative")" ||
    fail 'could not hash immutable-source runner working bytes'
[[ "$immutable_actual" == "$immutable_object" ]] ||
    fail 'immutable-source runner working bytes differ from exact-head authority'
immutable_source=''
capture_blob_exact "$git_application" "$immutable_object" immutable_source ||
    fail 'immutable-source runner exact-head bytes failed capture integrity'
"$bash_application" -p -n <<<"$immutable_source" ||
    fail 'immutable-source runner exact-head bytes failed privileged Bash syntax validation'
[[ "$immutable_source" == '#!/usr/bin/env -S bash -p'$'\n'* ]] ||
    fail 'immutable-source runner does not request privileged Bash in its direct-exec shebang'
[[ "$immutable_source" == *'[[ "$-" == *p* ]]'* ]] ||
    fail 'immutable-source runner does not require privileged Bash mode at runtime'
[[ "$immutable_source" == *'nxb_guard_git_environment=("${!GIT_@}")'* ]] ||
    fail 'immutable-source runner does not reject ambient Git authority before exact-head resolution'
[[ "$immutable_source" == *'ambient Git authority variables are not admitted before exact-head resolution'* ]] ||
    fail 'immutable-source runner is missing the pre-Git authority rejection contract'
[[ "$immutable_source" == *'hash-object --stdin'* ]] ||
    fail 'immutable-source runner is missing captured-byte Git object verification'
[[ "$immutable_source" == *"'scripts/nxb-153-validation-environment.py'"* ]] ||
    fail 'immutable-source runner does not resolve the exact-head environment authority helper'

immutable_line_number=0
immutable_cp_function_line=0
immutable_cp_function_count=0
immutable_audit_line=0
immutable_audit_count=0
immutable_unset_line=0
immutable_unset_count=0
immutable_export_line=0
immutable_export_count=0
immutable_handoff_line=0
immutable_handoff_count=0
while IFS= read -r line; do
    immutable_line_number=$((immutable_line_number + 1))
    if [[ "$line" == 'cp() {' ]]; then
        immutable_cp_function_count=$((immutable_cp_function_count + 1))
        immutable_cp_function_line="$immutable_line_number"
    fi
    if [[ "$line" == 'git -C "$repo_anchor" cat-file blob "$environment_object" | python3 -I - audit >/dev/null ||' ]]; then
        immutable_audit_count=$((immutable_audit_count + 1))
        immutable_audit_line="$immutable_line_number"
    fi
    if [[ "$line" == '    unset -f cp' ]]; then
        immutable_unset_count=$((immutable_unset_count + 1))
        immutable_unset_line="$immutable_line_number"
    fi
    if [[ "$line" == 'export -f cp' ]]; then
        immutable_export_count=$((immutable_export_count + 1))
        immutable_export_line="$immutable_line_number"
    fi
    if [[ "$line" == 'git -C "$repo_anchor" cat-file blob "$inner_object" | "$bash_application" -s -- "$@" ||' ]]; then
        immutable_handoff_count=$((immutable_handoff_count + 1))
        immutable_handoff_line="$immutable_line_number"
    fi
done <<< "$immutable_source"
[[ "$immutable_cp_function_count" -eq 1 ]] ||
    fail 'immutable-source runner must define exactly one trusted cp shim'
[[ "$immutable_audit_count" -eq 1 ]] ||
    fail 'immutable-source runner must contain exactly one canonical environment audit handoff'
[[ "$immutable_unset_count" -eq 1 ]] ||
    fail 'immutable-source runner trusted cp shim must contain exactly one self-removal'
[[ "$immutable_export_count" -eq 1 ]] ||
    fail 'immutable-source runner must contain exactly one trusted cp export'
[[ "$immutable_handoff_count" -eq 1 ]] ||
    fail 'immutable-source runner must contain exactly one canonical non-privileged child handoff'
[[ "$immutable_cp_function_line" -gt "$immutable_audit_line" ]] ||
    fail 'immutable-source runner trusted cp function is defined before environment audit'
[[ "$immutable_unset_line" -gt "$immutable_cp_function_line" ]] ||
    fail 'immutable-source runner trusted cp self-removal does not follow its function definition'
[[ "$immutable_export_line" -gt "$immutable_unset_line" ]] ||
    fail 'immutable-source runner trusted cp export does not follow the self-removing function body'
[[ "$immutable_handoff_line" -gt "$immutable_export_line" ]] ||
    fail 'immutable-source runner non-privileged child handoff does not occur after trusted cp export'
unset immutable_source

final_head="$("$git_application" rev-parse HEAD)" || fail 'could not re-resolve final Git HEAD'
[[ "$final_head" == "$head_sha" ]] || fail 'Git HEAD changed during Linux entry blob authority probe'

builtin printf 'NXB-153 Linux entry blob authority probe passed.\n'
builtin printf 'HEAD: %s\n' "$head_sha"
builtin printf 'Wrappers: %s\n' "${#wrappers[@]}"
builtin printf 'Immutable runners: 1\n'
