#!/usr/bin/env bash
set -euo pipefail
umask 077
if (( $# < 1 )); then
    echo 'Usage: bash tests/run-repeat.sh NEW_REPORT_DIR [ansible options]' >&2
    exit 2
fi
output=$(realpath -m -- "$1")
shift
for arg in "$@"; do
    case $arg in
        -C|--check|--tags|--tags=*|-t*|--skip-tags|--skip-tags=*|--step|--start-at-task|--start-at-task=*)
            echo "Option incompatible with measuring a complete run: $arg" >&2
            exit 2;;
    esac
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
export ANSIBLE_NOCOLOR=1 LC_ALL=C
mkdir -- "$output"

record_sources() {
    git rev-parse HEAD
    find ansible.cfg playbooks roles audit-script inventory tests -type f \
        ! -path '*/__pycache__/*' ! -name '*.pyc' \
        ! -path 'tests/*.log' ! -path 'tests/*.txt' -print0 |
        sort -z | xargs -0 -r sha256sum
}
record_sources > "$output/sources-before.txt"
{
    printf 'Controller time: %s\n' "$(date --iso-8601=seconds)"
    printf 'Kernel: %s\n' "$(uname -r)"
    git status --porcelain
    ansible --version
    ansible-galaxy collection list
    ssh -V
    git --version
    printf 'Source manifest SHA256: '
    sha256sum < "$output/sources-before.txt"
} > "$output/versions.txt" 2>&1

ansible-playbook playbooks/site.yml "$@" --diff 2>&1 | tee "$output/ansible-run01.log"
record_sources > "$output/sources-between.txt"
cmp -s "$output/sources-before.txt" "$output/sources-between.txt" || {
    echo 'Controller sources changed during the first run.' >&2
    exit 2
}

# Keep evidence even when the playbook assertion fails.
set +e
ansible-playbook tests/verify-repeat.yml "$@" --diff 2>&1 | tee "$output/ansible-run02.log"
repeat_rc=$?
set -e
record_sources > "$output/sources-after.txt"
cmp -s "$output/sources-before.txt" "$output/sources-after.txt" || {
    echo 'Controller sources changed during the second run.' >&2
    exit 2
}
if (( repeat_rc != 0 )); then exit "$repeat_rc"; fi
awk '
    /PLAY RECAP/ {recap=1}
    recap && /ok=[0-9]+/ {
        hosts++
        if ($0 !~ /[[:space:]]changed=0([[:space:]]|$)/) bad=1
    }
    END {if (!hosts || bad) exit 1}
' "$output/ansible-run02.log" || {
    echo 'Repeated run did not report changed=0 for every tested host.' >&2
    exit 1
}
echo 'Repeat: changed=0 and measured snapshots match.'
