#!/usr/bin/env bash
# Запускать на управляющей машине после первого применения playbooks/site.yml.
set -euo pipefail
umask 077

usage() {
    printf 'Использование: bash audit-script/run-repeat.sh НОВАЯ_ПАПКА [параметры ansible-playbook]\n'
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit 0; fi
if (( $# < 1 )); then usage >&2; exit 2; fi
report=$(realpath -m -- "$1")
shift
for arg in "$@"; do
    case $arg in
        -C|--check|--check=*|-t*|--tags|--tags=*|--skip-tags|--skip-tags=*|--step|--start-at-task|--start-at-task=*|--list-*|--syntax-check|--version|--help|-h)
            printf 'Для проверки нужен полный прогон. Недопустимый параметр: %s\n' "$arg" >&2
            exit 2 ;;
    esac
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
for file in audit-script/verify-repeat.yml audit-script/snapshot-state.sh playbooks/site.yml; do
    [[ -r $file ]] || { printf 'Нет доступного файла: %s\n' "$file" >&2; exit 2; }
done
command -v ansible-playbook >/dev/null || { printf 'Не найден ansible-playbook.\n' >&2; exit 2; }
mkdir -m 700 -- "$report" || exit 2
export CIS_REPEAT_REPORT_DIR="$report" ANSIBLE_STDOUT_CALLBACK=default ANSIBLE_NOCOLOR=1 LC_ALL=C.UTF-8
unset ANSIBLE_FORCE_COLOR

finish() {
    printf '%s\n' "$2" | tee "$report/result.txt"
    printf 'Журналы: %s\n' "$report"
    exit "$1"
}

record_sources() {
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git rev-parse HEAD; fi
    local -a inputs=("$repo/playbooks" "$repo/roles" "$repo/audit-script")
    [[ ! -f $repo/ansible.cfg ]] || inputs+=("$repo/ansible.cfg")
    [[ ! -d $repo/inventory ]] || inputs+=("$repo/inventory")
    find "${inputs[@]}" -path "$report" -prune -o -type f \
        ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 |
        sort -z | xargs -0 -r sha256sum
}

{
    printf 'Начало UTC: %s\n' "$(date -u +%FT%TZ)"
    ansible-playbook --version
} > "$report/versions.txt" 2>&1 || finish 2 'ERROR: не удалось собрать сведения о запуске.'
record_sources > "$report/sources-before.txt" || finish 2 'ERROR: не удалось снять контрольные суммы исходников.'

# Единственное применение site.yml находится между двумя снимками.
if ! ansible-playbook audit-script/verify-repeat.yml "$@" --diff 2>&1 | tee "$report/ansible-repeat.log"; then
    finish 2 'ERROR: Ansible завершился с ошибкой. Подробности в ansible-repeat.log.'
fi
record_sources > "$report/sources-after.txt" || finish 2 'ERROR: не удалось повторно снять контрольные суммы исходников.'
cmp -s "$report/sources-before.txt" "$report/sources-after.txt" ||
    finish 2 'ERROR: контролируемые исходники изменились во время прогона.'

shopt -s nullglob
before=("$report"/before-*.txt)
after=("$report"/after-*.txt)
(( ${#before[@]} > 0 && ${#before[@]} == ${#after[@]} )) ||
    finish 2 'ERROR: не получены полные пары снимков.'
: > "$report/snapshot.diff"
different=0
for baseline in "${before[@]}"; do
    name=${baseline##*/}
    current=$report/after-${name#before-}
    [[ -f $current ]] || finish 2 "ERROR: отсутствует второй снимок для $name."
    if diff -u --label "$name" --label "${current##*/}" "$baseline" "$current" >> "$report/snapshot.diff"; then
        continue
    else
        rc=$?
        (( rc == 1 )) || finish 2 'ERROR: не удалось сравнить снимки.'
        different=1
    fi
done

# Требуем успешную сводку для каждого хоста с парой снимков.
if awk -v expected="${#before[@]}" '
    /^PLAY RECAP/ {recap=1; next}
    recap && /[[:space:]]ok=[0-9]+/ {
        hosts++
        if ($0 !~ /[[:space:]]failed=0([[:space:]]|$)/ ||
            $0 !~ /[[:space:]]unreachable=0([[:space:]]|$)/) errors=1
        if ($0 !~ /[[:space:]]changed=0([[:space:]]|$)/) changes=1
    }
    END {if (hosts != expected || errors) exit 2; if (changes) exit 1}
' "$report/ansible-repeat.log"; then
    (( different == 0 )) || finish 1 'FAIL: Ansible показал changed=0, но снимки состояния различаются.'
else
    rc=$?
    (( rc == 1 )) || finish 2 'ERROR: сводка Ansible неполная или содержит ошибки.'
    finish 1 'FAIL: повторный прогон Ansible зарегистрировал изменения.'
fi

finish 0 'PASS: changed=0, failed=0, unreachable=0. Снимки проверяемого состояния совпадают.'
