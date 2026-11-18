#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C
umask 077
usage() {
    cat <<'HELP'
На управляющей машине: bash tests/functional.sh ssh REPORT USER SSH_HOST [IDENTITY]
На самой ВМ от root:   bash tests/functional.sh host REPORT TEST_USER
                       bash tests/functional.sh host REPORT TEST_USER PROFILE ALLOWED_FILE DENIED_FILE

SSH_HOST — адрес или alias из ssh_config (там же можно задать порт).
Для host нужен терминал. PAM login authenticate и sudo запросят пароль
тестового пользователя. Пароли вводятся в терминале и не идут в отчёт.
Параметры AppArmor задают существующий профиль и два пробных файла без секретов.
Коды выхода: 0 — все запущенные проверки прошли без пропусков, 1 — есть FAIL
или NOT_RUN; 2 — некорректный запуск. Отчёт остаётся при любом результате.
HELP
}
die() { echo "$*" >&2; exit 2; }
if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; exit; fi
(( $# >= 3 )) || { usage >&2; exit 2; }
mode=$1 report=$2 user=$3
shift 3
[[ $user =~ ^[a-z_][a-z0-9_-]*$ ]] || die 'Invalid test account name.'
case $mode in
    ssh)
        (( $# == 1 || $# == 2 )) || die 'Expected SSH host and optional identity.'
        [[ $1 =~ ^[a-zA-Z0-9_.:-]+$ && $1 != -* ]] || die 'Invalid SSH host.'
        ;;
    host)
        (( $# == 0 || $# == 3 )) || die 'Supply all three AppArmor parameters or none.'
        (( EUID == 0 )) || die 'Run this mode as root.'
        [[ -t 0 && -t 2 ]] || die 'Run this mode from an interactive terminal.'
        [[ $(id -u "$user") =~ ^[1-9][0-9]*$ ]] || die 'Use an existing non-root test user.'
        ;;
    *) die 'Expected ssh or host mode.';;
esac
(set -o noclobber; : > "$report") || die 'Cannot create a new report.'
exec 3>>"$report"
temp=$(mktemp -d) || die 'mktemp failed.'
trap 'rm -rf -- "$temp"' EXIT
trap 'exit 2' HUP INT TERM
printf 'FUNCTIONAL CHECKS\nMODE=%s\nTIME=%s\nUSER=%s\n' "$mode" "$(date --iso-8601=seconds)" "$user" >&3
bad=0
record() {
    printf '%s | %s | %s\n' "$1" "$2" "$3" | tee -a /dev/fd/3
    [[ $2 == PASS ]] || bad=1
}

probe_ssh() {
    local host=$1 output rc
    local -a options=(-o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no
        -o ControlPath=none -o PreferredAuthentications=publickey)
    if [[ -n ${2:-} ]]; then options+=(-o IdentitiesOnly=yes -i "$2"); fi
    ssh -V >&3 2>&3
    output=$(ssh "${options[@]}" -l "$user" -- "$host" 'id -un; cat /proc/sys/kernel/random/boot_id' 2>"$temp/ssh.err")
    rc=$?
    cat "$temp/ssh.err" >&3
    if (( rc == 0 )) && [[ ${output%%$'\n'*} == "$user" && ${output#*$'\n'} =~ ^[0-9a-f-]{36}$ ]]; then
        record SSH PASS "Fresh public-key session to $host; user=$user; boot_id=${output#*$'\n'}."
    else
        record SSH FAIL "Fresh key-based login or remote command failed (rc=$rc)."
    fi
}

probe_pam() {
    if ! command -v pamtester >/dev/null; then
        record PAM NOT_RUN 'Install pamtester on the test VM.'
        return
    fi
    printf 'PAM: ввод пароля пользователя %s для login.\n' "$user" >&2
    if pamtester login "$user" authenticate acct_mgmt; then
        record PAM PASS 'login: authenticate and acct_mgmt succeeded.'
    else
        record PAM FAIL 'login: authentication or account check failed.'
    fi
}

probe_sudo() {
    local rc output
    # -k with a command ignores cached credentials. No timestamp is used.
    output=$(runuser -u "$user" -- sudo -k -n -- /usr/bin/id -u 2>&1)
    rc=$?
    if (( rc != 0 )) && [[ $output == *'a password is required'* ]]; then
        record SUDO-NONINTERACTIVE PASS 'Uncached request required a password.'
    else
        record SUDO-NONINTERACTIVE FAIL "Expected a password requirement (rc=$rc): $output"
    fi
    printf 'sudo: ввод пароля пользователя %s для выполнения id -u от root.\n' "$user" >&2
    output=$(runuser -u "$user" -- sudo -k -- /usr/bin/id -u)
    rc=$?
    if (( rc == 0 )) && [[ $output == 0 ]]; then
        record SUDO-INTERACTIVE PASS 'Uncached invocation succeeded and returned uid 0.'
    else
        record SUDO-INTERACTIVE FAIL "Invocation did not return uid 0 (rc=$rc)."
    fi
}

probe_audit() {
    local path prior after pid rc attempt start_date start_time
    if ! command -v ausearch >/dev/null; then
        record AUDIT NOT_RUN 'ausearch is missing.'
        return
    fi
    for path in /etc/group /etc/passwd /etc/shadow /etc/gshadow /etc/sudoers; do
        if [[ ! -f $path ]]; then record AUDIT NOT_RUN "Missing $path."; continue; fi
        prior=$(sha256sum < "$path") || { record AUDIT FAIL "Cannot hash $path."; continue; }
        read -r start_date start_time < <(date '+%m/%d/%Y %H:%M:%S')
        # Opening in append mode without writing creates an event for this file.
        pid=$(bash -c 'printf "%s\n" "$$"; : >> "$1"' _ "$path")
        rc=$?
        if (( rc != 0 )) || [[ ! $pid =~ ^[0-9]+$ ]]; then
            record AUDIT FAIL "Cannot open $path without writing."
            continue
        fi
        after=$(sha256sum < "$path") || { record AUDIT FAIL "Cannot rehash $path."; continue; }
        if [[ $prior != "$after" ]]; then
            record AUDIT FAIL "File content changed concurrently: $path."
            continue
        fi
        for ((attempt=0; attempt<10; attempt++)); do
            ausearch --input-logs -ts "$start_date" "$start_time" -p "$pid" -f "$path" --raw >"$temp/event" 2>"$temp/audit.err"
            if grep -Eq "^type=SYSCALL .* success=yes .* pid=$pid([[:space:]]|$)" "$temp/event"; then
                cat "$temp/event" >&3
                record AUDIT PASS "$path: matching successful event; PID=$pid; content unchanged."
                break
            fi
            sleep 1
        done
        if (( attempt == 10 )); then
            cat "$temp/audit.err" >&3
            record AUDIT FAIL "$path: no matching successful event for PID=$pid."
        fi
    done
}

probe_apparmor() {
    local profile=${1:-} allowed=${2:-} denied=${3:-} label status
    if command -v aa-status >/dev/null; then
        printf '\nAPPARMOR STATUS\n' >&3
        aa-status >&3 2>&3
    fi
    if [[ -z $profile ]]; then
        record APPARMOR NOT_RUN 'Specify a profile and allowed/denied fixture files.'
        return
    fi
    if ! command -v aa-exec >/dev/null || [[ $allowed != /* || $denied != /* ||
         ! -f $allowed || ! -f $denied || $allowed -ef $denied ]]; then
        record APPARMOR NOT_RUN 'aa-exec and two distinct absolute fixture files are required.'
        return
    fi
    label=$(/usr/bin/cat /proc/self/attr/current 2>/dev/null) || label=''
    if [[ $label != unconfined ]] || ! /usr/bin/cat -- "$allowed" "$denied" >/dev/null 2>"$temp/aa.err"; then
        record APPARMOR NOT_RUN 'Both files must be readable without the profile.'
        return
    fi
    label=$(aa-exec -p "$profile" -- /usr/bin/cat /proc/self/attr/current 2>"$temp/aa.err")
    if [[ $label != "$profile (enforce)" ]]; then
        cat "$temp/aa.err" >&3
        record APPARMOR FAIL "Expected $profile (enforce), got: $label."
        return
    fi
    if ! aa-exec -p "$profile" -- /usr/bin/cat -- "$allowed" >/dev/null 2>"$temp/aa.err"; then
        cat "$temp/aa.err" >&3
        record APPARMOR FAIL 'The allowed read failed.'
        return
    fi
    aa-exec -p "$profile" -- /usr/bin/cat -- "$denied" >/dev/null 2>"$temp/aa.err"
    status=$?
    cat "$temp/aa.err" >&3
    if (( status == 1 )) && grep -Fxq "/usr/bin/cat: $denied: Permission denied" "$temp/aa.err"; then
        record APPARMOR PASS "$label: control read allowed, prohibited read blocked."
    else
        record APPARMOR FAIL "Expected an access denial on $denied, rc=$status."
    fi
}
if [[ $mode == ssh ]]; then
    probe_ssh "$@"
else
    printf 'HOST=%s\nBOOT_ID=%s\nKERNEL=%s\n' "$(hostname)" "$(cat /proc/sys/kernel/random/boot_id)" "$(uname -r)" >&3
    dpkg-query -W -f='${Package}=${Version}\n' pamtester sudo auditd apparmor apparmor-utils >&3 2>/dev/null || :
    probe_pam
    probe_sudo
    probe_audit
    probe_apparmor "$@"
fi
exit "$bad"
