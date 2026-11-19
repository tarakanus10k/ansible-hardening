#!/usr/bin/env bash
# 19 выбранных правил CIS Benchmark Debian 13 v1.1.0 (ssh, sudo, pam, audit).
# Учебная версия для курсового проекта: каждая проверка построена на команде
# аудита из соответствующего пункта бенчмарка (stat, sshd -T, grep, dpkg-query,
# apt-cache, systemctl, auditctl -l). Скрипт ничего не изменяет в системе.
# Коды выхода: 0 — все PASS, 1 — есть FAIL или REVIEW, 2 — ошибка запуска.
set -uo pipefail
export LC_ALL=C
umask 077

# ------------------------------ Каркас ------------------------------

# capture выполняет команду и запоминает её вывод; run ещё и пишет вывод в журнал.
capture() {
    printf '$' >&3
    printf ' %q' "$@" >&3
    printf '\n' >&3
    output=$("$@" 2>&1)
}

run() {
    local status=0
    capture "$@" || status=$?
    [[ -z $output ]] || printf '%s\n' "$output" >&3
    return "$status"
}

# check печатает заголовок, вызывает проверку и переводит её код в PASS/FAIL/REVIEW.
check() {
    local id=$1 title=$2 status
    shift 2
    printf '\n[%s] %s\n' "$id" "$title" >&3
    "$@" >&3
    case $? in
        0) status=PASS ;;
        1) status=FAIL; problems=1 ;;
        *) status=REVIEW; problems=1 ;;
    esac
    (( counts[$status] += 1 ))
    printf 'Результат: %s\n' "$status" >&3
}

# --------------------------- Общие проверки ---------------------------

# check_packages: 0 — все пакеты установлены, 1 — нет, 2 — ошибка запроса.
check_packages() {
    local package rc failed=0
    for package in "$@"; do
        run dpkg-query -W '-f=${db:Status-Status}\n' "$package"
        rc=$?
        case $rc in
            0) [[ $output == installed ]] || failed=1 ;;
            1) failed=1 ;;
            *) return 2 ;;
        esac
    done
    return "$failed"
}

# check_service: 0 — сервис включён и активен, иначе 1.
check_service() {
    run systemctl is-enabled "$1"
    [[ $output == enabled ]] || return 1
    run systemctl is-active "$1"
    [[ $output == active ]] || return 1
}

# perm_le: права $1 не шире маски $2 (например 0600 или 0700).
perm_le() {
    [[ $1 =~ ^[0-7]{1,4}$ ]] || return 2
    (( (8#$1 & ~$2) == 0 ))
}

# --------------------------- SSH (раздел 5.1) ---------------------------

# 5.1.1: stat /etc/ssh/sshd_config — права не шире 0600, владелец root:root.
check_ssh_files() {
    local mode owner
    [[ -f /etc/ssh/sshd_config ]] || return 1
    run stat -Lc '%a %u/%g' /etc/ssh/sshd_config || return 2
    read -r mode owner <<< "$output"
    perm_le "$mode" 0600 || return $?
    [[ $owner == 0/0 ]] || return 1
}

# 5.1.2: каталог sshd_config.d не шире 0700, файлы *.conf — не шире 0600.
check_ssh_directory() {
    local mode owner
    [[ -d /etc/ssh/sshd_config.d ]] || return 1
    run stat -Lc '%a %u/%g' /etc/ssh/sshd_config.d || return 2
    read -r mode owner <<< "$output"
    perm_le "$mode" 0700 || return $?
    [[ $owner == 0/0 ]] || return 1
    run find /etc/ssh/sshd_config.d -type f -name '*.conf' -exec stat -Lc '%a %u/%g' {} + || return 2
    while read -r mode owner; do
        perm_le "$mode" 0600 || return $?
        [[ $owner == 0/0 ]] || return 1
    done <<< "$output"
}

# 5.1.15/5.1.18/5.1.21/5.1.22: значение директивы из вывода `sshd -T`.
check_ssh_option() {
    local key=$1 value
    if ! capture sshd -T; then printf '%s\n' "$output"; return 2; fi
    run grep -Ei "^${key}[[:space:]]+" <<< "$output" || return 2
    read -r _ value <<< "$output"
    printf '%s = %s\n' "$key" "${value:-не найдено}"
    [[ -n $value ]] || return 2
    case $key in
        logingracetime)
            [[ $value =~ ^[0-9]+$ ]] || return 2
            (( 10#$value >= 1 && 10#$value <= 60 )) || return 1 ;;
        maxauthtries)
            [[ $value =~ ^[0-9]+$ ]] || return 2
            (( 10#$value <= 4 )) || return 1 ;;
        *)
            [[ $value == no ]] || return 1 ;;
    esac
}

# ------------------------ Sudo и su (раздел 5.2) ------------------------

# 5.2.1: установлен пакет sudo или sudo-rs.
check_sudo_installed() {
    local package found=0 unknown=0
    for package in sudo sudo-rs; do
        check_packages "$package"
        case $? in 0) found=1 ;; 1) ;; *) unknown=1 ;; esac
    done
    (( found )) && return 0
    (( unknown )) && return 2
    return 1
}

# 5.2.6: grep по /etc/sudoers и /etc/sudoers.d/* — timestamp_timeout от 0 до 15 минут.
check_sudo_timeout() {
    local line value found=0
    check_sudo_installed || return $?
    local -a files=()
    shopt -s nullglob
    files=(/etc/sudoers /etc/sudoers.d/*)
    shopt -u nullglob
    (( ${#files[@]} )) || return 2
    run grep -Eis '^[[:space:]]*Defaults.*timestamp_timeout' "${files[@]}"
    case $? in 0|1) ;; *) return 2 ;; esac
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        line=${line%%#*}
        value=$(grep -Eo 'timestamp_timeout[[:space:]]*=[[:space:]]*[^,[:space:]]+' <<< "$line")
        [[ -n $value ]] || { printf 'Настройка без значения: %s\n' "$line"; return 2; }
        value=${value#*=}
        value=${value//\"/}
        [[ $value =~ ^-?[0-9]+([.][0-9]+)?$ ]] || { printf 'Нечисловое значение: %s\n' "$value"; return 2; }
        awk -v v="$value" 'BEGIN { exit !(v >= 0 && v <= 15) }' \
            || { printf 'timestamp_timeout=%s: вне диапазона 0..15 минут.\n' "$value"; return 1; }
        found=1
    done <<< "$output"
    if (( ! found )); then
        printf 'Явная настройка timestamp_timeout не найдена; проверьте умолчание: sudo -V.\n'
        return 2
    fi
}

# 5.2.7: pam_wheel с use_uid group=... в /etc/pam.d/su, группа пуста.
check_su_restricted() {
    local line group name gid members
    [[ -f /etc/pam.d/su ]] || return 1
    run grep -E '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' /etc/pam.d/su || return $?
    line=${output%%$'\n'*}
    grep -Eq '\buse_uid\b' <<< "$line" || { printf 'В pam_wheel нет аргумента use_uid.\n'; return 1; }
    group=$(grep -Eo 'group=[^[:space:]#]+' <<< "$line")
    [[ -n $group ]] || { printf 'В pam_wheel не задана группа (group=...).\n'; return 1; }
    group=${group#*=}
    run getent group "$group"
    case $? in 0) ;; 2) return 1 ;; *) return 2 ;; esac
    [[ $output != *$'\n'* ]] || return 2
    IFS=: read -r name _ gid members <<< "$output"
    [[ $name == "$group" && $gid =~ ^[0-9]+$ ]] || return 2
    [[ -z $members ]] || { printf 'Группа %s не пуста: %s\n' "$group" "$members"; return 1; }
    capture getent passwd || return 2
    run grep -E "^[^:]+:[^:]*:[0-9]+:${gid}:" <<< "$output"
    case $? in
        0) printf 'Есть пользователи с основной группой %s.\n' "$group"; return 1 ;;
        1) ;;
        *) return 2 ;;
    esac
    printf 'pam_wheel включён, группа %s пуста.\n' "$group"
}

# --------------------------- PAM (раздел 5.3) ---------------------------

# 5.3.1.1: версия libpam-runtime совпадает с кандидатом локального кэша APT.
check_pam_version() {
    local installed candidate
    check_packages libpam-runtime || return $?
    run dpkg-query -W '-f=${Version}\n' libpam-runtime || return 2
    installed=$output
    run apt-cache policy libpam-runtime || return 2
    run grep -E '^[[:blank:]]*Candidate:[[:blank:]]+' <<< "$output" || return 2
    read -r _ candidate <<< "$output"
    printf 'Установлено: %s; кандидат локального кэша APT: %s.\n' "$installed" "${candidate:-не найден}"
    [[ -n $installed && -n $candidate && $candidate != '(none)' ]] || return 2
    [[ $installed == "$candidate" ]]
}

# 5.3.2.2: pam_faillock включён — preauth/authfail в common-auth, account в common-account.
check_pam_faillock() {
    local pre fail
    [[ -f /etc/pam.d/common-auth && -f /etc/pam.d/common-account ]] || return 1
    run grep -En '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_faillock\.so[[:space:]][^#]*\bpreauth\b' /etc/pam.d/common-auth || return $?
    pre=${output%%:*}
    run grep -En '^[[:space:]]*auth[[:space:]]+(required|requisite|\[default=die\])[[:space:]]+pam_faillock\.so[[:space:]][^#]*\bauthfail\b' /etc/pam.d/common-auth || return $?
    fail=${output%%:*}
    run grep -En '^[[:space:]]*account[[:space:]]+(required|requisite)[[:space:]]+pam_faillock\.so' /etc/pam.d/common-account || return $?
    (( pre < fail )) || { printf 'authfail должен идти после preauth.\n'; return 1; }
}

# faillock_value_ok: значение попадает в диапазон из бенчмарка.
faillock_value_ok() {
    case $1 in
        deny)        (( $2 >= 1 && $2 <= 5 )) ;;
        unlock_time) (( $2 == 0 || $2 >= 900 )) ;;
    esac
}

# 5.3.3.1.x: deny/unlock_time в faillock.conf; аргументы PAM-строк приоритетнее.
check_faillock_option() {
    local key=$1 line value conf_value='' found=0
    check_pam_faillock || return $?
    [[ -f /etc/security/faillock.conf ]] || return 1
    # значение из /etc/security/faillock.conf
    run grep -E "^[[:space:]]*${key}[[:space:]]*=" /etc/security/faillock.conf
    case $? in 0|1) ;; *) return 2 ;; esac
    if [[ -n $output ]]; then
        line=${output##*$'\n'}
        read -r conf_value _ <<< "${line#*=}"
    fi
    # аргументы pam_faillock в PAM-строках (переопределяют faillock.conf)
    run grep -E "pam_faillock\.so[^#]*\b(${key}|conf)[[:space:]]*=" /etc/pam.d/common-auth /etc/pam.d/common-account
    case $? in 0|1) ;; *) return 2 ;; esac
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        line=${line%%#*}
        if grep -Eq '\bconf[[:space:]]*=' <<< "$line"; then
            printf 'pam_faillock использует отдельный конфиг: %s\n' "$line"
            return 2
        fi
        value=$(grep -Eo "\b${key}[[:space:]]*=[[:space:]]*[0-9]+" <<< "$line")
        if [[ -z $value ]]; then
            printf 'Нечисловое значение в PAM-строке: %s\n' "$line"
            return 2
        fi
        value=${value#*=}
        printf 'Значение из PAM-строки: %s = %s\n' "$key" "$value"
        faillock_value_ok "$key" "$value" || { printf '%s=%s: вне допустимого диапазона.\n' "$key" "$value"; return 1; }
        found=1
    done <<< "$output"
    if (( found )); then return 0; fi
    # аргументов в PAM нет — действует faillock.conf
    if [[ -z $conf_value ]]; then
        printf 'Значение %s не задано ни в faillock.conf, ни в аргументах PAM.\n' "$key"
        return 1
    fi
    printf 'Значение из faillock.conf: %s = %s\n' "$key" "$conf_value"
    [[ $conf_value =~ ^[0-9]+$ ]] || return 1
    faillock_value_ok "$key" "$conf_value" || { printf '%s=%s: вне допустимого диапазона.\n' "$key" "$conf_value"; return 1; }
}

# ------------------------- Auditd (раздел 6.2) -------------------------

# audit_wa_present: среди строк есть правило с правами wa (-p wa или perm=wa).
audit_wa_present() {
    local line
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        grep -Eq -- '(-p[[:space:]]+wa([[:space:]]|$)|perm=wa([[:space:]]|$))' <<< "$line" && return 0
    done <<< "$1"
    return 1
}

# check_audit_path: правило для пути есть и в /etc/audit/rules.d, и в загруженных (auditctl -l).
check_audit_path() {
    local path=$1 esc=${path//./\\.} re failed=0
    re="(-w[[:space:]]+${esc}/?([[:space:]]|$)|-F[[:space:]]+(path|dir)=${esc}/?([[:space:]]|$))"
    local -a files=()
    shopt -s nullglob
    files=(/etc/audit/rules.d/*.rules)
    shopt -u nullglob
    (( ${#files[@]} )) || { printf 'Нет файлов *.rules в /etc/audit/rules.d.\n'; return 1; }
    run grep -E "$re" "${files[@]}"
    case $? in 0|1) ;; *) return 2 ;; esac
    audit_wa_present "$output" || { printf 'В /etc/audit/rules.d нет правила для %s с правами wa.\n' "$path"; failed=1; }
    run auditctl -l || return 2
    run grep -E "$re" <<< "$output"
    case $? in 0|1) ;; *) return 2 ;; esac
    audit_wa_present "$output" || { printf 'Среди загруженных правил нет правила для %s с правами wa.\n' "$path"; failed=1; }
    (( failed == 0 )) || return 1
}

# check_audit_rules: проверяет каждое из перечисленных путей.
check_audit_rules() {
    local path
    for path in "$@"; do
        check_audit_path "$path" || return $?
    done
}

# ------------------------------ Выполнение ------------------------------

main() {
    if (( $# > 1 )); then printf 'Использование: sudo bash audit_simple.sh [отчёт.log]\n' >&2; return 2; fi
    if (( EUID != 0 )); then printf 'Запустите на проверяемом хосте через sudo.\n' >&2; return 2; fi
    local log=${1:-output.log} problems=0 output=''
    local -A counts=([PASS]=0 [FAIL]=0 [REVIEW]=0)
    # noclobber не даст случайно стереть прежний отчёт
    set -o noclobber
    if ! exec 3> "$log"; then return 2; fi
    printf 'Debian 13 | CIS Benchmark v1.1.0 | 19 выбранных правил (учебная версия)\nХост: %s\nВремя: %s\n' \
        "$(hostname)" "$(date --iso-8601=seconds)" >&3
    check 5.1.1 'Права файлов sshd_config' check_ssh_files
    check 5.1.2 'Права каталога sshd_config.d' check_ssh_directory
    check 5.1.15 'LoginGraceTime от 1 до 60 секунд' check_ssh_option logingracetime
    check 5.1.18 'MaxAuthTries не больше 4' check_ssh_option maxauthtries
    check 5.1.21 'PermitEmptyPasswords = no' check_ssh_option permitemptypasswords
    check 5.1.22 'PermitRootLogin = no' check_ssh_option permitrootlogin
    check 5.2.1 'Установлен sudo или sudo-rs' check_sudo_installed
    check 5.2.6 'timestamp_timeout от 0 до 15 минут' check_sudo_timeout
    check 5.2.7 'Доступ к su ограничен пустой группой' check_su_restricted
    check 5.3.1.1 'Актуальная версия libpam-runtime по локальному кэшу APT' check_pam_version
    check 5.3.2.2 'pam_faillock включён в auth и account' check_pam_faillock
    check 5.3.3.1.1 'Блокировка после 1–5 неудачных попыток' check_faillock_option deny
    check 5.3.3.1.2 'Разблокировка через 900 секунд или вручную' check_faillock_option unlock_time
    check 6.2.1.1 'Установлены auditd и audispd-plugins' check_packages auditd audispd-plugins
    check 6.2.1.2 'auditd включён и активен' check_service auditd.service
    check 6.2.3.1 'Аудит изменений sudoers и sudoers.d' check_audit_rules /etc/sudoers /etc/sudoers.d
    check 6.2.3.12 'Аудит изменений /etc/group' check_audit_rules /etc/group
    check 6.2.3.13 'Аудит изменений /etc/passwd' check_audit_rules /etc/passwd
    check 6.2.3.14 'Аудит изменений /etc/shadow и /etc/gshadow' check_audit_rules /etc/shadow /etc/gshadow
    printf '\nИтого: PASS=%s FAIL=%s REVIEW=%s\n' "${counts[PASS]}" "${counts[FAIL]}" "${counts[REVIEW]}" >&3
    printf 'Отчёт записан в %s\n' "$log"
    return "$problems"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
