#!/usr/bin/env bash
# 20 выбранных правил ролей ssh, sudo, pam, audit для Debian 13 CIS v1.1.0.
# Скрипт только читает настройки; кэш APT должен быть обновлён отдельно.
# Коды выхода: 0 — все PASS, 1 — есть FAIL или REVIEW, 2 — ошибка запуска.
set -uo pipefail
export LC_ALL=C
umask 077

# capture записывает команду; run также записывает её вывод.
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

check_packages() {
    local package rc failed=0
    for package in "$@"; do
        run dpkg-query -W '-f=${db:Status-Status}\n' "$package"
        rc=$?
        case $rc in
            0) [[ $output == installed ]] || failed=1 ;;
            1) failed=1 ;;  # Для запроса одного пакета запись не найдена.
            *) return 2 ;;
        esac
    done
    return "$failed"
}

check_service() {
    local service=$1
    run systemctl is-enabled "$service"
    [[ $output == enabled ]] || {
        case $output in disabled|masked|masked-runtime|static|indirect|not-found|enabled-runtime) return 1 ;; *) return 2 ;; esac
    }
    run systemctl is-active "$service"
    [[ $output == active ]] || {
        case $output in inactive|failed|unknown) return 1 ;; *) return 2 ;; esac
    }
}

# Поддерживаем обычные Include Debian. Для нестандартных путей и Match
# сохраняем наблюдения, но не выставляем PASS по неполным данным.
ssh_scope() (
    shopt -s nocasematch
    local file line rc
    for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -e $file || $file == /etc/ssh/sshd_config ]] || continue
        run grep -Ei '^[[:blank:]]*(include|match)([[:blank:]=]|$)' "$file"
        rc=$?
        (( rc <= 1 )) || return 2
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            if [[ $file == /etc/ssh/sshd_config &&
                  $line =~ ^[[:blank:]]*include[[:blank:]]+(/etc/ssh/)?sshd_config\.d/\*\.conf[[:blank:]]*(#.*)?$ ]]; then
                continue
            fi
            if [[ $1 == permissions && $line =~ ^[[:blank:]]*match([[:blank:]=]|$) ]]; then
                continue
            fi
            printf 'Нестандартный Include или Match требует ручной проверки.\n'
            return 2
        done <<< "$output"
    done
)

check_ssh_files() {
    local mode uid gid
    [[ -f /etc/ssh/sshd_config ]] || return 1
    run stat -Lc '%a %u %g' /etc/ssh/sshd_config || return 2
    read -r mode uid gid <<< "$output"
    [[ $mode =~ ^[0-7]{1,4}$ && $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]] || return 2
    (( uid == 0 && gid == 0 && (8#$mode & ~0600) == 0 )) || return 1
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        run find -L /etc/ssh/sshd_config.d -xdev -type f -name '*.conf' \
            \( ! -uid 0 -o ! -gid 0 -o -perm /7177 \) -printf '%m %U %G %p\n' || return 2
        [[ -z $output ]] || return 1
    fi
    ssh_scope permissions
}

check_ssh_directory() {
    [[ -d /etc/ssh/sshd_config.d ]] || return 1
    run find -L /etc/ssh/sshd_config.d -maxdepth 0 \
        \( ! -uid 0 -o ! -gid 0 -o -perm /7077 \) -printf '%m %U %G %p\n' || return 2
    [[ -z $output ]] || return 1
    ssh_scope permissions
}

check_ssh_option() {
    local key=$1 value
    if ! capture sshd -T; then printf '%s\n' "$output"; return 2; fi
    run grep -E "^${key}[[:blank:]]+" <<< "$output" || return 2
    read -r _ value <<< "$output"
    printf '%s = %s\n' "$key" "${value:-не найдено}"
    [[ -n $value ]] || return 2
    case $key in
        logingracetime)
            [[ $value =~ ^[0-9]{1,9}$ ]] || return 2
            (( 10#$value >= 1 && 10#$value <= 60 )) || return 1 ;;
        maxauthtries)
            [[ $value =~ ^[0-9]{1,9}$ ]] || return 2
            (( 10#$value <= 4 )) || return 1 ;;
        permitemptypasswords|permitrootlogin)
            [[ $value == no ]] || return 1 ;;
    esac
    ssh_scope options
}

check_sudo_installed() {
    local package found=0 unknown=0
    for package in sudo sudo-rs; do
        check_packages "$package"
        case $? in 0) found=1 ;; 1) ;; *) unknown=1 ;; esac
    done
    (( found == 0 )) || return 0
    (( unknown == 0 )) || return 2
    return 1
}

# На входе — Defaults, развёрнутые cvtsudoers, включая @include/@includedir.
sudo_policy() {
    local mode=$1 line pending='' policy='' tail token value rc
    local review=0 bad=0 found=0
    # Сначала соединяем продолжения Defaults, чтобы grep видел всю настройку.
    while IFS= read -r line || [[ -n $line ]]; do
        line=$pending$line
        tail=${line##*[^\\]}
        if (( ${#tail} % 2 )); then pending=${line%\\}; continue; fi
        pending=''
        policy+=$line$'\n'
    done
    [[ -z $pending ]] || review=1
    while IFS= read -r line; do
        line=${line%%#*}
        [[ $line =~ ^[[:blank:]]*$ ]] && continue
        if [[ ! $line =~ ^[[:blank:]]*Defaults([[:blank:]:@\>!]|$) ]]; then review=1; fi
    done <<< "$policy"
    local option=authenticate
    [[ $mode != timeout ]] || option=timestamp_timeout
    run grep -E "^[[:blank:]]*Defaults([[:blank:]:@>!])[^#]*\\b${option}\\b" <<< "$policy"
    rc=$?
    (( rc <= 1 )) || return 2
    policy=$output
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        line=${line%%#*}
        if [[ $line == *\"* || $line == *\\* ]]; then review=1; continue; fi
        if [[ $mode == authenticate ]]; then
            if grep -Eq '(^|[[:blank:],])!authenticate([[:blank:],]|$)' <<< "$line"; then bad=1; fi
            continue
        fi
        [[ $line =~ ^[[:blank:]]*Defaults[[:blank:]] ]] || review=1
        if grep -Eq '(^|[[:blank:],])!timestamp_timeout([[:blank:],]|$)' <<< "$line"; then review=1; fi
        local tokens
        tokens=$(grep -Eo '(^|[[:blank:],])timestamp_timeout[[:blank:]]*=[[:blank:]]*[^,[:blank:]]+' <<< "$line")
        while IFS= read -r token; do
            [[ -n $token ]] || continue
            value=${token#*=}
            value=${value//[[:blank:]]/}
            if [[ ! $value =~ ^[-+]?[0-9]+([.][0-9]+)?$ ]]; then review=1; continue; fi
            [[ ! $line =~ ^[[:blank:]]*Defaults[[:blank:]] ]] || found=1
            # Разрешены 0..15 минут, включая дробные значения.
            if ! grep -Eq '^\+?0*(([0-9]|1[0-4])([.][0-9]+)?|15([.]0+)?)$|^-0+([.]0+)?$' <<< "$value"; then bad=1; fi
        done <<< "$tokens"
    done <<< "$policy"
    (( bad == 0 )) || return 1
    if [[ $mode == timeout && $found == 0 ]]; then
        printf 'Нет явного глобального timestamp_timeout; проверьте значение по умолчанию sudo -V.\n'
        review=1
    fi
    if (( review )); then printf 'Неоднозначная политика Defaults требует ручной проверки.\n'; return 2; fi
    return 0
}

check_sudo_policy() {
    local mode=$1 policy nss
    check_sudo_installed || return $?
    if ! capture sudo -V; then printf '%s\n' "$output"; return 2; fi
    printf '%s\n' "${output%%$'\n'*}"
    case $output in
        *sudo-rs*|*Sudo-rs*) printf 'Политика активного sudo-rs требует ручной проверки.\n'; return 2 ;;
        'Sudo version '*) ;;
        *) return 2 ;;
    esac
    run visudo -c || return 2
    if ! capture cvtsudoers -c /dev/null -i sudoers -f sudoers -d all -s aliases,privileges /etc/sudoers; then
        printf '%s\n' "$output"; return 2
    fi
    policy=$output
    sudo_policy "$mode" <<< "$policy" || return $?
    local rc
    run grep -E '^[[:blank:]]*sudoers[[:blank:]]*:' /etc/nsswitch.conf
    rc=$?
    (( rc <= 1 )) || return 2
    nss='^[[:blank:]]*sudoers[[:blank:]]*:[[:blank:]]*files[[:blank:]]*(#.*)?$'
    if [[ -n $output && ! $output =~ $nss ]]; then
        printf 'Внешний источник sudoers требует ручной проверки.\n'; return 2
    fi
}

check_su_restricted() {
    local group='' name password gid members lines line token prior=0 review=0 found=0
    local prefix='^\h*-?auth\h+(required|requisite)\h+(\S*/)?pam_wheel\.so\b'
    local -a args
    [[ -f /etc/pam.d/su ]] || return 1
    run grep -Pn '^\h*(-?auth|@include)\h+' /etc/pam.d/su || return $?
    lines=$output
    while IFS= read -r line; do
        line=${line#*:}
        line=${line%%#*}
        # Стандартные @include common-* не являются auth-правилами PAM.
        # Они не должны влиять на определение порядка pam_wheel.
        if grep -Pq '^\h*@include\h+' <<< "$line"; then continue; fi
        if grep -Pq '^\h*-?auth\h+sufficient\h+(\S*/)?pam_rootok\.so\h*$' <<< "$line"; then continue; fi
        if grep -Pq "$prefix" <<< "$line"; then
            local use_uid=0 bad=0
            group=''
            read -r -a args <<< "$line"
            for token in "${args[@]:3}"; do
                case $token in use_uid) use_uid=1 ;; group=*) group=${token#*=} ;; debug) ;; *) bad=1 ;; esac
            done
            if [[ -n $group && $use_uid == 1 && $bad == 0 ]]; then
                if (( prior )); then review=1; else found=1; break; fi
            fi
        fi
        prior=1
    done <<< "$lines"
    if (( ! found )); then
        if (( review )); then
            printf 'Перед pam_wheel есть auth-строки или Include: проверьте порядок PAM-стека.\n'
            return 2
        fi
        return 1
    fi
    run getent group "$group"
    case $? in 0) ;; 2) return 1 ;; *) return 2 ;; esac
    [[ $output != *$'\n'* ]] || return 2
    IFS=: read -r name password gid members <<< "$output"
    [[ $name == "$group" && $gid =~ ^[0-9]+$ ]] || return 2
    [[ -z $members ]] || return 1
    capture getent passwd || return 2
    local rc
    run grep -E "^[^:]+:[^:]*:[0-9]+:${gid}:" <<< "$output"
    rc=$?
    if (( rc == 0 )); then
        printf 'Найдены пользователи с основным GID ограничивающей группы.\n'; return 1
    fi
    (( rc == 1 )) || return 2
    printf 'pam_wheel включён, группа %s пуста.\n' "$group"
}

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

check_pam_faillock() {
    local control='(\[[^]#]+\]|\S+)'
    local module='(\S*/)?pam_faillock\.so(?=\h|#|$)'
    local stage file type pattern lines line number pre=0 fail=0 account=0 review=0 rc
    [[ -f /etc/pam.d/common-auth && -f /etc/pam.d/common-account ]] || return 1
    check_packages libpam-modules || return $?
    for stage in preauth authfail account; do
        file=/etc/pam.d/common-auth type=auth
        [[ $stage != account ]] || { file=/etc/pam.d/common-account; type=account; }
        pattern="^\\h*-?${type}\\h+${control}\\h+${module}"
        [[ $stage == account ]] || pattern+="\\h+([^#]*\\h+)?${stage}(?=\\h|#|$)"
        run grep -Pn "$pattern" "$file" || return $?
        lines=$output
        # Несколько реализаций одной стадии требуют проверки потока управления.
        [[ $lines != *$'\n'* ]] || review=1
        line=${lines%%$'\n'*}
        number=${line%%:*}
        line=${line#*:}
        case $stage in
            preauth) pre=$number ;;
            authfail) fail=$number ;;
            account) account=$number ;;
        esac
        pattern="^\\h*-?${type}\\h+(required|requisite)\\h+"
        [[ $stage != authfail ]] || pattern='^\h*-?auth\h+(required|requisite|\[default=die\])\h+'
        if ! grep -Pq "$pattern" <<< "$line"; then review=1; fi
    done
    (( pre < fail )) || return 1
    for file in /etc/pam.d/common-auth /etc/pam.d/common-account; do
        run grep -Pn '^\h*(@include\b|-?(auth|account)\h+(include|substack)\b)' "$file"
        rc=$?
        case $rc in 0) review=1 ;; 1) ;; *) return 2 ;; esac
        run grep -Pn '^\h*-?(auth|account)\h+sufficient\h+' "$file"
        rc=$?
        (( rc <= 1 )) || return 2
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            number=${line%%:*}
            if [[ $file == /etc/pam.d/common-auth ]]; then
                (( number >= pre )) || review=1
            else
                (( number >= account )) || review=1
            fi
        done <<< "$output"
    done
    if (( review )); then printf 'Нестандартный PAM-стек требует ручной проверки.\n'; return 2; fi
    return 0
}

check_faillock_option() {
    local key=$1 value line lines token rc review=0
    check_pam_faillock || return $?
    [[ -f /etc/security/faillock.conf ]] || return 1
    run grep -P "^\h*${key}\h*=" /etc/security/faillock.conf || return $?
    line=${output##*$'\n'}
    value=${line#*=}
    value=${value%%#*}
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s = %s\n' "$key" "${value:-не задано}"
    [[ $value =~ ^[0-9]{1,9}$ ]] || return 1
    case $key in
        deny) (( 10#$value >= 1 && 10#$value <= 5 )) || return 1 ;;
        unlock_time) (( 10#$value == 0 || 10#$value >= 900 )) || return 1 ;;
        *) return 2 ;;
    esac
    # Аргументы активных PAM-строк имеют приоритет над faillock.conf.
    local pam='^\h*-?(auth|account)\h+(\[[^]#]+\]|\S+)\h+(\S*/)?pam_faillock\.so\h+'
    run grep -Ph "${pam}[^#]*\\b(${key}|conf)=" /etc/pam.d/common-auth /etc/pam.d/common-account
    rc=$?
    (( rc <= 1 )) || return 2
    lines=$output
    while IFS= read -r line; do
        line=${line%%#*}
        [[ -n $line ]] || continue
        local tokens
        tokens=$(grep -Po "(?<!\\S)(${key}|conf)=\\S*" <<< "$line")
        while IFS= read -r token; do
            [[ -n $token ]] || continue
            if [[ $token == conf=* ]]; then
                printf 'Отдельная конфигурация: %s\n' "$token"; review=1; continue
            fi
            value=${token#*=}
            [[ $value =~ ^[0-9]{1,9}$ ]] || return 1
            case $key in
                deny) (( 10#$value >= 1 && 10#$value <= 5 )) || return 1 ;;
                unlock_time) (( 10#$value == 0 || 10#$value >= 900 )) || return 1 ;;
            esac
        done <<< "$tokens"
    done <<< "$lines"
    (( review == 0 )) || return 2
    return 0
}

# libaudit 4.0.2 может разворачивать perm=wa в список системных вызовов.
audit_syscalls() {
    local arch=$1
    [[ $arch == x86_64 || $arch == aarch64 ]] || return 2
    capture dpkg-query -W '-f=${Version}' libaudit1 || return 2
    [[ $output =~ (^|:)4\.0\.2([-+~]|$) ]] || return 2
    capture ausyscall --dump || return 2
    awk '
      BEGIN {
        split("rename mkdir rmdir creat link unlink symlink mknod mkdirat mknodat unlinkat renameat linkat symlinkat renameat2 acct swapon quotactl truncate ftruncate bind fallocate open openat openat2 chmod fchmod chown lchown fchown setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr fchownat fchmodat", names)
        for(i in names)required[names[i]]=1
      }
      $1 ~ /^[0-9]+$/ && $2 in required {printf "%s,", $2}
    ' <<< "$output"
}

audit_match() {
    # path, path|dir, disk|loaded, ожидаемые syscalls, native arch.
    awk -v target="$1" -v field="$2" -v source="$3" -v expected="$4" -v native="$5" '
      function clean(path){sub(/\/$/,"",path); return path}
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      {
        act=""; path=""; dir=""; perm=""; arch=""; calls=""; invalid=0; watch=""
        for(i=1;i<=NF;i++) {
          t=$i
          if(t=="-a" || t=="-A")act=$(++i)
          else if(t=="-w")watch=$(++i)
          else if(t=="-p")perm=$(++i)
          else if(t=="-k")i++
          else if(t=="-S")calls=calls "," $(++i)
          else if(t=="-F") {
            v=$(++i); k=v; sub(/=.*/,"",k); sub(/^[^=]*=/,"",v)
            if(k=="path")path=v; else if(k=="dir")dir=v; else if(k=="perm")perm=v
            else if(k=="arch")arch=v; else if(k!="key")invalid=1
          } else invalid=1
        }
        p=(field=="path"?path:dir)
        if(watch!="" && clean(watch)==clean(target)) {
          if(source=="disk"){print "Устаревшее постоянное правило -w: "$0; next}
          p=watch; act="always,exit"
        }
        if(clean(p)!=clean(target))next
        print source ": "$0
        if(invalid || (act!="always,exit" && act!="exit,always") || perm !~ /w/ || perm !~ /a/)next
        if(arch!="" && arch!="b64" && arch!=native)next
        if(calls=="" || calls==",all"){found=1; next}
        if(expected=="" || arch==""){review=1; next}
        n=split(expected,req,","); complete=1
        for(j=1;j<=n;j++)if(req[j]!="" && index(calls ",","," req[j] ",")==0)complete=0
        if(complete)found=1
      }
      END {
        if(found)exit 0
        if(review){print "Нужна проверка списка системных вызовов."; exit 2}
        print "Нет полного правила для "target; exit 1
      }
    '
}

check_audit_rules() {
    local state arch native expected='' disk loaded field path source rules rc failed=0 unknown=0
    local -a files=(/etc/audit/rules.d/*.rules)
    run auditctl -s || return 2
    state=$(awk '$1=="enabled" {print $2; exit}' <<< "$output")
    case $state in 0) return 1 ;; 1|2) ;; *) return 2 ;; esac
    if ! capture auditctl -l; then printf '%s\n' "$output"; return 2; fi
    loaded=$output
    [[ -e ${files[0]} ]] || { printf 'Нет постоянных файлов *.rules.\n'; return 1; }
    if ! capture sed -E 's/[[:space:]]*#.*$//; /^[[:space:]]*-D[[:space:]]*$/d' "${files[@]}"; then
        printf '%s\n' "$output"; return 2
    fi
    disk=$output
    if grep -Eq '(^|[[:space:],])never([[:space:],]|$)|^[[:space:]]*-(d|D|W)([[:space:]]|$)|^[[:space:]]*-e[[:space:]]+0([[:space:]]|$)' <<< "$disk"$'\n'"$loaded"; then
        printf 'Правила подавления/удаления событий требуют проверки порядка.\n'; return 2
    fi
    run uname -m || return 2
    arch=$output
    case $arch in x86_64) native=c000003e ;; aarch64) native=c00000b7 ;; *) return 2 ;; esac
    if grep -Eq '[[:space:]]-S[[:space:]]+[^[:space:]]+' <<< "$loaded"; then
        expected=$(audit_syscalls "$arch") || expected=''
    fi
    while (( $# )); do
        field=$1 path=$2
        shift 2
        for source in disk loaded; do
            case $source in disk) rules=$disk ;; loaded) rules=$loaded ;; esac
            audit_match "$path" "$field" "$source" "$expected" "$native" <<< "$rules"
            rc=$?
            case $rc in 0) ;; 1) failed=1 ;; *) unknown=1 ;; esac
        done
    done
    (( failed == 0 )) || return 1
    (( unknown == 0 )) || return 2
    return 0
}

main() {
    if (( $# > 1 )); then printf 'Использование: sudo bash audit.sh [отчёт.log]\n' >&2; return 2; fi
    if (( EUID != 0 )); then printf 'Запустите на проверяемом хосте через sudo.\n' >&2; return 2; fi
    local log=${1:-output.log} problems=0 output=''
    local -A counts=([PASS]=0 [FAIL]=0 [REVIEW]=0)
    # Укажите новый файл, чтобы случайно не стереть результаты «до».
    set -o noclobber
    if ! exec 3> "$log"; then return 2; fi
    printf 'Debian 13 | CIS Benchmark v1.1.0 | 20 выбранных правил\nХост: %s\nВремя: %s\n' \
        "$(hostname)" "$(date --iso-8601=seconds)" >&3
    check 5.1.1 'Права файлов sshd_config' check_ssh_files
    check 5.1.2 'Права каталога sshd_config.d' check_ssh_directory
    check 5.1.15 'LoginGraceTime от 1 до 60 секунд' check_ssh_option logingracetime
    check 5.1.18 'MaxAuthTries не больше 4' check_ssh_option maxauthtries
    check 5.1.21 'PermitEmptyPasswords = no' check_ssh_option permitemptypasswords
    check 5.1.22 'PermitRootLogin = no' check_ssh_option permitrootlogin
    check 5.2.1 'Установлен sudo или sudo-rs' check_sudo_installed
    check 5.2.5 'Повторная аутентификация sudo не отключена глобально' check_sudo_policy authenticate
    check 5.2.6 'timestamp_timeout от 0 до 15 минут' check_sudo_policy timeout
    check 5.2.7 'Доступ к su ограничен пустой группой' check_su_restricted
    check 5.3.1.1 'Актуальная версия libpam-runtime по локальному кэшу APT' check_pam_version
    check 5.3.2.2 'pam_faillock включён в auth и account' check_pam_faillock
    check 5.3.3.1.1 'Блокировка после 1–5 неудачных попыток' check_faillock_option deny
    check 5.3.3.1.2 'Разблокировка через 900 секунд или вручную' check_faillock_option unlock_time
    check 6.2.1.1 'Установлены auditd и audispd-plugins' check_packages auditd audispd-plugins
    check 6.2.1.2 'auditd включён и активен' check_service auditd.service
    check 6.2.3.1 'Аудит изменений sudoers и sudoers.d' check_audit_rules path /etc/sudoers dir /etc/sudoers.d
    check 6.2.3.12 'Аудит изменений /etc/group' check_audit_rules path /etc/group
    check 6.2.3.13 'Аудит изменений /etc/passwd' check_audit_rules path /etc/passwd
    check 6.2.3.14 'Аудит изменений /etc/shadow и /etc/gshadow' check_audit_rules path /etc/shadow path /etc/gshadow
    printf '\nИтого: PASS=%s FAIL=%s REVIEW=%s\n' "${counts[PASS]}" "${counts[FAIL]}" "${counts[REVIEW]}" >&3
    printf 'Отчёт записан в %s\n' "$log"
    return "$problems"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
