#!/usr/bin/env bash
# Двадцать правил плейбука для Debian 13, CIS Benchmark v1.1.0.
# Коды выхода: 0 — все PASS, 1 — есть FAIL или REVIEW, 2 — ошибка запуска.
set -uo pipefail
export LC_ALL=C
umask 077

# capture записывает команду, run также печатает её вывод.
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
    local service=$1 enabled active rc
    run systemctl is-enabled "$service"
    rc=$?
    enabled=$output
    (( rc <= 4 )) || return 2
    run systemctl is-active "$service"
    rc=$?
    active=$output
    (( rc <= 4 )) || return 2
    case $enabled in
        enabled) ;;
        disabled|masked|masked-runtime|static|indirect|not-found|enabled-runtime) return 1 ;;
        *) return 2 ;;
    esac
    case $active in
        active) return 0 ;;
        inactive|failed|unknown) return 1 ;;
        *) return 2 ;;
    esac
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
    if ! capture sshd -T; then
        printf '%s\n' "$output"
        return 2
    fi
    value=$(awk -v key="$key" '$1 == key {print $2; exit}' <<< "$output")
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

# sudo: выбор реализации и проверка активных Defaults.
check_sudo_installed() {
    local found=0 unknown=0 package
    for package in sudo sudo-rs; do
        check_packages "$package"
        case $? in
            0) found=1 ;;
            1) ;;
            *) unknown=1 ;;
        esac
    done
    (( found == 0 )) || return 0
    (( unknown == 0 )) || return 2
    return 1
}

timeout_policy() {
    # cvtsudoers может печатать одно выражение Defaults на нескольких строках.
    awk '
      function check_defaults(line, global, token, v) {
        if(line ~ /^[[:space:]]*($|#)/)return
        if(line !~ /^[[:space:]]*Defaults([[:space:]:@>!]|$)/) {
          review=1; print "Неожиданная строка при чтении sudoers: " line; return
        }
        if(line !~ /timestamp_timeout/)return
        if(line ~ /["\\]/){review=1; print "Сложная Defaults-строка: "line; return}
        global=(line ~ /^[[:space:]]*Defaults[[:space:]]/)
        if(!global){review=1; print "Scoped Defaults требует проверки применимости: "line}
        sub(/#.*/,"",line)
        if(line ~ /(^|[[:space:],])!timestamp_timeout([[:space:],]|$)/)review=1
        while(match(line,/(^|[[:space:],])timestamp_timeout[[:space:]]*=[[:space:]]*[^,[:space:]]+/)) {
          token=substr(line,RSTART,RLENGTH); v=token; sub(/^.*=[[:space:]]*/,"",v)
          print "Активная настройка: "token
          if(v !~ /^[-+]?[0-9]+([.][0-9]+)?$/) review=1
          else {count++; if(global)g++; if(v+0<0 || v+0>15)bad=1}
          line=substr(line,RSTART+RLENGTH)
        }
      }
      {
        line=pending $0
        # Нечётное число обратных косых черт в конце означает продолжение.
        if(match(line,/\\+$/) && RLENGTH%2) {
          pending=substr(line,1,length(line)-1)
          continued=1
          next
        }
        pending=""
        continued=0
        check_defaults(line)
      }
      END{
          if(continued){review=1; print "Незавершённое продолжение строки sudoers."}
          if(bad)exit 1; if(review)exit 2;
          if(!count || !g){print "Нет явного глобального timestamp_timeout (0..15 минут).";exit 1}}
    '
}

authenticate_policy() {
    awk '
      {
        line=pending $0
        if(match(line,/\\+$/) && RLENGTH%2) {
          pending=substr(line,1,length(line)-1); next
        }
        pending=""
        if(line ~ /^[[:space:]]*($|#)/)next
        if(line !~ /^[[:space:]]*Defaults([[:space:]:@>!]|$)/){review=1; next}
        sub(/#.*/, "", line)
        if(line ~ /(^|[[:space:],])!authenticate([[:space:],]|$)/) {
          print "Отключена аутентификация: "line; bad=1
        }
        if(line ~ /["\\]/)review=1
      }
      END {
        if(bad)exit 1
        if(review || pending!="")exit 2
        print "Defaults с !authenticate не найдены."
      }
    '
}

check_sudo_policy() {
    local checker=$1 actual_version policy nss
    check_sudo_installed || return $?
    if ! capture sudo -V; then
        printf '%s\n' "$output"
        return 2
    fi
    actual_version=${output%%$'\n'*}
    printf '%s\n' "$actual_version"
    case $actual_version in
        *sudo-rs*|*Sudo-rs*) printf 'Для активного sudo-rs проверьте политику Defaults вручную.\n'; return 2 ;;
        'Sudo version '*) ;;
        *) printf 'Не удалось определить реализацию sudo.\n'; return 2 ;;
    esac

    run visudo -c || return 2
    if ! capture cvtsudoers -c /dev/null -i sudoers -f sudoers -d all -s aliases,privileges /etc/sudoers; then
        printf '%s\n' "$output"
        return 2
    fi
    policy=$output
    "$checker" <<< "$policy" || return $?

    # Отдельный источник sudoers может изменить эффективную политику.
    run awk '/^[[:blank:]]*sudoers[[:blank:]]*:/ {sub(/#.*/, ""); print}' /etc/nsswitch.conf || return 2
    nss='^[[:blank:]]*sudoers[[:blank:]]*:[[:blank:]]*files[[:blank:]]*$'
    if [[ -n $output && ! $output =~ $nss ]]; then
        printf 'Нестандартный источник sudoers требует ручной проверки.\n'
        return 2
    fi
}

check_su_restricted() {
    local group entry name password gid members
    [[ -f /etc/pam.d/su ]] || return 1
    # Ограничение должно срабатывать до sufficient/include/substack.
    run awk '
      {sub(/#.*/, "")}
      $1=="@include" {prior=1}
      $1=="auth" || $1=="-auth" {
        if(($2=="required" || $2=="requisite") && $3 ~ /(^|\/)pam_wheel[.]so$/) {
          group=""; use_uid=0; bad=0
          for(i=4;i<=NF;i++) {
            if($i=="use_uid")use_uid=1
            else if($i ~ /^group=/){group=$i; sub(/^group=/,"",group)}
            else bad=1
          }
          if(group!="" && use_uid && !bad) {
            if(prior)review=1
            else {print group; found=1; exit}
          }
        }
        prior=1
      }
      END {if(!found){if(review)exit 2; exit 1}}
    ' /etc/pam.d/su || return $?
    group=$output
    run getent group "$group"
    case $? in 0) ;; 2) return 1 ;; *) return 2 ;; esac
    entry=$output
    [[ $entry != *$'\n'* ]] || return 2
    IFS=: read -r name password gid members <<< "$entry"
    [[ $name == "$group" && $gid =~ ^[0-9]+$ ]] || return 2
    [[ -z $members ]] || return 1
    capture getent passwd || return 2
    if awk -F: -v gid="$gid" '$4==gid {found=1; print $1} END {exit !found}' <<< "$output"; then
        printf 'В ограничивающей группе есть пользователи с основным GID %s.\n' "$gid"
        return 1
    fi
    printf 'Группа %s пуста, pam_wheel с use_uid включён перед остальным auth-стеком.\n' "$group"
}

# PAM: пакет libpam-runtime, модуль faillock и его эффективные параметры.
check_pam_version() {
    local installed candidate
    check_packages libpam-runtime || return $?
    run dpkg-query -W '-f=${Version}\n' libpam-runtime || return 2
    installed=$output
    run apt-cache policy libpam-runtime || return 2
    candidate=$(awk '$1 == "Candidate:" {print $2; exit}' <<< "$output")
    printf 'Установленная версия: %s. Кандидат из локального кэша APT: %s.\n' \
        "$installed" "${candidate:-не найден}"
    [[ -n $installed && -n $candidate && $candidate != '(none)' ]] || return 2
    [[ $installed == "$candidate" ]]
}

check_pam_faillock() {
    [[ -f /etc/pam.d/common-auth && -f /etc/pam.d/common-account ]] || return 1
    check_packages libpam-modules || return $?
    run awk '
      {
        sub(/#.*/, "")
        type=$1
        if(type=="@include" || $2=="include" || $2=="substack")review=1
        if(type!="auth" && type!="account")next
        line=$0
        sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+/, "", line)
        control=line
        if(line ~ /^\[/) {
          sub(/\].*$/, "]", control)
          sub(/^\[[^]]+\][[:space:]]+/, "", line)
        } else {
          sub(/[[:space:]].*$/, "", control)
          sub(/^[^[:space:]]+[[:space:]]+/, "", line)
        }
        n=split(line,args,/[[:space:]]+/)
        if(args[1] !~ /(^|\/)pam_faillock[.]so$/) {
          if(type=="auth" && !pre && control=="sufficient")review=1
          next
        }
        print FILENAME ":" FNR ": " $0
        if(type=="account") {
          if(control=="required" || control=="requisite")account=1
          else review=1
          next
        }
        for(i=2;i<=n;i++) {
          if(args[i]=="preauth") {
            pre=FNR
            if(control!="required" && control!="requisite")review=1
          }
          if(args[i]=="authfail") {
            fail=FNR
            if(control!="required" && control!="requisite" && control!="[default=die]")review=1
          }
        }
      }
      END {
        if(!pre || !fail || !account || pre>=fail)exit 1
        if(review)exit 2
      }
    ' /etc/pam.d/common-auth /etc/pam.d/common-account
}

check_faillock_option() {
    local key=$1 value
    check_pam_faillock || return $?
    [[ -f /etc/security/faillock.conf ]] || return 1
    run awk -F= -v key="$key" '
      {sub(/#.*/, ""); name=$1; gsub(/[[:space:]]/, "", name)}
      name==key {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)}
      END {print value}
    ' /etc/security/faillock.conf || return 2
    value=$output
    printf '%s = %s\n' "$key" "${value:-не задано}"
    [[ $value =~ ^[0-9]{1,9}$ ]] || return 1
    case $key in
        deny) (( 10#$value >= 1 && 10#$value <= 5 )) || return 1 ;;
        unlock_time) (( 10#$value == 0 || 10#$value >= 900 )) || return 1 ;;
        *) return 2 ;;
    esac
    # Параметры строки модуля имеют приоритет над faillock.conf.
    run awk -v key="$key" '
      {
        sub(/#.*/, "")
        if($0 !~ /^[[:space:]]*(auth|account)[[:space:]]+/)next
        line=$0
        sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+(\[[^]]+\]|[^[:space:]]+)[[:space:]]+/, "", line)
        n=split(line,args,/[[:space:]]+/)
        if(args[1] !~ /(^|\/)pam_faillock[.]so$/)next
        for(i=2;i<=n;i++) {
          if(args[i] ~ /^conf=/){print "Отдельный файл конфигурации: "args[i]; review=1}
          if(args[i] ~ ("^"key"=")) {
            v=args[i]; sub(/^[^=]*=/, "", v)
            print FILENAME ":" FNR ": "args[i]
            if(v !~ /^[0-9]+$/)bad=1
            else if(key=="deny" && (v+0<1 || v+0>5))bad=1
            else if(key=="unlock_time" && v+0!=0 && v+0<900)bad=1
          }
        }
      }
      END {if(bad)exit 1; if(review)exit 2}
    ' /etc/pam.d/common-auth /etc/pam.d/common-account
}

# Linux Audit: сверяем постоянные правила с правилами, загруженными в ядро.
# libaudit 4.0.2 может вывести perm=wa как развёрнутый список системных вызовов.
audit_syscalls() {
    local arch=$1
    [[ $arch == x86_64 || $arch == aarch64 ]] || return 2
    capture dpkg-query -W '-f=${Version}' libaudit1 || return 2
    [[ $output =~ (^|:)4\.0\.2([-+~]|$) ]] || return 2
    capture ausyscall --dump || return 2
    awk '
        BEGIN {
            split("rename mkdir rmdir creat link unlink symlink mknod mkdirat mknodat unlinkat renameat linkat symlinkat renameat2 acct swapon quotactl truncate ftruncate bind fallocate open openat openat2 chmod fchmod chown lchown fchown setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr fchownat fchmodat", names)
            for (i in names) required[names[i]]=1
        }
        $1 ~ /^[0-9]+$/ && $2 in required {printf "%s,", $2}
    ' <<< "$output"
}

audit_match() {
    # args: path, path|dir, disk|loaded, expected syscall names, native arch.
    # Only unrestricted always/exit rules qualify. Never execute rule text.
    awk -v target="$1" -v field="$2" -v source="$3" -v expected="$4" -v native="$5" '
      function clean(p){sub(/\/$/,"",p); return p}
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
        print source ": " $0
        if(invalid || (act!="always,exit" && act!="exit,always") || perm !~ /w/ || perm !~ /a/)next
        if(arch!="" && arch!="b64" && arch!=native)next
        if(calls=="" || calls==",all"){found=1;next}
        if(expected=="" || arch==""){review=1;next}
        n=split(expected,req,","); complete=1
        for(j=1;j<=n;j++)if(req[j]!="" && index(calls ",","," req[j] ",")==0)complete=0
        if(complete)found=1
      }
      END{if(found)exit 0; if(review){print "Список -S требует дополнительной проверки.";exit 3}
          print "Нет полного подходящего правила для "target;exit 1}
    '
}

check_audit_rules() {
    local state arch native expected='' disk loaded field path source rules rc failed=0 unknown=0
    local -a files=(/etc/audit/rules.d/*.rules)
    run auditctl -s || return 2
    state=$(awk '$1 == "enabled" {print $2; exit}' <<< "$output")
    case $state in
        0) return 1 ;;
        1|2) ;;
        *) return 2 ;;
    esac
    if ! capture auditctl -l; then
        printf '%s\n' "$output"
        return 2
    fi
    loaded=$output
    [[ -e ${files[0]} ]] || { printf 'Нет постоянных файлов *.rules.\n'; return 1; }
    if ! capture sed -E 's/[[:space:]]*#.*$//; /^[[:space:]]*-D[[:space:]]*$/d' "${files[@]}"; then
        printf '%s\n' "$output"
        return 2
    fi
    disk=$output
    if grep -Eq '(^|[[:space:],])never([[:space:],]|$)|^[[:space:]]*-(d|D|W)([[:space:]]|$)|^[[:space:]]*-e[[:space:]]+0([[:space:]]|$)' <<< "$disk"$'\n'"$loaded"; then
        printf 'Есть правила подавления или удаления событий. Проверьте порядок вручную.\n'
        return 2
    fi
    run uname -m || return 2
    arch=$output
    case $arch in
        x86_64) native=c000003e ;;
        aarch64) native=c00000b7 ;;
        *) native=unsupported ;;
    esac
    if grep -Eq '[[:space:]]-S[[:space:]]+[^[:space:]]+' <<< "$loaded"; then
        expected=$(audit_syscalls "$arch") || expected=''
    fi

    while (( $# )); do
        field=$1 path=$2
        shift 2
        for source in disk loaded; do
            case $source in
                disk) rules=$disk ;;
                loaded) rules=$loaded ;;
            esac
            audit_match "$path" "$field" "$source" "$expected" "$native" <<< "$rules"
            rc=$?
            case $rc in
                0) ;;
                1) failed=1 ;;
                *) unknown=1 ;;
            esac
        done
    done
    (( failed == 0 )) || return 1
    (( unknown == 0 )) || return 2
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
    check 5.2.5 'Повторная аутентификация sudo не отключена глобально' check_sudo_policy authenticate_policy
    check 5.2.6 'timestamp_timeout от 0 до 15 минут' check_sudo_policy timeout_policy
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
