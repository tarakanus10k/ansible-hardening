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

check_apparmor() {
    local rc file
    local disabled="(^|[[:space:]\"'])apparmor=0([[:space:]\"']|$)"
    local grub_variable='^[[:blank:]]*(export[[:blank:]]+)?GRUB_CMDLINE_LINUX(_[A-Z]+)?[[:blank:]]*='
    check_service apparmor.service || return $?
    run aa-status --profiled
    rc=$?
    case $rc in 1|2) return 1 ;; 0) ;; *) return 2 ;; esac
    [[ $output =~ ^[0-9]+$ ]] || return 2
    [[ $output =~ [1-9] ]] || return 1

    run grep -E "$disabled" /proc/cmdline
    case $? in 0) return 1 ;; 1) ;; *) return 2 ;; esac

    # В сгенерированном GRUB интересуют только команды загрузки ядра.
    if ! run grep -E '^[[:blank:]]*linux(efi|16)?[[:blank:]]' /boot/grub/grub.cfg; then
        printf 'Не удалось подтвердить параметры загрузчика GRUB.\n'
        return 2
    fi
    [[ ! $output =~ $disabled ]] || return 1

    for file in /etc/default/grub /etc/default/grub.d/*.cfg; do
        [[ -e $file ]] || continue
        run grep -E "${grub_variable}([^#]*[[:blank:]\"'])?apparmor=0([[:blank:]\"']|$)" "$file"
        case $? in 0) return 1 ;; 1) ;; *) return 2 ;; esac
    done
}

check_apparmor_sysctl() {
    local key=kernel.apparmor_restrict_unprivileged_unconfined effective
    run sysctl -n "$key" || return 2
    [[ $output == 1 ]] || return 1

    # --cat-config показывает итоговый порядок файлов, ничего не применяя.
    if ! run /usr/lib/systemd/systemd-sysctl --cat-config; then
        return 2
    fi
    effective=$(awk -F= -v key="$key" '
        /^[[:blank:]]*[#;]/ { next }
        NF > 1 {
            name=$1
            gsub(/[[:blank:]]/, "", name)
            sub(/^-/, "", name)
            gsub(/\//, ".", name)
            if (name == key) {
                value=$2
                sub(/[[:blank:]]*[#;].*$/, "", value)
                gsub(/[[:blank:]]/, "", value)
            }
        }
        END {print value}
    ' <<< "$output") || return 2
    printf 'Эффективное значение при загрузке: %s\n' "${effective:-не задано}"

    if [[ -f /etc/default/ufw ]]; then
        run grep -E '^[[:blank:]]*IPT_SYSCTL[[:blank:]]*=' /etc/default/ufw
        case $? in
            0) printf 'UFW может загружать отдельный файл sysctl. Требуется ручная проверка.\n'; return 2 ;;
            1) ;;
            *) return 2 ;;
        esac
    fi
    [[ $effective == 1 ]]
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

check_sudo_timeout() {
    local actual_version policy nss
    check_sudo_installed || return $?
    if ! capture sudo -V; then
        printf '%s\n' "$output"
        return 2
    fi
    actual_version=${output%%$'\n'*}
    printf '%s\n' "$actual_version"
    case $actual_version in
        *sudo-rs*|*Sudo-rs*) printf 'Для активного sudo-rs проверьте поддержку timestamp_timeout вручную.\n'; return 2 ;;
        'Sudo version '*) ;;
        *) printf 'Не удалось определить реализацию sudo.\n'; return 2 ;;
    esac

    run visudo -c || return 2
    if ! capture cvtsudoers -c /dev/null -i sudoers -f sudoers -d all -s aliases,privileges /etc/sudoers; then
        printf '%s\n' "$output"
        return 2
    fi
    policy=$output
    timeout_policy <<< "$policy" || return $?

    # Отдельный источник sudoers может изменить эффективную политику.
    run awk '/^[[:blank:]]*sudoers[[:blank:]]*:/ {sub(/#.*/, ""); print}' /etc/nsswitch.conf || return 2
    nss='^[[:blank:]]*sudoers[[:blank:]]*:[[:blank:]]*files[[:blank:]]*$'
    if [[ -n $output && ! $output =~ $nss ]]; then
        printf 'Нестандартный источник sudoers требует ручной проверки.\n'
        return 2
    fi
}

# PAM: пакет libpam-runtime и активные строки пяти common-стеков.
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

check_pam_unix() {
    local mode=$1 file rc missing=0
    local -a files=(/etc/pam.d/common-{account,auth,password,session,session-noninteractive})
    # Сопоставляем имя модуля в его поле, пропуская комментарии и аргументы других модулей.
    local pam_unix='^\h*-?(?:account|auth|password|session)\h+(?:\[[^#\]\r\n]+\]|[^#\h]+)\h+(?:[^#\h]+/)?pam_unix\.so(?=\h|#|$)'

    for file in "${files[@]}"; do
        if [[ ! -f $file ]]; then
            printf 'Отсутствует: %s\n' "$file"
            missing=1
        elif [[ ! -r $file ]]; then
            printf 'Не удалось прочитать: %s\n' "$file"
            return 2
        fi
    done
    (( missing == 0 )) || return 1

    if [[ $mode == nullok ]]; then
        run grep -PH -- "$pam_unix"'\h+(?:[^#\r\n]*\h+)?nullok(?=\h|#|$)' "${files[@]}"
        rc=$?
        case $rc in
            0) return 1 ;;  # Найдено запрещённое значение.
            1) printf 'Аргумент nullok в активных строках pam_unix не найден.\n'; return 0 ;;
            *) return 2 ;;
        esac
    fi

    run grep -PH -- "$pam_unix" "${files[@]}"
    rc=$?
    (( rc <= 1 )) || return 2
    for file in "${files[@]}"; do
        if [[ $'\n'$output != *$'\n'"$file:"* ]]; then
            printf 'Нет активной строки pam_unix: %s\n' "$file"
            missing=1
        fi
    done
    return "$missing"
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
    check 1.3.1.1 'Пакеты AppArmor' check_packages apparmor apparmor-utils
    check 1.3.1.2 'AppArmor включён' check_apparmor
    check 1.3.1.4 'Ограничение unprivileged unconfined' check_apparmor_sysctl
    check 5.1.1 'Права файлов sshd_config' check_ssh_files
    check 5.1.2 'Права каталога sshd_config.d' check_ssh_directory
    check 5.1.15 'LoginGraceTime от 1 до 60 секунд' check_ssh_option logingracetime
    check 5.1.18 'MaxAuthTries не больше 4' check_ssh_option maxauthtries
    check 5.1.21 'PermitEmptyPasswords = no' check_ssh_option permitemptypasswords
    check 5.1.22 'PermitRootLogin = no' check_ssh_option permitrootlogin
    check 5.2.1 'Установлен sudo или sudo-rs' check_sudo_installed
    check 5.2.6 'timestamp_timeout от 0 до 15 минут' check_sudo_timeout
    check 5.3.1.1 'Актуальная версия libpam-runtime по локальному кэшу APT' check_pam_version
    check 5.3.2.1 'pam_unix в пяти common-стеках' check_pam_unix enabled
    check 5.3.3.4.1 'pam_unix без nullok' check_pam_unix nullok
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
