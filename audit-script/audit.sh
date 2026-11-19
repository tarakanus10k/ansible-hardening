#!/usr/bin/env bash
# Восемь исходных проверок для Debian 13, CIS Benchmark v1.1.0.
# Коды выхода: 0 — все PASS, 1 — есть FAIL или REVIEW, 2 — ошибка запуска.
set -u
export LC_ALL=C
umask 077

# run пишет команду и её вывод, а output остаётся доступен функции проверки.
run() {
    printf '$' >&3
    printf ' %q' "$@" >&3
    printf '\n' >&3
    local status=0
    output=$("$@" 2>&1) || status=$?
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
    printf 'Результат: %s\n' "$status" >&3
}

check_packages() {
    local package rc failed=0
    for package in apparmor apparmor-utils; do
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

check_apparmor() {
    local rc file
    local disabled="(^|[[:space:]\"'])apparmor=0([[:space:]\"']|$)"
    local grub_variable='^[[:blank:]]*(export[[:blank:]]+)?GRUB_CMDLINE_LINUX(_[A-Z]+)?[[:blank:]]*='
    run systemctl is-enabled apparmor.service
    [[ $output == enabled ]] || {
        case $output in disabled|masked|static|indirect|not-found|enabled-runtime) return 1 ;; *) return 2 ;; esac
    }
    run systemctl is-active apparmor.service
    [[ $output == active ]] || {
        case $output in inactive|failed|unknown) return 1 ;; *) return 2 ;; esac
    }
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
    run sshd -T || return 2
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
        permitemptypasswords)
            [[ $value == no ]] || return 1 ;;
    esac
    ssh_scope options
}

main() {
    if (( $# > 1 )); then printf 'Использование: sudo bash audit.sh [отчёт.log]\n' >&2; return 2; fi
    if (( EUID != 0 )); then printf 'Запустите на проверяемом хосте через sudo.\n' >&2; return 2; fi
    local log=${1:-output.log} problems=0 output=''
    # Укажите новый файл, чтобы случайно не стереть результаты «до».
    set -o noclobber
    if ! exec 3> "$log"; then return 2; fi
    printf 'Debian 13 | CIS Benchmark v1.1.0 | 8 выбранных правил\nХост: %s\nВремя: %s\n' \
        "$(hostname)" "$(date --iso-8601=seconds)" >&3
    check 1.3.1.1 'Пакеты AppArmor' check_packages
    check 1.3.1.2 'AppArmor включён' check_apparmor
    check 1.3.1.4 'Ограничение unprivileged unconfined' check_apparmor_sysctl
    check 5.1.1 'Права файлов sshd_config' check_ssh_files
    check 5.1.2 'Права каталога sshd_config.d' check_ssh_directory
    check 5.1.15 'LoginGraceTime от 1 до 60 секунд' check_ssh_option logingracetime
    check 5.1.18 'MaxAuthTries не больше 4' check_ssh_option maxauthtries
    check 5.1.21 'PermitEmptyPasswords = no' check_ssh_option permitemptypasswords
    printf 'Отчёт записан в %s\n' "$log"
    return "$problems"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
