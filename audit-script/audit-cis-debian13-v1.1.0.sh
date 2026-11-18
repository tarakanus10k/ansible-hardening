#!/usr/bin/env bash
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
VERSION=5.1-bash
REPO=f73582a416ba21067ef943f1bcb820e966029e8c
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SCRIPT=$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")
WORK='' REPORT='' REMOTE='' PORT=22 IDENTITY=''
MODE=audit
declare -a CONTEXTS=()

usage() {
    cat <<'HELP'
Аудит выбранных правил CIS Debian Linux 13 Benchmark v1.1.0.

Локально:
  sudo bash audit-cis-debian13-v1.1.0.sh --output before.txt
  sudo bash audit-cis-debian13-v1.1.0.sh --output after.txt

Через SSH (запускать без локального sudo):
  bash audit-cis-debian13-v1.1.0.sh --ssh user@host --output after.txt
  bash audit-cis-debian13-v1.1.0.sh --ssh user@host --port 2222 \
    --identity ~/.ssh/id_ed25519 --output after.txt

Параметры:
  --output FILE       Новый текстовый отчёт; существующий файл не перезаписывается.
  --ssh HOST          SSH alias или user@host. Отчёт скачивается локально.
  --port NUMBER       Порт SSH (по умолчанию 22).
  --identity FILE     Приватный SSH-ключ на локальной машине.
  --snapshot          Снимок контрольных сумм и состояния для повторного прогона.
  --boot-evidence     Параметры GRUB, boot_id и состояние AppArmor.
                      Снимки локальны на ВМ. Без --output печатаются в stdout.
  --ssh-context STR  Дополнительный контекст sshd -T -C; можно повторять.
                     Пример: user=test,host=debian-srv,addr=192.168.100.20
  --help              Эта справка.

Покрытие: 20 правил из ролей ssh, pam, sudo, audit, apparmor на коммите
f73582a416ba21067ef943f1bcb820e966029e8c. Только фактические задачи;
оставшиеся в defaults переменные faillock не добавляют проверки.
1.3.1.1, 1.3.1.2, 1.3.1.4; 5.1.1, 5.1.2, 5.1.15, 5.1.18, 5.1.21,
5.1.22; 5.2.1, 5.2.6; 5.3.1.1, 5.3.2.1, 5.3.3.4.1;
6.2.1.1, 6.2.1.2, 6.2.3.1, 6.2.3.12, 6.2.3.13, 6.2.3.14.

true = PASS. false = FAIL, REVIEW (нужна ручная проверка) или ERROR.
Код выхода 0: всё PASS; 1: есть false, отчёт сохранён; 2: ошибка запуска.
Отсутствующий пакет/служба — FAIL; невозможность прочитать данные — ERROR.
SSH Match и внешняя политика sudo могут требовать REVIEW.

Нужны root на проверяемом Debian 13, Bash 5, awk, GNU grep, find,
coreutils, dpkg-query, apt-cache, systemctl. Для отдельных проверок:
sshd, sudo/visudo/cvtsudoers, auditctl/ausyscall, apparmor_status/aa-status.
Их отсутствие отражается в отчёте. Скрипт не устанавливает пакеты.
Кэш APT не обновляется: обновите его отдельно перед проверкой актуальности PAM.
Аудит не меняет настройки, не перезагружает службы, не вызывает sysctl --system,
augenrules --load, update-grub или pam-auth-update. Создаёт только отчёт и
временные файлы. Не проверяет реальные попытки входа и не сертифицирует CIS.
SSH проверяется по конфигурации на диске; перезагрузка демона не доказывается.
Правила auditd -w считаются устаревшими в постоянной конфигурации по v1.1.0.
Развёрнутые списки -S распознаются для libaudit 4.0.2, иначе REVIEW.
Сложные Include с пробелами/кавычками требуют REVIEW. Обычные Include рекурсивны.
HELP
}
die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || { printf 'Не найдена команда: %s\n' "$1"; return 2; }; }
cmd() { timeout 40 "$@"; }
cleanup() { [[ -z $WORK ]] || rm -rf -- "$WORK"; }
active() { sed -E 's/[[:space:]]*#.*$//; /^[[:space:]]*$/d' "$@"; }

check_packages() {
    need dpkg-query || return 2
    local name value rc bad=0
    for name in "$@"; do
        value=$(cmd dpkg-query -W '-f=${Status}' "$name" 2>&1); rc=$?
        printf '%s: %s\n' "$name" "$value"
        (( rc <= 1 )) || return 2
        [[ $rc == 0 && $value == 'install ok installed' ]] || bad=1
    done
    return "$bad"
}
service_state() {
    need systemctl || return 2
    local name=$1 enabled running rc1 rc2
    enabled=$(cmd systemctl is-enabled "$name" 2>&1); rc1=$?
    running=$(cmd systemctl is-active "$name" 2>&1); rc2=$?
    printf '%s: enabled=%s; active=%s\n' "$name" "$enabled" "$running"
    if [[ $enabled == enabled && $running == active ]]; then return 0; fi
    if [[ $enabled =~ ^(disabled|masked|static|indirect|not-found)$ || $running =~ ^(inactive|failed|unknown)$ ]]; then return 1; fi
    printf 'Не удалось однозначно определить состояние systemd (rc=%s/%s).\n' "$rc1" "$rc2"
    return 2
}

check_apparmor_enabled() {
    local rc bad=0 review=0 output n f
    service_state apparmor.service; rc=$?
    (( rc == 2 )) && return 2
    (( rc == 0 )) || bad=1
    if command -v apparmor_status >/dev/null; then f=apparmor_status
    elif command -v aa-status >/dev/null; then f=aa-status
    else printf 'Нет утилиты apparmor_status/aa-status.\n'; return 2; fi
    output=$(cmd "$f" 2>&1); rc=$?
    (( rc <= 2 )) || { printf 'Ошибка чтения AppArmor (rc=%s): %s\n' "$rc" "$output"; return 2; }
    n=$(awk '/^[[:space:]]*[0-9]+ profiles are loaded\./ {print $1; exit}' <<< "$output")
    if [[ $n =~ ^[0-9]+$ ]]; then
        printf 'Загружено профилей AppArmor: %s\n' "$n"
        (( 10#$n > 0 )) || bad=1
    elif (( rc == 1 || rc == 2 )); then printf '%s\n' "$output"; bad=1
    else printf 'Не удалось прочитать количество профилей (rc=%s): %s\n' "$rc" "$output"; return 2; fi
    if [[ -r /boot/grub/grub.cfg ]]; then
        output=$(grep -E '^[[:space:]]*linux(efi|16)?[[:space:]]' /boot/grub/grub.cfg || :)
        if [[ -z $output ]]; then printf 'В grub.cfg не найдены linux-записи; требуется проверка загрузчика.\n'; review=1; fi
        if grep -Eq '(^|[[:space:]])apparmor=0([[:space:]]|$)' <<< "$output"; then
            printf 'В grub.cfg найден apparmor=0.\n'; bad=1
        else printf 'grub.cfg: apparmor=0 в linux-записях не найден.\n'; fi
    else printf 'Нет доступного /boot/grub/grub.cfg: другой загрузчик/контейнер требует проверки.\n'; review=1; fi
    for f in /etc/default/grub /etc/default/grub.d/*.cfg; do
        [[ -e $f ]] || continue
        [[ -r $f ]] || return 2
        if active "$f" | grep -qE 'apparmor=0([^0-9]|$)'; then
            printf '%s: найден apparmor=0.\n' "$f"; bad=1
        fi
    done
    [[ -r /proc/cmdline ]] || return 2
    if grep -Eq '(^|[[:space:]])apparmor=0([[:space:]]|$)' /proc/cmdline; then
        printf 'Текущее ядро загружено с apparmor=0.\n'; bad=1
    fi
    (( bad == 0 )) || return 1
    (( review == 0 )) || return 3
}

sysctl_value_from_text() {
    awk -F= 'BEGIN{key="kernel.apparmor_restrict_unprivileged_unconfined"}
      /^[[:space:]]*[#;]/ {next}
      {k=$1; gsub(/^[[:space:]]*-?|[[:space:]]+$/, "", k); gsub(/\//,".",k)
       if(k==key){v=$2; sub(/[[:space:]]*[#;].*$/,"",v); gsub(/[[:space:]]/,"",v); found=1}}
      END{if(found)print v}'
}
check_apparmor_sysctl() {
    need sysctl || return 2
    local key=kernel.apparmor_restrict_unprivileged_unconfined value effective tool f uf rc
    if [[ ! -e /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined ]]; then
        printf 'Параметр отсутствует в работающем ядре: %s\n' "$key"; return 1
    fi
    value=$(cmd sysctl -n "$key" 2>&1) || { printf '%s\n' "$value"; return 2; }
    for tool in /usr/lib/systemd/systemd-sysctl /lib/systemd/systemd-sysctl; do [[ -x $tool ]] && break; done
    [[ -x $tool ]] || { printf 'Нет systemd-sysctl для чтения порядка конфигурации.\n'; return 2; }
    cmd "$tool" --cat-config > "$WORK/sysctl.conf" 2> "$WORK/err" || { cat "$WORK/err"; return 2; }
    effective=$(sysctl_value_from_text < "$WORK/sysctl.conf")
    printf 'Runtime: %s=%s\nПостоянная конфигурация systemd: %s\n' "$key" "$value" "${effective:-НЕ ЗАДАНО}"
    # UFW may load an additional file after systemd-sysctl; never source that file.
    if [[ -f /etc/default/ufw ]]; then
        uf=$(sed -nE 's/^[[:space:]]*IPT_SYSCTL[[:space:]]*=[[:space:]]*//p' /etc/default/ufw | tail -1)
        uf=${uf%\"}; uf=${uf#\"}; uf=${uf%\'}; uf=${uf#\'}
        if [[ -n $uf ]]; then
            [[ $uf == /* && -r $uf ]] || { printf 'Не удалось разобрать IPT_SYSCTL: %s\n' "$uf"; return 3; }
            f=$(sysctl_value_from_text < "$uf")
            if [[ -n $f ]]; then
                printf 'UFW (%s): %s\n' "$uf" "$f"
                [[ $f == 1 ]] || return 1
                effective=$f
            fi
        fi
    fi
    [[ $value == 1 && $effective == 1 ]]
}

declare -A SSH_SEEN=() SSH_FILES=() SSH_DIRS=()
SSH_MATCH=0 SSH_COMPLEX=0
ssh_visit() {
    local file=$1 real line key rest pattern child
    real=$(readlink -f -- "$file") || return 2
    [[ ${SSH_SEEN[$real]+yes} ]] && return 0
    SSH_SEEN[$real]=1 SSH_FILES[$file]=1
    [[ -r $file ]] || { printf 'Не прочитан %s\n' "$file"; return 2; }
    local -a patterns=()
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%%#*}
        read -r key rest <<< "$line"
        case ${key,,} in
            match) SSH_MATCH=1 ;;
            include)
                if [[ $rest == *\"* || $rest == *\'* || $rest == *\\* ]]; then SSH_COMPLEX=1; continue; fi
                read -r -a patterns <<< "$rest"
                for pattern in "${patterns[@]}"; do
                    [[ $pattern == /* ]] || pattern=/etc/ssh/$pattern
                    while IFS= read -r child; do
                        SSH_DIRS[$(dirname -- "$child")]=1
                        ssh_visit "$child" || return 2
                    done < <(compgen -G "$pattern" | sort)
                done ;;
        esac
    done < "$file"
}
ssh_inventory() {
    SSH_SEEN=() SSH_FILES=() SSH_DIRS=() SSH_MATCH=0 SSH_COMPLEX=0
    SSH_DIRS[/etc/ssh/sshd_config.d]=1
    ssh_visit /etc/ssh/sshd_config || return 2
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        find -L /etc/ssh/sshd_config.d -type f -name '*.conf' -print0 > "$WORK/ssh-files" || return 2
        local f
        while IFS= read -r -d '' f; do ssh_visit "$f" || return 2; done < "$WORK/ssh-files"
    fi
}
check_ssh_permissions() {
    ssh_inventory || return 2
    local kind=$1 f data mode uid gid bad=0 allowed
    local -a targets=()
    if [[ $kind == dir ]]; then targets=("${!SSH_DIRS[@]}"); allowed=$((0700))
    else targets=("${!SSH_FILES[@]}"); allowed=$((0600)); fi
    for f in "${targets[@]}"; do
        if [[ ! -e $f ]]; then printf 'Отсутствует: %s\n' "$f"; bad=1; continue; fi
        if [[ $kind == dir && ! -d $f || $kind == file && ! -f $f ]]; then printf 'Неверный тип: %s\n' "$f"; bad=1; continue; fi
        data=$(stat -Lc '%a %u %g' -- "$f") || return 2
        read -r mode uid gid <<< "$data"
        printf '%s: mode=%s uid=%s gid=%s\n' "$f" "$mode" "$uid" "$gid"
        (( uid == 0 && gid == 0 && (8#$mode & ~allowed) == 0 )) || bad=1
    done
    (( bad == 0 )) || return 1
    (( SSH_COMPLEX == 0 )) || { printf 'Include с кавычками/экранированием требует ручной проверки.\n'; return 3; }
}
ssh_value_ok() {
    local key=$1 value=$2
    case $key in
        logingracetime) [[ $value =~ ^[0-9]{1,8}$ ]] && (( 10#$value >= 1 && 10#$value <= 60 )) ;;
        maxauthtries) [[ $value =~ ^[0-9]{1,8}$ ]] && (( 10#$value <= 4 )) ;;
        permitemptypasswords|permitrootlogin) [[ $value == no ]] ;;
    esac
}
check_ssh_value() {
    need sshd || return 2
    ssh_inventory || return 2
    cmd sshd -t 2>&1 || return 2
    local key=$1 context value bad=0
    for context in '' "${CONTEXTS[@]}"; do
        if [[ -n $context ]]; then cmd sshd -T -C "$context" > "$WORK/sshd" 2> "$WORK/err"
        else cmd sshd -T > "$WORK/sshd" 2> "$WORK/err"; fi
        if (( $? != 0 )); then cat "$WORK/err"; return 2; fi
        value=$(awk -v key="$key" '$1==key{print $2;exit}' "$WORK/sshd")
        printf '%s: %s=%s\n' "${context:-global}" "$key" "${value:-НЕ ЗАДАНО}"
        ssh_value_ok "$key" "$value" || bad=1
    done
    (( bad == 0 )) || return 1
    if (( SSH_MATCH || SSH_COMPLEX )); then
        printf 'Есть Match/сложный Include: проверенные контексты корректны, все ветви не доказаны.\n'; return 3
    fi
}

check_sudo_installed() {
    local pkg found=0 rc
    for pkg in sudo sudo-rs; do
        check_packages "$pkg"; rc=$?
        (( rc == 2 )) && return 2
        (( rc == 0 )) && found=1
    done
    (( found == 1 ))
}
timeout_policy() {
    # Input is canonical sudoers emitted by cvtsudoers, not raw included files.
    # Exit 3 for syntax outside this deliberately small numeric Defaults parser.
    awk '
      /^[[:space:]]*Defaults/ && /timestamp_timeout/ {
        line=$0; if(line ~ /["\\]/){review=1; print "Сложная Defaults-строка: "line; next}
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
      END{if(bad)exit 1; if(review)exit 3;
          if(!count || !g){print "Нет явного глобального timestamp_timeout (0..15 минут).";exit 1}}
    '
}
check_sudo_timeout() {
    check_sudo_installed || return $?
    need sudo || return 2
    local ver rc external=0
    ver=$(cmd sudo -V 2>&1) || { printf '%s\n' "$ver"; return 2; }
    if grep -qi sudo-rs <<< "$ver"; then printf 'sudo-rs: необходима отдельная проверка поддержки timeout по версии.\n'; return 3; fi
    need visudo || return 2
    need cvtsudoers || return 2
    cmd visudo -c > "$WORK/visudo" 2>&1 || { cat "$WORK/visudo"; return 1; }
    cmd cvtsudoers -c /dev/null -i sudoers -f sudoers -d all -s aliases,privileges /etc/sudoers > "$WORK/sudoers" 2> "$WORK/err" || { cat "$WORK/err"; return 2; }
    [[ ! -s $WORK/err ]] || { cat "$WORK/err"; return 3; }
    timeout_policy < "$WORK/sudoers"; rc=$?
    printf 'Синтаксис проверен visudo; учтены активные include через cvtsudoers.\n'
    if [[ -r /etc/nsswitch.conf ]] && active /etc/nsswitch.conf | grep -Eq '^[[:space:]]*sudoers:.*\b(sss|ldap)\b'; then
        printf 'nsswitch включает sss/ldap: локальная политика проверена, внешняя не проверена.\n'
        external=1
    fi
    (( rc == 0 )) || return "$rc"
    (( external == 0 )) || return 3
}

check_pam_latest() {
    check_packages libpam-runtime || return $?
    need apt-cache || return 2
    local installed candidate
    installed=$(cmd dpkg-query -W '-f=${Version}' libpam-runtime) || return 2
    cmd apt-cache policy libpam-runtime > "$WORK/apt-policy" 2>&1 || { cat "$WORK/apt-policy"; return 2; }
    candidate=$(awk '$1=="Candidate:" {print $2}' "$WORK/apt-policy")
    printf 'Установлена: %s; кандидат APT: %s\n' "$installed" "${candidate:-неизвестно}"
    printf 'Проверка по локальному кэшу APT; скрипт не выполняет apt update.\n'
    [[ -n $candidate && $candidate != '(none)' ]] || return 3
    [[ $installed == "$candidate" ]]
}
check_pam() {
    local mode=$1 stack file rows bad=0
    for stack in account auth password session session-noninteractive; do
        file=/etc/pam.d/common-$stack
        [[ -f $file ]] || { printf 'Отсутствует: %s\n' "$file"; bad=1; continue; }
        [[ -r $file ]] || return 2
        rows=$(active "$file" | grep -E '(^|[[:space:]])([^[:space:]]*/)?pam_unix\.so([[:space:]]|$)' || :)
        if [[ $mode == enabled ]]; then
            printf '%s: %s\n' "$file" "${rows:-НЕТ pam_unix}"
            [[ -n $rows ]] || bad=1
        elif grep -Eq '(^|[[:space:]])nullok([[:space:]]|$)' <<< "$rows"; then
            printf '%s: найден nullok\n%s\n' "$file" "$rows"; bad=1
        else printf '%s: nullok отсутствует\n' "$file"; fi
    done
    return "$bad"
}

# Recognize the complete syscall expansion used by Debian 13 libaudit 4.0.2.
# Names follow audit-userspace v4.0.2 lib/permtab.h; unsupported native syscalls
# are removed with ausyscall. Other libaudit versions are not silently accepted.
audit_expected_syscalls() {
    local version arch name output
    version=$(dpkg-query -W '-f=${Version}' libaudit1 2>/dev/null) || return 3
    [[ $version =~ (^|:)4\.0\.2([-+~]|$) ]] || return 3
    arch=$(uname -m)
    [[ $arch == x86_64 || $arch == aarch64 ]] || return 3
    need ausyscall >/dev/null || return 3
    cmd ausyscall --dump > "$WORK/syscalls" 2>/dev/null || return 3
    for name in rename mkdir rmdir creat link unlink symlink mknod mkdirat mknodat unlinkat renameat linkat symlinkat renameat2 acct swapon quotactl truncate ftruncate bind fallocate open openat openat2 chmod fchmod chown lchown fchown setxattr lsetxattr fsetxattr removexattr lremovexattr fremovexattr fchownat fchmodat; do
        awk -v n="$name" '$2==n{found=1} END{exit !found}' "$WORK/syscalls" && printf '%s,' "$name"
    done
    return 0
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
          if(source=="disk"){print "Устаревшее постоянное правило -w: "$0; legacy=1; next}
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
    need auditctl || return 2
    local state expected='' path field rc bad=0 review=0 f native
    local -a files=()
    cmd auditctl -s > "$WORK/audit-status" 2>&1 || { cat "$WORK/audit-status"; return 2; }
    state=$(awk '$1=="enabled"{print $2}' "$WORK/audit-status")
    printf 'Ядро audit: enabled=%s\n' "$state"
    [[ $state == 1 || $state == 2 ]] || return 1
    cmd auditctl -l > "$WORK/audit-live" 2>&1 || { cat "$WORK/audit-live"; return 2; }
    [[ -d /etc/audit/rules.d ]] || { printf 'Нет каталога постоянных правил.\n'; return 1; }
    find /etc/audit/rules.d -maxdepth 1 -name '*.rules' -print0 | sort -zV > "$WORK/audit-files" || return 2
    : > "$WORK/audit-disk"
    while IFS= read -r -d '' f; do
        [[ -f $f && -r $f ]] || { printf 'Не прочитан файл: %s\n' "$f"; return 2; }
        files+=("$f")
        printf 'Файл правил: %s\n' "$f"
        # augenrules moves a standalone -D to the start of the merged rules.
        active "$f" | sed -E '/^[[:space:]]*-D[[:space:]]*$/d' >> "$WORK/audit-disk" || return 2
    done < "$WORK/audit-files"
    (( ${#files[@]} > 0 )) || { printf 'Нет файлов *.rules.\n'; return 1; }
    if grep -En '(^|[[:space:],])never([[:space:],]|$)|^[[:space:]]*-(d|D|W)([[:space:]]|$)|^[[:space:]]*-e[[:space:]]+0([[:space:]]|$)' "$WORK/audit-disk" "$WORK/audit-live"; then
        printf 'Подавляющие/удаляющие правила требуют анализа порядка.\n'; return 3
    fi
    expected=$(audit_expected_syscalls) || expected=''
    case $(uname -m) in x86_64)native=c000003e;; aarch64)native=c00000b7;; *)native=unsupported;; esac
    while (( $# )); do
        field=$1 path=$2; shift 2
        for f in disk live; do
            audit_match "$path" "$field" "$([[ $f == disk ]] && printf disk || printf loaded)" "$expected" "$native" < "$WORK/audit-$f"; rc=$?
            (( rc == 1 )) && bad=1
            (( rc == 3 )) && review=1
            (( rc == 0 || rc == 1 || rc == 3 )) || return 2
        done
    done
    (( bad == 0 )) || return 1
    (( review == 0 )) || return 3
}

TOTAL=0 PASSED=0 FAILED=0 ERRORS=0 REVIEWS=0
perform() {
    local id=$1 title=$2 page=$3 rc status result
    shift 3
    ( "$@" ) > "$WORK/evidence" 2>&1; rc=$?
    TOTAL=$((TOTAL+1)); result=false
    case $rc in
        0)status=PASS; result=true; PASSED=$((PASSED+1));;
        1)status=FAIL; FAILED=$((FAILED+1));;
        3)status=REVIEW; REVIEWS=$((REVIEWS+1));;
        *)status=ERROR; ERRORS=$((ERRORS+1));;
    esac
    {
        printf '\n[%s] %s\nРезультат: %s | Статус: %s | Страница CIS: %s\n' "$id" "$title" "$result" "$status" "$page"
        sed 's/^/  /' "$WORK/evidence"
        printf '%s\n' '--------------------------------------------------------------------------'
    } >> "$REPORT" || die 'Не удалось дописать отчёт'
    printf '%-12s %-5s %s\n' "$id" "$result" "$status"
}
target_check() {
    (( EUID == 0 )) || die 'Запустите через sudo или от root'
    [[ -r /etc/os-release ]] || die 'Нет /etc/os-release'
    grep -Eq '^ID="?debian"?$' /etc/os-release && grep -Eq '^VERSION_ID="?13"?$' /etc/os-release || die 'Скрипт предназначен для Debian 13'
}

target_versions() {
    printf 'kernel=%s\n' "$(uname -r)"
    dpkg-query -W -f='${Package}=${Version}\n' \
        bash python3 openssh-server sudo sudo-rs libpam-runtime libpam-modules \
        pamtester auditd audispd-plugins libaudit1 apparmor apparmor-utils \
        grub-common grub2-common systemd openscap-scanner ssg-debian 2>/dev/null || :
}

snapshot() {
    local file meta hash rules
    local -a paths=(
        /etc/ssh/sshd_config /etc/ssh/sshd_config.d
        /etc/pam.d/common-* /usr/share/pam-configs /var/cache/debconf/config.dat
        /etc/sudoers /etc/sudoers.d /etc/nsswitch.conf
        /etc/audit/audit.rules /etc/audit/rules.d
        /etc/default/grub /etc/default/grub.d /boot/grub/grub.cfg
        /etc/sysctl.conf /etc/sysctl.d
    )
    printf 'HOST=%s\nBOOT_ID=%s\n' "$(hostname)" "$(cat /proc/sys/kernel/random/boot_id)"
    find "${paths[@]}" -print0 > "$WORK/paths" 2>"$WORK/find.err"
    # Missing optional paths are recorded explicitly. Other errors invalidate the comparison.
    if grep -v 'No such file or directory$' "$WORK/find.err" >&2; then return 2; fi
    for file in "${paths[@]}"; do
        [[ -e $file || -L $file ]] || printf 'ABSENT %q\n' "$file"
    done
    sort -zu "$WORK/paths" > "$WORK/paths.sorted" || return 2
    while IFS= read -r -d '' file; do
        meta=$(stat -c '%F;%a;%u;%g' -- "$file") || return 2
        hash='-'
        if [[ -L $file ]]; then
            printf 'LINK %q -> %q\n' "$file" "$(readlink -- "$file")"
        fi
        if [[ -f $file ]]; then
            hash=$(sha256sum < "$file") || return 2
            hash=${hash%% *}
        fi
        printf 'FILE %q %s %s\n' "$file" "$meta" "$hash"
    done < "$WORK/paths.sorted"
    rules=$(cmd auditctl -l 2>&1) || { printf '%s\n' "$rules" >&2; return 2; }
    printf 'AUDIT_RULES_SHA256='
    printf '%s\n' "$rules" | sha256sum | awk '{print $1}'
    if [[ -r /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined ]]; then
        printf 'APPARMOR_SYSCTL=%s\n' "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined)"
    else printf 'APPARMOR_SYSCTL=absent\n'; fi
    target_versions
}

boot_evidence() {
    local f rc
    printf 'HOST=%s\nTIME=%s\nBOOT_ID=%s\n' "$(hostname)" "$(date --iso-8601=seconds)" "$(cat /proc/sys/kernel/random/boot_id)"
    printf 'CMDLINE=%s\n' "$(cat /proc/cmdline)"
    for f in /etc/default/grub /etc/default/grub.d/*.cfg /boot/grub/grub.cfg; do
        [[ -f $f ]] || continue
        printf '\n[%s]\n' "$f"
        grep -En '^[[:space:]]*((export[[:space:]]+)?GRUB_CMDLINE_LINUX|linux(efi|16)?[[:space:]])' "$f"
        rc=$?
        (( rc <= 1 )) || return 2
    done
    check_apparmor_enabled
    rc=$?
    printf '\nAPPARMOR_CHECK_RC=%s\n' "$rc"
    return "$rc"
}

run_evidence() {
    target_check
    WORK=$(mktemp -d /tmp/cis-bash.XXXXXXXXXX) || die 'mktemp'
    trap cleanup EXIT
    if [[ -n $REPORT ]]; then
        (set -o noclobber; : > "$REPORT") || die 'Не удалось создать отчёт'
        exec > "$REPORT"
    fi
    case $MODE in snapshot) snapshot;; boot) boot_evidence;; esac
}

run_local() {
    target_check
    WORK=$(mktemp -d /tmp/cis-bash.XXXXXXXXXX) || die 'mktemp'
    trap cleanup EXIT
    trap 'exit 2' HUP INT TERM
    [[ ! -e $REPORT && ! -L $REPORT ]] || die "Отчёт уже существует: $REPORT"
    (set -o noclobber; : > "$REPORT") || die 'Не удалось создать отчёт'
    chmod 600 "$REPORT" || die 'chmod отчёта'
    {
        printf 'АУДИТ CIS Debian Linux 13 Benchmark v1.1.0\n'
        printf 'Хост: %s\nВремя: %s\nВерсия скрипта: %s\n' "$(hostname)" "$(date --iso-8601=seconds)" "$VERSION"
        printf 'Состав проверок по коммиту: %s\nSHA256 скрипта: %s\n' "$REPO" "$(sha256sum "$SCRIPT" | awk '{print $1}')"
        printf 'Это 20 выбранных правил, не полный CIS Benchmark. Номера страниц печатные.\n'
        printf 'true = PASS. false = FAIL (нарушение), REVIEW (не доказано), ERROR (сбой).\n'
        printf 'Конфигурация не изменяется. SSH: состояние на диске; auditd: диск и ядро.\n'
        printf 'Актуальность PAM: локальный кэш APT. Настройки inventory автоматически не читаются.\n'
        printf 'Версии на проверяемом хосте:\n'
        target_versions
    } >> "$REPORT" || die 'Не удалось записать заголовок'
    perform 1.3.1.1 'Установлены apparmor и apparmor-utils' 161 check_packages apparmor apparmor-utils
    perform 1.3.1.2 'AppArmor включён, служба активна, профили загружены' 163 check_apparmor_enabled
    perform 1.3.1.4 'Ограничение непривилегированного unconfined AppArmor: 1' 169 check_apparmor_sysctl
    perform 5.1.1 'Права файлов конфигурации SSH: root:root, 0600 или строже' 558 check_ssh_permissions file
    perform 5.1.2 'Права каталогов SSH Include: root:root, 0700 или строже' 561 check_ssh_permissions dir
    perform 5.1.15 'LoginGraceTime: 1–60 секунд' 595 check_ssh_value logingracetime
    perform 5.1.18 'MaxAuthTries: не более 4' 602 check_ssh_value maxauthtries
    perform 5.1.21 'PermitEmptyPasswords: no' 608 check_ssh_value permitemptypasswords
    perform 5.1.22 'PermitRootLogin: no' 610 check_ssh_value permitrootlogin
    perform 5.2.1 'Установлен sudo или sudo-rs' 618 check_sudo_installed
    perform 5.2.6 'timestamp_timeout явно задан: 0–15 минут' 631 check_sudo_timeout
    perform 5.3.1.1 'Установлена актуальная версия libpam-runtime' 636 check_pam_latest
    perform 5.3.2.1 'pam_unix присутствует в пяти common-стеках' 645 check_pam enabled
    perform 5.3.3.4.1 'В активных строках pam_unix отсутствует nullok' 702 check_pam nullok
    perform 6.2.1.1 'Установлены auditd и audispd-plugins' 816 check_packages auditd audispd-plugins
    perform 6.2.1.2 'Служба auditd включена и активна' 818 service_state auditd.service
    perform 6.2.3.1 'Аудит изменений sudoers и sudoers.d' 838 check_audit_rules path /etc/sudoers dir /etc/sudoers.d
    perform 6.2.3.12 'Аудит изменений /etc/group' 871 check_audit_rules path /etc/group
    perform 6.2.3.13 'Аудит изменений /etc/passwd' 874 check_audit_rules path /etc/passwd
    perform 6.2.3.14 'Аудит изменений /etc/shadow и /etc/gshadow' 877 check_audit_rules path /etc/shadow path /etc/gshadow
    printf '\nИТОГО: %d; true: %d; false: %d; FAIL: %d; REVIEW: %d; ERROR: %d\n' "$TOTAL" "$PASSED" "$((TOTAL-PASSED))" "$FAILED" "$REVIEWS" "$ERRORS" | tee -a "$REPORT" || die 'Ошибка записи итога'
    printf 'Отчёт: %s\n' "$REPORT"
    (( PASSED == TOTAL ))
}

remote_run() {
    need ssh || die 'Нужен SSH-клиент'
    need scp || die 'Нужен scp'
    local host_pattern='^[][a-zA-Z0-9_.@:-]+$'
    [[ $REMOTE != -* && $REMOTE =~ $host_pattern ]] || die 'Некорректный SSH host'
    [[ ! -e $REPORT && ! -L $REPORT ]] || die "Отчёт уже существует: $REPORT"
    [[ -d $(dirname -- "$REPORT") ]] || die 'Каталог отчёта не существует'
    local -a ssh_args=(-p "$PORT") scp_args=(-P "$PORT") inner=()
    [[ -z $IDENTITY ]] || { ssh_args+=(-i "$IDENTITY"); scp_args+=(-i "$IDENTITY"); }
    local ids uid gid remote_dir remote_script remote_report command body rc q c
    ids=$(ssh "${ssh_args[@]}" "$REMOTE" 'id -u; id -g') || die 'Не удалось подключиться'
    read -r uid gid <<< "${ids//$'\n'/ }"
    [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]] || die 'Некорректный uid/gid'
    remote_dir=$(ssh "${ssh_args[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/cis-audit.XXXXXXXXXX') || die 'Не создан удалённый каталог'
    [[ $remote_dir =~ ^/tmp/cis-audit\.[a-zA-Z0-9]{10}$ ]] || die 'Неожиданный путь временного каталога'
    remote_script=$remote_dir/audit.sh remote_report=$remote_dir/report.txt
    scp "${scp_args[@]}" -- "$SCRIPT" "$REMOTE:$remote_script" || die "Загрузка не удалась; временные файлы: $remote_dir"
    inner=(bash "$remote_script" --output "$remote_report")
    for c in "${CONTEXTS[@]}"; do inner+=(--ssh-context "$c"); done
    printf -v command '%q ' "${inner[@]}"
    body="$command; rc=\$?; if [ \"\$rc\" -eq 0 ] || [ \"\$rc\" -eq 1 ]; then chown $uid:$gid '$remote_report' || exit 2; fi; exit \"\$rc\""
    # Quote for the remote login shell using POSIX single quotes (no eval locally).
    q=${body//\'/\'\\\'\'}
    command="bash -c '$q'"
    [[ $uid == 0 ]] || command="sudo -- $command"
    ssh -t "${ssh_args[@]}" "$REMOTE" "$command"; rc=$?
    (( rc == 0 || rc == 1 )) || die "Удалённый аудит не завершён (rc=$rc); файлы сохранены: $remote_dir"
    WORK=$(mktemp -d /tmp/cis-download.XXXXXXXXXX) || die 'mktemp'
    trap cleanup EXIT
    scp "${scp_args[@]}" -- "$REMOTE:$remote_report" "$WORK/report.txt" || die "Скачивание не удалось; отчёт остался: $remote_report"
    grep -q '^ИТОГО: 20;' "$WORK/report.txt" || die "Получен неполный отчёт; исходный файл: $remote_report"
    (set -o noclobber; cat "$WORK/report.txt" > "$REPORT") || die "Не удалось сохранить локальный отчёт; удалённый: $remote_report"
    chmod 600 "$REPORT" || die 'chmod'
    ssh "${ssh_args[@]}" "$REMOTE" "rm -f -- '$remote_script' '$remote_report' && rmdir -- '$remote_dir'" || printf 'Отчёт скачан; удалите временный каталог вручную: %s\n' "$remote_dir" >&2
    printf 'Отчёт скачан: %s\n' "$REPORT"
    return "$rc"
}
main() {
    (( BASH_VERSINFO[0] >= 5 )) || die 'Нужен Bash 5+'
    while (( $# )); do
        case $1 in
            --help|-h) usage; return 0;;
            --snapshot|--boot-evidence)
                [[ $MODE == audit ]] || die 'Выберите один режим'
                case $1 in --snapshot) MODE=snapshot;; *) MODE=boot;; esac
                shift;;
            --output|--ssh|--port|--identity|--ssh-context)
                (( $# >= 2 )) && [[ -n $2 ]] || die "Нет значения для $1"
                case $1 in
                    --output)REPORT=$2;; --ssh)REMOTE=$2;; --port)PORT=$2;;
                    --identity)IDENTITY=$2;; --ssh-context)CONTEXTS+=("$2");;
                esac; shift 2;;
            *)die "Неизвестный аргумент: $1";;
        esac
    done
    [[ $PORT =~ ^[0-9]{1,5}$ ]] && (( 10#$PORT >= 1 && 10#$PORT <= 65535 )) || die 'Некорректный порт'
    if [[ $MODE != audit ]]; then
        [[ -z $REMOTE && -z $IDENTITY && $PORT == 22 && ${#CONTEXTS[@]} == 0 ]] || die 'Режим снимков запускается локально'
        run_evidence
        return $?
    fi
    [[ -n $REPORT ]] || REPORT="cis-debian13-$(date +%Y%m%d-%H%M%S)-$$.txt"
    [[ $REPORT == /* ]] || REPORT=$PWD/$REPORT
    if [[ -n $REMOTE ]]; then remote_run
    else
        [[ -z $IDENTITY && $PORT == 22 ]] || die '--port/--identity требуют --ssh'
        run_local
    fi
}
# A test harness may source functions; normal execution always invokes main.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; exit $?; fi
