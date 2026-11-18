#!/usr/bin/env bash
# Выполняется Ansible на ВМ. В stdout попадает только проверяемое состояние.
set -euo pipefail
export LC_ALL=C
umask 077
(( EUID == 0 )) || { printf 'Для снимка состояния нужен root.\n' >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

shopt -s nullglob
paths=(
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d
    /etc/pam.d/common-* /usr/share/pam-configs /var/cache/debconf/config.dat
    /etc/sudoers /etc/sudoers.d /etc/nsswitch.conf
    /etc/audit/audit.rules /etc/audit/rules.d /etc/audit/auditd.conf
    /etc/apparmor.d /etc/default/grub /etc/default/grub.d /boot/grub/grub.cfg
    /etc/sysctl.conf /etc/sysctl.d
)
printf 'HOST=%s\n' "$(hostname)"
printf 'BOOT_ID='
cat /proc/sys/kernel/random/boot_id
printf 'CMDLINE='
cat /proc/cmdline

# Пути, типы, права и владельцы. Содержимое файлов остаётся на ВМ.
: > "$work/paths"
for path in "${paths[@]}"; do
    if [[ -e $path || -L $path ]]; then
        find -H "$path" -print0 >> "$work/paths"
    else
        printf 'ABSENT %q\n' "$path"
    fi
done
sort -zu "$work/paths" > "$work/sorted"
while IFS= read -r -d '' path; do
    metadata=$(stat -c '%F mode=%a uid=%u gid=%g' -- "$path")
    printf 'FILE %q %s' "$path" "$metadata"
    if [[ -L $path ]]; then
        target=$(readlink -- "$path")
        printf ' target=%q' "$target"
    fi
    if [[ -f $path ]]; then
        digest=$(sha256sum < "$path")
        printf ' sha256=%s' "${digest%% *}"
    fi
    printf '\n'
done < "$work/sorted"

printf '\nSERVICES\n'
for service in ssh.service auditd.service apparmor.service; do
    # InvocationID меняется при повторном запуске службы, даже если она снова active.
    printf '%s\n' "$service"
    systemctl show -p LoadState -p ActiveState -p SubState -p UnitFileState -p InvocationID -- "$service"
done

printf '\nAPPARMOR_SYSCTL='
sysctl_file=/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
if [[ -e $sysctl_file ]]; then cat "$sysctl_file"; else printf 'absent\n'; fi
printf '\nAPPARMOR_PROFILES\n'
profiles=/sys/kernel/security/apparmor/profiles
if [[ -r $profiles ]]; then sort -- "$profiles"; else printf 'unavailable\n'; fi

printf '\nAUDIT_KERNEL_RULES\n'
auditctl -l
