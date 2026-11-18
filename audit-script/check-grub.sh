#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
if (( $# != 4 )); then
    echo 'Usage: bash tests/check-grub.sh before.txt pending.txt rebooted.txt ansible.log' >&2
    exit 2
fi
before=$1 pending=$2 rebooted=$3 log=$4
fail() { printf 'GRUB FAIL | %s\n' "$*" >&2; exit 1; }
field() {
    awk -v key="$2" 'index($0,key "=")==1 {print substr($0,length(key)+2); exit}' "$1"
}
linux_entries() {
    awk -v strip="$2" '
      /^\[\/boot\/grub\/grub\.cfg\]$/ {in_grub=1; next}
      /^\[/ {in_grub=0}
      in_grub && /^[0-9]+:[[:space:]]*linux(efi|16)?[[:space:]]/ {
          sub(/^[0-9]+:/,"")
          sep=""
          for(i=1;i<=NF;i++)if(!strip || $i!="apparmor=0"){printf "%s%s",sep,$i; sep=" "}
          print ""
      }' "$1"
}
for f in "$@"; do [[ -s $f ]] || fail "Missing capture: $f"; done
boot_before=$(field "$before" BOOT_ID)
boot_pending=$(field "$pending" BOOT_ID)
boot_after=$(field "$rebooted" BOOT_ID)
[[ -n $boot_before && $boot_before == "$boot_pending" && -n $boot_after && $boot_before != "$boot_after" ]] ||
    fail 'Expected the same boot ID before the reboot and a new boot ID afterward.'
host=$(field "$before" HOST)
[[ -n $host && $host == "$(field "$pending" HOST)" && $host == "$(field "$rebooted" HOST)" ]] ||
    fail 'Captures identify different hosts.'
off_pattern='(^|[[:space:]])apparmor=0([[:space:]]|$)'
[[ $(field "$before" CMDLINE) =~ $off_pattern && $(field "$pending" CMDLINE) =~ $off_pattern ]] ||
    fail 'The initial kernel was not booted with apparmor=0.'
initial=$(linux_entries "$before" 0)
expected=$(linux_entries "$before" 1)
generated=$(linux_entries "$pending" 0)
[[ -n $initial && $initial =~ $off_pattern && -n $generated && $generated == "$expected" ]] ||
    fail 'Generated GRUB entries differ by more than removal of apparmor=0, or input evidence is incomplete.'
if ! awk '
    /^RUNNING HANDLER \[apparmor : Update-grub\]/ {h=1; next}
    /^[^[:space:]]/ && !/^changed: / {h=0}
    h && /^changed: / {done=1}
    END {exit !done}
' "$log"; then fail 'No successful Update-grub handler in the Ansible log.'; fi
actual=$(field "$rebooted" CMDLINE)
[[ -n $actual && ! $actual =~ $off_pattern && $(field "$rebooted" APPARMOR_CHECK_RC) == 0 ]] ||
    fail 'AppArmor is not verified after the reboot.'
normalize_cmdline() {
    awk '{sep=""; for(i=1;i<=NF;i++)if($i!="apparmor=0"){printf "%s%s",sep,$i; sep=" "}}'
}
[[ $(normalize_cmdline <<< "$(field "$before" CMDLINE)") == "$(normalize_cmdline <<< "$actual")" ]] ||
    fail 'Other arguments of the running kernel changed.'
printf 'GRUB PASS | handler ran, other generated arguments stayed equal, new kernel booted with AppArmor.\n'
