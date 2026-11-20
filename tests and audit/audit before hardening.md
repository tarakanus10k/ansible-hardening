# Аудит до харденинга
## SSH
**Скриншот вводимых команд:**
![[Снимок экрана 2026-11-20 195234.png]]
### 5.1.1 Ensure access to /etc/ssh/sshd_config is configured
**Команда:** `stat -Lc 'File: "%n" Mode: "%#a" Owner: "%U" Group: "%G"' /etc/ssh/sshd_config`
**Ожидаемый вывод:** `File: "/etc/ssh/sshd_config" Mode: "0600"  Owner: "root" Group: "root"`
**Вывод:** `File: "/etc/ssh/sshd_config" Mode: "0644"  Owner: "root" Group: "root"`
### 5.1.2 Ensure access to /etc/ssh/sshd_config.d/ directory is configured
**Команда:** ` find /etc/ssh/sshd_config.d/ -maxdepth 0 \( ! -user root -o ! -group root -o -perm /077 \)`
**Ожидаемый вывод:** ``
**Вывод:** `/etc/ssh/sshd_config.d/`
**Команда:** `sshd -T 2>/dev/null | awk '$1 == "include" {print $2}'`
**Ожидаемый вывод:** `пути до drop-in файлов | empty`
**Вывод:** ``
### 5.1.15 Ensure sshd LoginGraceTime is configured
**Команда:** `sshd -T | grep logingracetime`
**Ожидаемый вывод:** `logingracetime 60`
**Вывод:** `logingracetime 120`
### 5.1.18 Ensure sshd MaxAuthTries is configured
**Команда:** `sshd -T | grep maxauthtries`
**Ожидаемый вывод:** `maxauthtries 4`
**Вывод:** `maxauthtries 6`
### 5.1.21 Ensure sshd PermitEmptyPasswords is disabled
**Команда:** `sshd -T | grep permitemptypasswords`
**Ожидаемый вывод:** `permitemptypasswords no`
**Вывод:** `permitemptypasswords no`
### 5.1.22 Ensure sshd PermitRootLogin is disabled
**Команда:** `sshd -T | grep permitrootlogin`
**Ожидаемый вывод:** `permitrootlogin no`
**Вывод:** `permitrootlogin without-password`

## PAM
**Скриншот вводимых команд:**
![[image_2026-11-20_23-50-26.png]]
### 5.3.1.1 Ensure latest version of pam is installed
**Команда:** `dpkg-query -s libpam-runtime &>/dev/null && echo "libpam-runtime is installed"`
**Ожидаемый вывод:** `libpam-runtime is installed`
**Вывод:** `libpam-runtime is installed`
**Команда:** `apt list --upgradable 2>&1 | grep -P '^libpam-runtime\b'`
**Ожидаемый вывод:** ``
**Вывод:** ``
### 5.3.2.2 Ensure pam_faillock module is enabled
**Команда:** `grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account}`
**Ожидаемый вывод:**
```
/etc/pam.d/common-auth:auth     requisite                       
pam_faillock.so preauth 
/etc/pam.d/common-auth:auth     [default=die]                   
pam_faillock.so authfail 
/etc/pam.d/common-account:account       required                        
pam_faillock.so
```
**Вывод:** ``
### 5.3.3.1.1 Ensure password failed attempts lockout is configured
**Команда:** `grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf`
**Ожидаемый вывод:** `deny = [1-5]`
**Вывод:** ``
**Команда:** `grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth`
**Ожидаемый вывод:** ``
**Вывод:** ``
### 5.3.3.1.2 Ensure password unlock time is configured
**Команда:** `grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf`
**Ожидаемый вывод:** `unlock_time = 900`
**Вывод:** ``
**Команда:** `grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' /etc/pam.d/common-auth`
**Ожидаемый вывод:** ``
**Вывод:** ``

## SUDO
**Скриншот вводимых команд:**
![[Снимок экрана 2026-11-20 195449.png]]
### 5.2.1 Ensure sudo is installed
**Команда:** `dpkg-query -W -f='${db:Status-Status} ${Package}\n' sudo-rs sudo 2>/dev/null | awk '$1=="installed"{print $2}'`
**Ожидаемый вывод:** `sudo | sudo-rs`
**Вывод:** `sudo`
### 5.2.6 Ensure sudo timestamp_timeout is configured
**Команда:** `grep -rPsi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-09]+' \ /etc/sudoers /etc/sudoers.d/ 2>/dev/null`
**Ожидаемый вывод:** `/etc/sudoers:Defaults env_reset, timestamp_timeout=15`
**Вывод:** ``
### 5.2.7 Ensure access to the su command is restricted
**Команда:** `grep -Pi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)(?=.*\bgroup=\S+).*' /etc/pam.d/su`
**Ожидаемый вывод:** `auth required pam_wheel.so use_uid group=<group_name>`
**Вывод:** ``
**Команда:** `grep "^<group_name>:" /etc/group`
**Ожидаемый вывод:** `<group_name>:x:<GID>:`
**Вывод:** ``

## Итог
**SSH - 1 pass, 5 failed**
**PAM - 1 pass, 3 failed**
**SUDO - 1 pass, 2 failed**