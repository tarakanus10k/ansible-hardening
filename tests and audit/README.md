# Команды для аудита

```bash
# 5.1.1 Ensure access to /etc/ssh/sshd_config is configured
stat -Lc 'File: "%n" Mode: "%#a" Owner: "%U" Group: "%G"' /etc/ssh/sshd_config

# 5.1.2 Ensure access to /etc/ssh/sshd_config.d/ directory is configured
find /etc/ssh/sshd_config.d/ -maxdepth 0 \( ! -user root -o ! -group root -o -perm /077 \)

sshd -T 2>/dev/null | awk '$1 == "include" {print $2}'

# 5.1.15 Ensure sshd LoginGraceTime is configured
sshd -T | grep logingracetime

# 5.1.18 Ensure sshd MaxAuthTries is configured
sshd -T | grep maxauthtries

# 5.1.22 Ensure sshd PermitRootLogin is disabled
sshd -T | grep permitrootlogin

sshd -T -C user=sshuser | grep permitrootlogin

# 5.2.6 Ensure sudo timestamp_timeout is configured
grep -rPsi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-0 9]+' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# 5.2.7 Ensure access to the su command is restricted
grep -Pi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)( =.*\bgro up=\S+).*' /etc/pam.d/su

# 5.3.2.2 Ensure pam_faillock module is enabled
grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account}

# 5.3.3.1.1 Ensure password failed attempts lockout is configured
grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf

grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth

# 5.3.3.1.2 Ensure password unlock time is configured
grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf

grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' /etc/pam.d/common-auth
```