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

# 5.1.21 Ensure sshd PermitEmptyPasswords is disabled
sshd -T | grep permitemptypasswords

sshd -T -C user=sshuser | grep permitemptypasswords

# 5.1.22 Ensure sshd PermitRootLogin is disabled
sshd -T | grep permitrootlogin

sshd -T -C user=sshuser | grep permitrootlogin

# 5.2.1 Ensure sudo is installed
dpkg-query -W -f='${db:Status-Status} ${Package}\n' sudo-rs sudo 2>/dev/null | awk '$1=="installed"{print $2}'

# 5.2.6 Ensure sudo timestamp_timeout is configured
grep -rPsi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?timestamp_timeout\h*=\h*[-0 9]+' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# 5.2.7 Ensure access to the su command is restricted
grep -Pi '^\s*auth\s+(?:required|requisite)\s+pam_wheel\.so(?=.*\buse_uid\b)( =.*\bgro up=\S+).*' /etc/pam.d/su

# 5.3.1.1 Ensure latest version of pam is installed
dpkg-query -s libpam-runtime &>/dev/null && echo "libpam-runtime is installed"

apt list --upgradable 2>&1 | grep -P '^libpam-runtime\b'

# 5.3.2.2 Ensure pam_faillock module is enabled
grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/common-{auth,account}

# 5.3.3.1.1 Ensure password failed attempts lockout is configured
grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf

grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h ([^#\n\r]+\h +)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/common-auth

# 5.3.3.1.2 Ensure password unlock time is configured
grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf

grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h ([^#\n\r]+\h +)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' /etc/pam.d/common-auth

# 6.2.1.1 Ensure auditd packages are installed
dpkg-query -s auditd &>/dev/null && echo auditd is installed

dpkg-query -s audispd-plugins &>/dev/null && echo audispd-plugins is installed

# 6.2.1.2 Ensure auditd service is enabled and active
systemctl is-enabled auditd | grep '^enabled'

systemctl is-active auditd | grep '^active'

# 6.2.3.1 Ensure modification of the /etc/sudoers file is collected
auditctl -l | grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/sudoers'

grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/sudoers' /etc/audit/rules.d/*.rules

# 6.2.3.12 Ensure events that modify /etc/group information are collected
auditctl -l | grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/group'

grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/group' /etc/audit/rules.d/*.rules

# 6.2.3.13 Ensure events that modify /etc/passwd information are collected
auditctl -l | grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/passwd'

grep -Ps -- '^\h*[^#\n\r]+\h*\/etc\/passwd' /etc/audit/rules.d/*.rules

# 6.2.3.14 Ensure events that modify /etc/shadow and /etc/gshadow are collected
auditctl -l | grep -Ps -- '^\h*[^#\n\r]+\h*shadow'

grep -Ps -- 'shadow' /etc/audit/rules.d/*.rules
```