# Роль `pam`

Роль включает модуль `pam_faillock` и настраивает блокировку учётной записи после неудачных попыток входа в соответствии с CIS Debian 13 Benchmark v1.1.0.

## Файловая структура

```text
roles/pam/
├── defaults/
│   └── main.yml
├── handlers/
│   └── main.yml
├── tasks/
│   ├── main.yml
│   └── pam.yml
└── templates/
    ├── faillock.j2
    └── faillock_notify.j2
```

## Выполняемые правила

| Правило CIS | Переменная | Что делает роль |
|---|---|---|
| 5.3.2.2 Ensure `pam_faillock` module is enabled | `deb13cis_rule_5_3_2_2` | Создаёт профили `/usr/share/pam-configs/faillock` и `/usr/share/pam-configs/faillock_notify`, после чего обработчики включают их командой `pam-auth-update --force --enable`. |
| 5.3.3.1.1 Ensure password failed attempts lockout is configured | `deb13cis_rule_5_3_3_1_1` | Удаляет параметр `deny=` из PAM-профилей и задаёт в `/etc/security/faillock.conf` значение `deny = 3`. |
| 5.3.3.1.2 Ensure password unlock time is configured | `deb13cis_rule_5_3_3_1_2` | Удаляет параметр `unlock_time=` из PAM-профилей и задаёт в `/etc/security/faillock.conf` значение `unlock_time = 900`. |
