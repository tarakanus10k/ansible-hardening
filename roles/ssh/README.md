# Роль `ssh`

Роль настраивает SSH-сервер и права доступа к его конфигурации в соответствии с CIS Debian 13 Benchmark v1.1.0.

## Файловая структура

```text
roles/ssh/
├── defaults/
│   └── main.yml
├── handlers/
│   └── main.yml
├── tasks/
│   ├── main.yml
│   └── ssh.yml
└── templates/
    └── 10-ssh-hardening.conf.j2
```

## Выполняемые правила

| Правило CIS | Переменная | Что делает роль |
|---|---|---|
| 5.1.1 Ensure access to `/etc/ssh/sshd_config` is configured | `deb13cis_rule_5_1_1` | Устанавливает владельца `root:root` и права `0600` на `/etc/ssh/sshd_config`. |
| 5.1.2 Ensure access to `/etc/ssh/sshd_config.d/` directory is configured | `deb13cis_rule_5_1_2` | Устанавливает права `0700` на каталог `/etc/ssh/sshd_config.d/` и `0600` на находящиеся в нём файлы. Владелец — `root:root`. |
| 5.1.15 Ensure sshd `LoginGraceTime` is configured | `deb13cis_rule_5_1_15` | Создаёт `/etc/ssh/sshd_config.d/10-ssh-hardening.conf` с параметром `LoginGraceTime 60`. |
| 5.1.18 Ensure sshd `MaxAuthTries` is configured | `deb13cis_rule_5_1_18` | Добавляет в drop-in файл параметр `MaxAuthTries 3`. CIS допускает значение не больше 4. |
| 5.1.22 Ensure sshd `PermitRootLogin` is disabled | `deb13cis_rule_5_1_22` | Добавляет в drop-in файл параметр `PermitRootLogin no`. |
