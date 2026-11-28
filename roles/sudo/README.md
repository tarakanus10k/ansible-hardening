# Роль `sudo`

Роль настраивает тайм-аут повторной аутентификации `sudo` и ограничивает доступ к команде `su` в соответствии с CIS Debian 13 Benchmark v1.1.0.

## Файловая структура

```text
roles/sudo/
├── defaults/
│   └── main.yml
├── tasks/
│   ├── main.yml
│   └── sudo.yml
```

## Выполняемые правила

| Правило CIS | Переменная | Что делает роль |
|---|---|---|
| 5.2.6 Ensure sudo `timestamp_timeout` is configured | `deb13cis_rule_5_2_6` | Ищет `timestamp_timeout` в `/etc/sudoers` и `/etc/sudoers.d/*`. Если параметр отсутствует, добавляет `Defaults timestamp_timeout=5`; найденные значения заменяет на `5`. Изменения проверяются через `visudo -cf`. |
| 5.2.7 Ensure access to the `su` command is restricted | `deb13cis_rule_5_2_7` | Создаёт группу `sugroup`, очищает список её участников и добавляет в `/etc/pam.d/su` правило `auth required pam_wheel.so use_uid group=sugroup`. |
