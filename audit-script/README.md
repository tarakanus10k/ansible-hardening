Результаты:
- `report.html`: автономный HTML, фильтры true/false, причины и номера страниц;
- `report.json`: настоящие JSON boolean в поле result, статус и доказательства;
- stdout: номер правила, true/false и статус (TSV).

Коды завершения: 0 — все 20 true; 1 — хотя бы один false; 2 — ошибка запуска.
Код 1 — нормальный результат аудита, а не отсутствие отчёта.

## Удалённый запуск по SSH с автоматическим скачиванием

Запускайте на исходной машине (Linux/macOS с Bash, Python 3, OpenSSH ssh/scp),
без локального sudo:

```bash
bash audit-cis-debian13.sh --remote USER@HOST --output-dir ./audit-after
```

Можно использовать alias из ~/.ssh/config:

```bash
bash audit-cis-debian13.sh --remote debian-srv --output-dir ./audit-before
```

Нестандартный порт и отдельный ключ:

```bash
bash audit-cis-debian13.sh --remote USER@HOST --port 2222 \
  --identity ~/.ssh/id_ed25519 --output-dir ./audit-after
```