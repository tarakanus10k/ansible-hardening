# Создание плейбука
**Плейбуки** - это шаблоны автоматизации в `YAML`формате, который Ansible использует для развертывания и настройки управляемых узлов.

Файловая структура:
```
playbooks/
├-- site.yml
```

`site.yml` - является точкой входа, откуда будет запускаться весь проект
```yml
---
- name: Linux Debian 13 hardening
  hosts: all
  become: true
  
  roles:
    - ssh-hardening
    - pam-hardening
    - auditd-hardening
```
Описание параметров:
- `hosts` - для каких хостов применятся изменения (`all` - для всех хостов);
- `become` - использовать ли повышение привилегий;
- `roles` - список ролей, которые нужно применить на хосте.

Список ролей:
- [`ssh-hardening`](roles/ssh-hardening/README) - содержит таски для харденинга ssh сервиса;
- [`pam-hardening`](roles/pam-hardening/README) - содержит таски для харденинга pam сервиса;
- [`auditd-hardening`](roles/auditd-hardening/README) - содержит таски для харденинга audit сервиса.