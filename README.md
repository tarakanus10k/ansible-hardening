# Харденинг OS Linux с помощью ansible

- `ansible-hardening/`
  - `ansible.cfg`
  - `inventory/`
    - `hosts.yml`
    - `host_vars/debian-srv/`
      - `vars.yml`
      - `vault.yml`
  - `playbooks/`
    - `site.yml`
  - `roles/`
    - [`ssh/`](roles/ssh/)
    - [`pam/`](roles/pam/)
    - [`sudo/`](roles/sudo/)
  - `tests and audit/`
    - [`Аудит до харденинга`](tests%20and%20audit/audit%20before%20hardening.md)
    - [`Аудит после харденинга`](tests%20and%20audit/audit%20after%20hardening.md)
    - [`Первый запуск плейбука`](tests%20and%20audit/playbookrun01.log)
    - [`Второй запуск плейбука`](tests%20and%20audit/playbookrun02.log)

## Подготовка и запуск

**Управляющие узел (WSL):**
```bash
# SSH
sudo apt install openssh-client
ssh-keygen -t ed25519 -C "ansible-control" -f ~/.ssh/ed25519_ansible_key
ssh-copy-id -i ~/.ssh/ed25519_ansible_key.pub srvadmin@"your_ip_addr"
ssh -i ~/.ssh/ed25519_ansible_key srvadmin@"your_ip_addr" # тестовое подключение

# ANSIBLE
sudo apt install pipx
pipx ensurepath
pipx install --include-deps ansible
```

```bash
# проверка подключения
ansible -i inventory/hosts.yml linux_debian_13 -m ansible.builtin.ping --ask-vault-pass

# первый запуск
ansible-playbook -i inventory/hosts.yml playbooks/site.yml --diff --ask-vault-pass | tee "tests and audit/playbookrun01.log"

# повторный запуск для проверки идемпотентности
ansible-playbook -i inventory/hosts.yml playbooks/site.yml --diff --ask-vault-pass | tee "tests and audit/playbookrun02.log"
```