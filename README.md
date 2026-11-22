# Харденинг OS Linux с помощью ansible

#### 1. Машина №1 (wsl: debian13)
ssh:
```bash
# установка
sudo apt install openssh-server

# создание ключей
ssh-keygen -t ed25519 -C "ansible-control"
ssh-copy-id -i ~/.ssh/ed25519_ansible_key.pub srvadmin@192.168.100.10
ssh -i ~/.ssh/ed25519_ansible_key srvadmin@192.168.100.10 # проверка подключения
```
ansible:
```bash
# установка pipx
sudo apt install pipx
pipx ensurepath

# установка ansible
pipx install --include-deps ansible

# импорт плейбука
sudo apt install git # установка git
git clone https://github.com/tarakanus10k/ansible-hardening.git
ansible-vault create .ansible-hardening/inventory/host_vars/debian-srv/vault.yml
```

#### 2. Машина №2 (vmware: debian13)
пользователи:
- root
- srvadmin

#### 3. Тесты
```bash
# перед запуском
eval $(ssh-agent) && ssh-add ~/.ssh/ed25519_ansible_key

# Запуск плейбука (харденинг)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee "tests and audit/playbookrun01.log"
  
# Запуск плейбука (проверка на идемпотентность)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee "tests and audit/playbookrun02.log"
```

### 4. Результаты
- [Аудит до харденинга](tests%20and%20audit/audit%20before%20hardening.md)
- [Аудит после харденинга](tests%20and%20audit/audit%20after%20hardening.md)

- [Первый запуск плейбука](tests%20and%20audit/playbookrun01.log)
- [Второй запуск плейбука](tests%20and%20audit/playbookrun02.log)