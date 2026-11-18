# Харденинг OS Linux с помощью ansible

### Подготовка стендов

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

# импорт плейбука (аудит)
https://github.com/ansible-lockdown/DEBIAN13-CIS.git
```

#### 2. Машина №2 (vmware: debian13)
пользователи:
- root: пароль отсутствует
- srvadmin: пользователь, созданный при установке системы

#### 3. Тесты
```bash
# перед запуском
eval $(ssh-agent) && ssh-add ~/.ssh/ed25519_ansible_key

# АУДИТ (до)
scp -i ~/.ssh/ed25519_ansible_key ./audit-script/audit.sh srvadmin@192.168.100.10:~/
chmod +x ~/audit.sh
sudo bash ./audit.sh before-hardening.sh

# Запуск плейбука (харденинг)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee ~/ansible-hardening/tests/ansible-run01.log

# АУДИТ (после)
sudo bash ./audit.sh after-hardening.sh
  
# Запуск плейбука (проверка на идемпотентность)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee ~/ansible-hardening/tests/ansible-run02.log
```