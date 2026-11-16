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
openscap:
```bash
# установка
sudo apt install openscap-scanner ssg-base ssg-debderived ssg-debian
```

#### 2. Машина №2 (vmware: debian13)
пользователи:
- root: пароль отсутствует
- srvadmin: пользователь, созданный при установке системы
openscap:
```bash
# установка
sudo apt install openscap-scanner
```

#### 3. Тесты
```bash
# перед запуском
export SSH_ADDITIONAL_OPTIONS="-o StrictHostKeyChecking=accept-new"
eval $(ssh-agent) && ssh-add ~/.ssh/ed25519_ansible_key

# АУДИТ (до)
# OPENSCAP
oscap-ssh --sudo srvadmin@192.168.100.10 22 xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
  --results openscap-before.xml --report openscap-before.html \
  /usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml

# Запуск плейбука (харденинг)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee ~/ansible-hardening/tests/ansible-run01.log

# АУДИТ (после)
# OPENSCAP
oscap-ssh --sudo srvadmin@192.168.100.10 22 xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level2_server \
  --results openscap-after.xml --report openscap-after.html \
  /usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml
  
# Запуск плейбука (проверка на идемпотентность)
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee ~/ansible-hardening/tests/ansible-run02.log
```