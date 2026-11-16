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
cd ./ansible-hardening
ansible-vault create ./inventory/host_vars/debian-srv/vault.yml # шифрованный файл для секретных переменных
eval $(ssh-agent) && ssh-add ~/.ssh/ed25519_ansible_key
```
openscap:
```bash
# установка
sudo apt install openscap-scanner ssg-base ssg-debderived ssg-debian
export SSH_ADDITIONAL_OPTIONS="-o StrictHostKeyChecking=accept-new"
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
# Проверка удаленного хоста с помощью openscap (до харденинга)
oscap-ssh --sudo srvadmin@192.168.100.10 22 xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results before.xml --report before.html \
  /usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml

# Запуск плейбука
ansible-playbook playbooks/site.yml --diff --ask-vault-pass | tee ~/ansible-hardening/run-results.lo

# Проверка удаленного хоста с помощью openscap (после харденинга)
oscap-ssh --sudo srvadmin@192.168.100.10 22 xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results after.xml --report after.html \
  /usr/share/xml/scap/ssg/content/ssg-debian13-ds.xml
```