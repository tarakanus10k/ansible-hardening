# Харденинг OS Linux с помощью ansible

Linux широко распространен в серверной инфраструктуре и каждая машина нуждается в настройке. Ручная конфигурация может привести к уязвимостям системы, а при большом парке машин ручная настройка может занять огромные ресурсы. Для автоматизации данной задачи используют инструмент ansible.

Ansible - это инструмент автоматизации управления конфигурациями от Red Hat. Он позволяет автоматизировать удаленные задачи, обеспечивать надежную защиту OS сервера, значительно снижая поверхность для атак. При этом достигается высокая эффективность, скорость и надежность, а также минимизируются трудозатраты и риск человеческих ошибок.

Ansible использует простые, понятные человеку скрипты, называемые плейбуками, для автоматизации ваших задач. В плейбуке указывается желаемое состояние локальной или удаленной системы. Ansible гарантирует, что система останется в этом состоянии.

Для харденинга OS Linux будет использоваться связка Ansible и CIS Benchmarks.

CIS Benchmarks - это международно признанные стандарты и пошаговые руководства по безопасной настройки программного обеспечения, операционных систем, облачных платформ и сетевого оборудования. Назначением является закрыть уязвимости и минимизировать "поверхность атаки".

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
ansible-vault create ./inventory/group_vars/linux_debian_13/vault.yml # шифрованный файл для секретных переменных

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