# Тестирование
## SUDO
### 5.2.7 Ensure access to the su command is restricted
![Попытка использования su для переключения на другого пользователя](screenshots/su_command.png)

### 5.2.6 Ensure sudo timestamp_timeout is configured
![Проверка на время использования sudo, без ввода пароля](screenshots/timestamp_timeout.png)

## PAM
### 5.3.3.1.1 Ensure password failed attempts lockout is configured + 5.3.3.1.2 Ensure password unlock time is configured
![Попытка входа от другого пользователя, вводя неверный пароль](screenshots/pam-test-before01.png)

![Список заблокированных пользователей](screenshots/pam-test-before02.png)

![Попытка входа от другого пользователя, спустя 15 минут](screenshots/pam-test-after01.png)

![Список заблокированных пользователей, спустя 15 минут](screenshots/pam-test-after02.png)

## SSH
### 5.1.18 Ensure sshd MaxAuthTries is configured
![Попытка входа через ssh, вводя неверный пароль](screenshots/ssh_connection.png)