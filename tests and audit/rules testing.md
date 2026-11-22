# Тестирование
## SUDO
### 5.2.7 Ensure access to the su command is restricted
![Попытка использования su для переключения на другого пользователя](screenshots/su_command.png)

![Проверка на время использования sudo, без ввода пароля](screenshots/timestamp_timeout.png)

## PAM
### 5.3.3.1.1 Ensure password failed attempts lockout is configured + 5.3.3.1.2 Ensure password unlock time is configured
![Попытка входа от другого пользователя, вводя неверный пароль](screenshots/pam_faillock01.png)

![Список заблокированных пользователей](screenshots/pam_faillock02.png)

## SSH

![Попытка входа через ssh, вводя неверный пароль](screenshots/ssh_connection.png)