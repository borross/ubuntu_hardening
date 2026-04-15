# Ubuntu Hardening Script — VPS/VDS Edition

Скрипт автоматизированного харденинга Ubuntu 22.04 / 24.04 для виртуальных серверов.
Запускается от `root` сразу после получения чистого VPS/VDS и проводит полную настройку безопасности в один проход.

---

## Содержание

- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Переменные конфигурации](#переменные-конфигурации)
- [Что делает скрипт](#что-делает-скрипт)
  - [0. Обновление системы](#0-обновление-системы)
  - [1. Имя хоста, FQDN, DNS, часовой пояс, NTP](#1-имя-хоста-fqdn-dns-часовой-пояс-ntp)
  - [2. Генерация SSH-ключа](#2-генерация-ssh-ключа)
  - [3. Создание пользователя admin](#3-создание-пользователя-admin)
  - [4. Настройка SSH](#4-настройка-ssh)
  - [5. Блокировка root](#5-блокировка-root)
  - [6. Брандмауэр UFW](#6-брандмауэр-ufw)
  - [7. Fail2ban](#7-fail2ban)
  - [8. Защита cron](#8-защита-cron)
  - [9. Защита разделов](#9-защита-разделов)
  - [10. Параметры ядра (sysctl)](#10-параметры-ядра-sysctl)
  - [11. Blacklist модулей ядра](#11-blacklist-модулей-ядра)
  - [12. Отключение core dump](#12-отключение-core-dump)
  - [13. Auditd](#13-auditd)
  - [14. AppArmor](#14-apparmor)
  - [15. Настройка sudo](#15-настройка-sudo)
  - [16. Политика паролей](#16-политика-паролей)
  - [17. Права на системные файлы](#17-права-на-системные-файлы)
  - [18. Удаление телеметрии](#18-удаление-телеметрии)
  - [19. Автоматические обновления](#19-автоматические-обновления)
  - [20. Удаление приватного ключа](#20-удаление-приватного-ключа)
- [Подключение после настройки](#подключение-после-настройки)
- [Диагностика и мониторинг](#диагностика-и-мониторинг)
- [Что требует перезагрузки](#что-требует-перезагрузки)
- [Ручное включение форвардинга](#ручное-включение-форвардинга)

---

## Требования

| Параметр | Значение |
|---|---|
| ОС | Ubuntu 22.04 LTS / 24.04 LTS |
| Платформа | VPS / VDS (KVM, XEN, VMware, Hyper-V) |
| Пользователь | `root` |
| Сеть | Доступ в интернет для установки пакетов |
| Доступ | VNC или консоль провайдера на случай потери SSH |

> ⚠️ **Перед запуском убедитесь, что у вас открыта консоль провайдера (VNC/KVM).** Если SSH-сессия оборвётся в процессе, вы сможете продолжить через неё.

---

## Быстрый старт

```bash
# Скачать скрипт на сервер
wget -O ubuntu_hardening.sh https://your-repo/ubuntu_hardening.sh

# Проверить содержимое перед запуском
less ubuntu_hardening.sh

# Запустить
bash ubuntu_hardening.sh
```

Скрипт интерактивный — он будет задавать вопросы на каждом шаге. Всё, что можно пропустить, пропускается нажатием `Enter`.

---

## Переменные конфигурации

Настраиваются в начале файла скрипта:

```bash
ADMIN_USER="admin"          # имя создаваемого пользователя
SSH_PORT="20202"            # нестандартный порт SSH
KEY_PATH="/root/admin_ssh_key"  # путь для сохранения ключевой пары

# Форвардинг — отключён по умолчанию, включайте осознанно
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"
```

---

## Что делает скрипт

### 0. Обновление системы

Выполняет `apt-get upgrade` в неинтерактивном режиме и устанавливает все необходимые пакеты:

```
ufw  fail2ban  auditd  audispd-plugins  libpam-pwquality
unattended-upgrades  apt-listchanges  acl  chrony
```

Также определяет тип гипервизора через `systemd-detect-virt` — это используется для VPS-специфичных решений в дальнейших шагах.

---

### 1. Имя хоста, FQDN, DNS, часовой пояс, NTP

Единственный полностью интерактивный раздел. Все пункты можно пропустить через `Enter`.

#### Имя хоста

```bash
hostnamectl set-hostname <новое_имя>
```

Валидация по RFC 1123: только `a-z`, `0-9` и дефис, не более 63 символов. При смене имени автоматически обновляется `/etc/hosts`, чтобы `sudo` не выдавал `unable to resolve host`.

#### FQDN

```bash
# Записывается в /etc/hosts как:
127.0.1.1    server01.example.com  server01
```

Формат: `hostname.domain.tld`. Благодаря этой записи `hostname --fqdn` работает корректно без реального DNS. Валидируется через regex по RFC 1123.

#### DNS

Показывает текущие DNS-серверы, предлагает ввести основной и резервный (IPv4). Каждый адрес проверяется на корректность.

Популярные варианты:

| Провайдер | Основной | Резервный |
|---|---|---|
| Cloudflare | `1.1.1.1` | `1.0.0.1` |
| Google | `8.8.8.8` | `8.8.4.4` |
| Quad9 | `9.9.9.9` | `149.112.112.112` |
| Yandex | `77.88.8.8` | `77.88.8.1` |

Если активен `systemd-resolved` — настраивается через drop-in файл с DNS-over-TLS (`opportunistic`) и DNSSEC. Иначе пишется напрямую в `/etc/resolv.conf` с защитой `chattr +i`.

#### Часовой пояс

```bash
timedatectl set-timezone Europe/Moscow
```

Значение проверяется через `timedatectl list-timezones` перед применением.

#### NTP через Chrony

Chrony предпочтительнее `systemd-timesyncd` для VPS: быстрее восстанавливается после долгого простоя и точнее работает при нестабильной сети.

```
/etc/chrony/chrony.conf
```

По умолчанию используются пулы `pool.ntp.org` (0–3) и резервный `time.cloudflare.com` с NTS (зашифрованный NTP). Можно указать свои серверы — они вводятся через пробел.

`systemd-timesyncd` отключается, чтобы не конфликтовать с chrony. После запуска выполняется `chronyc makestep` — принудительная мгновенная синхронизация.

---

### 2. Генерация SSH-ключа

```bash
ssh-keygen -t ecdsa -b 521 -f /root/admin_ssh_key -C "admin@hostname-YYYYMMDD"
```

Генерируется ключевая пара ECDSA-521 **с паролем** (скрипт спросит его интерактивно). Содержимое приватного ключа выводится в терминал — скрипт делает паузу и ждёт подтверждения, что ключ скопирован.

| Файл | Права | Назначение |
|---|---|---|
| `/root/admin_ssh_key` | `600` | приватный ключ — скачать и удалить |
| `/root/admin_ssh_key.pub` | `644` | публичный ключ — остаётся на сервере |

> ⚠️ Приватный ключ нужно **скачать немедленно**, пока не завершился скрипт. В конце скрипта он будет предложен к удалению через `shred`.

---

### 3. Создание пользователя admin

```bash
useradd -m -s /bin/bash admin
usermod -aG sudo admin
```

Скрипт корректно обрабатывает ситуацию, когда группа `admin` уже существует (стандартная группа Ubuntu) — в этом случае используется флаг `-g` вместо создания новой группы.

Публичный ключ устанавливается в `~/.ssh/authorized_keys` с правами:

```
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

### 4. Настройка SSH

Файл: `/etc/ssh/sshd_config`

Перед изменением создаётся резервная копия: `/etc/ssh/sshd_config.bak.YYYYMMDDHHMMSS`

#### Ключевые параметры

| Параметр | Значение | Обоснование |
|---|---|---|
| `Port` | `20202` | Нестандартный порт снижает шум от автосканеров |
| `PermitRootLogin` | `no` | Прямой вход root запрещён |
| `PasswordAuthentication` | `no` | Только ключевая аутентификация |
| `LoginGraceTime` | `30` | Исправлен баг: `0` означает без лимита |
| `MaxAuthTries` | `3` | Максимум попыток на соединение |
| `MaxStartups` | `5:30:20` | Защита от медленных атак на handshake |
| `AllowUsers` | `admin` | Только указанный пользователь |
| `ClientAliveInterval` | `300` | Разрыв при 10 мин простоя |
| `LogLevel` | `VERBOSE` | Fingerprint ключа в каждой записи лога |
| `DebianBanner` | `no` | Скрыть версию ОС от сканеров |

#### Криптография (только современные алгоритмы)

```
HostKeyAlgorithms  : ecdsa-sha2-nistp521, ssh-ed25519, rsa-sha2-512/256
KexAlgorithms      : curve25519-sha256, ecdh-sha2-nistp521
Ciphers            : chacha20-poly1305, aes256-gcm, aes128-gcm
MACs               : hmac-sha2-512-etm, hmac-sha2-256-etm
```

После записи конфига выполняется `sshd -t` (проверка синтаксиса) и `ss -tlnp` (подтверждение что порт слушается).

---

### 5. Блокировка root

```bash
passwd -l root          # блокировка пароля root
```

Дополнительно команда `su` ограничивается только членами группы `sudo` через `pam_wheel.so` в `/etc/pam.d/su`.

---

### 6. Брандмауэр UFW

```bash
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
ufw limit 20202/tcp     # встроенный rate-limit: 6 попыток за 30 сек
```

Разрешён только SSH на настроенном порту. Используется `ufw limit` (а не `ufw allow`) — встроенная защита от брутфорса на уровне iptables, которая работает даже до Fail2ban.

> 💡 **VPS-специфика:** многие провайдеры (Hetzner, DigitalOcean, Vultr) предоставляют собственный firewall в панели управления. Рекомендуется продублировать правила и там — это защита в глубину.

---

### 7. Fail2ban

Файл: `/etc/fail2ban/jail.local`

| Параметр | Значение |
|---|---|
| Порт | `20202` (SSH) |
| Максимум попыток | 3 |
| Время бана | 24 часа |
| Backend | `systemd` (journald) |
| Banaction | `ufw` (интеграция с брандмауэром) |

---

### 8. Защита cron

```bash
chown root:root /etc/crontab /etc/cron.*/ /etc/cron.d/
chmod og-rwx    /etc/crontab /etc/cron.*/ /etc/cron.d/
```

Создаётся `/etc/cron.allow` и `/etc/at.allow` содержащие только `root`. Файлы `cron.deny` и `at.deny` удаляются — при наличии обоих файлов `cron.allow` имеет приоритет, но явное удаление `deny` исключает неоднозначность.

---

### 9. Защита разделов

Файл: `/etc/fstab`

| Раздел | Флаги | Назначение |
|---|---|---|
| `/tmp` | `nosuid,nodev,noexec,relatime` | Запрет выполнения скриптов из `/tmp` |
| `/dev/shm` | `nosuid,nodev,noexec` | Защита разделяемой памяти |
| `/var/tmp` | `bind → /tmp` | Наследует все флаги `/tmp` |
| `/home` | `nosuid,nodev,noexec` | Запрет исполнения из домашних каталогов |

Изменения применяются через `mount -o remount` без перезагрузки. Если `/home` не является отдельным разделом (типично для VPS) — создаётся `systemd` unit `remount-home.service`.

> **Примечание:** `seclabel` убрана из опций `/dev/shm` — она работает только с SELinux, а Ubuntu использует AppArmor.

---

### 10. Параметры ядра (sysctl)

Файл: `/etc/sysctl.d/99-hardening.conf`

#### Сетевая безопасность

| Параметр | Значение | Защита от |
|---|---|---|
| `rp_filter` | `1` | IP-спуфинга |
| `ip_forward` | `0` | Использования как роутера |
| `tcp_syncookies` | `1` | SYN-flood |
| `accept_redirects` | `0` | ICMP MITM-атак |
| `send_redirects` | `0` | Перенаправления трафика |
| `icmp_echo_ignore_broadcasts` | `1` | Smurf-атак |
| `log_martians` | `1` | Логирование подозрительных пакетов |
| `accept_ra` | `0` | IPv6 Router Advertisement атак |
| `tcp_rfc1337` | `1` | TIME-WAIT атак |

#### Безопасность ядра

| Параметр | Значение | Описание |
|---|---|---|
| `yama.ptrace_scope` | `1` | ptrace только от родительского процесса |
| `dmesg_restrict` | `1` | dmesg недоступен обычным пользователям |
| `kptr_restrict` | `2` | Адреса ядра скрыты из /proc и /sys |
| `sysrq` | `0` | Magic SysRq отключён |
| `randomize_va_space` | `2` | ASLR — максимальная рандомизация |
| `suid_dumpable` | `0` | Core dump для setuid-процессов запрещён |
| `protected_hardlinks` | `1` | Защита жёстких ссылок |
| `protected_symlinks` | `1` | Защита символических ссылок |
| `unprivileged_userns_clone` | `0` | Ограничение user namespaces |

> ⚠️ `kernel.unprivileged_userns_clone = 0` ломает **rootless Docker/Podman**. Если используете контейнеры без root — закомментируйте эту строку в `/etc/sysctl.d/99-hardening.conf`.

---

### 11. Blacklist модулей ядра

Файл: `/etc/modprobe.d/hardening-blacklist.conf`

#### Файловые системы с историей уязвимостей

`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`

Вектор атаки: автоматическое монтирование специально созданных образов через `udisks2` / `automount`.

#### Опасные сетевые протоколы

`dccp`, `sctp`, `rds`, `tipc`

Все четыре имеют длинную историю CVE в ядре Linux. На VPS они практически никогда не нужны.

> **VPS-специфика:** USB (`usb-storage`) и Firewire не блокируются — на виртуальных машинах их нет, а агрессивный blacklist может затронуть virtio-драйверы некоторых провайдеров.

Изменения вступают в силу **после перезагрузки**.

---

### 12. Отключение core dump

Три уровня блокировки:

```
/etc/security/limits.conf           → hard core 0
/etc/systemd/coredump.conf.d/       → Storage=none, ProcessSizeMax=0
sysctl kernel.core_pattern          → |/bin/false
```

Тройная блокировка нужна потому, что `limits.conf` применяется только к PAM-сессиям, systemd-coredump — к процессам systemd, а `sysctl` — ко всем остальным.

---

### 13. Auditd

Файл: `/etc/audit/rules.d/99-hardening.rules`

| Категория | Что отслеживается | Ключ |
|---|---|---|
| Идентификация | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | `identity` |
| Привилегии | `/etc/sudoers`, `/etc/sudoers.d/` | `sudoers` |
| SSH | `sshd_config`, `~/.ssh/` | `sshd_config`, `ssh_keys` |
| Cron | Все cron-директории, `/var/spool/cron/` | `cron` |
| Права файлов | `chmod`, `chown`, `fchown` и варианты | `file_perm` |
| Повышение привилегий | `setuid`, `setgid`, `execve` от root | `priv_esc`, `priv_exec` |
| Модули ядра | `insmod`, `rmmod`, `modprobe`, syscalls | `kernel_modules` |
| Сеть | `socket`, `connect`, `bind` | `net_socket`, `net_connect` |
| Загрузчик | `/boot/` | `boot` |

В конце правил — `-e 2`: правила становятся **неизменяемыми** до следующей перезагрузки. Это исключает возможность отключения аудита злоумышленником без reboot.

> **VPS-специфика:** используется `-f 1` (писать в syslog при ошибке), а не `-f 2` (паника ядра) — на VPS без физического доступа паника означает недоступный сервер.

Просмотр событий:
```bash
ausearch -k identity    | tail -20   # изменения passwd/shadow
ausearch -k sudoers     | tail -20   # изменения sudoers
ausearch -k ssh_keys    | tail -20   # изменения SSH-ключей
ausearch -k priv_exec   | tail -20   # выполнение команд от root
aureport --summary                   # общая сводка
```

---

### 14. AppArmor

Все существующие профили переводятся в режим `enforce` (вместо `complain`):

```bash
aa-enforce /etc/apparmor.d/*
```

В режиме `enforce` AppArmor блокирует запрещённые действия и пишет в syslog. В режиме `complain` — только логирует.

Проверка статуса:
```bash
aa-status
```

---

### 15. Настройка sudo

Файл: `/etc/sudoers.d/99-hardening`

| Настройка | Значение |
|---|---|
| `log_output` | Полная запись вывода всех sudo-команд |
| `logfile` | `/var/log/sudo.log` |
| `timestamp_timeout=5` | Сессия sudo истекает через 5 минут |
| `requiretty` | sudo требует реального терминала |
| `!visiblepw` | Пароль не отображается при вводе |
| `secure_path` | Фиксированный безопасный PATH |

---

### 16. Политика паролей

Файл: `/etc/security/pwquality.conf`

| Параметр | Значение |
|---|---|
| `minlen` | 16 символов |
| `dcredit` | минимум 1 цифра |
| `ucredit` | минимум 1 заглавная буква |
| `lcredit` | минимум 1 строчная буква |
| `ocredit` | минимум 1 спецсимвол |
| `maxrepeat` | не более 3 одинаковых подряд |
| `dictcheck` | проверка по словарю |
| `gecoscheck` | запрет использования имени пользователя |

Применяется при создании новых пользователей и смене паролей. SSH-аутентификация по паролю отключена — эти правила защищают пароль для `sudo`.

---

### 17. Права на системные файлы

```bash
chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 700 /boot
```

Убирается SUID у редко используемых утилит: `chfn`, `chsh`, `newgrp`.

История команд root перенаправляется в `/dev/null`:
```bash
ln -sf /dev/null /root/.bash_history
```

---

### 18. Удаление телеметрии

Удаляются пакеты:

| Пакет | Назначение |
|---|---|
| `ubuntu-report` | Отправка отчётов об использовании системы |
| `popularity-contest` | Статистика установленных пакетов |
| `apport` | Сбор и отправка crash-репортов |
| `whoopsie` | Отправщик crash-репортов в Canonical |

Отключаются systemd-сервисы `apport` и `whoopsie`. Если установлен Snap — отключается сбор snap-метрик.

---

### 19. Автоматические обновления

#### Конфигурация unattended-upgrades

Файл: `/etc/apt/apt.conf.d/50unattended-upgrades`

**Разрешённые источники:**
- `${distro_codename}-security` — только security-патчи
- `${distro_codename}-updates` — стабильные bugfix-обновления
- ESM Apps и ESM Infra (Ubuntu Pro)

**Blacklist — не обновлять автоматически:**

```
docker*   kube*   postgresql*   mysql*   mariadb*
nginx*    apache2*   redis*   mongodb*
```

Эти пакеты управляют критичными сервисами и требуют ручного контроля при обновлении.

**Параметры:**

| Параметр | Значение |
|---|---|
| `AutoFixInterruptedDpkg` | `true` — исправлять прерванные установки |
| `MinimalSteps` | `true` — атомарные обновления |
| `Remove-Unused-Dependencies` | `true` — убирать orphan-пакеты |
| `Automatic-Reboot` | `false` — не перезагружаться автоматически |
| `Mail` | `root` — уведомления root |
| `MailOnlyOnError` | `true` — писать только при ошибках |

#### Расписание через systemd drop-in

Файлы:
```
/etc/systemd/system/apt-daily.timer.d/override.conf
/etc/systemd/system/apt-daily-upgrade.timer.d/override.conf
```

| Таймер | Время | Назначение |
|---|---|---|
| `apt-daily` | 03:00 ± 10 мин | Обновление списков пакетов |
| `apt-daily-upgrade` | 03:30 ± 10 мин | Установка обновлений |

Разброс `RandomizedDelaySec=10m` нужен, чтобы все VPS одного провайдера не обращались к репозиториям одновременно.

> Используется drop-in (а не перезапись unit-файла), чтобы обновления системы не затирали кастомное расписание.

---

### 20. Удаление приватного ключа

В конце скрипт предлагает надёжно удалить приватный ключ с сервера:

```bash
shred -vuz /root/admin_ssh_key   # перезапись + удаление
```

Скрипт ждёт явного подтверждения. Если ключ ещё не скопирован — нажмите `N` и сделайте это из второго терминала:

```bash
scp root@<IP>:/root/admin_ssh_key ./admin_ssh_key
```

---

## Подключение после настройки

```bash
# Прямое подключение
ssh -p 20202 -i ./admin_ssh_key admin@<IP>

# Через ssh-agent (вводить пароль ключа один раз)
eval $(ssh-agent)
ssh-add ./admin_ssh_key
ssh -p 20202 admin@<IP>
```

Рекомендуется добавить в `~/.ssh/config` на клиентской машине:

```sshconfig
Host myserver
    HostName      <IP>
    Port          20202
    User          admin
    IdentityFile  ~/.ssh/admin_ssh_key
    AddKeysToAgent yes
```

После этого достаточно: `ssh myserver`

---

## Диагностика и мониторинг

```bash
# SSH
journalctl -u ssh -u sshd -f              # живой лог
ss -tlnp | grep 20202                     # слушает ли порт

# Fail2ban
fail2ban-client status sshd               # забаненные IP
fail2ban-client set sshd unbanip <IP>     # разбанить IP вручную

# UFW
ufw status verbose                        # активные правила

# Auditd
ausearch -k identity   | tail -20         # изменения пользователей
ausearch -k ssh_keys   | tail -20         # изменения SSH-ключей
ausearch -k priv_exec  | tail -20         # выполнение от root
aureport --summary                        # общая статистика

# AppArmor
aa-status                                 # профили и режимы

# NTP / Chrony
chronyc tracking                          # текущий источник и погрешность
chronyc sources -v                        # все источники
timedatectl show                          # статус синхронизации

# Автообновления
systemctl list-timers apt-daily*          # расписание таймеров
cat /var/log/unattended-upgrades/*.log    # лог последних обновлений
```

---

## Что требует перезагрузки

После выполнения скрипта необходима перезагрузка для применения:

- **Blacklist модулей ядра** — `DCCP`, `SCTP`, `RDS`, `TIPC` и редкие файловые системы
- **`kernel.unprivileged_userns_clone = 0`** — на некоторых ядрах применяется только после reboot
- **`/var/tmp` bind-mount** — если `mount --bind` не применился в текущей сессии
- **`/proc hidepid`** — если записан в fstab, но не перемонтирован

```bash
reboot
```

После перезагрузки проверьте доступность:
```bash
ssh -p 20202 -i ./admin_ssh_key admin@<IP>
```

---

## Ручное включение форвардинга

Если сервер используется как VPN-сервер или прокси, TCP-форвардинг можно включить:

```bash
# В переменных в начале скрипта перед запуском:
TCP_FORWARDING="yes"
GATEWAY_PORTS="yes"     # только если нужен проброс портов наружу

# Или после запуска — отредактировать sshd_config:
sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
systemctl restart ssh
```

Также потребуется разрешить форвардинг в UFW и sysctl:
```bash
ufw route allow in on eth0
sysctl -w net.ipv4.ip_forward=1
```
