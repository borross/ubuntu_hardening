# Ubuntu Hardening Script — VPS/VDS Edition (v2)

Скрипт автоматизированного харденинга Ubuntu 22.04 / 24.04 / 26.04 для виртуальных серверов.
Запускается от `root` сразу после получения чистого VPS/VDS и проводит полную настройку безопасности в один проход.

---

## Что нового в v2

| Исправление | Суть |
|---|---|
| **ssh.socket** | Ubuntu 22.10+ запускает SSH через socket-активацию, при которой `Port` в `sshd_config` игнорируется. Скрипт отключает `ssh.socket` — истинная причина проблемы «порт не поменялся» |
| **Контрольная точка входа** | Проверка SSH-входа под `admin` теперь **до** блокировки root, а не в конце скрипта |
| **Auditd: причина backlog exceeded** | Удалены правила аудита `socket`/`connect` — они генерировали тысячи событий/сек. Увеличение backlog лечило симптом, а не причину |
| **Auditd 3.x** | Убраны устаревшие `dispatcher = /sbin/audispd` и `disp_qos` — удалены из auditd 3.x (Ubuntu 22.04+) |
| **Auditd: arch=b32** | Ключевые правила продублированы для 32-битных syscalls — без этого аудит обходился 32-битными вызовами |
| **/etc/ssh 755** | Было `chmod 700 /etc/ssh` — это ломало исходящий `ssh`/`scp`/`git` для непривилегированных пользователей (нет доступа к `ssh_config`). Приватность обеспечивают права на сами файлы |
| **logrotate для audit удалён** | auditd ротирует логи сам; параллельный logrotate давал двойную ротацию и разрывы аудита |
| **Тип ключа на выбор** | ed25519 (рекомендуется) или ecdsa-521 |
| **passwd в цикле** | 3 ошибки ввода пароля больше не роняют скрипт из-за `set -e` |
| **chrony minsources** | При одном пользовательском NTP-сервере ставится `minsources 1`, иначе время никогда не синхронизировалось бы |
| **UFW: опрос портов** | Перед `ufw reset` показываются слушающие порты и можно открыть дополнительные (80, 443 и т.д.) |
| **noexec /tmp и apt** | Временный каталог apt перенесён в `/var/lib/apt/tmp` — иначе ночные unattended-upgrades могли падать |
| **userns под ядро** | `kernel.unprivileged_userns_clone` пишется только если существует в ядре; на 24.04+/26.04 используется `apparmor_restrict_unprivileged_userns` |
| **Повторный запуск** | Если правила auditd в immutable-режиме (`-e 2`), секция 13 пропускается с предупреждением вместо аварийного завершения |
| **usermod при повторном запуске** | Существующий пользователь теперь гарантированно добавляется в sudo |
| **rsyslog в зависимостях** | Минимальные образы 24.04+ могут идти без rsyslog, на котором построено логирование sudo |
| **Лог выполнения** | Весь вывод дублируется в `/root/hardening_<дата>.log`; при ошибке trap показывает номер строки |
| **Drop-in c Port** | Конфликтующие файлы `/etc/ssh/sshd_config.d/*` с директивой `Port` перемещаются в `/root/sshd_config.d.bak` |
| **История root** | Симлинк `.bash_history → /dev/null` убран — это антифорензика, помогающая скрывать следы; аудит команд ведёт auditd |
| **Мелочи** | `dpkg -s` вместо `dpkg -l` (ложное срабатывание на удалённых пакетах), фикс приоритета операторов в bind-mount `/var/tmp`, валидация NTP-серверов, `AddressFamily` вынесен в переменную |

---

## Требования

| Параметр | Значение |
|---|---|
| ОС | Ubuntu 22.04 / 24.04 / 26.04 LTS |
| Платформа | VPS / VDS (KVM, XEN, VMware, Hyper-V) |
| Пользователь | `root` |
| Сеть | Доступ в интернет для установки пакетов |
| Доступ | VNC или консоль провайдера на случай потери SSH |

> ⚠️ **Перед запуском убедитесь, что у вас открыта консоль провайдера (VNC/KVM).** Если SSH-сессия оборвётся в процессе, вы сможете продолжить через неё.

---

## Быстрый старт

```bash
wget -O ubuntu_hardening.sh https://raw.githubusercontent.com/borross/ubuntu_hardening/refs/heads/main/ubuntu_hardening.sh
less ubuntu_hardening.sh        # проверить содержимое перед запуском
bash ubuntu_hardening.sh
```

Скрипт интерактивный. Всё, что можно пропустить, пропускается нажатием `Enter`. Весь вывод дублируется в лог `/root/hardening_<дата>.log`.

---

## Переменные конфигурации

Настраиваются в начале файла скрипта:

```bash
ADMIN_USER="admin"              # имя создаваемого пользователя
SSH_PORT="20202"                # порт SSH (будет переспрошен интерактивно)
KEY_PATH="/root/admin_ssh_key"  # путь для сохранения ключевой пары

# any  = IPv4 + IPv6 (по умолчанию)
# inet = только IPv4 — НЕ ставьте на IPv6-only VPS!
SSH_ADDRESS_FAMILY="any"

# Форвардинг — отключён по умолчанию, включайте осознанно
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"
```

---

## Что делает скрипт

### 0. Обновление системы

`apt-get upgrade` в неинтерактивном режиме и установка пакетов:

```
ufw  fail2ban  auditd  audispd-plugins  libpam-pwquality
unattended-upgrades  apt-listchanges  acl  chrony  rsyslog
```

Также спрашивает порт SSH (1024–65535, по умолчанию 20202) и тип ключа (ed25519 / ecdsa-521), определяет гипервизор через `systemd-detect-virt` и рассчитывает лимиты логирования: квота логов — 10% свободного места на разделе `/var/log` (50–2048 МБ), audit backlog — из объёма RAM (`RAM_МБ × 8`, диапазон 8192–65536).

---

### 1. Имя хоста, FQDN, DNS, часовой пояс, NTP

Полностью интерактивный раздел, всё пропускается через `Enter`.

**Имя хоста** — `hostnamectl set-hostname`, валидация по RFC 1123, автообновление `/etc/hosts` (иначе `sudo` выдаёт `unable to resolve host`).

**FQDN** — запись в `/etc/hosts` вида `127.0.1.1  server01.example.com  server01`, чтобы `hostname --fqdn` работал без реального DNS.

**DNS** — валидация IPv4; через drop-in `systemd-resolved` с DNS-over-TLS (`opportunistic`) и DNSSEC, либо напрямую в `/etc/resolv.conf` с защитой `chattr +i`.

| Провайдер | Основной | Резервный |
|---|---|---|
| Cloudflare | `1.1.1.1` | `1.0.0.1` |
| Google | `8.8.8.8` | `8.8.4.4` |
| Quad9 | `9.9.9.9` | `149.112.112.112` |

**Часовой пояс** — `timedatectl set-timezone` с проверкой по `list-timezones`.

**NTP (chrony)** — chrony предпочтительнее `systemd-timesyncd` на VPS: быстрее восстанавливается после простоя, точнее при нестабильной сети. По умолчанию пулы `ubuntu.pool.ntp.org` + `time.cloudflare.com` (NTS). Пользовательские серверы валидируются (IP или hostname). `minsources` подстраивается: `1` при единственном сервере, иначе `2`.

---

### 2. Генерация SSH-ключа

```bash
ssh-keygen -t ed25519 -f /root/admin_ssh_key ...      # рекомендуется
ssh-keygen -t ecdsa -b 521 -f /root/admin_ssh_key ... # альтернатива
```

Ключ генерируется **с паролем** (запрашивается интерактивно). Приватный ключ выводится в терминал, скрипт ждёт подтверждения, что он сохранён.

> ⚠️ Скачайте приватный ключ немедленно: `scp root@<IP>:/root/admin_ssh_key ./admin_ssh_key`. В конце скрипт предложит удалить его через `shred`.

---

### 3. Создание пользователя admin

```bash
useradd -m -s /bin/bash admin     # с -g, если группа admin уже существует
usermod -aG sudo admin            # выполняется и при повторном запуске
```

`passwd` выполняется в цикле — ошибки ввода не прерывают скрипт. Публичный ключ ставится в `~/.ssh/authorized_keys` (700 / 600), дубликаты убираются через `sort -u`.

---

### 4. Настройка SSH

Файл: `/etc/ssh/sshd_config` (резервная копия создаётся автоматически).

Права: каталог `/etc/ssh` — **755** (700 ломало ssh-клиент для обычных пользователей), `sshd_config` и приватные host-ключи — 600.

| Параметр | Значение | Обоснование |
|---|---|---|
| `Port` | выбранный | Нестандартный порт снижает шум автосканеров |
| `AddressFamily` | `any` | Настраивается переменной; `inet` опасен на IPv6-only VPS |
| `PermitRootLogin` | `no` | Прямой вход root запрещён |
| `PasswordAuthentication` | `no` | Только ключевая аутентификация |
| `LoginGraceTime` | `30` | `0` означало бы «без лимита» |
| `MaxAuthTries` / `MaxStartups` | `3` / `5:30:20` | Защита от перебора и медленных атак |
| `AllowUsers` | `admin` | Только указанный пользователь |
| `LogLevel` | `VERBOSE` | Fingerprint ключа в каждой записи |
| `DebianBanner` | `no` | Скрыть версию ОС |

Криптография: только современные алгоритмы (curve25519, chacha20-poly1305, aes-gcm, hmac-sha2-etm).

После записи конфига:
1. drop-in файлы `sshd_config.d/*` с директивой `Port` перемещаются в `/root/sshd_config.d.bak`;
2. `sshd -t` — проверка синтаксиса;
3. **отключается `ssh.socket`** (socket-активация игнорирует `Port` из конфига — Ubuntu 22.10+);
4. рестарт службы (`ssh`/`sshd` определяется автоматически) и проверка порта через `ss -tlnp`;
5. **контрольная точка**: скрипт останавливается и требует подтвердить вход под `admin` из нового терминала. Отказ (`n`) прерывает скрипт **до** блокировки root.

---

### 5. Блокировка root

```bash
passwd -l root
```

`su` ограничивается членами группы `sudo` через `pam_wheel.so`.

---

### 6. Брандмауэр UFW

Перед сбросом правил скрипт показывает список слушающих портов (`ss -tlnp`) и позволяет перечислить дополнительные TCP-порты (например `80 443`) — они будут открыты после reset.

```bash
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward
ufw limit <PORT>/tcp     # rate-limit: 6 попыток за 30 сек
```

> 💡 **VPS-специфика:** у Hetzner/DO/Vultr есть свой firewall в панели — продублируйте правила и там.

---

### 7. Fail2ban

`/etc/fail2ban/jail.local`: backend `systemd`, banaction `ufw`, 3 попытки → бан 24 часа, порт — выбранный SSH-порт.

---

### 8. Защита cron

`chown root:root` + `chmod og-rwx` на `/etc/crontab` и все cron-каталоги. Создаются `/etc/cron.allow` и `/etc/at.allow` только с `root`; `deny`-файлы удаляются.

---

### 9. Защита разделов

| Раздел | Флаги |
|---|---|
| `/tmp` | `nosuid,nodev,noexec,relatime` |
| `/dev/shm` | `nosuid,nodev,noexec` (без `seclabel` — она только для SELinux) |
| `/var/tmp` | bind → `/tmp` |
| `/home` | `noexec,nosuid,nodev` (через systemd unit, если не отдельный раздел) |

Применяется через `remount` без перезагрузки. Так как `/tmp` теперь `noexec`, временный каталог apt переносится в `/var/lib/apt/tmp` (`/etc/apt/apt.conf.d/99tempdir`) — иначе часть maintainer-скриптов dpkg падала бы при ночных обновлениях.

---

### 10. Параметры ядра (sysctl)

Файл: `/etc/sysctl.d/99-hardening.conf`

Сеть: `rp_filter=1`, `ip_forward=0`, `tcp_syncookies=1`, запрет ICMP-редиректов, игнор broadcast ping, `log_martians=1`, `accept_ra=0`, `tcp_rfc1337=1`.

Ядро: `yama.ptrace_scope=1` (не 2 — чтобы работал strace на VPS), `dmesg_restrict=1`, `kptr_restrict=2`, `sysrq=0`, ASLR `randomize_va_space=2`, `suid_dumpable=0`, защита symlink/hardlink/fifo.

**User namespaces** — подбирается под ядро автоматически:
- `kernel.unprivileged_userns_clone = 0` — только если параметр существует (Debian-патч, отсутствует на новых ядрах);
- `kernel.apparmor_restrict_unprivileged_userns = 1` — на 24.04+/26.04.

> ⚠️ Ограничение userns ломает **rootless Docker/Podman** — при необходимости закомментируйте эти строки.

---

### 11. Blacklist модулей ядра

ФС с историей уязвимостей: `cramfs freevxfs jffs2 hfs hfsplus udf`.
Сетевые протоколы с историей CVE: `dccp sctp rds tipc`.

> **VPS-специфика:** USB/Firewire не блокируются — на виртуалках их нет, а блокировка может задеть virtio-драйверы.

Полная сила — после перезагрузки.

---

### 12. Отключение core dump

Три уровня: `limits.conf` (PAM-сессии) + `systemd-coredump` drop-in + `sysctl core_pattern=|/bin/false`.

---

### 13. Auditd

**Защита от повторного запуска:** если правила уже immutable (`enabled 2`), секция пропускается с предупреждением — изменить их можно только после reboot.

`auditd.conf` (без устаревших `dispatcher`/`disp_qos`):
- ротация: 5 файлов, суммарно не более 10% свободного места;
- при нехватке места — `ROTATE`, а не остановка;
- backlog из RAM (`-b`), режим сбоя `-f 1` (syslog, не паника — VPS без физической консоли).

Правила `/etc/audit/rules.d/99-hardening.rules`:

| Категория | Ключ | Примечание |
|---|---|---|
| passwd/shadow/group/sudoers | `identity`, `sudoers` | |
| sshd_config, `~/.ssh/` | `sshd_config`, `ssh_keys` | |
| Все cron-каталоги | `cron` | |
| chmod/chown (b64 **и b32**) | `file_perm` | фильтр `auid>=1000` |
| setuid/setgid, execve от root | `priv_esc`, `priv_exec` | b64 и b32 |
| Модули ядра | `kernel_modules` | |
| Новые слушающие сокеты | `net_bind` | только реальные пользователи |
| `/boot/` | `boot` | |

**Правила `socket`/`connect` намеренно отсутствуют** — аудит каждого сетевого вызова и был причиной `backlog limit exceeded`.

В конце — `-e 2`: правила неизменяемы до перезагрузки. Отдельный logrotate для audit.log **не создаётся** — auditd ротирует сам.

Просмотр: `ausearch -k identity | tail -20`, `aureport --summary`.

---

### 14. AppArmor

Все профили переводятся в `enforce`. Проверка: `aa-status`.

---

### 15. Настройка sudo

`/etc/sudoers.d/99-hardening`:

| Настройка | Значение |
|---|---|
| `timestamp_timeout=5` | Сессия sudo истекает через 5 минут |
| `!visiblepw` | Пароль не отображается при вводе |
| `secure_path` | Фиксированный безопасный PATH |

Логирование — через rsyslog (`/etc/rsyslog.d/50-sudo.conf` → `/var/log/sudo.log`). Опции `log_output` / `requiretty` не используются: первая требует I/O-плагин, отсутствующий в Ubuntu, вторая удалена из sudo 1.9.x.

---

### 16. Политика паролей

`/etc/security/pwquality.conf`: минимум 16 символов, все классы символов, `maxrepeat=3`, словарная проверка, `gecoscheck`. Защищает пароль для `sudo` (SSH по паролю отключён).

---

### 17. Права на системные файлы

```bash
chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 700 /boot
```

SUID снимается с `chfn`, `chsh`, `newgrp`.

> История команд root **больше не отключается**: симлинк `.bash_history → /dev/null` был антифорензикой, которая помогала атакующему скрывать следы. Команды от root аудирует auditd (ключ `priv_exec`).

---

### 18. Удаление телеметрии

Пакеты `ubuntu-report`, `popularity-contest`, `apport`, `whoopsie` удаляются (проверка через `dpkg -s` — надёжнее `dpkg -l`, который срабатывал и на удалённых пакетах). Отключаются сервисы apport/whoopsie и snap-метрики.

---

### 19. Автоматические обновления

`/etc/apt/apt.conf.d/50unattended-upgrades`:

- источники: `-security`, ESM, `-updates`;
- blacklist: `docker* kube* postgresql* mysql* mariadb* nginx* apache2* redis* mongodb*`;
- `Automatic-Reboot "false"`, `MailOnlyOnError "true"`.

Расписание через systemd drop-in (не перезапись unit): `apt-daily` 03:00 ± 10 мин, `apt-daily-upgrade` 03:30 ± 10 мин. Дефолтные `OnCalendar`/`OnBootSec` сбрасываются пустыми строками перед новым значением.

---

### 20. Удаление приватного ключа

`shred -vuz /root/admin_ssh_key` после явного подтверждения. Если ключ не скачан — `N` и скачивание из второго терминала.

---

## Подключение после настройки

```bash
ssh -p <PORT> -i ./admin_ssh_key admin@<IP>

# Через ssh-agent (пароль ключа один раз за сессию)
eval $(ssh-agent)
ssh-add ./admin_ssh_key
ssh -p <PORT> admin@<IP>
```

`~/.ssh/config` на клиенте:

```sshconfig
Host myserver
    HostName      <IP>
    Port          <PORT>
    User          admin
    IdentityFile  ~/.ssh/admin_ssh_key
    AddKeysToAgent yes
```

---

## Диагностика и мониторинг

```bash
# SSH
journalctl -u ssh -u sshd -f
ss -tlnp | grep <PORT>
systemctl status ssh.socket        # должен быть disabled/inactive

# Fail2ban / UFW
fail2ban-client status sshd
fail2ban-client set sshd unbanip <IP>
ufw status verbose

# Auditd
ausearch -k identity  | tail -20
ausearch -k ssh_keys  | tail -20
ausearch -k priv_exec | tail -20
aureport --summary
auditctl -s                        # backlog, lost, enabled

# AppArmor / Chrony
aa-status
chronyc tracking
chronyc sources -v

# Автообновления
systemctl list-timers apt-daily*
cat /var/log/unattended-upgrades/*.log

# Лог самого харденинга
ls -la /root/hardening_*.log
```

---

## Что требует перезагрузки

- Blacklist модулей ядра (DCCP, SCTP, редкие ФС)
- Ограничения user namespaces (на части ядер)
- `/var/tmp` bind-mount, если не применился в текущей сессии
- Любые изменения правил auditd при immutable-режиме (`-e 2`)

```bash
reboot
# затем:
ssh -p <PORT> -i ./admin_ssh_key admin@<IP>
```

---

## Повторный запуск скрипта

Скрипт можно запускать повторно, но с ограничениями:

- секция 13 (auditd) пропускается, пока правила immutable — новые правила из `/etc/audit/rules.d/` применятся после reboot;
- root уже заблокирован — запускайте через `sudo -i` из-под `admin`;
- дубликаты в `authorized_keys` и `/etc/hosts` не появляются (sort -u / sed).

---

## Ручное включение форвардинга

Для VPN/прокси-сервера:

```bash
# Перед запуском — в переменных скрипта:
TCP_FORWARDING="yes"
GATEWAY_PORTS="yes"     # только если нужен проброс портов наружу

# Или после — в sshd_config:
sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
systemctl restart ssh

# Плюс UFW и sysctl:
ufw route allow in on eth0
sysctl -w net.ipv4.ip_forward=1
```
