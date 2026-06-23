# Ubuntu Hardening Script — VPS/VDS Edition

Скрипт автоматизированного харденинга Ubuntu 22.04 / 24.04 / 26.04 для виртуальных серверов.
Запускается от `root` сразу после получения чистого VPS/VDS и проводит полную настройку безопасности в один проход.

Основан на практиках **CIS Ubuntu Linux Benchmark** с поправками на специфику VPS (нет физического доступа, консоль только через провайдера). Безопасные меры применяются всегда; рискованные (способные оборвать доступ или сломать нагрузку) — только по явным флагам.

---

## Содержание

- [Требования](#требования)
- [Быстрый старт](#быстрый-старт)
- [Опции командной строки (флаги риска)](#опции-командной-строки-флаги-риска)
- [Режим аудита (--audit-only)](#режим-аудита---audit-only)
- [Переменные конфигурации](#переменные-конфигурации)
- [Что делает скрипт](#что-делает-скрипт)
- [Сознательные отклонения от CIS](#сознательные-отклонения-от-cis)
- [Подключение после настройки](#подключение-после-настройки)
- [Диагностика и мониторинг](#диагностика-и-мониторинг)
- [Что требует перезагрузки](#что-требует-перезагрузки)
- [Восстановление при потере доступа](#восстановление-при-потере-доступа)
- [Ручное включение форвардинга](#ручное-включение-форвардинга)

---

## Требования

| Параметр | Значение |
|---|---|
| ОС | Ubuntu 22.04 / 24.04 / 26.04 LTS |
| Платформа | VPS / VDS (KVM, XEN, VMware, Hyper-V) |
| Пользователь | `root` |
| Сеть | Доступ в интернет для установки пакетов |
| Доступ | VNC или консоль провайдера на случай потери SSH |

> ⚠️ **Перед запуском убедитесь, что у вас открыта консоль провайдера (VNC/KVM).** Если SSH-сессия оборвётся в процессе, вы сможете продолжить через неё. Это особенно важно при использовании рискованных флагов (`--with-pam-lockout`, `--with-grub-password`, `--with-audit-strict`).

---

## Быстрый старт

```bash
# Скачать скрипт на сервер
wget -O ubuntu_hardening.sh https://your-repo/ubuntu_hardening.sh

# Проверить содержимое перед запуском
less ubuntu_hardening.sh

# Безопасный профиль (рекомендуется для первого прогона)
bash ubuntu_hardening.sh

# Сначала только посмотреть текущее состояние, ничего не меняя
bash ubuntu_hardening.sh --audit-only

# С отдельными рискованными мерами
bash ubuntu_hardening.sh --with-pwhistory --with-aide

# Всё рискованное разом (кроме двух самых опасных для VPS)
bash ubuntu_hardening.sh --all-risky
```

Скрипт интерактивный — задаёт вопросы по имени хоста, FQDN, DNS, часовому поясу, NTP, SSH-порту и паролю ключа. Всё, что можно пропустить, пропускается нажатием `Enter`.

---

## Опции командной строки (флаги риска)

Философия: **безопасные меры (🟢) применяются всегда**, рискованные (🟡/🔴) — только с явным флагом, чтобы не настраивать опасное «вслепую одним проходом».

| Флаг | Риск | Что делает | Что может сломать |
|---|---|---|---|
| `--with-pam-lockout` | 🔴 | `pam_faillock`: блок УЗ после 5 неудачных входов, авторазблок 15 мин | Локаут пользователя при ошибке в PAM (root **не** блокируется) |
| `--with-pwhistory` | 🟡 | `pam_pwhistory` (remember=5) + явный `yescrypt`, снятие `nullok` | Запрет повтора паролей; правит `common-password`/`common-auth` |
| `--with-password-aging` | 🔴 | Старение паролей в `login.defs` (max 365 / min 1 / warn 7) | Истечение пароля → требование смены (root не затронут) |
| `--with-tmout` | 🟡 | `TMOUT=900` — авто-выход из неактивных shell-сессий | Обрыв долгих интерактивных сессий по простою |
| `--with-aide` | 🟡 | Установка и инициализация AIDE + ежедневная проверка | Долгая инициализация, нагрузка на диск |
| `--with-audit-strict` | 🔴 | `auditd -f 2` — паника ядра при сбое аудита | **VPS уходит в офлайн** при невозможности записи аудита |
| `--no-userns` | 🟡 | Отключить unprivileged user namespaces | **Ломает rootless Docker/Podman** |
| `--with-fs-blacklist` | 🟡 | Расширенный blacklist редких ФС (afs, ceph, cifs, exfat, gfs2, NFS) | NFS/CIFS/ceph перестают монтироваться |
| `--minimize-services` | 🟡 | Интерактивный аудит и `purge` лишних серверных/клиентских сервисов | Удаление нужного сервиса (каждый — с подтверждением) |
| `--with-grub-password` | 🔴 | Пароль администратора GRUB (с `--unrestricted`) | Сложности с правкой меню загрузчика; нужна IP-KVM для проверки |
| `--with-tcp-forwarding` | 🟡 | Включить `AllowTcpForwarding` + `GatewayPorts` | Открывает SSH-туннелирование (нужно для VPN/прокси) |

**Мета-флаги:**

| Флаг | Описание |
|---|---|
| `--all-risky` | Включить всё рискованное, **кроме** `--with-audit-strict` и `--with-grub-password` (самые опасные для VPS) |
| `--audit-only` | Ничего не менять, только вывести отчёт о текущем соответствии |
| `-h`, `--help` | Справка |

> При старте скрипт печатает список активных рискованных опций, а в финальной сводке — таблицу `[ВКЛ]/[выкл]` по каждому флагу.

---

## Режим аудита (`--audit-only`)

```bash
bash ubuntu_hardening.sh --audit-only
```

Выполняет только проверки и выводит `PASS/FAIL` по ключевым пунктам (SSH, sysctl, root, auditd, UFW, fail2ban, AppArmor, chrony, права на файлы, AIDE), **не внося никаких изменений**. Требует `root` (нужно читать `/etc/shadow` и применённые sysctl). Удобно для предварительной оценки и для повторной проверки после применения харденинга.

---

## Переменные конфигурации

Настраиваются в начале файла скрипта. Флаги риска менять здесь не нужно — они управляются аргументами.

```bash
ADMIN_USER="admin"               # имя создаваемого пользователя
SSH_PORT="20202"                 # порт по умолчанию (будет переспрошен интерактивно)
KEY_PATH="/root/admin_ssh_key"   # путь для сохранения ключевой пары

# Форвардинг — отключён по умолчанию (или флаг --with-tcp-forwarding)
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"
```

---

## Что делает скрипт

Нумерация секций соответствует выводу скрипта.

### 0. Обновление системы

`apt-get upgrade` в неинтерактивном режиме + установка пакетов: `ufw fail2ban auditd audispd-plugins libpam-pwquality unattended-upgrades apt-listchanges acl chrony` и др. Удаляется `prelink` (CIS 1.5.4, мешает AIDE). `aide`/`aide-common` ставятся только при `--with-aide`. Определяется гипервизор через `systemd-detect-virt`.

### 1. Имя хоста, FQDN, DNS, часовой пояс, NTP

Единственный полностью интерактивный раздел; всё пропускается через `Enter`. Имя хоста и FQDN валидируются по RFC 1123, обновляется `/etc/hosts`. DNS — через `systemd-resolved` (DoT `opportunistic` + DNSSEC) или прямой записью в `resolv.conf` с `chattr +i`. Время — **chrony** (с `makestep`, NTS для Cloudflare), `systemd-timesyncd` отключается.

### 2. Генерация SSH-ключа

`ssh-keygen -t ecdsa -b 521` **с паролем** (запрашивается интерактивно). Приватный ключ выводится в терминал и сохраняется в `/root/admin_ssh_key` (600); публичный — `.pub` (644). Пауза для скачивания ключа.

### 3. Создание пользователя admin

`useradd -m -s /bin/bash`, добавление в `sudo`. Корректно обрабатывается существующая группа `admin` (флаг `-g`). Публичный ключ → `~/.ssh/authorized_keys` (700/600).

### 4. Настройка SSH

`/etc/ssh/sshd_config` (бэкап перед изменением). Ключевые параметры:

| Параметр | Значение | CIS |
|---|---|---|
| `Port` | `20202` (настраивается) | — |
| `PermitRootLogin` | `no` | 5.1.20 |
| `PasswordAuthentication` | `no` | — |
| `LoginGraceTime` | `30` | 5.1.13 |
| `MaxAuthTries` | `3` | 5.1.16 |
| `MaxStartups` | `5:30:20` | 5.1.18 |
| `AllowUsers` | `admin` | 5.1.4 |
| `ClientAliveInterval` | `300` | 5.1.7 |
| `GSSAPIAuthentication` | `no` | 5.1.9 |
| `HostbasedAuthentication` | `no` | 5.1.10 |
| `IgnoreRhosts` | `yes` | 5.1.11 |
| `PermitUserEnvironment` | `no` | 5.1.21 |
| `AllowAgentForwarding` | `no` | 5.1.8 |
| `LogLevel` | `VERBOSE` | 5.1.14 |
| `DebianBanner` | `no` | — |

Криптография: современные `HostKeyAlgorithms`, `KexAlgorithms`, `Ciphers`, `MACs` (CIS 5.1.6/5.1.12/5.1.15). После записи — `sshd -t`, `chmod 600` на `sshd_config` и `*.conf` из Include (CIS 5.1.1–5.1.2), проверка порта через `ss`.

### 5. Блокировка root

`passwd -l root`; `su` ограничен группой `sudo` через `pam_wheel.so` (CIS 5.2.7).

### 6. Брандмауэр UFW

`deny incoming` / `allow outgoing` / `deny forward`; SSH через `ufw limit` (rate-limit на уровне iptables). VPS-замечание про дублирование правил в панели провайдера.

### 7. Fail2ban

`jail.local`: 3 попытки → бан 24 ч, backend `systemd`, banaction `ufw`.

### 8. Защита cron

Права `og-rwx` на `/etc/crontab` и `cron.*`; `cron.allow`/`at.allow` только с `root`, удаление `*.deny` (CIS 2.4.1).

### 9. Защита разделов

`/etc/fstab` (бэкап): `/tmp`, `/dev/shm`, `/var/tmp` (bind→/tmp), `/home` с `nosuid,nodev,noexec`. Применение через `remount`; для `/home` без отдельного раздела — `systemd` unit `remount-home.service` (CIS 1.1.2).

### 10. Параметры ядра (sysctl)

`/etc/sysctl.d/99-hardening.conf`: антиспуфинг (`rp_filter`), `ip_forward=0`, `tcp_syncookies`, запрет ICMP-редиректов, **`accept_source_route=0`** (CIS 3.3.8), `log_martians`, `tcp_rfc1337`; безопасность ядра — `ptrace_scope=1`, `kptr_restrict=2`, `dmesg_restrict`, ASLR=2, защита symlink/hardlink.

> `kernel.unprivileged_userns_clone=0` вынесен под флаг `--no-userns` — **по умолчанию НЕ применяется**, т.к. ломает rootless-контейнеры. При флаге добавляется ещё и `apparmor_restrict_unprivileged_userns=1`.

### 11. Blacklist модулей ядра

`/etc/modprobe.d/hardening-blacklist.conf`: редкие ФС (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`) и протоколы с историей CVE (`dccp`, `sctp`, `rds`, `tipc`) — CIS 3.2.1–3.2.4.

> Расширенный список (`afs`, `ceph`, `cifs`, `exfat`, `gfs2`, NFS) добавляется только при `--with-fs-blacklist`. `ext`/`fuse`/`vfat`/`overlay`/`squashfs` **сознательно не блокируются** — это сломало бы корень ФС, snap, контейнеры и EFI.

### 12. Отключение core dump

Тройная блокировка: `limits.conf` (`hard core 0`), `systemd-coredump` (`Storage=none`), sysctl `core_pattern=|/bin/false` (CIS 1.5.3).

### 13. Auditd

`auditd.conf`: ротация и backlog рассчитываются от свободного места (≤10% диска) и RAM (`backlog=RAM_MB×8`), `disk_full_action=ROTATE`. Правила `99-hardening.rules`:

| Категория | Ключ | CIS |
|---|---|---|
| Идентификация (passwd/shadow/group/gshadow) | `identity` | 6.2.3.8 |
| sudoers | `sudoers` | 6.2.3.1 |
| SSH-конфиг и ключи | `sshd_config`, `ssh_keys` | — |
| cron | `cron` | — |
| Права/владельцы файлов | `file_perm` | 6.2.3.9 |
| Повышение привилегий | `priv_esc`, `priv_exec` | 6.2.3.6 |
| **Изменение времени** | `time-change` | 6.2.3.4 |
| **Неуспешный доступ (EACCES/EPERM)** | `file_access` | 6.2.3.7 |
| **Монтирование ФС** | `mounts` | 6.2.3.10 |
| **Удаление/переименование файлов** | `delete` | 6.2.3.13 |
| **Логин/сессии (lastlog/faillock/wtmp/btmp)** | `logins`, `session` | 6.2.3.11–12 |
| **Изменение AppArmor** | `MAC-policy` | 6.2.3.14 |
| **chcon/setfacl/chacl/usermod** | `perm_chng`, `usermod` | 6.2.3.15–18 |
| Модули ядра | `kernel_modules` | 6.2.3.19 |
| Сеть, загрузчик | `net_*`, `boot` | — |

Правила неизменяемы до перезагрузки (`-e 2`). Режим сбоя `-f 1` (syslog) для VPS; `-f 2` (паника) — только при `--with-audit-strict`.

### 14. AppArmor

Все профили переводятся в `enforce` (CIS 1.3.1.4).

### 15. Настройка sudo

`/etc/sudoers.d/99-hardening`: `timestamp_timeout=5`, `!visiblepw`, **`use_pty`** (CIS 5.2.2), `secure_path`. Логирование sudo через rsyslog → `/var/log/sudo.log`.

### 16. Политика паролей

`pwquality.conf`: `minlen=16`, все классы символов, `maxrepeat=3`, **`maxsequence=3`** (CIS 5.3.3.2.5), `dictcheck`, `gecoscheck`.

### 17. Права на системные файлы

`shadow/gshadow` → 600, `passwd/group` → 644, `/boot` → 700. Снятие SUID с `chfn/chsh/newgrp`. История root → `/dev/null`. **Права на backup-файлы** `passwd-`/`group-` (644), `shadow-`/`gshadow-` (640), `opasswd` (600), `shells` (644) — CIS 7.1.1–7.1.10.

### 18. Удаление телеметрии

Purge `ubuntu-report`, `popularity-contest`, `apport`, `whoopsie`; отключение сервисов и snap-метрик (CIS 1.5.5).

### 19. Автоматические обновления

`unattended-upgrades`: только `-security` + `-updates` + ESM, blacklist критичных сервисов (docker/kube/postgresql/mysql/mariadb/nginx/apache2/redis/mongodb), `Automatic-Reboot=false`, `MailOnlyOnError=true`. Расписание через systemd drop-in: `apt-daily` 03:00, `apt-daily-upgrade` 03:30, `RandomizedDelaySec=10m`.

### 20. Баннеры (issue / issue.net / motd) 🆕

Из `/etc/issue`, `/etc/issue.net` удаляются сведения об ОС и ставится юридический текст; `/etc/motd` очищается. Права 644 root:root (CIS 1.6.1–1.6.6).

### 21. Окружение пользователей 🆕

`umask 027` через `/etc/profile.d` (CIS 5.4.2.6/5.4.3.3), безопасный `PATH` для root (5.4.2.5), отчёт по системным УЗ с интерактивным shell (5.4.2.7). `TMOUT=900` — только при `--with-tmout`.

### 22. Загрузчик GRUB 🆕

В `GRUB_CMDLINE_LINUX` добавляются `audit=1 audit_backlog_limit=<calc>` (ранний аудит, CIS 6.2.1.3–4) и `apparmor=1 security=apparmor` (CIS 1.3.1.2) — идемпотентно. `chmod 600` на `grub.cfg` (CIS 1.4.2). Пароль GRUB (с `--unrestricted`, чтобы не ломать штатную загрузку) — только при `--with-grub-password`.

### 23. PAM: блокировка УЗ 🔴 `--with-pam-lockout` 🆕

`pam_faillock` (`faillock.conf`: deny=5, unlock_time=900) + правки `common-auth` (с бэкапом). **root не блокируется** (нет `even_deny_root`) — защита от локаута на VPS (CIS 5.3.3.1).

### 24. PAM: история паролей + yescrypt 🟡 `--with-pwhistory` 🆕

`pam_pwhistory` (remember=5, `use_authtok`, `enforce_for_root`) + гарантия `yescrypt` в `pam_unix`, снятие `nullok` из `common-password`/`common-auth` (CIS 5.3.2.4, 5.3.3.4). Бэкап файлов.

### 25. Старение паролей 🔴 `--with-password-aging` 🆕

`login.defs`: `PASS_MAX_DAYS=365`, `PASS_MIN_DAYS=1`, `PASS_WARN_AGE=7`; применяется к `admin` через `chage` (root не затронут) — CIS 5.4.1.

### 26. Минимизация сервисов 🟡 `--minimize-services` 🆕

Вывод слушающих портов (`ss -tulnp`); интерактивный `purge` кандидатов (avahi, cups, nfs, rpcbind, samba, snmp, telnet, rsh, vsftpd и др. — каждый с подтверждением); postfix → `loopback-only` (CIS 2.1–2.2).

### 27. AIDE — контроль целостности 🟡 `--with-aide` 🆕

`aideinit` + перенос базы; ежедневная проверка `/etc/cron.daily/aide-check` → syslog (CIS 6.3.1).

### 28. Аудит ФС и УЗ (только отчёт) 🆕

Отчёт в `/root/hardening-audit-report.txt` (600): world-writable файлы/каталоги без sticky (7.1.11), unowned (7.1.12), SUID/SGID baseline (7.1.13), дубли UID/GID, пустые пароли, группы из passwd, UID 0 кроме root (7.2.x, 5.4.2.1). **Без автоправок** — только для ручной оценки.

### 29. Удаление приватного ключа

`shred -vuz` после подтверждения. Финальная сводка с таблицей применённых мер и флагов.

---

## Сознательные отклонения от CIS

Эти решения оправданы спецификой VPS/VDS — это **не пробелы**, а осознанный выбор:

| Отклонение | CIS | Причина |
|---|---|---|
| `disk_full_action = ROTATE` (не halt/single) | 6.2.2.3 | halt = недоступный VPS без физической консоли |
| `auditd -f 1` (не `-f 2`) по умолчанию | — | паника ядра уронит VPS; строгий режим за `--with-audit-strict` |
| Пароль GRUB не по умолчанию | 1.4.1 | без IP-KVM делает удалённый ребут невозможным; за `--with-grub-password` |
| USB/Firewire не в blacklist | 1.1.1 | на виртуалке устройств нет, риск задеть virtio |
| `chrony` вместо `systemd-timesyncd` | 2.3 | точнее на нестабильной сети VPS |
| `ptrace_scope=1` (не `2`) | 1.5.2 | сохранение возможности `strace`/`gdb` для диагностики |
| Старение паролей не по умолчанию | 5.4.1 | риск локаута; за `--with-password-aging` |
| userns не отключается по умолчанию | — | не ломать rootless-контейнеры; за `--no-userns` |

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

`~/.ssh/config` на клиенте:

```sshconfig
Host myserver
    HostName      <IP>
    Port          20202
    User          admin
    IdentityFile  ~/.ssh/admin_ssh_key
    AddKeysToAgent yes
```

---

## Диагностика и мониторинг

```bash
# Соответствие харденингу (без изменений)
bash ubuntu_hardening.sh --audit-only

# SSH
journalctl -u ssh -u sshd -f
ss -tlnp | grep 20202

# Fail2ban / UFW
fail2ban-client status sshd
ufw status verbose

# Auditd (новые ключи)
ausearch -k time-change | tail -20
ausearch -k logins      | tail -20
ausearch -k delete      | tail -20
ausearch -k MAC-policy  | tail -20
aureport --summary

# AppArmor / Chrony
aa-status
chronyc tracking

# PAM-блокировка (если --with-pam-lockout)
faillock --user admin

# AIDE (если --with-aide)
aide --check

# Отчёт аудита ФС/УЗ
less /root/hardening-audit-report.txt
```

---

## Что требует перезагрузки

- **Blacklist модулей ядра** — DCCP, SCTP, RDS, TIPC и редкие ФС
- **GRUB cmdline** — `audit=1`, `apparmor=1` (применяются при следующей загрузке)
- **`/var/tmp` bind-mount** — если `mount --bind` не применился в текущей сессии
- **`kernel.unprivileged_userns_clone`** — только если задан `--no-userns`

```bash
reboot
# затем проверка:
ssh -p 20202 -i ./admin_ssh_key admin@<IP>
```

---

## Восстановление при потере доступа

Все рискованные правки делают бэкапы. Через консоль провайдера (VNC/KVM):

```bash
# SSH
cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config && systemctl restart ssh

# PAM (если сломался вход после --with-pam-lockout / --with-pwhistory)
cp /etc/pam.d/common-auth.bak.*     /etc/pam.d/common-auth
cp /etc/pam.d/common-password.bak.* /etc/pam.d/common-password

# Снять блокировку faillock
faillock --user admin --reset

# fstab / grub
cp /etc/fstab.bak.* /etc/fstab
cp /etc/default/grub.bak.* /etc/default/grub && update-grub
```

---

## Ручное включение форвардинга

Если сервер используется как VPN/прокси, запустите с `--with-tcp-forwarding`, либо после установки:

```bash
sed -i 's/^AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
systemctl restart ssh

# плюс разрешить форвардинг в UFW и sysctl
ufw route allow in on eth0
sysctl -w net.ipv4.ip_forward=1
```
