#!/usr/bin/env bash
# =============================================================================
#  Ubuntu Hardening Script — VPS/VDS Edition
#  Целевая платформа: Ubuntu 22.04 / 24.04 на виртуальном сервере
#  Запускать от root сразу после получения сервера
#
#  Использование: bash ubuntu_hardening.sh
#
#  Что делает скрипт:
#    1. Генерирует ECDSA-521 ключевую пару прямо на сервере
#    2. Создаёт пользователя admin и настраивает ключевой вход
#    3. Харденит SSH, ядро, файловую систему, сеть
#    4. Устанавливает UFW, Fail2ban, Auditd
#    5. Удаляет телеметрию
#
#  ВАЖНО для VPS:
#    Убедитесь, что у вас есть доступ к VNC/консоли провайдера
#    на случай потери SSH-доступа во время настройки!
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКИ — измените под себя
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_USER="admin"
SSH_PORT="20202"                     # значение по умолчанию, будет переспрошено
KEY_PATH="/root/admin_ssh_key"       # куда сохранить сгенерированную пару ключей

# Форвардинг отключён по умолчанию.
# На VPS туннели могут быть нужны для проксирования — включайте осознанно.
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"
# ──────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}===================================================${NC}";
            echo -e "${CYAN}  $*${NC}";
            echo -e "${CYAN}===================================================${NC}"; }

# ──────────────────────────────────────────────────────────────────────────────
# 0. Предстартовые проверки
# ──────────────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускайте скрипт от root"

# ── Выбор порта SSH ───────────────────────────────────────────────────────────
echo ""
echo -e "  SSH-порт по умолчанию: ${YELLOW}${SSH_PORT}${NC}"
echo "  Допустимый диапазон  : 1024–65535"
echo "  (Enter — оставить ${SSH_PORT})"
while true; do
    read -r -p "  Введите порт SSH: " USER_SSH_PORT
    if [[ -z "${USER_SSH_PORT}" ]]; then
        # Оставляем значение по умолчанию
        break
    elif [[ "${USER_SSH_PORT}" =~ ^[0-9]+$ ]]       && (( USER_SSH_PORT >= 1024 && USER_SSH_PORT <= 65535 )); then
        SSH_PORT="${USER_SSH_PORT}"
        break
    else
        echo -e "  ${RED}Некорректный порт.${NC} Введите число от 1024 до 65535."
    fi
done
info "Будет использован SSH-порт: ${SSH_PORT}"
echo ""

# Определяем гипервизор — некоторые настройки зависят от платформы
HYPERVISOR="bare"
if command -v systemd-detect-virt &>/dev/null; then
    HYPERVISOR=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    info "Обнаружен гипервизор: ${HYPERVISOR}"
fi

section "0. Обновление системы и установка пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq -o Dpkg::Options::="--force-confdef" \
                        -o Dpkg::Options::="--force-confold"
apt-get install -y -qq     ufw fail2ban auditd audispd-plugins     libpam-pwquality unattended-upgrades apt-listchanges     acl curl wget gnupg2 chrony
info "Пакеты установлены"

# ──────────────────────────────────────────────────────────────────────────────
# 1. Имя хоста, часовой пояс и синхронизация времени
# ──────────────────────────────────────────────────────────────────────────────
section "1. Имя хоста, часовой пояс, NTP"

# ── Имя хоста ─────────────────────────────────────────────────────────────────
CURRENT_HOSTNAME=$(hostname)
EFFECTIVE_HOSTNAME="${CURRENT_HOSTNAME}"
echo ""
echo -e "  Текущее имя хоста: ${YELLOW}${CURRENT_HOSTNAME}${NC}"
read -r -p "  Введите новое имя хоста (Enter — оставить текущее): " NEW_HOSTNAME
if [[ -n "${NEW_HOSTNAME}" && "${NEW_HOSTNAME}" != "${CURRENT_HOSTNAME}" ]]; then
    # RFC 1123: только a-z, 0-9 и дефис, не длиннее 63 символов
    if [[ "${NEW_HOSTNAME}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        hostnamectl set-hostname "${NEW_HOSTNAME}"
        EFFECTIVE_HOSTNAME="${NEW_HOSTNAME}"
        info "Имя хоста задано: ${NEW_HOSTNAME}"
    else
        warn "Недопустимые символы в имени хоста — оставляем ${CURRENT_HOSTNAME}"
    fi
else
    info "Имя хоста оставлено: ${CURRENT_HOSTNAME}"
fi

# ── FQDN ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "  Текущий FQDN: ${YELLOW}$(hostname --fqdn 2>/dev/null || echo 'не задан')${NC}"
echo "  Пример: ${EFFECTIVE_HOSTNAME}.example.com"
echo "  (Enter — пропустить, FQDN не будет задан)"
read -r -p "  Введите FQDN для этого сервера: " NEW_FQDN
if [[ -n "${NEW_FQDN}" ]]; then
    # Базовая валидация FQDN: метки через точки, каждая по RFC 1123
    if [[ "${NEW_FQDN}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        # Убираем старые записи для этого хоста, добавляем FQDN + short name
        sed -i "/127\.0\.1\.1/d" /etc/hosts
        echo -e "127.0.1.1\t${NEW_FQDN} ${EFFECTIVE_HOSTNAME}" >> /etc/hosts
        # Записываем canonical name в hostnamectl (статический hostname = short)
        hostnamectl set-hostname "${EFFECTIVE_HOSTNAME}"
        info "FQDN задан: ${NEW_FQDN}"
        info "/etc/hosts: 127.0.1.1 -> ${NEW_FQDN} ${EFFECTIVE_HOSTNAME}"
    else
        warn "Некорректный FQDN '${NEW_FQDN}' — пропускаем"
        warn "Формат: hostname.domain.tld (например server01.example.com)"
        # Обновляем /etc/hosts хотя бы для short name
        sed -i "/127\.0\.1\.1/d" /etc/hosts
        echo -e "127.0.1.1\t${EFFECTIVE_HOSTNAME}" >> /etc/hosts
    fi
else
    info "FQDN не задан — обновляем /etc/hosts для short name"
    sed -i "/127\.0\.1\.1/d" /etc/hosts
    echo -e "127.0.1.1\t${EFFECTIVE_HOSTNAME}" >> /etc/hosts
fi
# ── Часовой пояс ──────────────────────────────────────────────────────────────
CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone)
echo ""
echo -e "  Текущий часовой пояс: ${YELLOW}${CURRENT_TZ}${NC}"
echo "  Популярные варианты:"
echo "    Europe/Moscow   Europe/Berlin   Europe/London"
echo "    UTC             Asia/Dubai      America/New_York"
echo "  Полный список: timedatectl list-timezones"
echo ""
read -r -p "  Введите часовой пояс (Enter — оставить ${CURRENT_TZ}): " NEW_TZ
if [[ -n "${NEW_TZ}" ]]; then
    if timedatectl list-timezones | grep -qx "${NEW_TZ}"; then
        timedatectl set-timezone "${NEW_TZ}"
        info "Часовой пояс задан: ${NEW_TZ}"
    else
        warn "Неизвестный часовой пояс '${NEW_TZ}' — оставляем ${CURRENT_TZ}"
        warn "Проверьте: timedatectl list-timezones | grep <регион>"
    fi
else
    info "Часовой пояс оставлен: ${CURRENT_TZ}"
fi
# ── DNS ───────────────────────────────────────────────────────────────────────
echo ""
echo "  Текущие DNS-серверы:"
if command -v resolvectl &>/dev/null; then
    resolvectl status 2>/dev/null | grep "DNS Servers" | head -3 | sed 's/^/    /' || \
        grep "^nameserver" /etc/resolv.conf | sed 's/^/    /' || echo "    (не определены)"
else
    grep "^nameserver" /etc/resolv.conf | sed 's/^/    /' || echo "    (не определены)"
fi
echo ""
echo "  Популярные варианты:"
echo "    Cloudflare : 1.1.1.1  1.0.0.1"
echo "    Google     : 8.8.8.8  8.8.4.4"
echo "    Quad9      : 9.9.9.9  149.112.112.112"
echo "    Yandex     : 77.88.8.8  77.88.8.1"
echo ""
echo "  (Enter — пропустить, DNS не меняется)"
read -r -p "  Введите основной DNS: " DNS1
read -r -p "  Введите резервный DNS (Enter — пропустить): " DNS2

# Валидация IP-адреса
is_valid_ip() {
    local ip="$1"
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    read -ra octets <<< "${ip}"
    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

DNS_SERVERS=()
if [[ -n "${DNS1}" ]]; then
    if is_valid_ip "${DNS1}"; then
        DNS_SERVERS+=("${DNS1}")
    else
        warn "Некорректный IP '${DNS1}' — DNS не изменён"
        DNS1=""
    fi
fi
if [[ -n "${DNS2}" ]]; then
    if is_valid_ip "${DNS2}"; then
        DNS_SERVERS+=("${DNS2}")
    else
        warn "Некорректный IP '${DNS2}' — резервный DNS пропущен"
        DNS2=""
    fi
fi

if [[ ${#DNS_SERVERS[@]} -gt 0 ]]; then
    # Настраиваем через systemd-resolved (современный способ для Ubuntu 22.04+)
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        {
            echo "[Resolve]"
            echo "DNS=${DNS_SERVERS[*]}"
            echo "FallbackDNS="
            # DNS over TLS — если серверы поддерживают (Cloudflare, Google, Quad9)
            echo "DNSOverTLS=opportunistic"
            echo "DNSSEC=allow-downgrade"
        } > /etc/systemd/resolved.conf.d/custom-dns.conf
        systemctl restart systemd-resolved
        info "DNS настроен через systemd-resolved: ${DNS_SERVERS[*]}"
    else
        # Fallback: прямая запись в /etc/resolv.conf
        # Снимаем защиту от перезаписи если есть
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "# Настроено ubuntu_hardening.sh"
            for dns in "${DNS_SERVERS[@]}"; do
                echo "nameserver ${dns}"
            done
            echo "options timeout:2 attempts:3"
        } > /etc/resolv.conf
        # Защищаем от перезаписи DHCP-клиентом
        chattr +i /etc/resolv.conf
        info "DNS записан в /etc/resolv.conf: ${DNS_SERVERS[*]}"
        warn "/etc/resolv.conf защищён от перезаписи (chattr +i)"
    fi
else
    info "DNS не изменён"
fi

# ── NTP через Chrony ──────────────────────────────────────────────────────────
# Chrony точнее и надёжнее systemd-timesyncd: быстрее синхронизируется
# после долгого простоя, лучше работает при нестабильной сети на VPS.

# Отключаем systemd-timesyncd чтобы не конфликтовал с chrony
systemctl disable --now systemd-timesyncd 2>/dev/null || true

# Пользовательские NTP-серверы
echo ""
echo "  NTP-серверы по умолчанию:"
echo "    pool.ntp.org (0-3) + time.cloudflare.com"
echo ""
echo "  Свои NTP-серверы (например: ntp.vашprovider.ru или IP)."
echo "  Можно указать несколько через пробел."
echo "  (Enter — использовать серверы по умолчанию)"
read -r -p "  Введите свои NTP-серверы: " CUSTOM_NTP

if [[ -n "${CUSTOM_NTP}" ]]; then
    NTP_LINES=""
    for srv in ${CUSTOM_NTP}; do
        NTP_LINES+="server ${srv} iburst"$'\n'
    done
    info "Будут использованы пользовательские NTP: ${CUSTOM_NTP}"
else
    NTP_LINES="pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst
server time.cloudflare.com iburst nts"
    info "Используются NTP-серверы по умолчанию"
fi

cat > /etc/chrony/chrony.conf << EOF
# Сгенерировано ubuntu_hardening.sh
${NTP_LINES}

# Drift-файл: хранит погрешность часов между перезапусками
driftfile /var/lib/chrony/drift

# Разрешить большой прыжок времени только при первом старте
makestep 1.0 3

# Минимум источников для считать время синхронизированным
minsources 2

# Не принимать источник с большим rtt (нестабильная сеть на VPS)
maxdistance 1.5

# Разрешить chronyc только с localhost
bindcmdaddress 127.0.0.1
bindcmdaddress ::1

# Логирование
logdir /var/log/chrony
log measurements statistics tracking
EOF

systemctl enable --now chrony
sleep 2

# Принудительная первая синхронизация
chronyc makestep 2>/dev/null || true

info "Chrony запущен и настроен"
echo ""
echo "  Статус синхронизации времени:"
timedatectl show --property=NTPSynchronized --value 2>/dev/null | \
    grep -q "yes" && echo -e "    NTP синхронизирован: ${GREEN}yes${NC}" \
                  || echo -e "    NTP синхронизирован: ${YELLOW}ожидание...${NC}"
echo ""
chronyc tracking 2>/dev/null | grep -E "Reference ID|System time|Leap status" \
    | sed 's/^/    /' || true
echo ""
# ──────────────────────────────────────────────────────────────────────────────
# 2. Генерация SSH-ключевой пары ECDSA-521
# ──────────────────────────────────────────────────────────────────────────────
section "2. Генерация SSH-ключевой пары (ECDSA 521 бит)"

rm -f "${KEY_PATH}" "${KEY_PATH}.pub"

echo ""
echo -e "${YELLOW}Придумайте надёжный пароль для приватного ключа.${NC}"
echo -e "${YELLOW}Он будет запрашиваться при каждом подключении по SSH.${NC}"
echo ""
ssh-keygen -t ecdsa -b 521 \
           -f "${KEY_PATH}" \
           -C "${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"

chmod 600 "${KEY_PATH}"
chmod 644 "${KEY_PATH}.pub"

info "Ключевая пара создана:"
info "  Приватный ключ : ${KEY_PATH}"
info "  Публичный ключ : ${KEY_PATH}.pub"

echo ""
echo -e "${YELLOW}+----------------------------------------------------------+${NC}"
echo -e "${YELLOW}|  СКАЧАЙТЕ ПРИВАТНЫЙ КЛЮЧ ДО ЗАВЕРШЕНИЯ СКРИПТА!          |${NC}"
echo -e "${YELLOW}|                                                           |${NC}"
echo -e "${YELLOW}|  С другого терминала выполните:                           |${NC}"
echo -e "${YELLOW}|  scp root@<IP>:${KEY_PATH} ./admin_ssh_key    |${NC}"
echo -e "${YELLOW}|                                                           |${NC}"
echo -e "${YELLOW}|  Или скопируйте содержимое ниже и сохраните в файл.       |${NC}"
echo -e "${YELLOW}+----------------------------------------------------------+${NC}"
echo ""
echo "--- ПРИВАТНЫЙ КЛЮЧ (сохраните в безопасное место) ---"
cat "${KEY_PATH}"
echo "------------------------------------------------------"
echo ""
echo "--- ПУБЛИЧНЫЙ КЛЮЧ ---"
cat "${KEY_PATH}.pub"
echo "----------------------"
echo ""

read -r -p "Нажмите Enter, когда сохраните приватный ключ..."

# ──────────────────────────────────────────────────────────────────────────────
# 3. Создание пользователя-администратора
# ──────────────────────────────────────────────────────────────────────────────
section "3. Создание пользователя ${ADMIN_USER}"

if id "${ADMIN_USER}" &>/dev/null; then
    warn "Пользователь ${ADMIN_USER} уже существует — обновляем SSH-ключ"
else
    # Группа с именем пользователя может уже существовать на Ubuntu
    # (например, "admin" — встроенная группа). Используем её как primary group.
    if getent group "${ADMIN_USER}" &>/dev/null; then
        useradd -m -s /bin/bash -g "${ADMIN_USER}" "${ADMIN_USER}"
        warn "Группа '${ADMIN_USER}' уже существовала — использована как primary group"
    else
        useradd -m -s /bin/bash "${ADMIN_USER}"
    fi
    usermod -aG sudo "${ADMIN_USER}"
    info "Пользователь ${ADMIN_USER} создан и добавлен в sudo"
fi

warn "Задайте пароль для ${ADMIN_USER} (нужен только для sudo, не для SSH):"
passwd "${ADMIN_USER}"

SSH_DIR="/home/${ADMIN_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
mkdir -p "${SSH_DIR}"
cat "${KEY_PATH}.pub" >> "${AUTH_KEYS}"
sort -u "${AUTH_KEYS}" -o "${AUTH_KEYS}"
chown -R "${ADMIN_USER}:${ADMIN_USER}" "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chmod 600 "${AUTH_KEYS}"
info "Публичный ключ установлен для ${ADMIN_USER}"

# ──────────────────────────────────────────────────────────────────────────────
# 4. SSH hardening
# ──────────────────────────────────────────────────────────────────────────────
section "4. Настройка SSH (/etc/ssh/sshd_config)"

cat > /etc/ssh/my_banner << 'EOF'
*******************************************************************
*  WARNING: Unauthorized access is strictly prohibited.           *
*  All sessions are monitored and logged.                         *
*  Disconnect immediately if you are not an authorized user.      *
*******************************************************************
EOF

cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"

chmod 700 /etc/ssh
find /etc/ssh -type f -name "ssh_host_*_key"     -exec chmod 600 {} \;
find /etc/ssh -type f -name "ssh_host_*_key.pub" -exec chmod 644 {} \;

cat > /etc/ssh/sshd_config << EOF
# Generated by ubuntu_hardening.sh (VPS edition)

# Порт и протокол
Port ${SSH_PORT}
Protocol 2
AddressFamily inet

# Криптография — только современные алгоритмы
HostKeyAlgorithms ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Аутентификация
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
AuthenticationMethods publickey

# Тайм-ауты и лимиты
# ИСПРАВЛЕНО: LoginGraceTime 0 = без лимита (баг в оригинале), нужно 30
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
# 5 одновр. неаутентифицированных соединений; при 30% начинаем отказывать
MaxStartups 5:30:20
# Разрыв при простое: 5 мин x 2 = 10 минут
ClientAliveInterval 300
ClientAliveCountMax 2

# Только наш пользователь
AllowUsers ${ADMIN_USER}

# Форвардинг (отключён; включайте переменными в начале скрипта если нужны туннели)
AllowTcpForwarding ${TCP_FORWARDING}
GatewayPorts ${GATEWAY_PORTS}
X11Forwarding ${X11_FORWARDING}

# Прочее
PrintMotd no
PrintLastLog yes
Banner /etc/ssh/my_banner
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Скрыть версию SSH от сканеров
DebianBanner no
VersionAddendum none

# Verbose пишет fingerprint ключа при каждом входе — удобно для аудита
SyslogFacility AUTH
LogLevel VERBOSE
EOF

sshd -t && info "sshd_config прошёл валидацию" || error "Ошибка в sshd_config!"

# Имя службы SSH отличается в зависимости от версии Ubuntu
if systemctl list-units --type=service --all | grep -q "sshd.service"; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="ssh"
fi
systemctl restart "${SSH_SERVICE}"
systemctl is-active --quiet "${SSH_SERVICE}"     && info "SSH (${SSH_SERVICE}) перезапущен, активен на порту ${SSH_PORT}"     || error "SSH не запустился! Проверьте: journalctl -xe -u ${SSH_SERVICE}"

# Проверяем что порт реально слушается
sleep 1
ss -tlnp | grep ":${SSH_PORT}"     && info "Порт ${SSH_PORT} подтверждён в ss"     || warn "Порт ${SSH_PORT} не найден в ss — возможно нужна секунда или проверьте journalctl -xe"

# ──────────────────────────────────────────────────────────────────────────────
# 5. Блокировка root
# ──────────────────────────────────────────────────────────────────────────────
section "5. Блокировка учётной записи root"

passwd -l root
info "Пароль root заблокирован"

# su — только члены группы sudo
if grep -q "^#auth.*pam_wheel" /etc/pam.d/su 2>/dev/null; then
    sed -i 's/^#\(auth\s*required\s*pam_wheel.so\)/\1/' /etc/pam.d/su
else
    grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null || \
        echo "auth required pam_wheel.so group=sudo" >> /etc/pam.d/su
fi
info "su ограничен группой sudo"

# ──────────────────────────────────────────────────────────────────────────────
# 6. Firewall UFW
#    VPS-специфика: многие провайдеры (Hetzner, DO, Vultr) имеют свой
#    firewall поверх — дублируйте правила и там для защиты в глубину
# ──────────────────────────────────────────────────────────────────────────────
section "6. UFW — брандмауэр"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# limit = встроенный rate-limit UFW: 6 попыток за 30 сек -> блок
ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited"

ufw --force enable
ufw status verbose
info "UFW включён: входящий трафик запрещён кроме SSH:${SSH_PORT}"

# ──────────────────────────────────────────────────────────────────────────────
# 7. Fail2ban
# ──────────────────────────────────────────────────────────────────────────────
section "7. Fail2ban"

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = 1h
findtime  = 10m
maxretry  = 3
backend   = systemd
banaction = ufw

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 24h
EOF

systemctl enable --now fail2ban
info "Fail2ban: 3 неудачных попытки -> бан 24 часа"

# ──────────────────────────────────────────────────────────────────────────────
# 8. Cron hardening
# ──────────────────────────────────────────────────────────────────────────────
section "8. Защита планировщика cron"

for path in /etc/crontab \
            /etc/cron.hourly/ /etc/cron.daily/ \
            /etc/cron.weekly/ /etc/cron.monthly/ \
            /etc/cron.d/; do
    [[ -e "$path" ]] || continue
    chown root:root "$path"
    chmod og-rwx   "$path"
done

echo "root" > /etc/cron.allow && chmod 600 /etc/cron.allow
[[ -f /etc/cron.deny ]] && rm /etc/cron.deny

if command -v at &>/dev/null; then
    echo "root" > /etc/at.allow && chmod 600 /etc/at.allow
    [[ -f /etc/at.deny ]] && rm /etc/at.deny
fi

info "cron/at: доступ разрешён только root"

# ──────────────────────────────────────────────────────────────────────────────
# 9. Защита разделов (fstab)
#    VPS-специфика: /home почти всегда на том же разделе что /.
#    Используем systemd-unit для remount /home.
#    /var/tmp привязываем к /tmp через bind.
# ──────────────────────────────────────────────────────────────────────────────
section "9. Защита разделов (/tmp, /dev/shm, /var/tmp, /home)"

FSTAB="/etc/fstab"
cp "${FSTAB}" "${FSTAB}.bak.$(date +%Y%m%d%H%M%S)"

fstab_set() {
    local mountpoint="$1"
    local entry="$2"
    sed -i "\|\s${mountpoint}\s|d" "${FSTAB}"
    echo "${entry}" >> "${FSTAB}"
    info "fstab: ${mountpoint} настроен"
}

# /tmp
fstab_set "/tmp" \
    "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"

# /dev/shm  (seclabel убрана — только для SELinux, Ubuntu использует AppArmor)
fstab_set "/dev/shm" \
    "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0"

# /var/tmp -> bind к /tmp (наследует все защитные флаги; пропущен в оригинале)
if ! grep -qE "\s/var/tmp\s" "${FSTAB}"; then
    echo "/tmp /var/tmp none bind 0 0" >> "${FSTAB}"
    info "fstab: /var/tmp привязан к /tmp (bind)"
fi

# Применяем без перезагрузки
mount -o remount /tmp     2>/dev/null && info "  /tmp перемонтирован"     || warn "/tmp: применится после reboot"
mount -o remount /dev/shm 2>/dev/null && info "  /dev/shm перемонтирован" || warn "/dev/shm: применится после reboot"
mountpoint -q /var/tmp || mount --bind /tmp /var/tmp 2>/dev/null && \
    info "  /var/tmp примонтирован" || warn "/var/tmp: применится после reboot"

# /home — на VPS чаще не отдельный раздел
if grep -qE "\s/home\s" "${FSTAB}"; then
    sed -i "s|\(\s/home\s.*defaults\)|\1,noexec,nosuid,nodev|" "${FSTAB}"
    mount -o remount /home 2>/dev/null || warn "/home: применится после reboot"
    info "fstab: /home защищён (отдельный раздел)"
else
    warn "/home не является отдельным разделом — применяем через systemd unit"
    cat > /etc/systemd/system/remount-home.service << 'SVCEOF'
[Unit]
Description=Remount /home with noexec,nosuid,nodev
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/mount -o remount,noexec,nosuid,nodev /home
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable remount-home.service
    systemctl start  remount-home.service 2>/dev/null || \
        warn "remount-home запустится при следующей загрузке"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 10. Kernel / sysctl hardening
# ──────────────────────────────────────────────────────────────────────────────
section "10. Параметры ядра (sysctl)"

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# ============================================================
#  Сетевая безопасность
# ============================================================

# Обратная проверка пути (анти-спуфинг)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# VPS — не роутер, отключить форвардинг
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Защита от SYN-flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Не принимать ICMP-редиректы (MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Не отправлять редиректы
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Игнорировать broadcast ping (Smurf)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Логировать martian-пакеты (подозрительные источники)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# IPv6: отключить RA если IPv6 не нужен
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Защита от TIME-WAIT атак (RFC 1337)
net.ipv4.tcp_rfc1337 = 1

# ============================================================
#  Безопасность ядра
# ============================================================

# ptrace (Yama): 1 = только родительский процесс может трассировать
# (не 2, чтобы не сломать strace/gdb при отладке на VPS)
kernel.yama.ptrace_scope = 1

# Запретить чтение dmesg обычным пользователям
kernel.dmesg_restrict = 1

# Скрыть адреса ядра из /proc и /sys
kernel.kptr_restrict = 2

# Отключить SysRq (на VPS есть консоль провайдера)
kernel.sysrq = 0

# ASLR: максимальная рандомизация адресного пространства
kernel.randomize_va_space = 2

# Core dump: запретить
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false

# Защита symlink/hardlink (/tmp-атаки)
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Ограничить user namespaces
# Отключите если используете Docker/Podman rootless
kernel.unprivileged_userns_clone = 0
EOF

sysctl --system -q
info "Параметры ядра применены"

# ──────────────────────────────────────────────────────────────────────────────
# 11. Blacklist модулей ядра
#     VPS-специфика: USB/Firewire убраны — на виртуалке их нет,
#     а блокировка некоторых virtio-драйверов может сломать систему.
#     Блокируем только сетевые протоколы и ФС с историей уязвимостей.
# ──────────────────────────────────────────────────────────────────────────────
section "11. Blacklist опасных модулей ядра"

cat > /etc/modprobe.d/hardening-blacklist.conf << 'EOF'
# Редко используемые файловые системы (вектор атаки через autoMount)
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist udf
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false

# Устаревшие сетевые протоколы с историей CVE
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
install dccp /bin/false
install sctp /bin/false
install rds  /bin/false
install tipc /bin/false
EOF

update-initramfs -u -k all 2>/dev/null || true
info "Blacklist модулей применён (полная сила — после reboot)"

# ──────────────────────────────────────────────────────────────────────────────
# 12. Core dump — отключение
# ──────────────────────────────────────────────────────────────────────────────
section "12. Отключение core dump"

grep -q "hard core" /etc/security/limits.conf || \
cat >> /etc/security/limits.conf << 'EOF'
*    hard    core    0
*    soft    core    0
root hard    core    0
EOF

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

info "Core dump отключён"

# ──────────────────────────────────────────────────────────────────────────────
# 13. Auditd
# ──────────────────────────────────────────────────────────────────────────────
section "13. Auditd — аудит системных событий"

cat > /etc/audit/rules.d/99-hardening.rules << EOF
-D
-b 8192
# Режим сбоя 1 = писать в syslog (не 2/паника — VPS без физического доступа!)
-f 1

# Идентификация
-w /etc/passwd    -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/gshadow   -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH
-w /etc/ssh/sshd_config          -p wa -k sshd_config
-w /home/${ADMIN_USER}/.ssh/     -p wa -k ssh_keys

# Cron
-w /etc/crontab       -p wa -k cron
-w /etc/cron.d/       -p wa -k cron
-w /etc/cron.daily/   -p wa -k cron
-w /etc/cron.hourly/  -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/  -p wa -k cron
-w /var/spool/cron/   -p wa -k cron

# Управление привилегиями
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat             -k file_perm
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown      -k file_perm
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid   -k priv_esc
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000    -k priv_exec

# Модули ядра
-w /sbin/insmod    -p x -k kernel_modules
-w /sbin/rmmod     -p x -k kernel_modules
-w /sbin/modprobe  -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules

# Сеть
-a always,exit -F arch=b64 -S socket  -F a0=2 -k net_socket
-a always,exit -F arch=b64 -S connect          -k net_connect
-a always,exit -F arch=b64 -S bind             -k net_bind

# Загрузчик и ядро
-w /boot/ -p wa -k boot

# Сделать правила неизменяемыми до перезагрузки
-e 2
EOF

service auditd restart 2>/dev/null || systemctl restart auditd
info "auditd настроен и запущен"

# ──────────────────────────────────────────────────────────────────────────────
# 14. AppArmor
# ──────────────────────────────────────────────────────────────────────────────
section "14. AppArmor"

if ! dpkg -l apparmor-utils &>/dev/null 2>&1; then
    apt-get install -y -qq apparmor apparmor-utils
fi

systemctl enable --now apparmor
find /etc/apparmor.d/ -maxdepth 1 -type f | while read -r profile; do
    aa-enforce "$profile" 2>/dev/null || true
done
info "AppArmor: профили переведены в enforce"

# ──────────────────────────────────────────────────────────────────────────────
# 15. sudo hardening
# ──────────────────────────────────────────────────────────────────────────────
section "15. Настройка sudo"

cat > /etc/sudoers.d/99-hardening << 'EOF'
Defaults    log_output
Defaults    logfile=/var/log/sudo.log
Defaults    timestamp_timeout=5
Defaults    !visiblepw
Defaults    requiretty
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/99-hardening
visudo -c && info "sudo: конфигурация корректна" || warn "Проверьте sudoers вручную!"

# ──────────────────────────────────────────────────────────────────────────────
# 16. Политика паролей (PAM / pwquality)
# ──────────────────────────────────────────────────────────────────────────────
section "16. Политика паролей"

cat > /etc/security/pwquality.conf << 'EOF'
minlen = 16
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
dictcheck = 1
gecoscheck = 1
EOF

info "Политика паролей: минимум 16 символов, все классы символов"

# ──────────────────────────────────────────────────────────────────────────────
# 17. Права на системные файлы
# ──────────────────────────────────────────────────────────────────────────────
section "17. Права на системные файлы"

chmod 600 /etc/shadow /etc/gshadow
chmod 644 /etc/passwd /etc/group
chmod 700 /boot 2>/dev/null || true

# История shell root -> /dev/null
ln -sf /dev/null /root/.bash_history 2>/dev/null || true

# Убрать SUID у нечасто используемых утилит
for bin in /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp; do
    [[ -u "$bin" ]] && { chmod u-s "$bin"; info "Убран SUID: $bin"; }
done

info "Права на системные файлы настроены"

# ──────────────────────────────────────────────────────────────────────────────
# 18. Удаление телеметрии
# ──────────────────────────────────────────────────────────────────────────────
section "18. Удаление телеметрии"

for pkg in ubuntu-report popularity-contest apport whoopsie; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        apt-get purge -y -qq "$pkg" && info "Удалён: $pkg"
    fi
done

apt-get autoremove -y -qq
apt-get autoclean -qq

systemctl disable --now apport.service   2>/dev/null || true
systemctl disable --now whoopsie.service 2>/dev/null || true

if command -v snap &>/dev/null; then
    snap set system metrics.status=disabled 2>/dev/null || true
    info "Snap-метрики отключены"
fi

info "Телеметрия удалена"

# ──────────────────────────────────────────────────────────────────────────────
# 19. Автоматические security-обновления
# ──────────────────────────────────────────────────────────────────────────────
section "19. Автоматические security-обновления"

# ── Конфигурация unattended-upgrades ─────────────────────────────────────────
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Разрешённые источники обновлений
Unattended-Upgrade::Allowed-Origins {
    // Только security-патчи
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    // Стабильные обновления (bugfix, не только security)
    "${distro_id}:${distro_codename}-updates";
};

// Критичные сервисы — обновлять вручную, чтобы контролировать даунтайм
Unattended-Upgrade::Package-Blacklist {
    "docker*";
    "kube*";
    "postgresql*";
    "mysql*";
    "mariadb*";
    "nginx*";
    "apache2*";
    "redis*";
    "mongodb*";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// На VPS не включаем авто-reboot — делайте сами в удобное время
Unattended-Upgrade::Automatic-Reboot "false";

// Писать письмо root только при ошибках, а не после каждого успешного прогона
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

# ── Периодичность запуска apt ─────────────────────────────────────────────────
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# ── Таймер apt-daily: фиксированное время 03:00 вместо случайного в течение дня
# Используем systemd drop-in — не перезаписываем системный unit
mkdir -p /etc/systemd/system/apt-daily.timer.d
cat > /etc/systemd/system/apt-daily.timer.d/override.conf << 'EOF'
[Timer]
# Сбрасываем расписание по умолчанию (OnBootSec + OnUnitActiveSec)
OnBootSec=
OnCalendar=
OnUnitActiveSec=
# Запуск в 03:00 с разбросом до 10 минут (чтобы не все VPS стучались одновременно)
OnCalendar=*-*-* 03:00
RandomizedDelaySec=10m
EOF

# ── Таймер apt-daily-upgrade: через 30 минут после apt-daily (загрузки списков)
mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
cat > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf << 'EOF'
[Timer]
OnBootSec=
OnCalendar=
OnUnitActiveSec=
# 30 минут после apt-daily — достаточно для скачивания списков пакетов
OnCalendar=*-*-* 03:30
RandomizedDelaySec=10m
EOF

systemctl daemon-reload
systemctl restart apt-daily.timer apt-daily-upgrade.timer

info "Автообновления настроены:"
info "  apt-daily         : 03:00 ± 10 мин (обновление списков)"
info "  apt-daily-upgrade : 03:30 ± 10 мин (установка обновлений)"
info "  Blacklist: docker, kube, postgresql, mysql, nginx и др."
info "  Письмо root: только при ошибках"

# Показываем следующий плановый запуск
echo ""
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager 2>/dev/null \
    | sed 's/^/  /' || true

# ──────────────────────────────────────────────────────────────────────────────
# 20. Удаление приватного ключа с сервера
# ──────────────────────────────────────────────────────────────────────────────
section "20. Финальный шаг — удаление приватного ключа с сервера"

echo ""
echo -e "${RED}+------------------------------------------------------------+${NC}"
echo -e "${RED}|  ПОСЛЕДНИЙ ШАГ: УДАЛЕНИЕ ПРИВАТНОГО КЛЮЧА С СЕРВЕРА       |${NC}"
echo -e "${RED}|                                                            |${NC}"
echo -e "${RED}|  Проверьте вход в новом терминале:                         |${NC}"
echo -e "${RED}|  ssh -p ${SSH_PORT} -i ./admin_ssh_key ${ADMIN_USER}@<IP>         |${NC}"
echo -e "${RED}|                                                            |${NC}"
echo -e "${RED}|  Если ключ НЕ скачан — скачайте сейчас, не закрывая окно! |${NC}"
echo -e "${RED}+------------------------------------------------------------+${NC}"
echo ""
read -r -p "Вы скачали ключ и вход работает? Удалить с сервера? [y/N]: " confirm

if [[ "${confirm}" =~ ^[Yy]$ ]]; then
    if command -v shred &>/dev/null; then
        shred -vuz "${KEY_PATH}"
    else
        rm -f "${KEY_PATH}"
    fi
    info "Приватный ключ надёжно удалён с сервера"
    info "Публичный ключ оставлен: ${KEY_PATH}.pub"
else
    warn "Ключ оставлен по адресу: ${KEY_PATH}"
    warn "Удалите вручную после скачивания: shred -vuz ${KEY_PATH}"
fi

# ──────────────────────────────────────────────────────────────────────────────
# ИТОГ
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}+============================================================+${NC}"
echo -e "${GREEN}|             HARDENING ЗАВЕРШЁН УСПЕШНО                    |${NC}"
echo -e "${GREEN}+============================================================+${NC}"
echo ""
printf "  %-48s %s\n" "SSH-ключ ECDSA-521 сгенерирован"        "[OK]"
printf "  %-48s %s\n" "Пользователь '${ADMIN_USER}' создан"    "[OK]"
printf "  %-48s %s\n" "SSH: порт ${SSH_PORT}, только ключи"    "[OK]"
printf "  %-48s %s\n" "Root заблокирован"                      "[OK]"
printf "  %-48s %s\n" "UFW: разрешён только SSH:${SSH_PORT}"   "[OK]"
printf "  %-48s %s\n" "Fail2ban: 3 попытки -> бан 24ч"         "[OK]"
printf "  %-48s %s\n" "sysctl: сеть + ядро"                    "[OK]"
printf "  %-48s %s\n" "Blacklist: опасные ФС/протоколы"        "[OK]"
printf "  %-48s %s\n" "/tmp /dev/shm /var/tmp: noexec"         "[OK]"
printf "  %-48s %s\n" "Cron: только root"                      "[OK]"
printf "  %-48s %s\n" "Auditd: полный аудит"                   "[OK]"
printf "  %-48s %s\n" "Core dump отключён"                     "[OK]"
printf "  %-48s %s\n" "AppArmor: enforce"                      "[OK]"
printf "  %-48s %s\n" "sudo: лог + тайм-аут 5 мин"            "[OK]"
printf "  %-48s %s\n" "Политика паролей: 16+ символов"         "[OK]"
printf "  %-48s %s\n" "Телеметрия удалена"                     "[OK]"
printf "  %-48s %s\n" "Автообновления security"                "[OK]"
echo ""
echo -e "  ${YELLOW}Требуется перезагрузка для:${NC}"
echo "    - blacklist модулей ядра (DCCP, SCTP, редкие ФС)"
echo "    - /var/tmp bind-mount (если не применился)"
echo "    - kernel.unprivileged_userns_clone"
echo ""
echo -e "  ${CYAN}Подключение после reboot:${NC}"
echo "    ssh -p ${SSH_PORT} -i ./admin_ssh_key ${ADMIN_USER}@<IP>"
echo ""
echo -e "  ${CYAN}Полезные команды:${NC}"
echo "    fail2ban-client status sshd       # статус банов"
echo "    ufw status verbose                # правила фаервола"
echo "    ausearch -k identity | tail -20   # последние события auditd"
echo "    aa-status                         # статус AppArmor"
echo ""
