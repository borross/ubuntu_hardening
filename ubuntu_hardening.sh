#!/usr/bin/env bash
# =============================================================================
#  Ubuntu Hardening Script — VPS/VDS Edition  (v2, bugfix release)
#  Целевая платформа: Ubuntu 22.04 / 24.04 / 26.04 на виртуальном сервере
#  Запускать от root сразу после получения сервера
#
#  Использование: bash ubuntu_hardening.sh
#
#  Изменения v2 (кратко):
#    - ssh.socket отключается (socket-активация игнорировала Port) 
#    - выбор типа ключа: ed25519 (рекомендуется) или ecdsa-521
#    - контрольная точка входа ПЕРЕД блокировкой root
#    - auditd: убраны шумные правила connect/socket (причина backlog exceeded),
#      убраны устаревшие dispatcher/disp_qos, добавлены arch=b32 правила,
#      повторный запуск при immutable-правилах не роняет скрипт
#    - chrony: minsources подстраивается под число серверов
#    - UFW: перед reset показывает слушающие порты и позволяет открыть свои
#    - фикс /etc/ssh (755, а не 700 — иначе ломается ssh-клиент)
#    - passwd в цикле (3 ошибки ввода не роняют скрипт из-за set -e)
#    - фикс noexec /tmp для apt (TempDir)
#    - лог выполнения в /root/hardening_<дата>.log, trap на ошибки
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

# Семейство адресов для SSH:
#   any  — IPv4 + IPv6 (безопасное значение по умолчанию)
#   inet — только IPv4 (НЕ ставьте на IPv6-only VPS — потеряете доступ!)
SSH_ADDRESS_FAMILY="any"

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

# ── Лог выполнения: весь вывод дублируется в файл ─────────────────────────────
RUN_LOG="/root/hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${RUN_LOG}") 2>&1
info "Лог выполнения: ${RUN_LOG}"

# ── Trap: при аварийном завершении показываем строку ──────────────────────────
trap 'echo -e "${RED}[x]${NC} Скрипт аварийно остановлен на строке ${LINENO} (см. ${RUN_LOG})"' ERR

# ── Проверка версии Ubuntu ────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
    error "Не удалось определить версию ОС (/etc/os-release не найден)"
fi
source /etc/os-release
UBUNTU_VERSION="${VERSION_ID:-unknown}"
case "${UBUNTU_VERSION}" in
    22.04|24.04|26.04)
        info "Версия Ubuntu: ${UBUNTU_VERSION} — поддерживается"
        ;;
    *)
        warn "Версия Ubuntu: ${UBUNTU_VERSION} — не тестировалась"
        warn "Скрипт написан для 22.04 / 24.04 / 26.04. Продолжить?"
        read -r -p "  [y/N]: " _ver_confirm
        [[ "${_ver_confirm}" =~ ^[Yy]$ ]] || error "Прерывание по версии ОС"
        ;;
esac

# ── Расчёт лимитов логирования (не более 10% свободного места на диске) ───────
LOG_PARTITION=$(df --output=target /var/log 2>/dev/null | tail -1 || df /var/log | awk 'NR==2{print $6}')
FREE_KB=$(df -k "${LOG_PARTITION}" | awk 'NR==2{print $4}')
LOG_QUOTA_MB=$(( FREE_KB / 10 / 1024 ))
(( LOG_QUOTA_MB < 50   )) && LOG_QUOTA_MB=50
(( LOG_QUOTA_MB > 2048 )) && LOG_QUOTA_MB=2048

AUDIT_NUM_LOGS=5
AUDIT_MAX_FILE_MB=$(( LOG_QUOTA_MB / AUDIT_NUM_LOGS ))
(( AUDIT_MAX_FILE_MB < 10 )) && AUDIT_MAX_FILE_MB=10

# Audit backlog — буфер в ОПЕРАТИВНОЙ памяти ядра, рассчитывается из RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
AUDIT_BACKLOG=$(( TOTAL_RAM_KB / 1024 * 8 ))
(( AUDIT_BACKLOG < 8192  )) && AUDIT_BACKLOG=8192
(( AUDIT_BACKLOG > 65536 )) && AUDIT_BACKLOG=65536

info "Раздел /var/log : ${LOG_PARTITION}, свободно: $(( FREE_KB / 1024 )) МБ"
info "Квота логов (10%): ${LOG_QUOTA_MB} МБ  |  audit backlog: ${AUDIT_BACKLOG}"
info "  auditd: ${AUDIT_NUM_LOGS} файлов × ${AUDIT_MAX_FILE_MB} МБ"

# ── Выбор порта SSH ───────────────────────────────────────────────────────────
echo ""
echo -e "  SSH-порт по умолчанию: ${YELLOW}${SSH_PORT}${NC}"
echo "  Допустимый диапазон  : 1024–65535"
echo "  (Enter — оставить ${SSH_PORT})"
while true; do
    read -r -p "  Введите порт SSH: " USER_SSH_PORT
    if [[ -z "${USER_SSH_PORT}" ]]; then
        break
    elif [[ "${USER_SSH_PORT}" =~ ^[0-9]+$ ]] \
      && (( USER_SSH_PORT >= 1024 && USER_SSH_PORT <= 65535 )); then
        SSH_PORT="${USER_SSH_PORT}"
        break
    else
        echo -e "  ${RED}Некорректный порт.${NC} Введите число от 1024 до 65535."
    fi
done
info "Будет использован SSH-порт: ${SSH_PORT}"
echo ""

# ── Выбор типа SSH-ключа ──────────────────────────────────────────────────────
echo -e "  Тип SSH-ключа:"
echo -e "    1) ${GREEN}ed25519${NC}   — современный, быстрый, рекомендуется"
echo "    2) ecdsa-521 — NIST P-521 (совместимость со старыми требованиями)"
echo "  (Enter — ed25519)"
KEY_TYPE="ed25519"
while true; do
    read -r -p "  Выбор [1/2]: " _key_choice
    case "${_key_choice}" in
        ""|1) KEY_TYPE="ed25519";   break ;;
        2)    KEY_TYPE="ecdsa-521"; break ;;
        *)    echo -e "  ${RED}Введите 1 или 2.${NC}" ;;
    esac
done
info "Тип ключа: ${KEY_TYPE}"
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
# rsyslog добавлен явно: минимальные образы 24.04+ могут идти без него,
# а на нём построено логирование sudo (секция 15)
apt-get install -y -qq \
    ufw fail2ban auditd audispd-plugins \
    libpam-pwquality unattended-upgrades apt-listchanges \
    acl curl wget gnupg2 chrony rsyslog
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
    if [[ "${NEW_FQDN}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        sed -i "/127\.0\.1\.1/d" /etc/hosts
        echo -e "127.0.1.1\t${NEW_FQDN} ${EFFECTIVE_HOSTNAME}" >> /etc/hosts
        hostnamectl set-hostname "${EFFECTIVE_HOSTNAME}"
        info "FQDN задан: ${NEW_FQDN}"
        info "/etc/hosts: 127.0.1.1 -> ${NEW_FQDN} ${EFFECTIVE_HOSTNAME}"
    else
        warn "Некорректный FQDN '${NEW_FQDN}' — пропускаем"
        warn "Формат: hostname.domain.tld (например server01.example.com)"
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

# Валидация NTP-сервера: IPv4 или hostname по RFC 1123
is_valid_ntp_server() {
    local srv="$1"
    is_valid_ip "${srv}" && return 0
    [[ "${srv}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
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
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        {
            echo "[Resolve]"
            echo "DNS=${DNS_SERVERS[*]}"
            echo "FallbackDNS="
            echo "DNSOverTLS=opportunistic"
            echo "DNSSEC=allow-downgrade"
        } > /etc/systemd/resolved.conf.d/custom-dns.conf
        systemctl restart systemd-resolved
        info "DNS настроен через systemd-resolved: ${DNS_SERVERS[*]}"
    else
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "# Настроено ubuntu_hardening.sh"
            for dns in "${DNS_SERVERS[@]}"; do
                echo "nameserver ${dns}"
            done
            echo "options timeout:2 attempts:3"
        } > /etc/resolv.conf
        chattr +i /etc/resolv.conf
        info "DNS записан в /etc/resolv.conf: ${DNS_SERVERS[*]}"
        warn "/etc/resolv.conf защищён от перезаписи (chattr +i)"
    fi
else
    info "DNS не изменён"
fi

# ── NTP через Chrony ──────────────────────────────────────────────────────────
systemctl disable --now systemd-timesyncd 2>/dev/null || true

echo ""
echo "  NTP-серверы по умолчанию:"
echo "    pool.ntp.org (0-3) + time.cloudflare.com"
echo ""
echo "  Свои NTP-серверы (например: ntp.vashprovider.ru или IP)."
echo "  Можно указать несколько через пробел."
echo "  (Enter — использовать серверы по умолчанию)"
read -r -p "  Введите свои NTP-серверы: " CUSTOM_NTP

NTP_SOURCE_COUNT=0
if [[ -n "${CUSTOM_NTP}" ]]; then
    NTP_LINES=""
    for srv in ${CUSTOM_NTP}; do
        if is_valid_ntp_server "${srv}"; then
            NTP_LINES+="server ${srv} iburst"$'\n'
            NTP_SOURCE_COUNT=$(( NTP_SOURCE_COUNT + 1 ))
        else
            warn "Некорректный NTP-сервер '${srv}' — пропущен"
        fi
    done
    if (( NTP_SOURCE_COUNT == 0 )); then
        warn "Ни один пользовательский NTP не прошёл валидацию — используем серверы по умолчанию"
        CUSTOM_NTP=""
    else
        info "Будут использованы пользовательские NTP (${NTP_SOURCE_COUNT} шт.)"
    fi
fi
if [[ -z "${CUSTOM_NTP}" ]]; then
    NTP_LINES="pool 0.ubuntu.pool.ntp.org iburst
pool 1.ubuntu.pool.ntp.org iburst
pool 2.ubuntu.pool.ntp.org iburst
pool 3.ubuntu.pool.ntp.org iburst
server time.cloudflare.com iburst nts"
    NTP_SOURCE_COUNT=5
    info "Используются NTP-серверы по умолчанию"
fi

# minsources: при одном источнике требование "минимум 2" заблокировало бы
# синхронизацию навсегда — подстраиваемся под реальное число серверов
NTP_MINSOURCES=2
(( NTP_SOURCE_COUNT < 2 )) && NTP_MINSOURCES=1

cat > /etc/chrony/chrony.conf << EOF
# Сгенерировано ubuntu_hardening.sh
${NTP_LINES}

# Drift-файл: хранит погрешность часов между перезапусками
driftfile /var/lib/chrony/drift

# Разрешить большой прыжок времени только при первом старте
makestep 1.0 3

# Минимум источников чтобы считать время синхронизированным
# (1, если задан единственный пользовательский сервер)
minsources ${NTP_MINSOURCES}

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
# 2. Генерация SSH-ключевой пары
# ──────────────────────────────────────────────────────────────────────────────
section "2. Генерация SSH-ключевой пары (${KEY_TYPE})"

rm -f "${KEY_PATH}" "${KEY_PATH}.pub"

echo ""
echo -e "${YELLOW}Придумайте надёжный пароль для приватного ключа.${NC}"
echo -e "${YELLOW}Он будет запрашиваться при каждом подключении по SSH.${NC}"
echo ""
if [[ "${KEY_TYPE}" == "ed25519" ]]; then
    ssh-keygen -t ed25519 \
               -f "${KEY_PATH}" \
               -C "${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"
else
    ssh-keygen -t ecdsa -b 521 \
               -f "${KEY_PATH}" \
               -C "${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"
fi

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
    info "Пользователь ${ADMIN_USER} создан"
fi

# usermod вынесен из ветки else: если пользователь существовал,
# но не был в sudo — раньше он туда не попадал (баг)
usermod -aG sudo "${ADMIN_USER}"
info "Пользователь ${ADMIN_USER} состоит в группе sudo"

# passwd в цикле: 3 ошибки ввода возвращают ≠0 и при set -e
# раньше роняли весь скрипт на середине
warn "Задайте пароль для ${ADMIN_USER} (нужен только для sudo, не для SSH):"
until passwd "${ADMIN_USER}"; do
    warn "Пароль не задан (несовпадение или слабый) — попробуйте ещё раз"
done

SSH_DIR="/home/${ADMIN_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
mkdir -p "${SSH_DIR}"
cat "${KEY_PATH}.pub" >> "${AUTH_KEYS}"
sort -u "${AUTH_KEYS}" -o "${AUTH_KEYS}"
chown -R "${ADMIN_USER}:$(id -gn "${ADMIN_USER}")" "${SSH_DIR}"
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

# ИСПРАВЛЕНО: было chmod 700 /etc/ssh — это ломало ssh-КЛИЕНТ для
# непривилегированных пользователей (нет доступа к /etc/ssh/ssh_config).
# Каталог должен быть 755, приватность обеспечивают права на сами файлы.
chmod 755 /etc/ssh
chmod 600 /etc/ssh/sshd_config
find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key"     -exec chmod 600 {} \;
find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key.pub" -exec chmod 644 {} \;

cat > /etc/ssh/sshd_config << EOF
# Generated by ubuntu_hardening.sh (VPS edition, v2)

# Порт и протокол
Port ${SSH_PORT}
Protocol 2
# any = IPv4+IPv6; inet = только IPv4 (настраивается переменной в скрипте)
AddressFamily ${SSH_ADDRESS_FAMILY}

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
# LoginGraceTime 0 = без лимита (баг в оригинале), нужно 30
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 5:30:20
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

# Drop-in файлы могут переопределять наш Port — убираем конфликтующие
if [[ -d /etc/ssh/sshd_config.d ]]; then
    if grep -rqs "^\s*Port\s" /etc/ssh/sshd_config.d/ 2>/dev/null; then
        mkdir -p /root/sshd_config.d.bak
        grep -rls "^\s*Port\s" /etc/ssh/sshd_config.d/ | while read -r f; do
            mv "$f" /root/sshd_config.d.bak/
            warn "Drop-in с директивой Port перемещён в /root/sshd_config.d.bak: $(basename "$f")"
        done
    fi
fi

sshd -t && info "sshd_config прошёл валидацию" || error "Ошибка в sshd_config!"

# ── ГЛАВНЫЙ ФИКС «порт не поменялся»: socket-активация SSH ────────────────────
# Ubuntu 22.10+ / 24.04 по умолчанию запускают SSH через ssh.socket.
# В этом режиме порт задаёт systemd-сокет, а Port в sshd_config ИГНОРИРУЕТСЯ.
# Переключаемся на классический режим службы.
if systemctl is-enabled ssh.socket &>/dev/null; then
    warn "Обнаружена socket-активация SSH (ssh.socket) — отключаем"
    systemctl disable --now ssh.socket
    systemctl enable ssh.service 2>/dev/null || true
    systemctl daemon-reload
    info "ssh.socket отключён: порт теперь управляется через sshd_config"
fi

# Имя службы SSH отличается в зависимости от версии Ubuntu
if systemctl list-units --type=service --state=running --all | grep -q "sshd.service"; then
    SSH_SERVICE="sshd"
else
    SSH_SERVICE="ssh"
fi
systemctl restart "${SSH_SERVICE}"
systemctl is-active --quiet "${SSH_SERVICE}" \
    && info "SSH (${SSH_SERVICE}) перезапущен, активен на порту ${SSH_PORT}" \
    || error "SSH не запустился! Проверьте: journalctl -xe -u ${SSH_SERVICE}"

# Проверяем что порт реально слушается
sleep 1
ss -tlnp | grep -q ":${SSH_PORT}\b" \
    && info "Порт ${SSH_PORT} подтверждён в ss" \
    || warn "Порт ${SSH_PORT} не найден в ss — проверьте journalctl -xe -u ${SSH_SERVICE}"

# ── КОНТРОЛЬНАЯ ТОЧКА: проверка входа ДО блокировки root ──────────────────────
# Раньше вход проверялся только в самом конце (секция 20), а root
# блокировался в секции 5 — при проблеме с ключом можно было потерять доступ.
echo ""
echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
echo -e "${YELLOW}|  КОНТРОЛЬНАЯ ТОЧКА — проверьте вход СЕЙЧАС                |${NC}"
echo -e "${YELLOW}|                                                            |${NC}"
echo -e "${YELLOW}|  В НОВОМ терминале (не закрывая этот):                     |${NC}"
echo -e "${YELLOW}|  ssh -p ${SSH_PORT} -i ./admin_ssh_key ${ADMIN_USER}@<IP>          |${NC}"
echo -e "${YELLOW}|                                                            |${NC}"
echo -e "${YELLOW}|  Следующий шаг заблокирует root — убедитесь, что вход      |${NC}"
echo -e "${YELLOW}|  под ${ADMIN_USER} работает!                               |${NC}"
echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
echo ""
while true; do
    read -r -p "Вход под ${ADMIN_USER} по ключу работает? [y = продолжить / n = прервать]: " _login_ok
    case "${_login_ok}" in
        [Yy]) break ;;
        [Nn]) error "Прервано пользователем: вход не работает. Root НЕ заблокирован, исправьте проблему и перезапустите скрипт." ;;
        *)    echo "  Введите y или n." ;;
    esac
done

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

# ИСПРАВЛЕНО: раньше ufw --force reset молча закрывал порты уже работающих
# сервисов (веб-сервер и т.п.). Показываем, что слушается, и даём открыть.
echo ""
echo "  Сейчас на сервере слушаются порты:"
ss -tlnp 2>/dev/null | awk 'NR>1 {print "    " $4 "  " $NF}' | sort -u || true
echo ""
echo "  UFW закроет ВСЁ входящее, кроме SSH:${SSH_PORT}."
echo "  Если нужны другие порты (например 80 443) — перечислите через пробел."
echo "  (Enter — открыть только SSH)"
read -r -p "  Дополнительные TCP-порты: " EXTRA_PORTS

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# limit = встроенный rate-limit UFW: 6 попыток за 30 сек -> блок
ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited"

if [[ -n "${EXTRA_PORTS:-}" ]]; then
    for p in ${EXTRA_PORTS}; do
        if [[ "${p}" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )); then
            ufw allow "${p}/tcp" comment "user-defined"
            info "UFW: открыт порт ${p}/tcp"
        else
            warn "Некорректный порт '${p}' — пропущен"
        fi
    done
fi

ufw --force enable
ufw status verbose
info "UFW включён: входящий трафик запрещён кроме SSH:${SSH_PORT}${EXTRA_PORTS:+ и ${EXTRA_PORTS}}"

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

fstab_set "/tmp" \
    "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"

# /dev/shm  (seclabel убрана — только для SELinux, Ubuntu использует AppArmor)
fstab_set "/dev/shm" \
    "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0"

# /var/tmp -> bind к /tmp (наследует все защитные флаги)
if ! grep -qE "\s/var/tmp\s" "${FSTAB}"; then
    echo "/tmp /var/tmp none bind 0 0" >> "${FSTAB}"
    info "fstab: /var/tmp привязан к /tmp (bind)"
fi

# Применяем без перезагрузки
mount -o remount /tmp     2>/dev/null && info "  /tmp перемонтирован"     || warn "/tmp: применится после reboot"
mount -o remount /dev/shm 2>/dev/null && info "  /dev/shm перемонтирован" || warn "/dev/shm: применится после reboot"
# ИСПРАВЛЕНО: было a || b && c — из-за приоритета операторов
# сообщение "примонтирован" выводилось даже когда mount не выполнялся
if mountpoint -q /var/tmp; then
    info "  /var/tmp уже примонтирован"
elif mount --bind /tmp /var/tmp 2>/dev/null; then
    info "  /var/tmp примонтирован (bind)"
else
    warn "/var/tmp: применится после reboot"
fi

# ФИКС noexec /tmp для apt: часть maintainer-скриптов dpkg выполняется
# из временного каталога — переносим его, иначе ночные unattended-upgrades
# могут падать с Permission denied
mkdir -p /var/lib/apt/tmp
cat > /etc/apt/apt.conf.d/99tempdir << 'EOF'
// /tmp смонтирован с noexec — apt использует отдельный каталог
APT::ExtractTemplates::TempDir "/var/lib/apt/tmp";
EOF
info "apt: временный каталог перенесён в /var/lib/apt/tmp (совместимость с noexec /tmp)"

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
EOF

# ── User namespaces: параметр зависит от ядра ─────────────────────────────────
# kernel.unprivileged_userns_clone — Debian/Ubuntu-патч, отсутствует на новых
# ядрах (24.04+/26.04). Там вместо него apparmor_restrict_unprivileged_userns.
# Пишем только те параметры, которые реально существуют в ядре.
{
    echo ""
    echo "# ============================================================"
    echo "#  Ограничение user namespaces (подобрано под текущее ядро)"
    echo "#  Отключите/закомментируйте если используете rootless Docker/Podman"
    echo "# ============================================================"
    if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
        echo "kernel.unprivileged_userns_clone = 0"
    fi
    if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
        echo "kernel.apparmor_restrict_unprivileged_userns = 1"
    fi
} >> /etc/sysctl.d/99-hardening.conf

sysctl --system -q
info "Параметры ядра применены"

# ──────────────────────────────────────────────────────────────────────────────
# 11. Blacklist модулей ядра
#     VPS-специфика: USB/Firewire убраны — на виртуалке их нет,
#     а блокировка некоторых virtio-драйверов может сломать систему.
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

# Повторный запуск скрипта: если правила уже immutable (-e 2),
# любая попытка их изменить или перезапустить auditd уронит скрипт.
if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
    warn "Правила auditd в режиме immutable (enabled 2) — изменить можно только после reboot"
    warn "Секция 13 пропущена. Новые правила применятся при следующей загрузке,"
    warn "если файлы /etc/audit/ уже содержат нужную конфигурацию."
else

# ── auditd.conf — лимиты хранения, рассчитанные из свободного места ──────────
# ИСПРАВЛЕНО: убраны dispatcher/disp_qos — удалены в auditd 3.x (Ubuntu 22.04+),
# audispd больше не существует как отдельный бинарник
mkdir -p /etc/audit
cat > /etc/audit/auditd.conf << EOF
# Сгенерировано ubuntu_hardening.sh
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = root

# Ротация: ${AUDIT_NUM_LOGS} файлов по ${AUDIT_MAX_FILE_MB} МБ каждый
# Итого: ~$(( AUDIT_NUM_LOGS * AUDIT_MAX_FILE_MB )) МБ — не более 10% свободного места
max_log_file = ${AUDIT_MAX_FILE_MB}
num_logs = ${AUDIT_NUM_LOGS}
max_log_file_action = ROTATE

# При нехватке места — не падать, а писать в syslog и ротировать
space_left = $(( AUDIT_MAX_FILE_MB * 2 ))
space_left_action = SYSLOG
admin_space_left = $(( AUDIT_MAX_FILE_MB ))
admin_space_left_action = ROTATE
disk_full_action = ROTATE
disk_error_action = SYSLOG

name_format = HOSTNAME

# Флаш: каждые 50 записей, асинхронно
flush = INCREMENTAL_ASYNC
freq = 50
EOF

# ── Правила аудита ─────────────────────────────────────────────────────────────
# ИСПРАВЛЕНО:
#   - удалены правила на socket/connect: аудит КАЖДОГО сетевого вызова на
#     сервере генерирует тысячи событий/сек — это и была главная причина
#     "backlog limit exceeded", увеличение буфера лечило симптом
#   - net_bind оставлен с фильтром по auid (новые слушающие сокеты — редкое
#     и действительно интересное событие)
#   - добавлены arch=b32 правила: без них 32-битные syscalls не аудировались
#     (классический способ обхода аудита)
#   - убран --backlog_wait_time 1: значение 1 мс УМЕНЬШАЛО ожидание
#     и увеличивало потери (комментарий в старой версии был неверным)
cat > /etc/audit/rules.d/99-hardening.rules << EOF
-D
# backlog рассчитан из RAM: ${AUDIT_BACKLOG} записей
-b ${AUDIT_BACKLOG}
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

# Управление привилегиями (b64 + b32 — иначе 32-битные вызовы не аудируются)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -k priv_esc
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec

# Модули ядра
-w /sbin/insmod    -p x -k kernel_modules
-w /sbin/rmmod     -p x -k kernel_modules
-w /sbin/modprobe  -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules

# Сеть: только bind реальных пользователей (новый слушающий сокет — редкое
# и значимое событие). socket/connect НЕ аудируем — источник backlog exceeded.
-a always,exit -F arch=b64 -S bind -F auid>=1000 -F auid!=unset -k net_bind

# Загрузчик и ядро
-w /boot/ -p wa -k boot

# Сделать правила неизменяемыми до перезагрузки
-e 2
EOF

# ИСПРАВЛЕНО: файл /etc/logrotate.d/audit удалён из скрипта.
# auditd ротирует логи сам (max_log_file_action = ROTATE); параллельный
# logrotate с рестартом auditd давал двойную ротацию и разрывы аудита.
rm -f /etc/logrotate.d/audit

mkdir -p /var/log/audit
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
info "auditd настроен: backlog=${AUDIT_BACKLOG}, ${AUDIT_NUM_LOGS}×${AUDIT_MAX_FILE_MB}МБ (≤10% диска)"

fi  # конец проверки immutable

# ──────────────────────────────────────────────────────────────────────────────
# 14. AppArmor
# ──────────────────────────────────────────────────────────────────────────────
section "14. AppArmor"

if ! dpkg -s apparmor-utils &>/dev/null; then
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
# Тайм-аут sudo-сессии — 5 минут
Defaults    timestamp_timeout=5
# Не показывать символы при вводе пароля
Defaults    !visiblepw
# Фиксированный безопасный PATH — защита от подмены системных утилит
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/99-hardening

visudo -c && info "sudo: конфигурация корректна" || warn "Проверьте sudoers вручную!"

# Логирование sudo через rsyslog (без плагинов, работает на всех версиях)
if ! grep -qs "sudo" /etc/rsyslog.d/*.conf 2>/dev/null; then
    cat > /etc/rsyslog.d/50-sudo.conf << 'RSYSEOF'
# Логи sudo в отдельный файл
:programname, isequal, "sudo" /var/log/sudo.log
& stop
RSYSEOF
    systemctl restart rsyslog 2>/dev/null || true
    info "sudo: логирование через rsyslog -> /var/log/sudo.log"
fi

touch /var/log/sudo.log
chmod 600 /var/log/sudo.log

info "sudo настроен: тайм-аут 5 мин, secure_path, лог -> /var/log/sudo.log"

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

# ИЗМЕНЕНО: symlink ~/.bash_history -> /dev/null удалён.
# Отключение истории — антифорензика: она помогает атакующему скрыть
# следы больше, чем защищает. Аудит команд root ведёт auditd (priv_exec).

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
    # dpkg -s вместо dpkg -l: -l возвращал 0 даже для удалённых пакетов (статус rc)
    if dpkg -s "$pkg" &>/dev/null; then
        apt-get purge -y -qq "$pkg" && info "Удалён: $pkg" || warn "Не удалось удалить: $pkg"
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

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

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
echo -e "${RED}|  Если ключ НЕ скачан — скачайте сейчас, не закрывая окно! |${NC}"
echo -e "${RED}|  scp -P 22 root@<IP>:${KEY_PATH} ./admin_ssh_key |${NC}"
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
printf "  %-48s %s\n" "SSH-ключ ${KEY_TYPE} сгенерирован"      "[OK]"
printf "  %-48s %s\n" "Пользователь '${ADMIN_USER}' создан"    "[OK]"
printf "  %-48s %s\n" "SSH: порт ${SSH_PORT}, только ключи"    "[OK]"
printf "  %-48s %s\n" "ssh.socket отключён (Port применяется)" "[OK]"
printf "  %-48s %s\n" "Root заблокирован (после проверки входа)" "[OK]"
printf "  %-48s %s\n" "UFW: разрешён только SSH:${SSH_PORT}"   "[OK]"
printf "  %-48s %s\n" "Fail2ban: 3 попытки -> бан 24ч"         "[OK]"
printf "  %-48s %s\n" "sysctl: сеть + ядро"                    "[OK]"
printf "  %-48s %s\n" "Blacklist: опасные ФС/протоколы"        "[OK]"
printf "  %-48s %s\n" "/tmp /dev/shm /var/tmp: noexec"         "[OK]"
printf "  %-48s %s\n" "Cron: только root"                      "[OK]"
printf "  %-48s %s\n" "Auditd: аудит без шумных правил"        "[OK]"
printf "  %-48s %s\n" "Core dump отключён"                     "[OK]"
printf "  %-48s %s\n" "AppArmor: enforce"                      "[OK]"
printf "  %-48s %s\n" "sudo: лог + тайм-аут 5 мин"            "[OK]"
printf "  %-48s %s\n" "Политика паролей: 16+ символов"         "[OK]"
printf "  %-48s %s\n" "Телеметрия удалена"                     "[OK]"
printf "  %-48s %s\n" "Автообновления security"                "[OK]"
echo ""
echo -e "  ${YELLOW}Лог выполнения:${NC} ${RUN_LOG}"
echo ""
echo -e "  ${YELLOW}Требуется перезагрузка для:${NC}"
echo "    - blacklist модулей ядра (DCCP, SCTP, редкие ФС)"
echo "    - /var/tmp bind-mount (если не применился)"
echo "    - ограничения user namespaces (на части ядер)"
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
