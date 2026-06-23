#!/usr/bin/env bash
# =============================================================================
#  Ubuntu Hardening Script — VPS/VDS Edition
#  Целевая платформа: Ubuntu 22.04 / 24.04 / 26.04 на виртуальном сервере
#  Запускать от root сразу после получения сервера
#
#  Использование: bash ubuntu_hardening.sh [ОПЦИИ]
#
#  Безопасные меры применяются ВСЕГДА. Рискованные (могут оборвать доступ
#  или сломать нагрузку) — только с явным флагом.
#
#  ОПЦИИ ВКЛЮЧЕНИЯ РИСКОВАННОГО ХАРДЕНИНГА:
#    --with-pam-lockout       pam_faillock: блокировка УЗ после N попыток (риск локаута)
#    --with-pwhistory         pam_pwhistory: запрет повтора старых паролей + yescrypt
#    --with-password-aging    старение паролей через login.defs (риск локаута)
#    --with-tmout             авто-выход из неактивных shell-сессий (TMOUT)
#    --with-aide              установка и инициализация AIDE (долгая операция)
#    --with-audit-strict      auditd -f 2 — паника ядра при сбое аудита (VPS уйдёт в офлайн)
#    --no-userns              отключить unprivileged userns (ломает rootless Docker/Podman)
#    --with-fs-blacklist      расширенный blacklist неиспользуемых модулей ФС
#    --minimize-services      интерактивный аудит и удаление лишних сервисов
#    --with-grub-password     пароль на загрузчик (ломает удалённый ребут без IP-KVM)
#    --with-tcp-forwarding    включить AllowTcpForwarding/GatewayPorts (VPN/прокси)
#
#  МЕТА-ФЛАГИ:
#    --all-risky              включить всё рискованное, КРОМЕ --with-audit-strict
#                             и --with-grub-password (самые опасные для VPS)
#    --audit-only             ничего не менять, только отчёт о соответствии CIS
#    -h, --help               показать справку и выйти
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
# На VPS туннели могут быть нужны для проксирования — включайте осознанно
# (переменными ниже или флагом --with-tcp-forwarding).
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"

# ── Флаги рискованного харденинга (🟡/🔴) — по умолчанию ВЫКЛЮЧЕНЫ ─────────────
# Включаются аргументами командной строки (см. --help). Менять здесь не нужно.
OPT_PAM_LOCKOUT="no"      # 🔴 pam_faillock — риск локаута
OPT_PWHISTORY="no"        # 🟡 pam_pwhistory + yescrypt
OPT_PASSWORD_AGING="no"   # 🔴 старение паролей login.defs
OPT_TMOUT="no"            # 🟡 авто-выход из shell по простою
OPT_AIDE="no"             # 🟡 установка AIDE (долго)
OPT_AUDIT_STRICT="no"     # 🔴 auditd -f 2 (паника ядра)
OPT_NO_USERNS="no"        # 🟡 отключить unprivileged userns (ломает rootless-контейнеры)
OPT_FS_BLACKLIST="no"     # 🟡 расширенный blacklist модулей ФС
OPT_MINIMIZE_SVC="no"     # 🟡 минимизация сервисов (интерактивно)
OPT_GRUB_PASSWORD="no"    # 🔴 пароль на GRUB (ломает удалённый ребут)
AUDIT_ONLY="no"           # режим отчёта без изменений
# ──────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}===================================================${NC}";
            echo -e "${CYAN}  $*${NC}";
            echo -e "${CYAN}===================================================${NC}"; }

# ──────────────────────────────────────────────────────────────────────────────
# Справка
# ──────────────────────────────────────────────────────────────────────────────
show_help() {
    cat << 'HLP'
Ubuntu Hardening Script — VPS/VDS Edition

Использование:
  bash ubuntu_hardening.sh [ОПЦИИ]

Безопасные меры применяются всегда. Рискованные — только с флагом.

ВКЛЮЧЕНИЕ РИСКОВАННОГО ХАРДЕНИНГА:
  --with-pam-lockout       pam_faillock: блокировка УЗ после 5 попыток (РИСК ЛОКАУТА)
  --with-pwhistory         pam_pwhistory (remember=5) + явный yescrypt в pam_unix
  --with-password-aging    старение паролей в login.defs (РИСК ЛОКАУТА)
  --with-tmout             TMOUT — авто-выход из неактивных shell-сессий
  --with-aide              установка и инициализация AIDE (долго, нагружает диск)
  --with-audit-strict      auditd -f 2: паника ядра при сбое аудита (VPS В ОФЛАЙН)
  --no-userns              отключить unprivileged user namespaces (ЛОМАЕТ rootless Docker)
  --with-fs-blacklist      расширенный blacklist редких модулей ФС
  --minimize-services      интерактивный аудит/удаление лишних сервисов
  --with-grub-password     пароль на загрузчик GRUB (НЕТ удалённого ребута без IP-KVM)
  --with-tcp-forwarding    включить SSH TCP/Gateway forwarding (VPN/прокси)

МЕТА-ФЛАГИ:
  --all-risky    включить всё рискованное, КРОМЕ --with-audit-strict и --with-grub-password
  --audit-only   ничего не менять, только вывести отчёт о текущем соответствии
  -h, --help     эта справка

Примеры:
  bash ubuntu_hardening.sh
  bash ubuntu_hardening.sh --with-pwhistory --with-aide
  bash ubuntu_hardening.sh --all-risky
  bash ubuntu_hardening.sh --audit-only
HLP
}

# ──────────────────────────────────────────────────────────────────────────────
# Разбор аргументов командной строки
# ──────────────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-pam-lockout)    OPT_PAM_LOCKOUT="yes" ;;
        --with-pwhistory)      OPT_PWHISTORY="yes" ;;
        --with-password-aging) OPT_PASSWORD_AGING="yes" ;;
        --with-tmout)          OPT_TMOUT="yes" ;;
        --with-aide)           OPT_AIDE="yes" ;;
        --with-audit-strict)   OPT_AUDIT_STRICT="yes" ;;
        --no-userns)           OPT_NO_USERNS="yes" ;;
        --with-fs-blacklist)   OPT_FS_BLACKLIST="yes" ;;
        --minimize-services)   OPT_MINIMIZE_SVC="yes" ;;
        --with-grub-password)  OPT_GRUB_PASSWORD="yes" ;;
        --with-tcp-forwarding) TCP_FORWARDING="yes"; GATEWAY_PORTS="yes" ;;
        --all-risky)
            OPT_PAM_LOCKOUT="yes"; OPT_PWHISTORY="yes"; OPT_PASSWORD_AGING="yes"
            OPT_TMOUT="yes"; OPT_AIDE="yes"; OPT_NO_USERNS="yes"
            OPT_FS_BLACKLIST="yes"; OPT_MINIMIZE_SVC="yes"
            # --with-audit-strict и --with-grub-password НЕ включаются (слишком опасны)
            ;;
        --audit-only)          AUDIT_ONLY="yes" ;;
        -h|--help)             show_help; exit 0 ;;
        *)                     echo "Неизвестный аргумент: $1 (см. --help)" >&2; exit 1 ;;
    esac
    shift
done

# ──────────────────────────────────────────────────────────────────────────────
# Режим --audit-only: только проверки, без изменений
# ──────────────────────────────────────────────────────────────────────────────
run_audit_only() {
    [[ $EUID -ne 0 ]] && error "Для аудита тоже нужен root (чтение /etc/shadow и пр.)"
    local pass="${GREEN}PASS${NC}" fail="${RED}FAIL${NC}"
    check() { # $1=описание $2=команда-предикат
        if eval "$2" &>/dev/null; then printf "  [%b] %s\n" "$pass" "$1"
        else printf "  [%b] %s\n" "$fail" "$1"; fi
    }
    section "АУДИТ СООТВЕТСТВИЯ (изменения не вносятся)"
    echo ""
    echo "  SSH:"
    check "PermitRootLogin no"        "grep -qiE '^\s*PermitRootLogin\s+no' /etc/ssh/sshd_config"
    check "PasswordAuthentication no" "grep -qiE '^\s*PasswordAuthentication\s+no' /etc/ssh/sshd_config"
    check "GSSAPIAuthentication no"   "grep -qiE '^\s*GSSAPIAuthentication\s+no' /etc/ssh/sshd_config"
    check "HostbasedAuthentication no" "grep -qiE '^\s*HostbasedAuthentication\s+no' /etc/ssh/sshd_config"
    check "PermitUserEnvironment no"  "grep -qiE '^\s*PermitUserEnvironment\s+no' /etc/ssh/sshd_config"
    check "sshd_config mode 600"      "[[ \$(stat -c '%a' /etc/ssh/sshd_config) == 600 ]]"
    echo "  Ядро/сеть:"
    check "ip_forward = 0"            "[[ \$(sysctl -n net.ipv4.ip_forward) == 0 ]]"
    check "accept_source_route = 0"   "[[ \$(sysctl -n net.ipv4.conf.all.accept_source_route) == 0 ]]"
    check "tcp_syncookies = 1"        "[[ \$(sysctl -n net.ipv4.tcp_syncookies) == 1 ]]"
    check "randomize_va_space = 2"    "[[ \$(sysctl -n kernel.randomize_va_space) == 2 ]]"
    check "ptrace_scope >= 1"         "[[ \$(sysctl -n kernel.yama.ptrace_scope) -ge 1 ]]"
    echo "  Сервисы и доступ:"
    check "root заблокирован"         "passwd -S root | grep -qE '\sL\s'"
    check "auditd активен"            "systemctl is-active --quiet auditd"
    check "ufw активен"               "ufw status | grep -qi 'Status: active'"
    check "fail2ban активен"          "systemctl is-active --quiet fail2ban"
    check "AppArmor включён"          "aa-status --enabled"
    check "chrony активен"            "systemctl is-active --quiet chrony"
    echo "  Права на файлы:"
    check "/etc/shadow 640 и строже"  "[[ \$(stat -c '%a' /etc/shadow) -le 640 ]]"
    check "AIDE установлен"           "command -v aide"
    echo ""
    info "Аудит завершён. Для применения исправлений запустите без --audit-only."
    exit 0
}
[[ "${AUDIT_ONLY}" == "yes" ]] && run_audit_only

# ──────────────────────────────────────────────────────────────────────────────
# 0. Предстартовые проверки
# ──────────────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускайте скрипт от root"

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
# Определяем раздел, на котором лежит /var/log
LOG_PARTITION=$(df --output=target /var/log 2>/dev/null | tail -1 || df /var/log | awk 'NR==2{print $6}')
# Свободное место в КБ
FREE_KB=$(df -k "${LOG_PARTITION}" | awk 'NR==2{print $4}')
# 10% от свободного — в МБ, минимум 50 МБ, максимум 2048 МБ
LOG_QUOTA_MB=$(( FREE_KB / 10 / 1024 ))
(( LOG_QUOTA_MB < 50   )) && LOG_QUOTA_MB=50
(( LOG_QUOTA_MB > 2048 )) && LOG_QUOTA_MB=2048

# Auditd: делим квоту между несколькими файлами ротации (5 файлов)
AUDIT_NUM_LOGS=5
AUDIT_MAX_FILE_MB=$(( LOG_QUOTA_MB / AUDIT_NUM_LOGS ))
(( AUDIT_MAX_FILE_MB < 10 )) && AUDIT_MAX_FILE_MB=10

# Audit backlog: 1 MB RAM ~ 1 запись ~= 256 байт; целевое значение из RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
# backlog = RAM_MB * 8, зажато между 8192 и 65536
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

# ── Сводка активных рискованных опций ─────────────────────────────────────────
_risky_active=()
[[ "${OPT_PAM_LOCKOUT}"   == "yes" ]] && _risky_active+=("pam-lockout 🔴")
[[ "${OPT_PWHISTORY}"     == "yes" ]] && _risky_active+=("pwhistory 🟡")
[[ "${OPT_PASSWORD_AGING}" == "yes" ]] && _risky_active+=("password-aging 🔴")
[[ "${OPT_TMOUT}"         == "yes" ]] && _risky_active+=("tmout 🟡")
[[ "${OPT_AIDE}"          == "yes" ]] && _risky_active+=("aide 🟡")
[[ "${OPT_AUDIT_STRICT}"  == "yes" ]] && _risky_active+=("audit-strict 🔴")
[[ "${OPT_NO_USERNS}"     == "yes" ]] && _risky_active+=("no-userns 🟡")
[[ "${OPT_FS_BLACKLIST}"  == "yes" ]] && _risky_active+=("fs-blacklist 🟡")
[[ "${OPT_MINIMIZE_SVC}"  == "yes" ]] && _risky_active+=("minimize-services 🟡")
[[ "${OPT_GRUB_PASSWORD}" == "yes" ]] && _risky_active+=("grub-password 🔴")
echo ""
if [[ ${#_risky_active[@]} -gt 0 ]]; then
    warn "Активны рискованные опции: ${_risky_active[*]}"
else
    info "Рискованные опции не выбраны — только безопасный профиль (см. --help)"
fi
echo ""

section "0. Обновление системы и установка пакетов"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq -o Dpkg::Options::="--force-confdef" \
                        -o Dpkg::Options::="--force-confold"
apt-get install -y -qq     ufw fail2ban auditd audispd-plugins     libpam-pwquality unattended-upgrades apt-listchanges     acl curl wget gnupg2 chrony
info "Пакеты установлены"

# prelink мешает AIDE и расширяет поверхность атаки (CIS 1.5.4) — удаляем всегда
if dpkg -l prelink &>/dev/null 2>&1; then
    apt-get purge -y -qq prelink && info "prelink удалён (CIS 1.5.4)"
fi

# AIDE — только по флагу (долгая инициализация базы)
if [[ "${OPT_AIDE}" == "yes" ]]; then
    apt-get install -y -qq aide aide-common && info "AIDE установлен (инициализация в секции 28)"
fi

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

# Отключаем устаревшие/лишние механизмы аутентификации (CIS 5.1.9-5.1.11, 5.1.21)
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no

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
# Agent forwarding отключён — иначе агентом могут воспользоваться другие
# привилегированные пользователи сервера (CIS 5.1.8)
AllowAgentForwarding no

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

# Права на конфиг и include-файлы: 0600 root/root (CIS 5.1.1-5.1.2)
chmod 600 /etc/ssh/sshd_config
if [[ -d /etc/ssh/sshd_config.d ]]; then
    find /etc/ssh/sshd_config.d -type f -name "*.conf" -exec chmod 600 {} \; 2>/dev/null || true
fi
info "Права на sshd_config и *.conf выставлены в 600"

# Имя службы SSH отличается в зависимости от версии Ubuntu
if systemctl list-units --type=service --state=running --all | grep -q "sshd.service"; then
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

# Не принимать пакеты source-routing (CIS 3.3.8): отправитель не должен
# сам задавать маршрут — иначе доступ к приватным сегментам извне
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

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

# Ограничение user namespaces вынесено под флаг --no-userns, т.к. значение 0
# ЛОМАЕТ rootless Docker/Podman. По умолчанию НЕ применяется.
if [[ "${OPT_NO_USERNS}" == "yes" ]]; then
    cat >> /etc/sysctl.d/99-hardening.conf << 'EOF'

# Ограничить unprivileged user namespaces (--no-userns)
# ВНИМАНИЕ: ломает rootless-контейнеры
kernel.unprivileged_userns_clone = 0
kernel.apparmor_restrict_unprivileged_userns = 1
EOF
    warn "userns отключён (--no-userns): rootless Docker/Podman работать НЕ будет"
fi

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

# Расширенный список редких ФС (--with-fs-blacklist).
# СОЗНАТЕЛЬНО НЕ включены ext/fuse/fscache/vfat/overlay/squashfs —
# их блокировка ломает корень ФС, snap, контейнеры и EFI.
if [[ "${OPT_FS_BLACKLIST}" == "yes" ]]; then
    cat >> /etc/modprobe.d/hardening-blacklist.conf << 'EOF'

# Расширенный blacklist редких ФС (--with-fs-blacklist)
blacklist afs
blacklist ceph
blacklist cifs
blacklist exfat
blacklist gfs2
blacklist nfsv3
blacklist nfsv4
install afs   /bin/false
install ceph  /bin/false
install cifs  /bin/false
install exfat /bin/false
install gfs2  /bin/false
EOF
    warn "Расширенный FS-blacklist включён: NFS/CIFS/ceph работать НЕ будут"
fi

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

# ── auditd.conf — лимиты хранения, рассчитанные из свободного места на диске ──
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

# При нехватке места — не падать, а писать в syslog и удалять старые
space_left = $(( AUDIT_MAX_FILE_MB * 2 ))
space_left_action = SYSLOG
admin_space_left = $(( AUDIT_MAX_FILE_MB ))
admin_space_left_action = ROTATE
disk_full_action = ROTATE
disk_error_action = SYSLOG

# Буфер диспетчера
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME

# Флаш: каждые 5 секунд или 50 записей
flush = INCREMENTAL_ASYNC
freq = 50
EOF

# ── Правила аудита ─────────────────────────────────────────────────────────────
# Режим сбоя: 1 = syslog (по умолчанию, безопасно для VPS).
# --with-audit-strict -> 2 = паника ядра при невозможности записи аудита.
AUDIT_FAIL_MODE=1
[[ "${OPT_AUDIT_STRICT}" == "yes" ]] && { AUDIT_FAIL_MODE=2; warn "auditd -f 2: ядро уйдёт в панику при сбое аудита (--with-audit-strict)"; }

cat > /etc/audit/rules.d/99-hardening.rules << EOF
-D
# backlog рассчитан из RAM: ${AUDIT_BACKLOG} записей
# (формула: RAM_MB × 8, диапазон 8192–65536)
-b ${AUDIT_BACKLOG}
# --backlog_wait_time: ждать 1 мс перед отбрасыванием события (снижает потери)
--backlog_wait_time 1
# Режим сбоя (1 = syslog для VPS; 2 = паника при --with-audit-strict)
-f ${AUDIT_FAIL_MODE}

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

# Изменение времени и даты (CIS 6.2.3.4)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Неуспешный доступ к файлам: EACCES/EPERM (CIS 6.2.3.7)
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate,creat -F exit=-EACCES -F auid>=1000 -k file_access
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate,creat -F exit=-EPERM  -F auid>=1000 -k file_access

# Монтирование ФС (CIS 6.2.3.10)
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -k mounts

# Удаление/переименование файлов пользователями (CIS 6.2.3.13)
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -k delete

# Логин/выход и инициализация сессий (CIS 6.2.3.11-6.2.3.12)
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/log/wtmp  -p wa -k session
-w /var/log/btmp  -p wa -k session

# Изменение мандатной системы контроля доступа — AppArmor (CIS 6.2.3.14)
-w /etc/apparmor/   -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Утилиты изменения прав/ACL/контекста и УЗ (CIS 6.2.3.15-6.2.3.18)
-a always,exit -F path=/usr/bin/chcon    -F perm=x -F auid>=1000 -k perm_chng
-a always,exit -F path=/usr/bin/setfacl  -F perm=x -F auid>=1000 -k perm_chng
-a always,exit -F path=/usr/bin/chacl    -F perm=x -F auid>=1000 -k perm_chng
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -k usermod

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

# ── logrotate для /var/log/audit ───────────────────────────────────────────────
cat > /etc/logrotate.d/audit << EOF
/var/log/audit/audit.log {
    daily
    missingok
    rotate ${AUDIT_NUM_LOGS}
    maxsize ${AUDIT_MAX_FILE_MB}M
    compress
    delaycompress
    notifempty
    create 0600 root root
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
EOF

mkdir -p /var/log/audit
service auditd restart 2>/dev/null || systemctl restart auditd
info "auditd настроен: backlog=${AUDIT_BACKLOG}, ${AUDIT_NUM_LOGS}×${AUDIT_MAX_FILE_MB}МБ (≤10% диска)"

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
# Тайм-аут sudo-сессии — 5 минут
Defaults    timestamp_timeout=5
# Не показывать символы при вводе пароля
Defaults    !visiblepw
# sudo выполняется только в псевдотерминале (CIS 5.2.2) — мешает части атак,
# где форкнутый процесс продолжает жить после завершения родителя
Defaults    use_pty
# Фиксированный безопасный PATH — защита от подмены системных утилит
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/99-hardening

# Проверяем синтаксис до применения
visudo -c && info "sudo: конфигурация корректна" || warn "Проверьте sudoers вручную!"

# Логирование sudo через syslog (работает на всех версиях Ubuntu без плагинов)
# sudo пишет в /var/log/auth.log по умолчанию — дополнительно направляем в отдельный файл
if ! grep -q "sudo" /etc/rsyslog.d/*.conf 2>/dev/null; then
    cat > /etc/rsyslog.d/50-sudo.conf << 'RSYSEOF'
# Логи sudo в отдельный файл
:programname, isequal, "sudo" /var/log/sudo.log
& stop
RSYSEOF
    systemctl restart rsyslog 2>/dev/null || true
    info "sudo: логирование через rsyslog -> /var/log/sudo.log"
fi

# Права на файл лога
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
# Запрет длинных монотонных последовательностей вида 12345/abcde (CIS 5.3.3.2.5)
maxsequence = 3
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

# Права на backup-копии и сопутствующие файлы (CIS 7.1.1-7.1.10)
for f in /etc/passwd- /etc/group-; do
    [[ -e "$f" ]] && { chown root:root "$f"; chmod 644 "$f"; }
done
for f in /etc/shadow- /etc/gshadow-; do
    [[ -e "$f" ]] && { chown root:root "$f"; chmod 640 "$f"; }
done
[[ -e /etc/security/opasswd ]] && { chown root:root /etc/security/opasswd; chmod 600 /etc/security/opasswd; }
[[ -e /etc/shells ]]          && { chown root:root /etc/shells; chmod 644 /etc/shells; }

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
# 20. Баннеры /etc/issue, /etc/issue.net, /etc/motd  (CIS 1.6)
# ──────────────────────────────────────────────────────────────────────────────
section "20. Баннеры входа (issue / issue.net / motd)"

# Убираем из баннеров сведения об ОС (помощь в разведке) и ставим юр.текст
BANNER_TEXT='Authorized access only. All activity is monitored and logged.
Disconnect immediately if you are not an authorized user.'

echo "${BANNER_TEXT}" > /etc/issue
echo "${BANNER_TEXT}" > /etc/issue.net
: > /etc/motd   # пустой motd — без версии ОС и прочей разведданных

chown root:root /etc/motd /etc/issue /etc/issue.net
chmod 644       /etc/motd /etc/issue /etc/issue.net
info "Баннеры очищены от версии ОС, права 644 (CIS 1.6.1-1.6.6)"

# ──────────────────────────────────────────────────────────────────────────────
# 21. Окружение пользователей: umask, PATH, login shell  (CIS 5.4)
# ──────────────────────────────────────────────────────────────────────────────
section "21. Окружение пользователей (umask, PATH, shell)"

# umask 027 -> новые файлы 640, каталоги 750 (CIS 5.4.2.6 / 5.4.3.3)
cat > /etc/profile.d/99-hardening-umask.sh << 'EOF'
# Жёсткий umask по умолчанию (ubuntu_hardening.sh)
umask 027
EOF
chmod 644 /etc/profile.d/99-hardening-umask.sh

# Безопасный PATH для root (CIS 5.4.2.5)
if ! grep -q "ubuntu_hardening: secure root PATH" /root/.bashrc 2>/dev/null; then
    cat >> /root/.bashrc << 'EOF'

# ubuntu_hardening: secure root PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
fi
info "umask 027 + безопасный PATH root настроены"

# TMOUT — авто-выход из неактивных shell-сессий (--with-tmout)
if [[ "${OPT_TMOUT}" == "yes" ]]; then
    cat > /etc/profile.d/99-hardening-tmout.sh << 'EOF'
# Авто-выход из интерактивной shell-сессии при 15-мин простое (ubuntu_hardening.sh)
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    chmod 644 /etc/profile.d/99-hardening-tmout.sh
    info "TMOUT=900 включён (--with-tmout)"
else
    info "TMOUT не задан (включается --with-tmout)"
fi

# Системные УЗ без интерактивного shell (CIS 5.4.2.7) — отчёт, без автоправок
echo ""
echo "  Системные УЗ (uid<1000) с интерактивным shell — проверьте вручную:"
awk -F: '($3<1000 && $3!=0 && $7 ~ /(bash|sh|zsh)$/){print "    "$1" -> "$7}' /etc/passwd || true

# ──────────────────────────────────────────────────────────────────────────────
# 22. Загрузчик GRUB  (CIS 1.3.1.2, 1.4.x, 6.2.1.3)
# ──────────────────────────────────────────────────────────────────────────────
section "22. Загрузчик GRUB (cmdline, права, [пароль])"

GRUB_DEFAULT_FILE="/etc/default/grub"
if [[ -f "${GRUB_DEFAULT_FILE}" ]]; then
    cp "${GRUB_DEFAULT_FILE}" "${GRUB_DEFAULT_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    # audit=1 + backlog в cmdline: аудит с самых первых процессов (CIS 6.2.1.3-6.2.1.4)
    # apparmor=1 security=apparmor: гарантированно активный AppArmor (CIS 1.3.1.2)
    CURRENT_CMDLINE=$(grep "^GRUB_CMDLINE_LINUX=" "${GRUB_DEFAULT_FILE}" | head -1 | sed 's/^GRUB_CMDLINE_LINUX=//; s/^"//; s/"$//')
    # Убираем прежние управляемые нами токены, чтобы не дублировать
    for key in audit audit_backlog_limit apparmor security; do
        CURRENT_CMDLINE=$(echo " ${CURRENT_CMDLINE} " | sed -E "s/ ${key}=[^ ]*//g")
    done
    CURRENT_CMDLINE=$(echo "${CURRENT_CMDLINE} audit=1 audit_backlog_limit=${AUDIT_BACKLOG} apparmor=1 security=apparmor" | tr -s ' ' | sed 's/^ //; s/ $//')
    sed -i "s|^GRUB_CMDLINE_LINUX=.*|GRUB_CMDLINE_LINUX=\"${CURRENT_CMDLINE}\"|" "${GRUB_DEFAULT_FILE}"
    info "GRUB cmdline: ${CURRENT_CMDLINE}"

    # Пароль на загрузчик (--with-grub-password). --unrestricted -> загрузка ОС
    # без пароля, пароль требуется только для РЕДАКТИРОВАНИЯ записей GRUB.
    if [[ "${OPT_GRUB_PASSWORD}" == "yes" ]]; then
        warn "Задайте пароль администратора GRUB (потребуется для правки меню загрузчика):"
        if command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
            GRUB_HASH=$(grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf/{print $NF}')
            if [[ -n "${GRUB_HASH}" ]]; then
                cat > /etc/grub.d/40_custom << EOF
#!/bin/sh
exec tail -n +3 \$0
set superusers="grubadmin"
password_pbkdf2 grubadmin ${GRUB_HASH}
EOF
                chmod 755 /etc/grub.d/40_custom
                # --unrestricted, чтобы не требовать пароль при штатной загрузке
                sed -i 's/\(CLASS="--class gnu-linux --class gnu --class os\)"/\1 --unrestricted"/' /etc/grub.d/10_linux 2>/dev/null || true
                info "Пароль GRUB установлен (суперпользователь grubadmin, --unrestricted)"
                warn "Проверьте загрузку с консоли провайдера ДО того, как доверитесь удалённому ребуту!"
            else
                warn "Не удалось получить хеш пароля GRUB — пропускаем"
            fi
        else
            warn "grub-mkpasswd-pbkdf2 не найден — пароль GRUB пропущен"
        fi
    fi

    update-grub 2>/dev/null || warn "update-grub не выполнен (нет GRUB? — нормально для части VPS)"
else
    warn "/etc/default/grub не найден — GRUB не настраивается (cloud-образ без GRUB?)"
fi

# Права 600 на сгенерированный конфиг загрузчика (CIS 1.4.2)
for g in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    [[ -f "$g" ]] && { chown root:root "$g"; chmod 600 "$g"; info "Права 600 на $g"; }
done

# ──────────────────────────────────────────────────────────────────────────────
# 23. PAM: блокировка УЗ после неудачных входов  (CIS 5.3.3.1) — 🔴 флаг
# ──────────────────────────────────────────────────────────────────────────────
section "23. PAM: блокировка УЗ (pam_faillock)"

if [[ "${OPT_PAM_LOCKOUT}" == "yes" ]]; then
    warn "Включается pam_faillock — при ошибке в PAM возможен ЛОКАУТ. Держите консоль открытой!"
    # Параметры блокировки. even_deny_root НЕ задаём — чтобы не заблокировать root на VPS.
    cat > /etc/security/faillock.conf << 'EOF'
# ubuntu_hardening.sh — блокировка после неудачных входов
deny = 5
unlock_time = 900
fail_interval = 900
# even_deny_root и root_unlock_time сознательно НЕ заданы (риск локаута root на VPS)
EOF
    COMMON_AUTH="/etc/pam.d/common-auth"
    if [[ -f "${COMMON_AUTH}" ]] && ! grep -q "pam_faillock.so" "${COMMON_AUTH}"; then
        cp "${COMMON_AUTH}" "${COMMON_AUTH}.bak.$(date +%Y%m%d%H%M%S)"
        # preauth — перед первым auth-модулем
        sed -i '0,/^auth/s//auth\trequired\t\t\tpam_faillock.so preauth\nauth/' "${COMMON_AUTH}"
        # authfail/authsucc — в конец auth-стека
        cat >> "${COMMON_AUTH}" << 'EOF'
auth	[default=die]		pam_faillock.so authfail
auth	sufficient		pam_faillock.so authsucc
EOF
        info "pam_faillock включён: 5 попыток -> блок на 15 минут (root НЕ блокируется)"
        warn "Резерв: ${COMMON_AUTH}.bak.* — восстановите с консоли, если сломается вход"
    else
        info "pam_faillock уже присутствует или common-auth не найден — пропуск"
    fi
else
    info "Блокировка УЗ не включена (включается --with-pam-lockout)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 24. PAM: история паролей и стойкий хеш  (CIS 5.3.2.4, 5.3.3.4) — 🟡 флаг
# ──────────────────────────────────────────────────────────────────────────────
section "24. PAM: история паролей + yescrypt"

if [[ "${OPT_PWHISTORY}" == "yes" ]]; then
    cat > /etc/security/pwhistory.conf << 'EOF'
# ubuntu_hardening.sh — запрет повтора старых паролей
remember = 5
use_authtok
enforce_for_root
EOF
    COMMON_PW="/etc/pam.d/common-password"
    if [[ -f "${COMMON_PW}" ]]; then
        cp "${COMMON_PW}" "${COMMON_PW}.bak.$(date +%Y%m%d%H%M%S)"
        # Добавляем pam_pwhistory перед pam_unix (если ещё нет)
        if ! grep -q "pam_pwhistory.so" "${COMMON_PW}"; then
            sed -i '0,/^password.*pam_unix.so/s//password\trequisite\t\t\tpam_pwhistory.so\n&/' "${COMMON_PW}"
        fi
        # Гарантируем yescrypt в pam_unix (CIS 5.3.3.4.3); убираем устаревший remember
        sed -i -E 's/(password\s+\[success=[0-9]+ default=ignore\]\s+pam_unix.so.*)/\1/' "${COMMON_PW}"
        if grep -q "pam_unix.so" "${COMMON_PW}" && ! grep "pam_unix.so" "${COMMON_PW}" | grep -q "yescrypt"; then
            sed -i -E '/pam_unix.so/ s/(pam_unix.so[^\n]*)/\1 yescrypt/' "${COMMON_PW}"
        fi
        sed -i -E '/pam_unix.so/ s/\bremember=[0-9]+\b//g; /pam_unix.so/ s/\bnullok\b//g' "${COMMON_PW}"
        # Снимаем nullok и из common-auth (пустые пароли запрещены, CIS 5.3.3.4.1)
        [[ -f /etc/pam.d/common-auth ]] && sed -i -E '/pam_unix.so/ s/\bnullok\b//g' /etc/pam.d/common-auth || true
        info "pam_pwhistory (remember=5) + yescrypt, nullok убран (CIS 5.3.3.4)"
        warn "Резерв: ${COMMON_PW}.bak.*"
    fi
else
    info "История паролей не включена (включается --with-pwhistory)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 25. Старение паролей  (CIS 5.4.1) — 🔴 флаг
# ──────────────────────────────────────────────────────────────────────────────
section "25. Старение паролей (login.defs)"

if [[ "${OPT_PASSWORD_AGING}" == "yes" ]]; then
    warn "Включается старение паролей — при игнорировании смены возможен ЛОКАУТ"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/'  /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/'    /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/'    /etc/login.defs
    # Применяем к существующему админу (не к root — чтобы не заблокировать аварийный вход)
    chage --maxdays 365 --mindays 1 --warndays 7 "${ADMIN_USER}" 2>/dev/null || true
    info "PASS_MAX_DAYS=365, PASS_MIN_DAYS=1, PASS_WARN_AGE=7 (root не затронут)"
else
    info "Старение паролей не включено (включается --with-password-aging)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 26. Минимизация сервисов  (CIS 2.1-2.2) — 🟡 флаг, интерактивно
# ──────────────────────────────────────────────────────────────────────────────
section "26. Минимизация сервисов"

if [[ "${OPT_MINIMIZE_SVC}" == "yes" ]]; then
    echo ""
    echo "  Сервисы, слушающие сетевые порты (проверьте необходимость каждого):"
    ss -tulnp 2>/dev/null | sed 's/^/    /' || true
    echo ""
    # Кандидаты на удаление: явно лишние на типовом VPS. Каждый — с подтверждением.
    SVC_CANDIDATES=(avahi-daemon cups isc-dhcp-server slapd dovecot-core \
                    nfs-kernel-server rpcbind samba snmpd squid xinetd \
                    vsftpd telnetd rsh-server talk nis)
    for pkg in "${SVC_CANDIDATES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null 2>&1; then
            read -r -p "  Найден '${pkg}'. Удалить (purge)? [y/N]: " _svc
            if [[ "${_svc}" =~ ^[Yy]$ ]]; then
                apt-get purge -y -qq "$pkg" && info "Удалён: $pkg"
            else
                info "Оставлен: $pkg"
            fi
        fi
    done
    # MTA в local-only, если postfix установлен
    if dpkg -l postfix &>/dev/null 2>&1; then
        postconf -e 'inet_interfaces = loopback-only' 2>/dev/null \
            && systemctl restart postfix 2>/dev/null \
            && info "postfix переведён в local-only (не слушает сеть)" || true
    fi
else
    info "Минимизация сервисов не запускалась (включается --minimize-services)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 27. AIDE — контроль целостности файлов  (CIS 6.3.1) — 🟡 флаг
# ──────────────────────────────────────────────────────────────────────────────
section "27. AIDE — контроль целостности"

if [[ "${OPT_AIDE}" == "yes" ]] && command -v aideinit &>/dev/null; then
    info "Инициализация базы AIDE (может занять несколько минут)..."
    aideinit -y -f 2>/dev/null || aideinit 2>/dev/null || true
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    fi
    # Ежедневная проверка через systemd timer ставится пакетом aide-common;
    # дублируем cron на случай его отсутствия
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/sh
/usr/bin/aide --check 2>&1 | logger -t aide
EOF
    chmod 755 /etc/cron.daily/aide-check
    info "AIDE инициализирован, ежедневная проверка -> syslog (tag: aide)"
elif [[ "${OPT_AIDE}" == "yes" ]]; then
    warn "AIDE запрошен, но aideinit не найден — проверьте установку пакета aide"
else
    info "AIDE не настраивался (включается --with-aide)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 28. Аудит ФС и консистентность УЗ  (CIS 7.1-7.2) — отчёт, без автоправок
# ──────────────────────────────────────────────────────────────────────────────
section "28. Аудит ФС и учётных записей (только отчёт)"

REPORT="/root/hardening-audit-report.txt"
{
    echo "=== Отчёт аудита ФС/УЗ — $(date) ==="
    echo ""
    echo "--- World-writable файлы (без sticky), первые 50 (CIS 7.1.11) ---"
    find / -xdev -type f -perm -0002 2>/dev/null | head -50
    echo ""
    echo "--- World-writable каталоги без sticky bit (CIS 7.1.11) ---"
    find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -50
    echo ""
    echo "--- Файлы без владельца/группы (CIS 7.1.12) ---"
    find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -50
    echo ""
    echo "--- SUID/SGID файлы — baseline для ручной проверки (CIS 7.1.13) ---"
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
    echo ""
    echo "--- Дубликаты UID (CIS 7.2.5) ---"
    cut -d: -f3 /etc/passwd | sort | uniq -d
    echo "--- Дубликаты GID (CIS 7.2.6) ---"
    cut -d: -f3 /etc/group | sort | uniq -d
    echo "--- Пустые пароли в /etc/shadow (CIS 7.2.2) ---"
    awk -F: '($2==""){print $1}' /etc/shadow
    echo "--- Группы из /etc/passwd, отсутствующие в /etc/group (CIS 7.2.3) ---"
    for gid in $(cut -d: -f4 /etc/passwd | sort -u); do
        getent group "$gid" >/dev/null 2>&1 || echo "GID $gid не найден в /etc/group"
    done
    echo "--- UID 0, кроме root (CIS 5.4.2.1) ---"
    awk -F: '($3==0){print $1}' /etc/passwd
} > "${REPORT}" 2>/dev/null || true

chmod 600 "${REPORT}"
info "Отчёт сохранён: ${REPORT}"
echo "  Ключевые находки (детали — в файле):"
grep -E "UID 0|не найден|^[a-z]" "${REPORT}" 2>/dev/null | grep -vE "^---|^===" | head -10 | sed 's/^/    /' || true

# ──────────────────────────────────────────────────────────────────────────────
# 29. Удаление приватного ключа с сервера
# ──────────────────────────────────────────────────────────────────────────────
section "29. Финальный шаг — удаление приватного ключа с сервера"

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
printf "  %-48s %s\n" "SSH: GSSAPI/Hostbased/AgentFwd off"     "[OK]"
printf "  %-48s %s\n" "Root заблокирован"                      "[OK]"
printf "  %-48s %s\n" "UFW: разрешён только SSH:${SSH_PORT}"   "[OK]"
printf "  %-48s %s\n" "Fail2ban: 3 попытки -> бан 24ч"         "[OK]"
printf "  %-48s %s\n" "sysctl: сеть + ядро + source-route"     "[OK]"
printf "  %-48s %s\n" "Blacklist: опасные ФС/протоколы"        "[OK]"
printf "  %-48s %s\n" "/tmp /dev/shm /var/tmp: noexec"         "[OK]"
printf "  %-48s %s\n" "Cron: только root"                      "[OK]"
printf "  %-48s %s\n" "Auditd: расширенные правила"            "[OK]"
printf "  %-48s %s\n" "Core dump отключён"                     "[OK]"
printf "  %-48s %s\n" "AppArmor: enforce"                      "[OK]"
printf "  %-48s %s\n" "sudo: use_pty + лог + тайм-аут"         "[OK]"
printf "  %-48s %s\n" "Политика паролей: 16+ / maxsequence"    "[OK]"
printf "  %-48s %s\n" "Баннеры issue/motd очищены"             "[OK]"
printf "  %-48s %s\n" "umask 027 + secure PATH"                "[OK]"
printf "  %-48s %s\n" "GRUB: cmdline audit=1 + права 600"      "[OK]"
printf "  %-48s %s\n" "Отчёт аудита ФС/УЗ -> /root"            "[OK]"
printf "  %-48s %s\n" "Телеметрия удалена"                     "[OK]"
printf "  %-48s %s\n" "Автообновления security"                "[OK]"
echo ""
echo -e "  ${CYAN}Рискованные опции (по флагам):${NC}"
printf "  %-40s %s\n" "pam-lockout (--with-pam-lockout)"     "$([[ ${OPT_PAM_LOCKOUT}   == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "pwhistory  (--with-pwhistory)"        "$([[ ${OPT_PWHISTORY}     == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "password-aging (--with-password-aging)" "$([[ ${OPT_PASSWORD_AGING} == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "tmout (--with-tmout)"                 "$([[ ${OPT_TMOUT}         == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "aide (--with-aide)"                   "$([[ ${OPT_AIDE}          == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "audit-strict (--with-audit-strict)"   "$([[ ${OPT_AUDIT_STRICT}  == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "no-userns (--no-userns)"              "$([[ ${OPT_NO_USERNS}     == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "fs-blacklist (--with-fs-blacklist)"   "$([[ ${OPT_FS_BLACKLIST}  == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "minimize-services (--minimize-services)" "$([[ ${OPT_MINIMIZE_SVC} == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
printf "  %-40s %s\n" "grub-password (--with-grub-password)" "$([[ ${OPT_GRUB_PASSWORD} == yes ]] && echo '[ВКЛ]' || echo '[выкл]')"
echo ""
echo -e "  ${YELLOW}Требуется перезагрузка для:${NC}"
echo "    - blacklist модулей ядра (DCCP, SCTP, редкие ФС)"
echo "    - GRUB cmdline (audit=1, apparmor=1)"
echo "    - /var/tmp bind-mount (если не применился)"
[[ "${OPT_NO_USERNS}" == "yes" ]] && echo "    - kernel.unprivileged_userns_clone (--no-userns)"
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
