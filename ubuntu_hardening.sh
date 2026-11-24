#!/usr/bin/env bash
# =============================================================================
#  Ubuntu Hardening Script — VPS/VDS Edition  (v4.0)
#  Целевая платформа: Ubuntu 22.04 / 24.04 / 26.04 на виртуальном сервере
#  Запускать от root сразу после получения сервера
#
#  Использование:
#    bash ubuntu_hardening.sh                      # полный харденинг (интерактивно)
#    bash ubuntu_hardening.sh --config hard.conf --yes   # без вопросов (cloud-init, Ansible)
#    bash ubuntu_hardening.sh --only ssh,ufw       # только выбранные шаги
#    bash ubuntu_hardening.sh --audit              # проверка без изменений
#    bash ubuntu_hardening.sh --rollback [метка]   # откат файлов прогона
#    bash ubuntu_hardening.sh --luks <режим> ...   # шифрование LUKS2 (см. --help)
#    bash ubuntu_hardening.sh --help
#
#  История изменений — CHANGELOG.md. Главное в v4:
#    - неинтерактивный режим (--config/--yes), выбор шагов (--only/--skip),
#      проверка (--audit), откат (--rollback), единый каталог резервных копий
#    - исправлены: права /var/log/sudo.log, дубли в limits.conf, grep -q в
#      пайпах под pipefail, ERR-trap в функциях, пропуск auditd при immutable
#    - ожидание cloud-init и блокировки apt; Docker: форвардинг и UFW
#    - chrony/pwquality — drop-in вместо перезаписи файлов дистрибутива
#    - SSH: ключи root можно перенести администратору, порт 22 допустим,
#      AllowAgentForwarding/PermitTunnel/PermitUserEnvironment no
#    - auditd: b32-правила access/kexec, удаление, xattr, SUID-бинарники
#    - journald с квотой, login.defs, необязательные faillock/AIDE/hidepid
#
#  ВАЖНО для VPS:
#    Убедитесь, что у вас есть доступ к VNC/консоли провайдера
#    на случай потери SSH-доступа во время настройки!
# =============================================================================

set -Eeuo pipefail

SCRIPT_VERSION="4.0"

# ──────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКИ — значения по умолчанию.
# Любую из них можно задать в файле --config (КЛЮЧ=значение) или в окружении
# с префиксом UH_ (например UH_SSH_PORT=2222). Приоритет: окружение > --config
# > ответы прошлого прогона (если вы согласились их использовать) > значения ниже.
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_USER="admin"                   # имя администратора
SSH_PORT="20202"                     # 22 или 1024–65535
KEY_PATH="/root/admin_ssh_key"       # куда сохранить сгенерированную пару ключей

# Источник SSH-ключа администратора:
#   root      — ключи из /root/.ssh/authorized_keys (если есть — по умолчанию)
#   provided  — свой публичный ключ (SSH_PUBKEY)
#   ed25519   — сгенерировать ed25519 на сервере
#   ecdsa-521 — сгенерировать ECDSA P-521 на сервере
SSH_KEY_SOURCE=""
SSH_PUBKEY=""                        # для provided: "ssh-ed25519 AAAA... comment"
ADMIN_PASSWORD_HASH=""               # для --yes: хеш пароля (openssl passwd -6 / mkpasswd)

NEW_HOSTNAME=""                      # пусто — не менять
NEW_FQDN=""                          # пусто — не задавать
TIMEZONE=""                          # пусто — не менять (например Europe/Moscow)
DNS_SERVERS=""                       # пусто — не менять; IPv4/IPv6 через пробел
DNSSEC_MODE="no"                     # no | allow-downgrade | yes (allow-downgrade бывает нестабилен)
NTP_SERVERS=""                       # свои NTP-серверы через пробел (добавляются к штатным)
NTP_REPLACE_DEFAULTS="no"            # yes — использовать ТОЛЬКО NTP_SERVERS
NTP_ADD_NTS="yes"                    # добавить time.cloudflare.com (NTS, аутентифицированное время)
EXTRA_PORTS=""                       # дополнительные порты UFW: "80 443 51820/udp"
DOCKER_ALLOW_PORTS="auto"            # порты КОНТЕЙНЕРОВ, открытые извне ("80/tcp 443/tcp");
                                     # auto — те, что сейчас опубликованы на 0.0.0.0/::
FAIL2BAN_IGNOREIP=""                 # свои IP/подсети, которые fail2ban не банит

# Семейство адресов для SSH:
#   any  — IPv4 + IPv6 (безопасное значение по умолчанию)
#   inet — только IPv4 (НЕ ставьте на IPv6-only VPS — потеряете доступ!)
SSH_ADDRESS_FAMILY="any"

# Форвардинг SSH отключён по умолчанию.
TCP_FORWARDING="no"
GATEWAY_PORTS="no"
X11_FORWARDING="no"
AGENT_FORWARDING="no"

# IP-форвардинг ядра: auto — включить, если найдены Docker/Podman/LXD/WireGuard
# (иначе контейнеры теряют сеть после очередного sysctl --system); yes | no
IP_FORWARD="auto"
# Docker публикует порты в обход UFW. auto — при найденном Docker добавить
# цепочку DOCKER-USER в /etc/ufw/after.rules; yes — всегда; no — не трогать
DOCKER_UFW_FIX="auto"

# /tmp: auto — tmpfs при RAM >= 2 ГБ, иначе каталог на диске с noexec; tmpfs | disk
TMP_MODE="auto"
# noexec на /home ломает ~/.local/bin, VS Code Remote, rustup, nvm, pipx
HOME_NOEXEC="yes"
# Router Advertisement IPv6: auto — оставить, если у сервера есть глобальный IPv6
IPV6_ACCEPT_RA="auto"                # auto | yes | no
LOG_MARTIANS="yes"                   # в некоторых сетях провайдеров очень шумно

# AppArmor: yes — перевести complain-профили в enforce. Может сломать
# программы, чьи профили дистрибутив намеренно держит в complain.
APPARMOR_ENFORCE_ALL="no"

# Политика паролей: yes — требовать все классы символов (CIS);
# no — только длина 16+ и словарная проверка (подход NIST SP 800-63B)
PASSWORD_CLASSES="yes"
PASSWORD_MAX_DAYS="365"              # срок действия пароля администратора (sudo)

# Необязательные меры (по умолчанию выключены — см. README)
ENABLE_FAILLOCK="no"                 # блокировка после 5 неверных паролей sudo/su на 15 мин
ENABLE_AIDE="no"                     # контроль целостности файлов (aideinit — несколько минут)
KERNEL_CMDLINE_HARDENING="no"        # slab_nomerge init_on_alloc=1 ... (нужен reboot)
HIDEPID="no"                         # /proc: чужие процессы не видны (hidepid=invisible)
REMOTE_SYSLOG=""                     # host:port — пересылка syslog и auditd по TCP (без TLS!)
DISABLE_SERVICES=""                  # для --yes: какие лишние службы отключить ("cups avahi-daemon")

# Сохранённые параметры прогона и резервные копии
STATE_FILE="/etc/ubuntu_hardening.conf"
BACKUP_ROOT="/var/backups/ubuntu_hardening"

# ── Настройки LUKS (переопределяются аргументами --luks) ─────────────────────
LUKS_NAME="securedata"               # --name        /dev/mapper/<имя>
LUKS_MOUNT="/srv/secure"             # --mount       точка монтирования
LUKS_FS="ext4"                       # --fs          ext4 | xfs
LUKS_MOUNT_OPTS="defaults,nodev,nosuid"   # --mount-opts
LUKS_UNLOCK="manual"                 # --unlock      manual | keyfile | tang
LUKS_TANG_URL=""                     # --tang        http://tang.example.net
LUKS_DISCARDS="no"                   # --discards    TRIM (раскрывает занятые блоки)
LUKS_PERF="yes"                      # --no-perf     no_read/no_write_workqueue
LUKS_PREFILL="no"                    # --prefill     заполнить том шумом (долго)
LUKS_CIPHER="aes-xts-plain64"        # --cipher
LUKS_KEY_SIZE="512"                  # --key-size
LUKS_DROPBEAR_PORT="2222"            # --dropbear-port
LUKS_PREPARE_ONLY="no"               # --prepare     dropbear до шифрования root
LUKS_KEYS_DIR="/etc/cryptsetup-keys.d"
LUKS_BACKUP_DIR="/root/luks-backup"
LUKS_STAMP="$(date +%Y%m%d_%H%M%S)"
# ──────────────────────────────────────────────────────────────────────────────

# Ключи, которые можно задавать через --config / UH_*
CONFIG_KEYS=(ADMIN_USER SSH_PORT SSH_KEY_SOURCE SSH_PUBKEY ADMIN_PASSWORD_HASH
    NEW_HOSTNAME NEW_FQDN TIMEZONE DNS_SERVERS DNSSEC_MODE NTP_SERVERS
    NTP_REPLACE_DEFAULTS NTP_ADD_NTS EXTRA_PORTS DOCKER_ALLOW_PORTS
    FAIL2BAN_IGNOREIP SSH_ADDRESS_FAMILY
    TCP_FORWARDING GATEWAY_PORTS X11_FORWARDING AGENT_FORWARDING IP_FORWARD
    DOCKER_UFW_FIX TMP_MODE HOME_NOEXEC IPV6_ACCEPT_RA LOG_MARTIANS
    APPARMOR_ENFORCE_ALL PASSWORD_CLASSES PASSWORD_MAX_DAYS ENABLE_FAILLOCK
    ENABLE_AIDE KERNEL_CMDLINE_HARDENING HIDEPID REMOTE_SYSLOG DISABLE_SERVICES
    ALLOW_UNTESTED_OS)
ALLOW_UNTESTED_OS="no"

RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${RUN_STAMP}"
ASSUME_YES="no"
CURRENT_STEP=""
declare -A STEP_WARNS=()
declare -A STEP_STATUS=()
declare -A STEP_NOTE=()
declare -A TRACKED=()
EXIT_HOOKS=()
TMP_FILES=()

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"
            if [[ -n "${CURRENT_STEP}" ]]; then
                STEP_WARNS[${CURRENT_STEP}]=$(( ${STEP_WARNS[${CURRENT_STEP}]:-0} + 1 ))
            fi; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}===================================================${NC}";
            echo -e "${CYAN}  $*${NC}";
            echo -e "${CYAN}===================================================${NC}"; }

usage() {
    cat << 'EOF'
Использование:
  bash ubuntu_hardening.sh [опции]             полный харденинг
  bash ubuntu_hardening.sh --luks <режим> [аргументы] [опции]

Опции харденинга:
  --config <файл>       значения настроек (КЛЮЧ=значение, см. README и example.conf)
  -y, --yes             без вопросов: значения из --config/UH_*/умолчаний.
                        Требует ключ root или SSH_PUBKEY и ADMIN_PASSWORD_HASH
  --only <шаги>         выполнить только эти шаги (через запятую)
  --skip <шаги>         пропустить эти шаги
  --list-steps          список шагов
  --audit               проверить текущее состояние, ничего не меняя (код 1 при FAIL)
  --rollback [метка]    восстановить файлы, изменённые прогоном (без метки — список)
  --version             версия скрипта

Режимы --luks:
  status                         состояние шифрования
  data  <устройство>             зашифровать отдельный диск/раздел (ДАННЫЕ УДАЛЯЮТСЯ)
  file  <путь> <размер>          файл-контейнер, например /var/lib/secure.img 20G
  swap                           убрать открытый swap (zram / dm-crypt со случайным ключом)
  remote-unlock                  SSH в initramfs (dropbear) для root на LUKS; на 26.04 — Tang
  docker                         перенести данные Docker (и containerd) на зашифрованный
                                 том (создайте его заранее: data или file); Docker не
                                 стартует без тома, при --unlock manual — после luks-unlock

Шифрование всего корня (ext4 на обычном разделе, GRUB; СНАПШОТ ОБЯЗАТЕЛЕН):
  encrypt-root <раздел>          из rescue-системы провайдера, пароль сразу;
                                 если /boot внутри корня — создаёт раздел /boot
  encrypt-root-auto              с работающей системы (нужен отдельный /boot,
                                 22.04/24.04): шифрование при следующей загрузке
  encrypt-root-finish            после такой загрузки: задать пароль, удалить
                                 временный ключ (до этого защиты НЕТ)
  encrypt-root-cancel            отменить подготовку encrypt-root-auto

Опции --luks:
  --name <имя>          имя маппинга (securedata)
  --mount <путь>        точка монтирования (/srv/secure)
  --fs ext4|xfs         файловая система (ext4)
  --mount-opts <опции>  опции монтирования (defaults,nodev,nosuid)
  --unlock <способ>     manual  — пароль после входа: sudo luks-unlock <имя> (по умолчанию)
                        keyfile — ключ на root-ФС, автомонтирование
                        tang    — авторазблокировка через Tang/Clevis (нужен --tang)
  --tang <URL>          адрес Tang-сервера
  --discards            включить TRIM
  --no-perf             не использовать no_read/no_write_workqueue
  --prefill             заполнить том через dm-crypt (скрыть занятость блоков)
  --cipher <шифр>       aes-xts-plain64 (по умолчанию)
  --key-size <бит>      512 (по умолчанию)
  --user <имя>          администратор, чьи ключи пускать в initramfs
  --dropbear-port <n>   порт SSH в initramfs (2222)
  --prepare             remote-unlock: настроить dropbear до шифрования root

Примеры:
  bash ubuntu_hardening.sh --config /root/hardening.conf --yes
  bash ubuntu_hardening.sh --only sysctl,auditd
  bash ubuntu_hardening.sh --audit
  bash ubuntu_hardening.sh --luks data /dev/vdb --name pgdata --mount /var/lib/postgresql
  bash ubuntu_hardening.sh --luks file /var/lib/secure.img 20G --unlock keyfile
  bash ubuntu_hardening.sh --luks remote-unlock --tang http://tang.example.net
  bash ubuntu_hardening.sh --luks data /dev/vdb && bash ubuntu_hardening.sh --luks docker
  bash ubuntu_hardening.sh --luks encrypt-root /dev/vda1      # в rescue-системе
  bash ubuntu_hardening.sh --luks encrypt-root-auto           # на сервере, затем reboot

Модель угроз: LUKS на VPS защищает снапшоты, бэкапы, отключённые тома и списанные
диски. НЕ защищает от гипервизора, читающего RAM работающей ВМ, и от взлома
работающей системы. Подробности и восстановление — LUKS.md.
EOF
}

# ── Шаги полного прогона ─────────────────────────────────────────────────────
STEPS_ALL=(packages host key user ssh root ufw fail2ban cron mounts sysctl
           modules coredump auditd apparmor sudo accounts perms telemetry
           updates journald aide luks finish)
declare -A STEP_TITLE=(
    [packages]="0. Обновление системы и пакеты"
    [host]="1. Имя хоста, FQDN, DNS, часовой пояс, NTP"
    [key]="2. SSH-ключ администратора"
    [user]="3. Пользователь-администратор"
    [ssh]="4. Настройка SSH"
    [root]="5. Блокировка root, su только для sudo"
    [ufw]="6. Брандмауэр UFW"
    [fail2ban]="7. Fail2ban"
    [cron]="8. Защита cron/at"
    [mounts]="9. Защита разделов"
    [sysctl]="10. Параметры ядра (sysctl)"
    [modules]="11. Blacklist модулей ядра"
    [coredump]="12. Отключение core dump"
    [auditd]="13. Auditd"
    [apparmor]="14. AppArmor"
    [sudo]="15. Настройка sudo"
    [accounts]="16. Пароли, login.defs, faillock"
    [perms]="17. Права на системные файлы"
    [telemetry]="18. Удаление телеметрии"
    [updates]="19. Автоматические обновления"
    [journald]="19.1 Журнал systemd и пересылка логов"
    [aide]="19.2 Контроль целостности (AIDE)"
    [luks]="19.5 Шифрование LUKS (необязательно)"
    [finish]="20. Приватный ключ, лишние службы, итог"
)

# ── Разбор аргументов ─────────────────────────────────────────────────────────
RUN_MODE="harden"
LUKS_ARGS=()
CONFIG_FILE=""
ONLY_STEPS=""
SKIP_STEPS=""
ROLLBACK_STAMP=""
while (( $# )); do
    case "$1" in
        --luks)       RUN_MODE="luks"; shift; LUKS_ARGS=("$@"); break ;;
        --config)     CONFIG_FILE="${2:?--config: нужен путь к файлу}"; shift 2 ;;
        -y|--yes)     ASSUME_YES="yes"; shift ;;
        --only)       ONLY_STEPS="${2:?--only: нужен список шагов}"; shift 2 ;;
        --skip)       SKIP_STEPS="${2:?--skip: нужен список шагов}"; shift 2 ;;
        --audit)      RUN_MODE="audit"; shift ;;
        --rollback)   RUN_MODE="rollback"; shift
                      if (( $# )) && [[ "$1" != -* ]]; then ROLLBACK_STAMP="$1"; shift; fi ;;
        --list-steps) for s in "${STEPS_ALL[@]}"; do printf '  %-10s %s\n' "$s" "${STEP_TITLE[$s]}"; done; exit 0 ;;
        --version)    echo "ubuntu_hardening.sh ${SCRIPT_VERSION}"; exit 0 ;;
        -h|--help)    usage; exit 0 ;;
        *)            echo "Неизвестный аргумент: $1"; echo; usage; exit 1 ;;
    esac
done

for _list in "${ONLY_STEPS}" "${SKIP_STEPS}"; do
    for _s in ${_list//,/ }; do
        [[ -n "${STEP_TITLE[${_s}]:-}" ]] || error "Неизвестный шаг '${_s}' (см. --list-steps)"
    done
done

# ──────────────────────────────────────────────────────────────────────────────
# Общие функции
# ──────────────────────────────────────────────────────────────────────────────

# apt ждёт освобождения блокировки dpkg (cloud-init и unattended-upgrades
# на только что созданном VPS держат её по несколько минут)
APT_GET=(apt-get -o DPkg::Lock::Timeout=300)

ensure_pkgs() {
    local missing=() p
    for p in "$@"; do dpkg -s "$p" &>/dev/null || missing+=("$p"); done
    if (( ${#missing[@]} )); then
        info "Установка пакетов: ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive "${APT_GET[@]}" install -y -qq "${missing[@]}"
    fi
}

confirm() {   # confirm "вопрос" -> 0 если y; в режиме --yes — всегда "нет"
    local ans
    if [[ "${ASSUME_YES}" == "yes" ]]; then
        echo "$1 [y/N]: n (режим --yes)"
        return 1
    fi
    read -r -p "$1 [y/N]: " ans
    [[ "${ans}" =~ ^[Yy]$ ]]
}

backup_file() {
    mkdir -p "${LUKS_BACKUP_DIR}"; chmod 700 "${LUKS_BACKUP_DIR}"
    [[ -f "$1" ]] && cp -a "$1" "${LUKS_BACKUP_DIR}/$(basename "$1").${LUKS_STAMP}"
    return 0
}

# ── Обработчики выхода ───────────────────────────────────────────────────────
add_exit_hook()    { EXIT_HOOKS+=("$1"); }
remove_exit_hook() {
    local h keep=()
    for h in "${EXIT_HOOKS[@]}"; do [[ "$h" == "$1" ]] || keep+=("$h"); done
    EXIT_HOOKS=("${keep[@]}")
}
make_tmp() {   # make_tmp <var> [каталог] — временный файл, удаляется при выходе
    local __f
    __f=$(mktemp "${2:-/tmp}/.uh.XXXXXX")
    TMP_FILES+=("${__f}")
    printf -v "$1" '%s' "${__f}"
}

# ── Резервные копии и журнал изменений для --rollback ─────────────────────────
# track <файл>... — вызвать ДО изменения файла. Первый вызов за прогон
# сохраняет копию (или помечает файл как новый, если его не было).
track() {
    local f
    for f in "$@"; do
        [[ -n "${TRACKED[$f]:-}" ]] && continue
        TRACKED[$f]=1
        mkdir -p "${BACKUP_DIR}/files"; chmod 700 "${BACKUP_ROOT}" "${BACKUP_DIR}"
        if [[ -e "$f" || -L "$f" ]]; then
            cp -a --parents "$f" "${BACKUP_DIR}/files/"
            echo "saved ${f}" >> "${BACKUP_DIR}/manifest"
        else
            echo "new ${f}" >> "${BACKUP_DIR}/manifest"
        fi
    done
}
# Действие, которое откат должен отменить: unit-enable/unit-disable <юнит>,
# statoverride-remove <файл>
track_action() {
    mkdir -p "${BACKUP_DIR}"; chmod 700 "${BACKUP_ROOT}" "${BACKUP_DIR}"
    echo "$*" >> "${BACKUP_DIR}/manifest"
}
# write_file <файл> [права] < содержимое — сохранить копию и записать
write_file() {
    local f="$1" mode="${2:-}"
    track "$f"
    mkdir -p "$(dirname "$f")"
    cat > "$f"
    [[ -z "${mode}" ]] || chmod "${mode}" "$f"
}

# ── Чтение файла состояния / --config без source (никакого выполнения кода) ──
kv_get() {   # kv_get <файл> <ключ>
    [[ -r "$1" ]] || return 0
    awk -v k="$2" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' "$1"
}
load_kv_file() {   # load_kv_file <файл> — только ключи из CONFIG_KEYS
    local file="$1" line key val known
    [[ -r "${file}" ]] || error "Не удаётся прочитать ${file}"
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "${line}" =~ ^[[:space:]]*([A-Z0-9_]+)[[:space:]]*=(.*)$ ]] \
            || { warn "${file}: строка пропущена: ${line}"; continue; }
        key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
        if [[ "${val}" =~ ^\"(.*)\"$ || "${val}" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
        known="no"
        for k in "${CONFIG_KEYS[@]}"; do [[ "$k" == "${key}" ]] && known="yes"; done
        if [[ "${known}" == "yes" ]]; then printf -v "${key}" '%s' "${val}"
        else warn "${file}: неизвестный ключ ${key} — пропущен"; fi
    done < "${file}"
}
load_env_overrides() {
    local k v
    for k in "${CONFIG_KEYS[@]}"; do
        v="UH_${k}"
        [[ -n "${!v+x}" ]] && printf -v "$k" '%s' "${!v}"
    done
    return 0
}

# ask <переменная> <вопрос> — Enter оставляет текущее значение, "-" очищает.
# В режиме --yes вопрос не задаётся.
ask() {
    local __var="$1" __prompt="$2" __ans
    [[ "${ASSUME_YES}" == "yes" ]] && return 0
    read -r -p "  ${__prompt}" __ans || __ans=""
    if [[ "${__ans}" == "-" ]]; then printf -v "${__var}" '%s' ""
    elif [[ -n "${__ans}" ]]; then printf -v "${__var}" '%s' "${__ans}"; fi
}

is_valid_ipv4() {
    local ip="$1" octet
    [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    for octet in ${ip}; do (( 10#${octet} <= 255 )) || return 1; done
}
is_valid_ip() {   # IPv4 или IPv6
    is_valid_ipv4 "$1" && return 0
    [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    if command -v python3 &>/dev/null; then
        python3 -I -c 'import ipaddress,sys; ipaddress.IPv6Address(sys.argv[1])' "$1" 2>/dev/null
    fi
}
is_valid_hostname_fqdn() {
    [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}
is_valid_port() {   # 22 или 1024–65535
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( 10#$1 == 22 || (10#$1 >= 1024 && 10#$1 <= 65535) ))
}
# Список "свой" (выбранных) ключей: строки key-type base64 [comment] без опций
pubkeys_from_file() {   # pubkeys_from_file <authorized_keys>
    awk '!/^[[:space:]]*(#|$)/ {
        for (i = 1; i <= NF; i++)
            if ($i ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/) {
                line = $i; for (j = i + 1; j <= NF; j++) line = line " " $j
                print line; break
            }
    }' "$1" 2>/dev/null
}
# Проверка одной строки ключа: 0 и печать отпечатка, если ключ годен
check_pubkey() {
    local key="$1" tmp fp bits
    [[ "${key}" =~ ^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa)\  ]] || return 1
    tmp=$(mktemp)
    printf '%s\n' "${key}" > "${tmp}"
    fp=$(ssh-keygen -l -f "${tmp}" 2>/dev/null) || { rm -f "${tmp}"; return 1; }
    rm -f "${tmp}"
    if [[ "${key}" == ssh-rsa* ]]; then
        bits=$(awk '{print $1}' <<< "${fp}")
        (( bits >= 3072 )) || { echo "RSA ${bits} бит (нужно >= 3072)"; return 2; }
    fi
    echo "${fp}"
}


# Argon2id: память фиксируется при форматировании и потом нужна при КАЖДОЙ
# разблокировке (в т.ч. в initramfs). Default cryptsetup — до 1 ГБ: на VPS
# с 1 ГБ RAM, а тем более после даунгрейда тарифа, это OOM при загрузке.
luks_pbkdf_memory_kb() {
    local total_kb mem
    total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo)
    mem=$(( total_kb / 4 ))
    (( mem > 1048576 )) && mem=1048576
    (( mem < 65536 ))   && mem=65536
    echo "${mem}"
}

luks_check_cipher() {
    if [[ "${LUKS_CIPHER}" == aes-* ]] && ! grep -qw aes /proc/cpuinfo; then
        warn "CPU не сообщает AES-NI — AES будет медленным."
        warn "Альтернатива для слабых vCPU: --cipher xchacha12,aes-adiantum-plain64 --key-size 256"
        warn "Сравнить: cryptsetup benchmark"
        confirm "Продолжить с ${LUKS_CIPHER}?" || exit 1
    fi
}

luks_format() {
    local target="$1"
    local mem; mem=$(luks_pbkdf_memory_kb)
    info "LUKS2: ${LUKS_CIPHER}/${LUKS_KEY_SIZE}, argon2id (память ${mem} КБ), сектор 4096"
    echo -e "${YELLOW}Пароль LUKS — единственный ключ к данным. Без него и без"
    echo -e "резервной копии заголовка данные НЕ восстановить.${NC}"
    cryptsetup luksFormat \
        --type luks2 \
        --cipher "${LUKS_CIPHER}" --key-size "${LUKS_KEY_SIZE}" \
        --hash sha512 \
        --pbkdf argon2id --pbkdf-memory "${mem}" --iter-time 3000 \
        --sector-size 4096 \
        --label "${LUKS_NAME}" \
        --verify-passphrase \
        "${target}"
}

luks_open() {   # luks_open <источник> [ключевой файл]
    local src="$1" keyfile="${2:-}"
    local args=()
    [[ -n "${keyfile}" ]] && args+=(--key-file "${keyfile}")
    [[ "${LUKS_DISCARDS}" == "yes" ]] && args+=(--allow-discards)
    if [[ "${LUKS_PERF}" == "yes" ]]; then
        # --persistent сохраняет флаги в заголовке LUKS2 (cryptsetup >= 2.3.4, ядро >= 5.9)
        if cryptsetup open "${args[@]}" --persistent \
               --perf-no_read_workqueue --perf-no_write_workqueue \
               "${src}" "${LUKS_NAME}"; then
            return 0
        fi
        warn "Флаги производительности не поддержаны — открываю без них"
    fi
    cryptsetup open "${args[@]}" "${src}" "${LUKS_NAME}"
}

luks_header_backup() {
    local src="$1"
    local out="${LUKS_BACKUP_DIR}/luks-header-${LUKS_NAME}-${LUKS_STAMP}.img"
    mkdir -p "${LUKS_BACKUP_DIR}"; chmod 700 "${LUKS_BACKUP_DIR}"
    cryptsetup luksHeaderBackup "${src}" --header-backup-file "${out}"
    chmod 600 "${out}"
    echo ""
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|  Резервная копия заголовка LUKS:                           |${NC}"
    echo -e "${YELLOW}|  ${out}${NC}"
    echo -e "${YELLOW}|  Скачайте её в надёжное место и удалите с сервера:         |${NC}"
    echo -e "${YELLOW}|    sudo cp <файл> ~${ADMIN_USER}/ && sudo chown ${ADMIN_USER} ~${ADMIN_USER}/<файл>${NC}"
    echo -e "${YELLOW}|    scp -P <порт> ${ADMIN_USER}@<IP>:<файл> .               |${NC}"
    echo -e "${YELLOW}|    shred -u <файл>   (на сервере, в обоих местах)           |${NC}"
    echo -e "${YELLOW}|  Копия открывается СТАРЫМ паролем даже после его смены.    |${NC}"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
}

# Идемпотентная запись строки: удаляем старую по ключу и добавляем новую
set_line() {   # set_line <файл> <awk-условие на $0> <строка>
    local file="$1" cond="$2" line="$3"
    backup_file "${file}"
    touch "${file}"
    awk -v c="${cond}" '!($1 == c)' "${file}" > "${file}.tmp" && mv "${file}.tmp" "${file}"
    echo "${line}" >> "${file}"
}

luks_audit_rules() {
    local f=/etc/audit/rules.d/60-luks.rules
    [[ -d /etc/audit/rules.d ]] || return 0
    cat > "${f}" << 'EOF'
# ubuntu_hardening.sh --luks — изменения конфигурации шифрования
-w /etc/crypttab              -p wa -k luks
-w /etc/cryptsetup-keys.d/    -p wa -k luks
-w /etc/dropbear/initramfs/   -p wa -k luks
-w /etc/initramfs-tools/      -p wa -k luks
EOF
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        info "auditd: правила ${f} применятся после перезагрузки (immutable)"
    else
        augenrules --load &>/dev/null || true
        info "auditd: добавлены правила для конфигурации LUKS"
    fi
}

luks_install_helpers() {
    cat > /usr/local/sbin/luks-unlock << 'EOF'
#!/bin/sh
# Разблокировать и смонтировать том из /etc/crypttab: luks-unlock [имя]
set -eu
name="${1:-securedata}"
src=$(awk -v n="$name" '$1==n {print $2; exit}' /etc/crypttab)
[ -n "$src" ] || { echo "Нет '$name' в /etc/crypttab" >&2; exit 1; }
case "$src" in
    UUID=*) src="/dev/disk/by-uuid/${src#UUID=}" ;;
esac
[ -e "/dev/mapper/$name" ] || cryptsetup open "$src" "$name"
mp=$(awk -v d="/dev/mapper/$name" '$1==d {print $2; exit}' /etc/fstab)
if [ -n "$mp" ] && ! mountpoint -q "$mp"; then mount "$mp"; fi
# bind-точки с x-systemd.requires-mounts-for=<этот том> (например, /var/lib/docker)
if [ -n "$mp" ]; then
    awk -v m="x-systemd.requires-mounts-for=$mp" '!/^[[:space:]]*#/ {
        n = split($4, o, ","); for (i = 1; i <= n; i++) if (o[i] == m) print $2 }' /etc/fstab |
    while read -r b; do mountpoint -q "$b" || mount "$b"; done
fi
# Сервисы, ждущие этот том: по одному имени юнита на строку
if [ -f "/etc/luks-unlock.d/$name.services" ]; then
    grep -v '^\s*#' "/etc/luks-unlock.d/$name.services" | xargs -r systemctl start
fi
echo "OK: $name -> ${mp:-(без точки монтирования)}"
EOF
    cat > /usr/local/sbin/luks-lock << 'EOF'
#!/bin/sh
# Остановить сервисы, отмонтировать и закрыть том: luks-lock [имя]
set -eu
name="${1:-securedata}"
if [ -f "/etc/luks-unlock.d/$name.services" ]; then
    grep -v '^\s*#' "/etc/luks-unlock.d/$name.services" | xargs -r systemctl stop
fi
mp=$(awk -v d="/dev/mapper/$name" '$1==d {print $2; exit}' /etc/fstab)
# сначала зависимые bind-точки (например, /var/lib/docker), затем сам том
if [ -n "$mp" ]; then
    awk -v m="x-systemd.requires-mounts-for=$mp" '!/^[[:space:]]*#/ {
        n = split($4, o, ","); for (i = 1; i <= n; i++) if (o[i] == m) print $2 }' /etc/fstab |
    while read -r b; do
        if mountpoint -q "$b"; then umount -R "$b"; fi
    done
fi
if [ -n "$mp" ] && mountpoint -q "$mp"; then umount "$mp"; fi
if [ -e "/dev/mapper/$name" ]; then cryptsetup close "$name"; fi
echo "Закрыт: $name"
EOF
    chmod 750 /usr/local/sbin/luks-unlock /usr/local/sbin/luks-lock
    mkdir -p /etc/luks-unlock.d
}

# ──────────────────────────────────────────────────────────────────────────────
# Общая часть для data/file: формат, ФС, crypttab, fstab, способ разблокировки
# ──────────────────────────────────────────────────────────────────────────────
luks_setup_volume() {
    local src="$1" crypttab_src="$2"

    case "${LUKS_UNLOCK}" in
        manual|keyfile|tang) ;;
        *) error "--unlock: manual | keyfile | tang" ;;
    esac
    [[ "${LUKS_UNLOCK}" == "tang" && -z "${LUKS_TANG_URL}" ]] && error "Для --unlock tang задайте --tang URL"
    [[ -e "/dev/mapper/${LUKS_NAME}" ]] && error "/dev/mapper/${LUKS_NAME} уже существует — задайте другое --name"
    case "${LUKS_FS}" in
        ext4) ensure_pkgs e2fsprogs ;;
        xfs)  ensure_pkgs xfsprogs ;;
        *)    error "--fs: ext4 или xfs" ;;
    esac

    luks_check_cipher
    luks_format "${src}"
    # Для устройств адресуемся по UUID LUKS — он известен только после форматирования
    if [[ "${crypttab_src}" == "__UUID__" ]]; then
        crypttab_src="UUID=$(cryptsetup luksUUID "${src}")"
    fi

    local keyfile=""
    if [[ "${LUKS_UNLOCK}" == "keyfile" ]]; then
        mkdir -p "${LUKS_KEYS_DIR}"; chmod 700 "${LUKS_KEYS_DIR}"
        keyfile="${LUKS_KEYS_DIR}/${LUKS_NAME}.key"
        ( umask 077; head -c 4096 /dev/urandom > "${keyfile}" )
        chmod 400 "${keyfile}"
        info "Добавляю ключевой файл (введите пароль LUKS)"
        cryptsetup luksAddKey "${src}" "${keyfile}"
        warn "Ключевой файл лежит на root-ФС: том защищён, только если его снапшот"
        warn "или диск утекут ОТДЕЛЬНО от root-диска (или если root тоже зашифрован)."
    fi

    luks_open "${src}" "${keyfile}"

    if [[ "${LUKS_PREFILL}" == "yes" ]]; then
        info "Заполняю том нулями через dm-crypt (на диске это шум) — может быть долго"
        dd if=/dev/zero of="/dev/mapper/${LUKS_NAME}" bs=4M status=progress oflag=direct 2>&1 || true
    fi

    info "Создаю ФС ${LUKS_FS}"
    if [[ "${LUKS_FS}" == "ext4" ]]; then
        mkfs.ext4 -q -L "${LUKS_NAME}" "/dev/mapper/${LUKS_NAME}"
    else
        mkfs.xfs -q -L "${LUKS_NAME}" "/dev/mapper/${LUKS_NAME}"
    fi

    # crypttab / fstab
    local copts="luks" fopts="${LUKS_MOUNT_OPTS}" pass=2
    [[ "${LUKS_DISCARDS}" == "yes" ]] && copts+=",discard"
    case "${LUKS_UNLOCK}" in
        manual)
            copts+=",noauto"
            fopts+=",noauto,nofail"; pass=0
            set_line /etc/crypttab "${LUKS_NAME}" "${LUKS_NAME} ${crypttab_src} none ${copts}"
            ;;
        keyfile)
            fopts+=",nofail,x-systemd.device-timeout=30s"
            set_line /etc/crypttab "${LUKS_NAME}" "${LUKS_NAME} ${crypttab_src} ${keyfile} ${copts}"
            ;;
        tang)
            ensure_pkgs clevis clevis-luks clevis-systemd
            info "Привязка к Tang ${LUKS_TANG_URL} (подтвердите отпечаток ключа Tang и введите пароль LUKS)"
            clevis luks bind -d "${src}" tang "{\"url\":\"${LUKS_TANG_URL}\"}"
            systemctl enable clevis-luks-askpass.path &>/dev/null || true
            copts+=",_netdev"
            fopts+=",nofail,_netdev"
            set_line /etc/crypttab "${LUKS_NAME}" "${LUKS_NAME} ${crypttab_src} none ${copts}"
            ;;
    esac
    chmod 600 /etc/crypttab
    set_line /etc/fstab "/dev/mapper/${LUKS_NAME}" \
        "/dev/mapper/${LUKS_NAME} ${LUKS_MOUNT} ${LUKS_FS} ${fopts} 0 ${pass}"

    mkdir -p "${LUKS_MOUNT}"
    systemctl daemon-reload
    mount "${LUKS_MOUNT}"
    chmod 750 "${LUKS_MOUNT}"
    info "Том смонтирован: /dev/mapper/${LUKS_NAME} -> ${LUKS_MOUNT}"

    luks_install_helpers
    luks_audit_rules
    luks_header_backup "${src}"

    echo ""
    case "${LUKS_UNLOCK}" in
        manual)
            info "После перезагрузки том НЕ открывается сам. Разблокировать:"
            echo "    sudo luks-unlock ${LUKS_NAME}     (закрыть: sudo luks-lock ${LUKS_NAME})"
            echo "  Сервисы, которые надо запускать после разблокировки, перечислите в"
            echo "    /etc/luks-unlock.d/${LUKS_NAME}.services  (по одному на строку)"
            echo "  и отключите их автозапуск: systemctl disable <сервис>"
            ;;
        keyfile) info "Том откроется и смонтируется автоматически при загрузке" ;;
        tang)    info "Том откроется автоматически, если Tang доступен; иначе — sudo luks-unlock ${LUKS_NAME}" ;;
    esac
}

# ──────────────────────────────────────────────────────────────────────────────
# Режим data — отдельный диск или раздел
# ──────────────────────────────────────────────────────────────────────────────
luks_mode_data() {
    local dev="${1:-}"
    [[ -n "${dev}" ]] || error "Укажите устройство: ubuntu_hardening.sh --luks data /dev/vdb"
    [[ -b "${dev}" ]] || error "${dev} — не блочное устройство"
    dev=$(readlink -f "${dev}")

    section "LUKS: шифрование устройства ${dev}"

    # Защита от уничтожения системного диска
    local name mp type
    while read -r name type mp; do
        if [[ -n "${mp}" ]]; then
            error "${name} смонтирован в ${mp} — отказ"
        fi
        if [[ "${type}" =~ ^(lvm|crypt|raid.*|md)$ ]]; then
            error "${name} уже используется (${type}) — отказ"
        fi
    done < <(lsblk -lnpo NAME,TYPE,MOUNTPOINT "${dev}")
    if swapon --show=NAME --noheadings | grep -q "^${dev}"; then
        error "${dev} используется как swap — отказ"
    fi
    if pvs --noheadings -o pv_name 2>/dev/null | grep -q "${dev}"; then
        error "${dev} — физический том LVM — отказ"
    fi

    echo ""
    lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT "${dev}"
    if wipefs -n "${dev}" 2>/dev/null | grep -q .; then
        warn "На ${dev} найдены сигнатуры (ФС/таблица разделов):"
        wipefs -n "${dev}" | sed 's/^/    /'
    fi
    echo ""
    echo -e "${RED}ВСЕ ДАННЫЕ НА ${dev} БУДУТ УНИЧТОЖЕНЫ.${NC}"
    local typed
    read -r -p "  Для подтверждения введите путь устройства полностью: " typed
    [[ "${typed}" == "${dev}" ]] || error "Подтверждение не совпало — отмена"

    ensure_pkgs cryptsetup
    wipefs -a "${dev}" >/dev/null
    luks_setup_volume "${dev}" "__UUID__"
}

# ──────────────────────────────────────────────────────────────────────────────
# Режим file — файл-контейнер (второго диска нет)
# ──────────────────────────────────────────────────────────────────────────────
luks_mode_file() {
    local path="${1:-}" size="${2:-}"
    [[ -n "${path}" && -n "${size}" ]] || error "Использование: ubuntu_hardening.sh --luks file /var/lib/secure.img 20G"
    [[ "${path}" = /* ]] || error "Нужен абсолютный путь"
    [[ -e "${path}" ]] && error "${path} уже существует — отказ"
    [[ "${size}" =~ ^[0-9]+[MGT]$ ]] || error "Размер в формате 512M / 20G / 1T"

    section "LUKS: файл-контейнер ${path} (${size})"
    ensure_pkgs cryptsetup

    local dir; dir=$(dirname "${path}")
    mkdir -p "${dir}"
    local fstype; fstype=$(findmnt -no FSTYPE --target "${dir}")
    [[ "${fstype}" == "tmpfs" ]] && error "${dir} на tmpfs — контейнер исчезнет при перезагрузке"

    local need avail
    need=$(numfmt --from=iec "${size}")
    avail=$(df --output=avail -B1 "${dir}" | tail -1)
    (( need + 1073741824 < avail )) || error "Мало места в ${dir}: нужно ${size} + 1G запаса"

    ( umask 077; fallocate -l "${size}" "${path}" )
    chmod 600 "${path}"
    # cryptsetup сам подключит loop-устройство; systemd-cryptsetup — тоже
    luks_setup_volume "${path}" "${path}"
    warn "Исключите ${path} из бэкапов на уровне файлов — копируйте содержимое ${LUKS_MOUNT}"
}

# ──────────────────────────────────────────────────────────────────────────────
# Режим swap — на диске не должно оставаться открытых страниц памяти
#   swap-файл   -> заменяется на zram (swap поверх loop на файле склонен к
#                  взаимоблокировкам под нехваткой памяти)
#   swap-раздел -> dm-crypt со случайным ключом при каждой загрузке
# ──────────────────────────────────────────────────────────────────────────────
luks_setup_zram() {
    if ! modprobe -n zram &>/dev/null; then
        error "Модуля zram нет в ядре (часть VPS-ядер). Установите linux-modules-extra-$(uname -r) или используйте swap-раздел."
    fi
    if apt-cache show systemd-zram-generator &>/dev/null; then
        ensure_pkgs systemd-zram-generator
        cat > /etc/systemd/zram-generator.conf << 'EOF'
# ubuntu_hardening.sh --luks: сжатый swap в RAM вместо открытого swap на диске
[zram0]
zram-size = min(ram / 2, 4096)
compression-algorithm = zstd
swap-priority = 100
EOF
        systemctl daemon-reload
        systemctl restart systemd-zram-setup@zram0.service
    else
        ensure_pkgs zram-tools
        backup_file /etc/default/zramswap
        cat > /etc/default/zramswap << 'EOF'
ALGO=zstd
PERCENT=50
PRIORITY=100
EOF
        systemctl enable --now zramswap.service
        systemctl restart zramswap.service
    fi
    info "zram-swap активен:"
    swapon --show | sed 's/^/    /'
}

luks_mode_swap() {
    section "Шифрование swap"
    local swaps; swaps=$(swapon --show=NAME,TYPE --noheadings --raw | grep -v '^/dev/zram' || true)
    if [[ -z "${swaps}" ]]; then
        info "Дискового swap нет."
        confirm "Включить zram-swap (сжатый swap в RAM)?" && luks_setup_zram
        return 0
    fi
    echo "  Активный дисковый swap:"
    echo "${swaps}" | sed 's/^/    /'
    confirm "Отключить открытый дисковый swap и заменить защищённым?" || exit 0

    local avail_kb used_kb
    avail_kb=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)
    used_kb=$(free -k | awk '/^Swap/{print $3}')
    (( used_kb < avail_kb )) || error "Занятый swap (${used_kb} КБ) не помещается в свободную RAM — освободите память"

    local name type n=0
    while read -r name type; do
        case "${type}" in
            file)
                info "swap-файл ${name}: swapoff, затирание, удаление, zram"
                swapoff "${name}"
                backup_file /etc/fstab
                awk -v f="${name}" '$1!=f' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab
                # затираем остатки памяти (на thin/SSD-хранилище не гарантировано, но лучше, чем ничего)
                shred -n 0 -z -u "${name}" || rm -f "${name}"
                luks_setup_zram
                ;;
            partition)
                local partuuid; partuuid=$(blkid -s PARTUUID -o value "${name}" || true)
                [[ -n "${partuuid}" ]] || error "У ${name} нет PARTUUID — нельзя надёжно адресовать (mkswap при загрузке опасен)"
                n=$(( n + 1 ))
                local map="cryptswap${n}"
                local olduuid; olduuid=$(blkid -s UUID -o value "${name}" || true)
                info "swap-раздел ${name} -> /dev/mapper/${map} (случайный ключ при загрузке)"
                swapoff "${name}"
                backup_file /etc/fstab
                # убираем старую запись swap, как бы она ни была записана
                awk -v d="${name}" -v u="${olduuid}" -v p="${partuuid}" '
                    $3=="swap" && ($1==d || $1=="UUID="u || $1=="PARTUUID="p ||
                                   $1=="/dev/disk/by-uuid/"u || $1=="/dev/disk/by-partuuid/"p) {next}
                    {print}' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab
                set_line /etc/crypttab "${map}" \
                    "${map} PARTUUID=${partuuid} /dev/urandom swap,plain,cipher=aes-xts-plain64,size=512"
                set_line /etc/fstab "/dev/mapper/${map}" "/dev/mapper/${map} none swap sw,nofail 0 0"
                chmod 600 /etc/crypttab
                systemctl daemon-reload
                systemctl start "systemd-cryptsetup@${map}.service"
                # systemd обычно сам делает mkswap (опция swap); на случай старых версий:
                swapon "/dev/mapper/${map}" 2>/dev/null \
                    || { mkswap -q "/dev/mapper/${map}" && swapon "/dev/mapper/${map}"; }
                ;;
            *) warn "Неизвестный тип swap ${type} (${name}) — пропущен" ;;
        esac
    done <<< "${swaps}"

    # Гибернация в swap со случайным ключом невозможна, а старый RESUME=
    # указывал бы на исчезнувший раздел (задержка загрузки)
    mkdir -p /etc/initramfs-tools/conf.d
    backup_file /etc/initramfs-tools/conf.d/resume
    echo "RESUME=none" > /etc/initramfs-tools/conf.d/resume
    update-initramfs -u -k all &>/dev/null || true
    info "Готово. Текущий swap:"
    swapon --show | sed 's/^/    /'
}

# ──────────────────────────────────────────────────────────────────────────────
# Режим remote-unlock — ввод пароля root-LUKS по SSH из initramfs (dropbear)
# ──────────────────────────────────────────────────────────────────────────────
prefix_to_mask() {
    local p=$1 mask="" i
    for i in 1 2 3 4; do
        if (( p >= 8 )); then mask+="255"; p=$(( p - 8 ))
        else mask+=$(( 256 - 2 ** (8 - p) )); p=0; fi
        (( i < 4 )) && mask+="."
    done
    echo "${mask}"
}

luks_root_is_luks() {
    local src; src=$(findmnt -no SOURCE /)
    lsblk -s -lnpo TYPE "${src}" 2>/dev/null | grep -qx crypt
}

luks_mode_remote_unlock() {
    section "Удалённая разблокировка root-LUKS (dropbear в initramfs)"

    if ! luks_root_is_luks; then
        if [[ "${LUKS_PREPARE_ONLY}" == "yes" ]]; then
            warn "Root пока не зашифрован — режим подготовки (--prepare)"
        else
            error "Корневая ФС не на LUKS. Сначала зашифруйте root (LUKS.md), либо --prepare для подготовки."
        fi
    fi

    # Ubuntu 25.10+/26.04: initramfs собирает dracut — dropbear-initramfs не работает
    if [[ "$(luks_initramfs_tool "")" == "dracut" ]]; then
        luks_remote_unlock_dracut
        return 0
    fi

    ensure_pkgs cryptsetup cryptsetup-initramfs dropbear-initramfs

    local dbdir=/etc/dropbear/initramfs
    [[ -d "${dbdir}" ]] || dbdir=/etc/dropbear-initramfs     # старые релизы
    [[ -d "${dbdir}" ]] || error "Каталог конфигурации dropbear-initramfs не найден"

    # Ключи: те же, что у ADMIN_USER, но только с принудительной командой разблокировки
    local src_keys="/home/${ADMIN_USER}/.ssh/authorized_keys"
    [[ -s "${src_keys}" ]] || error "Нет ${src_keys} — укажите --user"
    backup_file "${dbdir}/authorized_keys"
    grep -E '^(ssh-ed25519|ecdsa-sha2-|ssh-rsa|sk-)' "${src_keys}" | \
        sed 's|^|no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="cryptroot-unlock" |' \
        > "${dbdir}/authorized_keys"
    chmod 600 "${dbdir}/authorized_keys"
    info "Ключи ${ADMIN_USER} скопированы в ${dbdir}/authorized_keys ($(wc -l < "${dbdir}/authorized_keys") шт.)"

    backup_file "${dbdir}/dropbear.conf"
    cat > "${dbdir}/dropbear.conf" << EOF
# ubuntu_hardening.sh --luks: только ключи, без форвардинга, принудительно cryptroot-unlock
DROPBEAR_OPTIONS="-p ${LUKS_DROPBEAR_PORT} -s -j -k -I 120 -c cryptroot-unlock"
EOF

    # Сеть в initramfs: klibc ipconfig понимает только IPv4
    luks_ask_ip kernel
    if [[ -n "${LUKS_IPARG}" ]]; then
        cat > /etc/default/grub.d/90-luks-remote-unlock.cfg << EOF
# ubuntu_hardening.sh --luks: сеть в initramfs для SSH-разблокировки
GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} ${LUKS_IPARG}"
EOF
        info "Параметр ядра: ${LUKS_IPARG}"
    fi

    # Опционально: авторазблокировка через Tang, dropbear остаётся запасным путём
    if [[ -n "${LUKS_TANG_URL}" ]] && luks_root_is_luks; then
        ensure_pkgs clevis clevis-luks clevis-initramfs
        local rootdev
        rootdev=$(lsblk -s -lnpo NAME,TYPE "$(findmnt -no SOURCE /)" | awk '$2=="crypt"{getline; print $1; exit}')
        if [[ -n "${rootdev}" ]] && cryptsetup isLuks "${rootdev}"; then
            info "Привязка ${rootdev} к Tang ${LUKS_TANG_URL}"
            clevis luks bind -d "${rootdev}" tang "{\"url\":\"${LUKS_TANG_URL}\"}"
        else
            warn "Не удалось определить LUKS-устройство root — Tang пропущен"
        fi
    fi

    # cryptsetup-initramfs должен включать модули и crypttab в образ
    if ! grep -qs '^CRYPTSETUP=y' /etc/cryptsetup-initramfs/conf-hook; then
        echo "CRYPTSETUP=y" >> /etc/cryptsetup-initramfs/conf-hook
    fi

    update-initramfs -u -k all
    update-grub
    luks_audit_rules

    echo ""
    info "Отпечатки ключей dropbear (проверьте при первом подключении):"
    for k in "${dbdir}"/dropbear_*_host_key; do
        [[ -f "$k" ]] && dropbearkey -y -f "$k" 2>/dev/null | grep -i fingerprint | sed 's/^/    /'
    done
    cat << EOF

  На своём компьютере добавьте в ~/.ssh/config:

    Host myvps-unlock
        HostName <IP>
        Port ${LUKS_DROPBEAR_PORT}
        User root
        IdentityFile ~/.ssh/admin_ssh_key
        UserKnownHostsFile ~/.ssh/known_hosts.initramfs

  После перезагрузки:  ssh myvps-unlock   -> ввести пароль LUKS

  Не забудьте открыть TCP ${LUKS_DROPBEAR_PORT} в firewall ПРОВАЙДЕРА
  (UFW в initramfs не работает, правило в UFW не нужно).
  Первую перезагрузку проводите с открытой VNC-консолью.
EOF
    lsinitramfs "/boot/initrd.img-$(uname -r)" | grep -q 'cryptroot-unlock' \
        && info "initramfs содержит cryptroot-unlock" \
        || warn "cryptroot-unlock не найден в initramfs — проверьте /etc/crypttab"
}

# ──────────────────────────────────────────────────────────────────────────────
# Режим status
# ──────────────────────────────────────────────────────────────────────────────
luks_mode_status() {
    section "Состояние шифрования"
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT | sed 's/^/  /'
    echo ""
    if luks_root_is_luks; then info "Корневая ФС: на LUKS"; else warn "Корневая ФС: НЕ зашифрована"; fi
    info "Initramfs: $(luks_initramfs_tool "")"
    if [[ -f "${LUKS_CONVERT_DIR}/convert.conf" ]]; then
        if luks_root_is_luks; then
            warn "Корень зашифрован ВРЕМЕННЫМ ключом из initramfs — защиты пока нет."
            warn "Завершите: sudo bash ubuntu_hardening.sh --luks encrypt-root-finish"
        else
            warn "Подготовлено шифрование корня при следующей загрузке (отмена: --luks encrypt-root-cancel)"
        fi
    fi
    [[ -f /boot/luks-convert.failed ]] && warn "Автошифрование корня не удалось: см. /boot/luks-convert.log"
    grep -qw aes /proc/cpuinfo && info "AES-NI: есть" || warn "AES-NI: нет (рассмотрите Adiantum)"

    local m
    for m in $(lsblk -lnpo NAME,TYPE | awk '$2=="crypt"{print $1}'); do
        echo ""
        cryptsetup status "${m}" 2>/dev/null | grep -E "type|cipher|keysize|device|sector size|flags" \
            | sed "s|^|  ${m##*/}: |" || true
    done
    echo ""
    echo "  Swap:"
    local sw; sw=$(swapon --show --noheadings)
    if [[ -z "${sw}" ]]; then echo "    нет"; else echo "${sw}" | sed 's/^/    /'; fi
    swapon --show=NAME --noheadings | grep -vqE '^/dev/(zram|mapper/|dm-)' \
        && warn "Есть НЕзашифрованный swap — ubuntu_hardening.sh --luks swap" || true
    echo ""
    if [[ -s /etc/crypttab ]]; then
        echo "  /etc/crypttab:"; grep -v '^\s*#' /etc/crypttab | sed 's/^/    /'
    fi
    dpkg -s dropbear-initramfs &>/dev/null && info "dropbear-initramfs установлен" || true
}


# ──────────────────────────────────────────────────────────────────────────────
# LUKS — шифрование корневого раздела
#   encrypt-root         из rescue-системы провайдера: пароль вводится сразу,
#                        при необходимости создаётся отдельный раздел /boot
#   encrypt-root-auto    с работающей системы: шифрование выполняется при
#                        следующей загрузке временным ключом из initramfs
#   encrypt-root-finish  после такой загрузки: пароль вместо временного ключа
#
#  Ограничения (оба режима): корень — ext4 на обычном разделе (не LVM/RAID),
#  загрузчик GRUB. XFS не умеет уменьшаться, а место под заголовок LUKS
#  (32 МБ) берётся именно уменьшением ФС.
# ──────────────────────────────────────────────────────────────────────────────
LUKS_ROOT_NAME="root_crypt"
LUKS_CONVERT_DIR="/etc/luks-convert"
LUKS_BOOT_MB=1024
LUKS_TARGET="/mnt/luks-target"
LUKS_NO_REBOOT="no"
MIB=$(( 1024 * 1024 ))

# Каким инструментом собирается initramfs в системе с корнем $1 ("" — текущая).
# Ubuntu 25.10+ (в т.ч. 26.04 LTS) — dracut; 22.04 / 24.04 — initramfs-tools.
luks_initramfs_tool() {
    local R="${1:-}"
    if [[ -d "${R}/usr/lib/dracut" && -x "${R}/usr/bin/dracut" ]]; then
        if [[ ! -x "${R}/usr/sbin/mkinitramfs" ]] \
           || grep -qsi dracut "${R}/usr/sbin/update-initramfs"; then
            echo "dracut"; return 0
        fi
        local ver; ver=$(awk -F'"' '/^VERSION_ID=/{print $2}' "${R}/etc/os-release" 2>/dev/null)
        if [[ -n "${ver}" ]] && awk -v v="${ver}" 'BEGIN{exit !(v+0 >= 25.10)}'; then
            echo "dracut"; return 0
        fi
    fi
    echo "initramfs-tools"
}

# Пересборка initramfs всех ядер; $1 — корень (для chroot) или ""
luks_regen_initramfs() {
    local R="${1:-}" tool; tool=$(luks_initramfs_tool "${R}")
    local run=(); [[ -n "${R}" ]] && run=(chroot "${R}")
    if [[ "${tool}" == "dracut" ]]; then
        "${run[@]}" dracut --regenerate-all --force
    else
        "${run[@]}" update-initramfs -u -k all
    fi
}

# Список файлов образа initramfs; $1 — образ, $2 — корень или ""
luks_initramfs_list() {
    local img="$1" R="${2:-}" tool; tool=$(luks_initramfs_tool "${R}")
    local run=(); [[ -n "${R}" ]] && run=(chroot "${R}")
    if [[ "${tool}" == "dracut" ]]; then
        "${run[@]}" lsinitrd "${img}" 2>/dev/null
    else
        "${run[@]}" lsinitramfs "${img}" 2>/dev/null
    fi
}

luks_require_tools() {
    local missing=() t
    for t in "$@"; do command -v "$t" &>/dev/null || missing+=("$t"); done
    if (( ${#missing[@]} )) && command -v apt-get &>/dev/null; then
        info "Устанавливаю недостающие утилиты: ${missing[*]}"
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            cryptsetup e2fsprogs fdisk util-linux udev || true
        missing=()
        for t in "$@"; do command -v "$t" &>/dev/null || missing+=("$t"); done
    fi
    (( ${#missing[@]} == 0 )) || error "Не найдены утилиты: ${missing[*]}"
}

luks_require_cryptsetup_version() {
    local v maj min
    v=$(cryptsetup --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
    maj=${v%%.*}; min=${v#*.}
    [[ -n "${v}" ]] && (( maj > 2 || (maj == 2 && min >= 4) )) \
        || error "Нужен cryptsetup 2.4 или новее (сейчас: ${v:-нет}) — шифрование на месте в старых версиях ненадёжно"
}

# Сведения о разделе: LP_DISK, LP_NUM, LP_START, LP_SIZE (в 512-байтных секторах)
luks_part_info() {
    local part="$1" name
    name=$(basename "$(readlink -f "${part}")")
    [[ -f "/sys/class/block/${name}/partition" ]] || error "${part} — не раздел диска"
    LP_NUM=$(< "/sys/class/block/${name}/partition")
    LP_START=$(< "/sys/class/block/${name}/start")
    LP_SIZE=$(< "/sys/class/block/${name}/size")
    LP_DISK="/dev/$(lsblk -no PKNAME "${part}" | head -1)"
    [[ -b "${LP_DISK}" ]] || error "Не найден диск для ${part}"
}

# Устройство по записи fstab (UUID=, LABEL=, PARTUUID=, путь)
luks_resolve_spec() {
    local spec="$1"
    case "${spec}" in
        UUID=*)     blkid -U "${spec#UUID=}" 2>/dev/null ;;
        LABEL=*)    blkid -L "${spec#LABEL=}" 2>/dev/null ;;
        PARTUUID=*) blkid -t "PARTUUID=${spec#PARTUUID=}" -o device 2>/dev/null | head -1 ;;
        /dev/*)     readlink -f "${spec}" ;;
        *)          echo "" ;;
    esac
}

# Можно ли уменьшить ФС на устройстве $1 до $2 байт (работает и на смонтированной)
luks_check_shrinkable() {
    local dev="$1" target="$2" bs min
    bs=$(dumpe2fs -h "${dev}" 2>/dev/null | awk -F: '/^Block size/{gsub(/ /,"",$2); print $2}')
    min=$(resize2fs -P "${dev}" 2>/dev/null | awk -F: '/[Mm]inimum size/{gsub(/ /,"",$2); print $2}')
    [[ "${bs}" =~ ^[0-9]+$ && "${min}" =~ ^[0-9]+$ ]] || error "Не удалось оценить минимальный размер ФС ${dev}"
    if (( min * bs >= target )); then
        error "ФС ${dev} нельзя уменьшить до $(( target / MIB )) МБ: по оценке resize2fs нужно не меньше $(( min * bs / MIB )) МБ. Освободите ~$(( (min * bs - target) / MIB + 200 )) МБ или увеличьте диск"
    fi
}

luks_e2fsck() {   # e2fsck с допустимыми кодами 0/1
    local rc=0
    e2fsck -f -p "$1" || rc=$?
    (( rc <= 1 )) || error "e2fsck $1 вернул код ${rc} — исправьте ФС вручную (e2fsck -f $1)"
}

# Общие настройки целевой системы перед загрузкой с зашифрованного корня
luks_target_tweaks() {
    local R="${1:-}" f
    # cloud-init не должен растягивать раздел/ФС под LUKS
    if [[ -d "${R}/etc/cloud/cloud.cfg.d" ]]; then
        printf 'growpart: {mode: off}\nresize_rootfs: false\n' \
            > "${R}/etc/cloud/cloud.cfg.d/99-luks-no-growpart.cfg"
    fi
    # Облачные образы сначала грузятся БЕЗ initrd (root=PARTUUID) — с LUKS это
    # гарантированный сбой первой попытки загрузки
    for f in "${R}"/etc/default/grub.d/*.cfg; do
        [[ -f "${f}" ]] || continue
        if grep -q '^GRUB_FORCE_PARTUUID' "${f}"; then
            sed -i 's/^GRUB_FORCE_PARTUUID/#GRUB_FORCE_PARTUUID/' "${f}"
            info "Отключён GRUB_FORCE_PARTUUID в $(basename "${f}")"
        fi
    done
    if [[ "$(luks_initramfs_tool "${R}")" == "initramfs-tools" ]]; then
        mkdir -p "${R}/etc/initramfs-tools/conf.d" "${R}/etc/cryptsetup-initramfs"
        echo "RESUME=none" > "${R}/etc/initramfs-tools/conf.d/resume"
        grep -qs '^CRYPTSETUP=y' "${R}/etc/cryptsetup-initramfs/conf-hook" \
            || echo "CRYPTSETUP=y" >> "${R}/etc/cryptsetup-initramfs/conf-hook"
    fi
    return 0
}

# Заглушка grub.cfg на EFI-разделе: после переноса /boot она должна искать
# новый раздел (Ubuntu: search.fs_uuid <uuid> root / prefix=/boot/grub)
luks_fix_efi_stub() {
    local esp="$1" boot_uuid="$2" f
    [[ -d "${esp}/EFI" ]] || return 0
    for f in "${esp}"/EFI/*/grub.cfg; do
        [[ -f "${f}" ]] || continue
        grep -q 'search.fs_uuid' "${f}" || continue
        cp "${f}" "${f}.bak-luks"
        printf "search.fs_uuid %s root\nset prefix=(\$root)'/grub'\nconfigfile \$prefix/grub.cfg\n" \
            "${boot_uuid}" > "${f}"
        info "EFI: ${f#"${esp}"/} -> /boot на ${boot_uuid}"
    done
}

luks_chroot_mount() {   # $1 корень-устройство, $2 /boot, $3 EFI (необяз.)
    mkdir -p "${LUKS_TARGET}"
    mount "$1" "${LUKS_TARGET}"
    mount "$2" "${LUKS_TARGET}/boot"
    if [[ -n "${3:-}" ]]; then
        mkdir -p "${LUKS_TARGET}/boot/efi"
        mount "$3" "${LUKS_TARGET}/boot/efi"
    fi
    local d
    for d in dev dev/pts proc sys run; do mount --bind "/${d}" "${LUKS_TARGET}/${d}"; done
    if [[ -d /sys/firmware/efi/efivars ]]; then
        mount --bind /sys/firmware/efi/efivars "${LUKS_TARGET}/sys/firmware/efi/efivars" 2>/dev/null || true
    fi
}

luks_chroot_umount() {
    mountpoint -q "${LUKS_TARGET}" || return 0
    sync
    umount -R "${LUKS_TARGET}" 2>/dev/null || umount -Rl "${LUKS_TARGET}" 2>/dev/null || true
}

# Установка пакетов внутрь chroot: DNS rescue-системы, службы не запускаются
luks_chroot_pkgs() {
    local T="${LUKS_TARGET}" missing=() p rc=0
    for p in "$@"; do chroot "${T}" dpkg -s "${p}" &>/dev/null || missing+=("${p}"); done
    (( ${#missing[@]} )) || return 0
    info "Установка в целевую систему: ${missing[*]}"
    mv "${T}/etc/resolv.conf" "${T}/etc/resolv.conf.luks-bak" 2>/dev/null || true
    cat /etc/resolv.conf > "${T}/etc/resolv.conf" 2>/dev/null || true
    printf '#!/bin/sh\nexit 101\n' > "${T}/usr/sbin/policy-rc.d"
    chmod 755 "${T}/usr/sbin/policy-rc.d"
    { chroot "${T}" env DEBIAN_FRONTEND=noninteractive apt-get update -qq \
      && chroot "${T}" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"; } || rc=$?
    rm -f "${T}/usr/sbin/policy-rc.d" "${T}/etc/resolv.conf"
    mv "${T}/etc/resolv.conf.luks-bak" "${T}/etc/resolv.conf" 2>/dev/null || true
    (( rc == 0 )) || error "Не удалось установить ${missing[*]} в целевую систему (нет сети в rescue?)"
}

# ── Создание раздела /boot из конца корневого раздела (только rescue) ────────
luks_carve_boot() {
    local part="$1" ss label p s rc
    luks_part_info "${part}"
    ss=$(blockdev --getss "${LP_DISK}")
    (( ss == 512 )) || error "Логический сектор ${ss} байт — поддерживается только 512"
    label=$(sfdisk --dump "${LP_DISK}" | awk -F': ' '/^label:/{print $2}')
    for p in /sys/class/block/"$(basename "${LP_DISK}")"/"$(basename "${LP_DISK}")"*; do
        [[ -f "${p}/start" ]] || continue
        s=$(< "${p}/start")
        if (( s > LP_START )); then
            error "После корневого раздела есть другие разделы — место под /boot взять неоткуда. Используйте переустановку с шифрованием (LUKS.md, «Переустановка с шифрованием»)"
        fi
    done
    if [[ "${label}" == "dos" ]]; then
        (( LP_NUM <= 4 )) || error "Корень на логическом разделе MBR — не поддерживается"
        (( $(sfdisk --dump "${LP_DISK}" | grep -c ' : start=') < 4 )) \
            || error "В таблице MBR уже 4 раздела — новый создать нельзя"
    fi

    local bs min_blocks part_bytes new_fs_bytes boot_sec new_part_sec boot_start
    bs=$(dumpe2fs -h "${part}" 2>/dev/null | awk -F: '/^Block size/{gsub(/ /,"",$2); print $2}')
    min_blocks=$(resize2fs -P "${part}" 2>/dev/null | awk -F: '/[Mm]inimum size/{gsub(/ /,"",$2); print $2}')
    [[ "${bs}" =~ ^[0-9]+$ && "${min_blocks}" =~ ^[0-9]+$ ]] || error "Не удалось определить размер ФС ${part}"
    part_bytes=$(( LP_SIZE * 512 ))
    boot_sec=$(( LUKS_BOOT_MB * 2048 ))
    new_fs_bytes=$(( (part_bytes - boot_sec * 512 - 64 * MIB) / MIB * MIB ))
    if (( new_fs_bytes < min_blocks * bs + min_blocks * bs / 10 + 512 * MIB )); then
        error "Мало свободного места в корне: нужно ~$(( LUKS_BOOT_MB + 600 )) МБ свободных"
    fi
    new_part_sec=$(( (new_fs_bytes / MIB + 48) * 2048 ))   # ФС + 48 МБ (заголовок LUKS + запас)
    boot_start=$(( (LP_START + new_part_sec + 2047) / 2048 * 2048 ))
    (( boot_start + boot_sec <= LP_START + LP_SIZE )) || error "Расчёт разметки не сошёлся — отмена"

    info "Уменьшаю ФС до $(( new_fs_bytes / MIB )) МБ (освобождается ${LUKS_BOOT_MB} МБ под /boot)"
    resize2fs "${part}" "$(( new_fs_bytes / 1024 ))K"

    mkdir -p "${LUKS_BACKUP_DIR}"; chmod 700 "${LUKS_BACKUP_DIR}"
    sfdisk --dump "${LP_DISK}" > "${LUKS_BACKUP_DIR}/ptable-${LUKS_STAMP}.sfdisk"
    info "Резервная копия таблицы разделов: ${LUKS_BACKUP_DIR}/ptable-${LUKS_STAMP}.sfdisk"
    echo ", ${new_part_sec}" | sfdisk --no-reread --wipe-partitions never -N "${LP_NUM}" "${LP_DISK}" >/dev/null
    echo "${boot_start}, ${boot_sec}, L" | sfdisk --no-reread --wipe-partitions never --append "${LP_DISK}" >/dev/null
    partx -u "${LP_DISK}" 2>/dev/null || true
    partx -a "${LP_DISK}" 2>/dev/null || true
    udevadm settle 2>/dev/null || sleep 2

    # Ядро должно увидеть новую разметку — иначе дальше работать опасно
    local name newpart=""
    name=$(basename "$(readlink -f "${part}")")
    (( $(< "/sys/class/block/${name}/size") == new_part_sec )) \
        || error "Ядро не перечитало таблицу разделов. Перезагрузите rescue-систему и запустите снова — ФС уже уменьшена, это безопасно"
    for p in /sys/class/block/"$(basename "${LP_DISK}")"/"$(basename "${LP_DISK}")"*; do
        [[ -f "${p}/start" ]] && (( $(< "${p}/start") == boot_start )) && newpart="/dev/$(basename "${p}")"
    done
    [[ -b "${newpart}" ]] || error "Новый раздел /boot не появился — перезагрузите rescue-систему и запустите снова"

    wipefs -a "${newpart}" >/dev/null
    mkfs.ext4 -q -L boot "${newpart}"
    LUKS_NEW_BOOT="${newpart}"
    info "Создан раздел /boot: ${newpart} (${LUKS_BOOT_MB} МБ)"

    # Переносим содержимое /boot и прописываем раздел в fstab ДО шифрования:
    # при повторном запуске скрипт увидит отдельный /boot и не будет резать снова
    mkdir -p "${LUKS_TARGET}" /mnt/luks-newboot
    mount "${part}" "${LUKS_TARGET}"
    mount "${newpart}" /mnt/luks-newboot
    cp -a "${LUKS_TARGET}/boot/." /mnt/luks-newboot/
    cp -a "${LUKS_TARGET}/etc/fstab" "${LUKS_TARGET}/etc/fstab.bak.luks-${LUKS_STAMP}"
    echo "UUID=$(blkid -s UUID -o value "${newpart}") /boot ext4 defaults 0 2" >> "${LUKS_TARGET}/etc/fstab"
    cp "${LUKS_BACKUP_DIR}/ptable-${LUKS_STAMP}.sfdisk" /mnt/luks-newboot/ptable-before-luks.sfdisk
    sync
    umount /mnt/luks-newboot "${LUKS_TARGET}"
    rc=0; e2fsck -f -p "${part}" || rc=$?
    (( rc <= 1 )) || error "e2fsck после переноса /boot: код ${rc}"
}

# ── Режим encrypt-root: из rescue-системы ────────────────────────────────────
luks_mode_encrypt_root() {
    local part="${1:-}"
    section "Шифрование корневого раздела (rescue-режим)"
    [[ -n "${part}" && -b "${part}" ]] \
        || error "Укажите раздел с корнем установленной Ubuntu: --luks encrypt-root /dev/vda1  (список: lsblk -f)"
    part=$(readlink -f "${part}")

    luks_require_tools cryptsetup e2fsck resize2fs dumpe2fs sfdisk partx blkid lsblk \
                       mkfs.ext4 blockdev wipefs chroot
    luks_require_cryptsetup_version
    modprobe dm_crypt 2>/dev/null || true

    if lsblk -lnpo MOUNTPOINT "${part}" | grep -q .; then
        error "${part} смонтирован. Этот режим запускается из rescue-системы провайдера, а не на самом сервере (для работающей системы: --luks encrypt-root-auto)"
    fi
    cryptsetup isLuks "${part}" && error "${part} уже зашифрован"
    [[ "$(blkid -s TYPE -o value "${part}")" == "ext4" ]] \
        || error "На ${part} не ext4 ($(blkid -s TYPE -o value "${part}")). Поддерживается только ext4: XFS не уменьшается, LVM — через переустановку"

    # ── Что за система на разделе ──
    mkdir -p "${LUKS_TARGET}"
    mount -o ro "${part}" "${LUKS_TARGET}"
    local os="" boot_spec="" efi_spec="" boot_dev="" efi_dev="" tool has_grub="no" dropbear="no"
    os=$(awk -F'"' '/^PRETTY_NAME=/{print $2}' "${LUKS_TARGET}/etc/os-release" 2>/dev/null || true)
    boot_spec=$(awk '!/^[[:space:]]*#/ && $2=="/boot"{print $1}' "${LUKS_TARGET}/etc/fstab")
    efi_spec=$(awk '!/^[[:space:]]*#/ && $2=="/boot/efi"{print $1}' "${LUKS_TARGET}/etc/fstab")
    tool=$(luks_initramfs_tool "${LUKS_TARGET}")
    [[ -x "${LUKS_TARGET}/usr/sbin/grub-install" || -d "${LUKS_TARGET}/boot/grub" ]] && has_grub="yes"
    [[ -s "${LUKS_TARGET}/etc/dropbear/initramfs/authorized_keys" ]] && dropbear="yes"
    umount "${LUKS_TARGET}"
    [[ "${os}" == Ubuntu* ]] || error "На ${part} не найдена Ubuntu (${os:-нет /etc/os-release})"
    [[ "${has_grub}" == "yes" ]] || error "Загрузчик целевой системы не GRUB — не поддерживается"
    [[ -n "${boot_spec}" ]] && boot_dev=$(luks_resolve_spec "${boot_spec}")
    [[ -n "${efi_spec}" ]] && efi_dev=$(luks_resolve_spec "${efi_spec}")
    if [[ -n "${boot_spec}" && -z "${boot_dev}" ]]; then
        error "В fstab есть /boot (${boot_spec}), но устройство не найдено"
    fi

    # ── План и подтверждение ──
    echo ""
    lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL "$(lsblk -no PKNAME "${part}" | sed 's|^|/dev/|')" | sed 's/^/    /'
    echo ""
    echo "  Система     : ${os}  (initramfs: ${tool})"
    echo "  Корень      : ${part} — будет зашифрован LUKS2 на месте"
    if [[ -n "${boot_dev}" ]]; then
        echo "  /boot       : ${boot_dev} — отдельный раздел, остаётся как есть"
    else
        echo "  /boot       : внутри корня -> будет создан раздел ${LUKS_BOOT_MB} МБ в конце ${part}"
    fi
    [[ -n "${efi_dev}" ]] && echo "  EFI         : ${efi_dev}"
    if [[ "${dropbear}" == "yes" && "${tool}" == "initramfs-tools" ]]; then
        echo "  Разблокировка: SSH (dropbear уже настроен) или VNC"
    else
        echo "  Разблокировка: VNC-консоль (SSH/Tang — после загрузки: --luks remote-unlock)"
    fi
    echo ""
    warn "Операция переписывает весь раздел. После обрыва (rescue, сеть, питание) шифрование"
    warn "продолжается: cryptsetup repair ${part} && cryptsetup reencrypt --resume-only ${part}."
    warn "Без снапшота не начинайте."
    confirm "Снапшот диска в панели провайдера сделан?" || exit 1
    local typed
    read -r -p "  Для подтверждения введите путь корневого раздела полностью: " typed
    [[ "${typed}" == "${part}" ]] || error "Подтверждение не совпало — отмена"

    add_exit_hook luks_chroot_umount

    # ── /boot ──
    LUKS_NEW_BOOT=""
    luks_e2fsck "${part}"
    if [[ -z "${boot_dev}" ]]; then
        luks_carve_boot "${part}"
        boot_dev="${LUKS_NEW_BOOT}"
    fi

    # ── Шифрование ──
    luks_check_cipher
    local part_bytes fs_bytes bs blocks
    part_bytes=$(blockdev --getsize64 "${part}")
    bs=$(dumpe2fs -h "${part}" 2>/dev/null | awk -F: '/^Block size/{gsub(/ /,"",$2); print $2}')
    blocks=$(dumpe2fs -h "${part}" 2>/dev/null | awk -F: '/^Block count/{gsub(/ /,"",$2); print $2}')
    fs_bytes=$(( bs * blocks ))
    if (( fs_bytes > part_bytes - 40 * MIB )); then
        luks_check_shrinkable "${part}" "$(( part_bytes - 64 * MIB ))"
        info "Уменьшаю ФС на 64 МБ под заголовок LUKS"
        resize2fs "${part}" "$(( (part_bytes - 64 * MIB) / 1024 ))K"
    fi
    echo ""
    echo -e "${YELLOW}Сейчас задаётся пароль LUKS — он понадобится при КАЖДОЙ загрузке.${NC}"
    echo -e "${YELLOW}Шифрование идёт со скоростью диска; не прерывайте rescue-сессию.${NC}"
    local discard_opt=""; [[ "${LUKS_DISCARDS}" == "yes" ]] && discard_opt=",discard"
    cryptsetup reencrypt --encrypt --type luks2 --reduce-device-size 32M \
        --cipher "${LUKS_CIPHER}" --key-size "${LUKS_KEY_SIZE}" --hash sha512 \
        --pbkdf argon2id --pbkdf-memory "$(luks_pbkdf_memory_kb)" --iter-time 3000 \
        --label root --verify-passphrase "${part}"
    info "Шифрование завершено. Откройте том тем же паролем:"
    cryptsetup open "${part}" "${LUKS_ROOT_NAME}"
    luks_e2fsck "/dev/mapper/${LUKS_ROOT_NAME}"
    resize2fs "/dev/mapper/${LUKS_ROOT_NAME}"

    # ── Резервная копия заголовка (rescue-система временная — скачать сейчас) ──
    mkdir -p "${LUKS_BACKUP_DIR}"; chmod 700 "${LUKS_BACKUP_DIR}"
    local hdr="${LUKS_BACKUP_DIR}/luks-header-root-${LUKS_STAMP}.img"
    cryptsetup luksHeaderBackup "${part}" --header-backup-file "${hdr}"
    chmod 600 "${hdr}"

    # ── Настройка системы в chroot ──
    luks_chroot_mount "/dev/mapper/${LUKS_ROOT_NAME}" "${boot_dev}" "${efi_dev}"
    local T="${LUKS_TARGET}" luks_uuid boot_uuid
    luks_uuid=$(cryptsetup luksUUID "${part}")
    boot_uuid=$(blkid -s UUID -o value "${boot_dev}")
    if [[ "${tool}" == "dracut" ]]; then
        luks_chroot_pkgs cryptsetup systemd-cryptsetup
    else
        luks_chroot_pkgs cryptsetup cryptsetup-initramfs
    fi
    luks_target_tweaks "${T}"
    [[ -f "${T}/etc/crypttab" ]] && cp -a "${T}/etc/crypttab" "${T}/etc/crypttab.bak.luks-${LUKS_STAMP}"
    awk -v n="${LUKS_ROOT_NAME}" '$1 != n' "${T}/etc/crypttab" 2>/dev/null > "${T}/etc/crypttab.tmp" || true
    echo "${LUKS_ROOT_NAME} UUID=${luks_uuid} none luks${discard_opt}" >> "${T}/etc/crypttab.tmp"
    mv "${T}/etc/crypttab.tmp" "${T}/etc/crypttab"; chmod 600 "${T}/etc/crypttab"
    if [[ "${tool}" == "dracut" ]]; then
        # dracut: явно указываем LUKS-устройство корня в параметрах ядра
        echo "GRUB_CMDLINE_LINUX=\"\${GRUB_CMDLINE_LINUX} rd.luks.name=${luks_uuid}=${LUKS_ROOT_NAME}\"" \
            > "${T}/etc/default/grub.d/90-luks-root.cfg"
    fi

    info "Пересборка initramfs (${tool})"
    luks_regen_initramfs "${T}"
    info "Обновление конфигурации GRUB"
    chroot "${T}" update-grub

    if [[ -n "${LUKS_NEW_BOOT}" ]]; then
        # /boot переехал: загрузчик должен искать его на новом разделе
        luks_fix_efi_stub "${T}/boot/efi" "${boot_uuid}"
        if [[ "$(sfdisk --dump "${LP_DISK}" | awk -F': ' '/^label:/{print $2}')" == "dos" ]] \
           || sfdisk --dump "${LP_DISK}" | grep -qi 'type=21686148-6449-6E6F-744E-656564454649'; then
            luks_chroot_pkgs grub-pc-bin
            info "BIOS: переустановка GRUB на ${LP_DISK}"
            chroot "${T}" grub-install --target=i386-pc "${LP_DISK}"
        fi
    fi

    # ── Проверки ──
    local img ok="yes" fsuuid
    fsuuid=$(blkid -s UUID -o value "/dev/mapper/${LUKS_ROOT_NAME}")
    for img in "${T}"/boot/initrd.img-*; do
        [[ -f "${img}" ]] || continue
        if ! luks_initramfs_list "/boot/${img##*/}" "${T}" | grep -qE 'cryptroot/crypttab|crypttab|systemd-cryptsetup'; then
            warn "В ${img##*/} не найдена конфигурация шифрования"; ok="no"
        fi
    done
    grep -q "root=UUID=${fsuuid}" "${T}/boot/grub/grub.cfg" \
        || { warn "В grub.cfg корень задан не через UUID ФС (${fsuuid})"; ok="no"; }

    remove_exit_hook luks_chroot_umount
    luks_chroot_umount
    cryptsetup close "${LUKS_ROOT_NAME}" 2>/dev/null || true

    echo ""
    [[ "${ok}" == "yes" ]] && info "Корень зашифрован, система настроена." \
                          || warn "Корень зашифрован, но проверки выше выдали предупреждения — не перезагружайтесь, пока не разберётесь (VNC, chroot)"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|  СКАЧАЙТЕ резервную копию заголовка LUKS ДО перезагрузки:  |${NC}"
    echo -e "${YELLOW}|  ${hdr}${NC}"
    echo -e "${YELLOW}|  rescue-система временная — после перезагрузки файла не будет|${NC}"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo ""
    echo "  Дальше: отключите rescue-режим в панели и перезагрузите сервер."
    echo "  Пароль LUKS при загрузке — в VNC-консоли$( [[ "${dropbear}" == "yes" && "${tool}" == "initramfs-tools" ]] && echo " или по SSH (dropbear)")."
    echo "  После входа: sudo bash ubuntu_hardening.sh --luks status"
    [[ "${dropbear}" == "yes" ]] || echo "  SSH- или Tang-разблокировка: sudo bash ubuntu_hardening.sh --luks remote-unlock"
}

# ── Режим encrypt-root-auto: подготовка на работающей системе ────────────────
#
# Как это работает:
#   1. Сейчас: создаётся временный ключ, в initramfs добавляется сценарий
#      шифрования (ключ — внутри initramfs на незашифрованном /boot).
#   2. Перезагрузка: до монтирования корня сценарий проверяет ФС, уменьшает
#      её на 64 МБ, шифрует раздел на месте (cryptsetup reencrypt) временным
#      ключом, открывает его и растягивает ФС обратно. Загрузка продолжается.
#      При обрыве питания шифрование продолжается со следующей загрузки.
#      Если шифрование не началось — система грузится как раньше.
#   3. После загрузки: --luks encrypt-root-finish задаёт пароль, удаляет
#      временный ключ и сценарий. До этого шага защиты по сути НЕТ: ключ
#      лежит рядом с диском.
luks_write_initramfs_tools_hook() {
    local bins="$1"
    cat > /etc/initramfs-tools/hooks/luks-convert << EOF
#!/bin/sh
# ubuntu_hardening.sh --luks encrypt-root-auto: временный сценарий шифрования корня
PREREQ=""
prereqs() { echo "\$PREREQ"; }
case "\$1" in prereqs) prereqs; exit 0 ;; esac
. /usr/share/initramfs-tools/hook-functions
[ -f ${LUKS_CONVERT_DIR}/convert.conf ] || exit 0
for b in ${bins}; do copy_exec "\$b"; done
manual_add_modules dm_mod dm_crypt xts aesni_intel aes_generic sha256_generic sha512_generic cryptd crypto_simd
mkdir -p "\${DESTDIR}${LUKS_CONVERT_DIR}"
cp ${LUKS_CONVERT_DIR}/convert.conf ${LUKS_CONVERT_DIR}/convert.key "\${DESTDIR}${LUKS_CONVERT_DIR}/"
chmod 600 "\${DESTDIR}${LUKS_CONVERT_DIR}/"*
EOF
    chmod 755 /etc/initramfs-tools/hooks/luks-convert

    cat > /etc/initramfs-tools/scripts/local-top/luks-convert << 'EOF'
#!/bin/sh
# ubuntu_hardening.sh --luks encrypt-root-auto: шифрование корня при загрузке
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "$1" in prereqs) prereqs; exit 0 ;; esac

. /scripts/functions
CONF=/etc/luks-convert/convert.conf
KEY=/etc/luks-convert/convert.key
[ -f "$CONF" ] || exit 0
. "$CONF"
LOG=/run/luks-convert.log
mkdir -p /run/cryptsetup

say() { echo "luks-convert: $*"; echo "$(date '+%F %T') $*" >> "$LOG"; }

wait_dev() {
    i=0
    while [ ! -b "$1" ] && [ "$i" -lt 120 ]; do sleep 0.5; i=$((i + 1)); done
    [ -b "$1" ]
}

# Журнал и флаг сбоя — на незашифрованный /boot (виден после загрузки)
boot_mount() {
    modprobe -q ext4 2>/dev/null
    mkdir -p /run/luks-boot
    wait_dev "/dev/disk/by-uuid/$BOOT_UUID" && mount -t ext4 -o "$1" "/dev/disk/by-uuid/$BOOT_UUID" /run/luks-boot 2>/dev/null
}
save_log() {
    if boot_mount rw; then
        cat "$LOG" >> /run/luks-boot/luks-convert.log 2>/dev/null
        [ -n "$1" ] && echo "$1" > /run/luks-boot/luks-convert.failed
        umount /run/luks-boot
    fi
}

# Чтобы root=UUID=<ФС> указывал на расшифрованное устройство, а не на раздел
fix_links() {
    udevadm trigger --action=change --sysname-match="$(basename "$DEV")" 2>/dev/null
    udevadm settle 2>/dev/null
    target=$(readlink -f "/dev/mapper/$MAP_NAME")
    i=0
    while [ "$(readlink -f "/dev/disk/by-uuid/$FS_UUID" 2>/dev/null)" != "$target" ] && [ "$i" -lt 20 ]; do
        sleep 0.5; i=$((i + 1))
    done
    if [ "$(readlink -f "/dev/disk/by-uuid/$FS_UUID" 2>/dev/null)" != "$target" ]; then
        mkdir -p /dev/disk/by-uuid
        ln -sf "$target" "/dev/disk/by-uuid/$FS_UUID"
    fi
}

open_root() {
    [ -b "/dev/mapper/$MAP_NAME" ] && return 0
    cryptsetup open --key-file "$KEY" "$DEV" "$MAP_NAME"
}

grow_fs() {
    e2fsck -f -p "/dev/mapper/$MAP_NAME" >> "$LOG" 2>&1
    resize2fs "/dev/mapper/$MAP_NAME" >> "$LOG" 2>&1
}

wait_dev "/dev/disk/by-partuuid/$SRC_PARTUUID" || { say "раздел $SRC_PARTUUID не найден — пропуск"; exit 0; }
DEV=$(readlink -f "/dev/disk/by-partuuid/$SRC_PARTUUID")
for m in dm_mod dm_crypt aesni_intel aes_generic xts sha256_generic sha512_generic cryptd crypto_simd; do
    modprobe -q "$m" 2>/dev/null
done

# ── Уже LUKS: продолжить прерванное шифрование и/или просто открыть ──
if cryptsetup isLuks "$DEV"; then
    if cryptsetup luksDump "$DEV" 2>/dev/null | grep -qi "reencrypt"; then
        say "продолжаю прерванное шифрование $DEV — не выключайте сервер"
        # после обрыва LUKS2 требует восстановить «горячую зону» — иначе resume откажет
        cryptsetup repair --key-file "$KEY" --batch-mode "$DEV" >> "$LOG" 2>&1
        if ! cryptsetup reencrypt --resume-only --key-file "$KEY" --batch-mode "$DEV"; then
            save_log "resume"
            panic "luks-convert: не удалось продолжить шифрование. См. LUKS.md (раздел «Восстановление»)"
        fi
        open_root || panic "luks-convert: не удалось открыть $DEV"
        grow_fs; say "шифрование завершено"; save_log ""
    else
        open_root || panic "luks-convert: не удалось открыть $DEV временным ключом"
    fi
    fix_links
    exit 0
fi

# ── Обычный ext4: шифруем ──
if boot_mount ro; then
    if [ -f /run/luks-boot/luks-convert.failed ]; then
        umount /run/luks-boot
        say "предыдущая попытка не удалась — пропуск (см. /boot/luks-convert.log)"
        exit 0
    fi
    umount /run/luks-boot
fi

say "НАЧИНАЮ ШИФРОВАНИЕ $DEV. Не выключайте сервер — это займёт время."
e2fsck -f -p "$DEV" >> "$LOG" 2>&1; rc=$?
if [ "$rc" -gt 1 ]; then say "e2fsck: код $rc — шифрование отменено"; save_log "e2fsck $rc"; exit 0; fi

SECT=$(cat "/sys/class/block/$(basename "$DEV")/size")
NEWK=$(( (SECT * 512 - 64 * 1024 * 1024) / 1024 / 4 * 4 ))
if ! resize2fs "$DEV" "${NEWK}K" >> "$LOG" 2>&1; then
    say "resize2fs не удался — шифрование отменено"; save_log "resize2fs"; exit 0
fi

if ! cryptsetup reencrypt --encrypt --type luks2 --reduce-device-size 32M \
        --cipher "$CIPHER" --key-size "$KEY_SIZE" --hash sha512 \
        --pbkdf argon2id --pbkdf-memory "$PBKDF_MEM" --iter-time 2000 \
        --label root --key-file "$KEY" --batch-mode "$DEV"; then
    if cryptsetup isLuks "$DEV"; then
        say "сбой во время шифрования — пробую продолжить"
        cryptsetup repair --key-file "$KEY" --batch-mode "$DEV" >> "$LOG" 2>&1
        if ! cryptsetup reencrypt --resume-only --key-file "$KEY" --batch-mode "$DEV"; then
            save_log "reencrypt"
            panic "luks-convert: шифрование прервано. Перезагрузка продолжит его; см. LUKS.md"
        fi
    else
        say "шифрование не началось — загрузка без него"
        resize2fs "$DEV" >> "$LOG" 2>&1
        save_log "reencrypt-start"; exit 0
    fi
fi

open_root || panic "luks-convert: зашифровано, но не открывается временным ключом"
grow_fs
fix_links
say "готово: корень зашифрован. После входа: sudo bash ubuntu_hardening.sh --luks encrypt-root-finish"
save_log ""
exit 0
EOF
    chmod 755 /etc/initramfs-tools/scripts/local-top/luks-convert
    echo "UMASK=0077" > /etc/initramfs-tools/conf.d/luks-convert
}

luks_mode_encrypt_root_auto() {
    section "Шифрование корневого раздела при следующей загрузке"
    [[ -f "${LUKS_CONVERT_DIR}/convert.conf" ]] && \
        error "Подготовка уже выполнена. Перезагрузитесь, а после загрузки: --luks encrypt-root-finish"
    luks_root_is_luks && error "Корень уже зашифрован"

    local tool; tool=$(luks_initramfs_tool "")
    [[ "${tool}" == "initramfs-tools" ]] || error "Initramfs собирается ${tool} (Ubuntu 25.10+/26.04). Автоматический режим пока поддерживает только initramfs-tools (22.04/24.04). Используйте --luks encrypt-root из rescue-режима."

    local src fstype bsrc
    src=$(findmnt -no SOURCE /)
    fstype=$(findmnt -no FSTYPE /)
    [[ "${fstype}" == "ext4" ]] || error "Корень на ${fstype}, поддерживается только ext4"
    [[ "$(lsblk -no TYPE "${src}")" == "part" ]] || error "Корень не на обычном разделе (${src}: LVM/RAID/весь диск) — не поддерживается"
    bsrc=$(findmnt -no SOURCE /boot 2>/dev/null || true)
    if [[ -z "${bsrc}" || "${bsrc}" == "${src}" ]]; then
        error "/boot не на отдельном разделе. На работающей системе создать его нельзя (корень не уменьшить, пока он смонтирован). Используйте --luks encrypt-root из rescue-режима — он создаст /boot сам."
    fi
    [[ "$(findmnt -no FSTYPE /boot)" == "ext4" ]] || error "/boot должен быть ext4"
    [[ -f /boot/grub/grub.cfg ]] || error "Загрузчик не GRUB — не поддерживается"

    local partuuid fsuuid bootuuid avail_root avail_boot disk_gb
    partuuid=$(blkid -s PARTUUID -o value "${src}")
    fsuuid=$(blkid -s UUID -o value "${src}")
    bootuuid=$(blkid -s UUID -o value "${bsrc}")
    [[ -n "${partuuid}" && -n "${fsuuid}" && -n "${bootuuid}" ]] || error "Не удалось определить UUID разделов"
    avail_root=$(df --output=avail -k / | tail -1)
    avail_boot=$(df --output=avail -k /boot | tail -1)
    (( avail_root > 524288 )) || error "На / нужно минимум 512 МБ свободного места"
    luks_check_shrinkable "${src}" "$(( $(blockdev --getsize64 "${src}") - 64 * MIB ))"
    (( avail_boot > 102400 )) || error "На /boot нужно минимум 100 МБ свободного места"
    disk_gb=$(( $(blockdev --getsize64 "${src}") / 1024 / 1024 / 1024 ))

    ensure_pkgs cryptsetup cryptsetup-initramfs e2fsprogs
    luks_require_cryptsetup_version
    luks_check_cipher

    echo ""
    echo "  Корень : ${src} (${disk_gb} ГБ, ext4)     /boot : ${bsrc} (не шифруется)"
    echo ""
    echo "  Что произойдёт:"
    echo "    1. Сейчас — временный ключ и сценарий шифрования добавляются в initramfs."
    echo "    2. Перезагрузка — раздел шифруется ДО монтирования корня. Ход виден в"
    echo "       VNC-консоли. Время — порядка $(( disk_gb * 10 / 100 + 1 ))–$(( disk_gb * 10 / 30 + 1 )) мин (зависит от диска)."
    echo "    3. Система загружается сама. Войдите и выполните:"
    echo "       sudo bash ubuntu_hardening.sh --luks encrypt-root-finish"
    echo "       — до этого шага ключ лежит на незашифрованном /boot, защиты нет."
    echo ""
    warn "Если питание пропадёт во время шифрования — оно продолжится при следующей загрузке."
    warn "Если шифрование не начнётся — система загрузится как раньше (журнал: /boot/luks-convert.log)."
    echo ""
    confirm "Снапшот диска в панели провайдера сделан?" || exit 1
    confirm "VNC-консоль провайдера доступна?" || exit 1
    local typed
    read -r -p "  Для подтверждения введите путь корневого раздела (${src}): " typed
    [[ "${typed}" == "${src}" ]] || error "Подтверждение не совпало — отмена"

    # ── Временный ключ и параметры ──
    mkdir -p "${LUKS_CONVERT_DIR}"; chmod 700 "${LUKS_CONVERT_DIR}"
    ( umask 077; head -c 4096 /dev/urandom > "${LUKS_CONVERT_DIR}/convert.key" )
    chmod 400 "${LUKS_CONVERT_DIR}/convert.key"
    cat > "${LUKS_CONVERT_DIR}/convert.conf" << EOF
SRC_PARTUUID=${partuuid}
FS_UUID=${fsuuid}
BOOT_UUID=${bootuuid}
MAP_NAME=${LUKS_ROOT_NAME}
CIPHER=${LUKS_CIPHER}
KEY_SIZE=${LUKS_KEY_SIZE}
PBKDF_MEM=$(luks_pbkdf_memory_kb)
DISCARDS=${LUKS_DISCARDS}
EOF
    chmod 600 "${LUKS_CONVERT_DIR}/convert.conf"

    # ── Загрузчик: корень должен задаваться UUID ФС, а не PARTUUID ──
    luks_target_tweaks ""
    update-grub
    grep -q "root=UUID=${fsuuid}" /boot/grub/grub.cfg || {
        rm -rf "${LUKS_CONVERT_DIR}"
        error "В grub.cfg корень задан не через UUID ФС (проверьте GRUB_DISABLE_LINUX_UUID) — отмена"
    }

    # ── Сценарий в initramfs ──
    local bins="" b p
    for b in cryptsetup e2fsck resize2fs udevadm; do
        p=$(command -v "${b}") || { rm -rf "${LUKS_CONVERT_DIR}"; error "Нет утилиты ${b}"; }
        bins+="${p} "
    done
    luks_write_initramfs_tools_hook "${bins}"
    update-initramfs -u -k all
    chmod 600 /boot/initrd.img-* 2>/dev/null || true

    local img; img="/boot/initrd.img-$(uname -r)"
    if ! lsinitramfs "${img}" | grep -q 'luks-convert/convert.key' \
       || ! lsinitramfs "${img}" | grep -q 'local-top/luks-convert' \
       || ! lsinitramfs "${img}" | grep -qE 'sbin/cryptsetup$'; then
        rm -f /etc/initramfs-tools/hooks/luks-convert /etc/initramfs-tools/scripts/local-top/luks-convert \
              /etc/initramfs-tools/conf.d/luks-convert
        rm -rf "${LUKS_CONVERT_DIR}"
        update-initramfs -u -k all
        error "initramfs собран без сценария шифрования — изменения отменены"
    fi
    rm -f /boot/luks-convert.failed
    luks_audit_rules

    info "Всё готово к шифрованию при следующей загрузке."
    echo ""
    echo "  Откройте VNC-консоль и перезагрузите сервер. После загрузки:"
    echo "    sudo bash ubuntu_hardening.sh --luks encrypt-root-finish"
    echo "  Отменить до перезагрузки: sudo bash ubuntu_hardening.sh --luks encrypt-root-cancel"
    if [[ "${LUKS_NO_REBOOT}" != "yes" ]] && confirm "Перезагрузить сейчас?"; then
        sync
        systemctl reboot
    fi
}

# Отмена подготовки до перезагрузки (или после неудачной попытки)
luks_mode_encrypt_root_cancel() {
    section "Отмена автоматического шифрования корня"
    luks_root_is_luks && error "Корень уже зашифрован — отменять нечего. Завершите: --luks encrypt-root-finish"
    rm -f /etc/initramfs-tools/hooks/luks-convert /etc/initramfs-tools/scripts/local-top/luks-convert \
          /etc/initramfs-tools/conf.d/luks-convert /boot/luks-convert.failed
    [[ -f "${LUKS_CONVERT_DIR}/convert.key" ]] && shred -uz "${LUKS_CONVERT_DIR}/convert.key"
    rm -rf "${LUKS_CONVERT_DIR}"
    update-initramfs -u -k all
    info "Подготовка отменена, временный ключ удалён"
}

# ── Режим encrypt-root-finish: пароль вместо временного ключа ────────────────
luks_mode_encrypt_root_finish() {
    section "Завершение шифрования корня"
    [[ -f "${LUKS_CONVERT_DIR}/convert.conf" && -f "${LUKS_CONVERT_DIR}/convert.key" ]] \
        || error "Нет ${LUKS_CONVERT_DIR} — автоматическое шифрование не готовилось или уже завершено"
    luks_root_is_luks || {
        warn "Корень не зашифрован. Журнал попытки:"
        tail -20 /boot/luks-convert.log 2>/dev/null | sed 's/^/    /' || true
        error "Шифрование не выполнилось. Причина — в /boot/luks-convert.log; отмена: --luks encrypt-root-cancel"
    }
    local SRC_PARTUUID="" DISCARDS="no" dev key="${LUKS_CONVERT_DIR}/convert.key"
    SRC_PARTUUID=$(awk -F= '$1=="SRC_PARTUUID"{print $2}' "${LUKS_CONVERT_DIR}/convert.conf")
    DISCARDS=$(awk -F= '$1=="DISCARDS"{print $2}' "${LUKS_CONVERT_DIR}/convert.conf")
    dev=$(readlink -f "/dev/disk/by-partuuid/${SRC_PARTUUID}")
    cryptsetup isLuks "${dev}" || error "${dev} не LUKS"
    if cryptsetup luksDump "${dev}" | grep -qi reencrypt; then
        error "Шифрование ещё не завершено (идёт или прервано) — перезагрузитесь, оно продолжится"
    fi

    # 1. Пароль
    echo ""
    echo -e "${YELLOW}Задайте пароль LUKS. Он понадобится при КАЖДОЙ загрузке сервера.${NC}"
    cryptsetup luksAddKey --key-file "${key}" --pbkdf argon2id \
        --pbkdf-memory "$(luks_pbkdf_memory_kb)" --iter-time 3000 "${dev}"
    info "Проверка пароля:"
    until cryptsetup open --test-passphrase "${dev}"; do
        warn "Пароль не подошёл — попробуйте ещё раз (Ctrl+C — прервать; временный ключ пока цел)"
    done

    # 2. crypttab и обычная разблокировка паролем
    local luks_uuid discard_opt=""
    luks_uuid=$(cryptsetup luksUUID "${dev}")
    [[ "${DISCARDS}" == "yes" ]] && discard_opt=",discard"
    set_line /etc/crypttab "${LUKS_ROOT_NAME}" "${LUKS_ROOT_NAME} UUID=${luks_uuid} none luks${discard_opt}"
    chmod 600 /etc/crypttab

    # 3. Убираем сценарий (копии — на случай отката)
    mkdir -p "${LUKS_CONVERT_DIR}/disabled"
    mv /etc/initramfs-tools/hooks/luks-convert "${LUKS_CONVERT_DIR}/disabled/hook" 2>/dev/null || true
    mv /etc/initramfs-tools/scripts/local-top/luks-convert "${LUKS_CONVERT_DIR}/disabled/local-top" 2>/dev/null || true
    rm -f /etc/initramfs-tools/conf.d/luks-convert

    # 4. Разблокировка по сети (необязательно) + пересборка initramfs
    echo ""
    echo "  Как вводить пароль при загрузке?"
    echo "    1) по SSH (dropbear в initramfs) — рекомендуется для VPS"
    echo "    2) только VNC-консоль провайдера"
    local ch; read -r -p "  Выбор [1/2]: " ch
    if [[ "${ch}" != "2" ]]; then
        # в подоболочке: ошибка настройки dropbear не должна оборвать finish
        luks_run remote-unlock
    fi
    update-initramfs -u -k all

    # 5. Проверка: в каждом initramfs есть crypttab корня и НЕТ временного ключа
    local img bad="no"
    for img in /boot/initrd.img-*; do
        [[ -f "${img}" ]] || continue
        if ! lsinitramfs "${img}" | grep -q 'cryptroot/crypttab'; then
            warn "${img##*/}: нет cryptroot/crypttab"; bad="yes"
        fi
        if lsinitramfs "${img}" | grep -q 'luks-convert'; then
            warn "${img##*/}: всё ещё содержит временный ключ"; bad="yes"
        fi
    done
    if [[ "${bad}" == "yes" ]]; then
        mv "${LUKS_CONVERT_DIR}/disabled/hook" /etc/initramfs-tools/hooks/luks-convert 2>/dev/null || true
        mv "${LUKS_CONVERT_DIR}/disabled/local-top" /etc/initramfs-tools/scripts/local-top/luks-convert 2>/dev/null || true
        echo "UMASK=0077" > /etc/initramfs-tools/conf.d/luks-convert
        update-initramfs -u -k all
        error "initramfs собран некорректно — временный ключ и сценарий возвращены, система по-прежнему загрузится. Пароль добавлен; запустите finish ещё раз после разбора"
    fi

    # 6. Удаляем временный ключ из LUKS и с диска
    cryptsetup luksRemoveKey "${dev}" "${key}"
    shred -uz "${key}"
    rm -rf "${LUKS_CONVERT_DIR}"
    rm -f /boot/initrd.img-*.bak /boot/initrd.img-*.old-dkms 2>/dev/null || true
    info "Временный ключ удалён из заголовка LUKS и с диска"

    # 7. Смена мастер-ключа (необязательно)
    echo ""
    echo "  Временный ключ лежал на незашифрованном /boot. Если за это время провайдер"
    echo "  мог сделать снапшот (автобэкапы, ручные снапшоты), по нему можно извлечь"
    echo "  мастер-ключ тома. Смена мастер-ключа это исключает: том перешифровывается"
    echo "  на лету, сервер продолжает работать, время — как у первого шифрования."
    if confirm "Сменить мастер-ключ сейчас?"; then
        cryptsetup reencrypt --resilience checksum "${dev}"
        info "Мастер-ключ заменён"
    else
        warn "Мастер-ключ не менялся — удалите снапшоты диска, сделанные до этого момента"
    fi

    LUKS_NAME="${LUKS_ROOT_NAME}" luks_header_backup "${dev}"
    echo ""
    info "Шифрование корня завершено. Проверьте перезагрузку с открытой VNC-консолью."
    luks_mode_status
}

# Параметр ядра ip= для сети в initramfs. $1: kernel (initramfs-tools/klibc)
# или dracut. Результат — в LUKS_IPARG (пусто, если IPv4 не найден).
luks_ask_ip() {
    local style="$1" dev gw cidr addr prefix mask ch
    LUKS_IPARG=""
    dev=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    gw=$(ip -4 route show default | awk '{print $3; exit}')
    cidr=$(ip -4 -o addr show dev "${dev}" scope global 2>/dev/null | awk '{print $4; exit}')
    if [[ -z "${dev}" || -z "${cidr}" ]]; then
        warn "Не найден IPv4 по умолчанию. Сеть в initramfs настраивается только по IPv4 —"
        warn "на IPv6-only VPS используйте VNC-консоль. Сетевой параметр не задан."
        return 0
    fi
    addr=${cidr%/*}; prefix=${cidr#*/}; mask=$(prefix_to_mask "${prefix}")
    echo ""
    echo "  Обнаружено: ${dev}  ${addr}/${prefix}  шлюз ${gw}"
    echo "    1) статический IP (рекомендуется — работает и без DHCP)"
    echo "    2) DHCP"
    read -r -p "  Выбор [1/2]: " ch
    if [[ "${ch}" == "2" ]]; then
        [[ "${style}" == "dracut" ]] && LUKS_IPARG="rd.neednet=1 ip=${dev}:dhcp" \
                                     || LUKS_IPARG="ip=:::::${dev}:dhcp"
    else
        # /32 с шлюзом вне подсети (Hetzner и др.) — initramfs это часто не умеет
        (( prefix == 32 )) && warn "Префикс /32 (on-link шлюз). Если initramfs не поднимет сеть — выберите DHCP."
        [[ "${style}" == "dracut" ]] && LUKS_IPARG="rd.neednet=1 ip=${addr}::${gw}:${mask}::${dev}:none" \
                                     || LUKS_IPARG="ip=${addr}::${gw}:${mask}::${dev}:off"
    fi
    warn "Имя интерфейса в initramfs обычно совпадает (${dev}); проверьте один раз через VNC."
    return 0
}

# Сетевая разблокировка на системах с dracut (Ubuntu 25.10+/26.04): только Tang
luks_remote_unlock_dracut() {
    warn "Initramfs собирается dracut (Ubuntu 25.10+/26.04): dropbear-initramfs здесь не работает."
    if [[ -z "${LUKS_TANG_URL}" ]]; then
        error "Сетевая разблокировка на этой системе — через Tang: --luks remote-unlock --tang http://tang.example.net. Без Tang пароль вводится в VNC-консоли провайдера."
    fi
    luks_root_is_luks || error "Корень не на LUKS — Tang привязывается к уже зашифрованному тому"
    ensure_pkgs clevis clevis-luks clevis-dracut
    local rootdev
    rootdev=$(lsblk -s -lnpo NAME,TYPE "$(findmnt -no SOURCE /)" | awk '$2=="crypt"{getline; print $1; exit}')
    [[ -n "${rootdev}" ]] && cryptsetup isLuks "${rootdev}" || error "Не удалось определить LUKS-устройство корня"
    info "Привязка ${rootdev} к Tang ${LUKS_TANG_URL} (подтвердите отпечаток ключа Tang, введите пароль LUKS)"
    clevis luks bind -d "${rootdev}" tang "{\"url\":\"${LUKS_TANG_URL}\"}"
    luks_ask_ip dracut
    if [[ -n "${LUKS_IPARG}" ]]; then
        cat > /etc/default/grub.d/90-luks-remote-unlock.cfg << EOF
# ubuntu_hardening.sh --luks: сеть в initramfs (dracut) для Tang
GRUB_CMDLINE_LINUX="\${GRUB_CMDLINE_LINUX} ${LUKS_IPARG}"
EOF
        info "Параметры ядра: ${LUKS_IPARG}"
    fi
    dracut --regenerate-all --force
    update-grub
    luks_audit_rules
    info "Tang настроен: при доступном Tang-сервере корень откроется сам, иначе — пароль в VNC."
    echo "  Первую перезагрузку проводите с открытой VNC-консолью."
}

# ──────────────────────────────────────────────────────────────────────────────
# LUKS — данные Docker на зашифрованном томе: --luks docker
#
#  Каталог Docker (и containerd — в Docker 29+ там образы и слои контейнеров)
#  переносится на уже созданный зашифрованный том и подключается обратно
#  bind-монтированием. Пути не меняются, daemon.json и config.toml не трогаются.
#  Docker не может стартовать, пока том не открыт (RequiresMountsFor), а пустые
#  точки монтирования неизменяемы (chattr +i) — без тома запись на открытый
#  диск невозможна. Старые данные сохраняются до явного удаления.
# ──────────────────────────────────────────────────────────────────────────────

# Каталог данных Docker: из работающего демона, из daemon.json или по умолчанию
luks_docker_root() {
    local r=""
    r=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)
    if [[ -z "${r}" && -f /etc/docker/daemon.json ]]; then
        r=$(sed -n 's/.*"data-root"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/docker/daemon.json | head -1)
    fi
    echo "${r:-/var/lib/docker}"
}

luks_containerd_root() {
    local r=""
    if [[ -f /etc/containerd/config.toml ]]; then
        r=$(sed -n 's/^[[:space:]]*root[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' /etc/containerd/config.toml | head -1)
    fi
    echo "${r:-/var/lib/containerd}"
}

# Неизменяемая пустая точка монтирования на нижележащей ФС (даже если поверх
# уже что-то смонтировано): bind-вид корня -> chattr +i
luks_protect_mountpoint() {
    local mp="$1" view=/run/luks-rootview fs_mp rel
    fs_mp=$(findmnt -no TARGET --target "$(dirname "${mp}")")
    rel="${mp#"${fs_mp%/}"}"
    mkdir -p "${view}"
    mount --bind "${fs_mp}" "${view}"
    if [[ -d "${view}${rel}" ]] && [[ -z "$(ls -A "${view}${rel}" 2>/dev/null)" ]]; then
        chattr +i "${view}${rel}" 2>/dev/null && info "  ${mp}: пустая точка монтирования защищена (chattr +i)" \
            || warn "  chattr +i не поддерживается ФС для ${mp}"
    else
        warn "  ${mp}: под точкой монтирования есть файлы — chattr не ставлю, проверьте вручную"
    fi
    umount "${view}"
}

# Перенос одного каталога: $1 исходный, $2 новый на томе, $3 mp тома, $4 noauto|auto
luks_docker_move_dir() {
    local src="$1" dst="$2" mp="$3" mode="$4" opts n_src n_dst
    if mountpoint -q "${src}"; then
        error "${src} уже является точкой монтирования — перенос не поддерживается (проверьте findmnt ${src})"
    fi
    mkdir -p "${dst}"
    chmod --reference="${src}" "${dst}" 2>/dev/null || chmod 710 "${dst}"
    info "Копирование ${src} -> ${dst}"
    rsync -aHAXS --numeric-ids --info=progress2 "${src}/" "${dst}/"
    n_src=$(find "${src}" -xdev | wc -l)
    n_dst=$(find "${dst}" -xdev | wc -l)
    (( n_src == n_dst )) || error "Копия не совпадает (${n_src} / ${n_dst} объектов) — исходный ${src} не тронут"
    info "  скопировано объектов: ${n_dst}"

    mv "${src}" "${src}.pre-luks"
    mkdir -p "${src}"
    chmod --reference="${src}.pre-luks" "${src}"
    chattr +i "${src}" 2>/dev/null || warn "  chattr +i для ${src} не поддерживается"

    opts="bind,x-systemd.requires-mounts-for=${mp}"
    [[ "${mode}" == "noauto" ]] && opts+=",noauto" || opts+=",nofail"
    set_line /etc/fstab "${dst}" "${dst} ${src} none ${opts} 0 0"
    systemctl daemon-reload
    mount "${src}"
    info "  ${src} -> bind на ${dst}"
}

luks_systemd_requires() {   # $1 юнит, $2 путь
    local unit="$1" path="$2"
    mkdir -p "/etc/systemd/system/${unit}.d"
    cat > "/etc/systemd/system/${unit}.d/10-luks-data.conf" << EOF
# ubuntu_hardening.sh --luks docker: не запускаться без зашифрованного тома
[Unit]
RequiresMountsFor=${path}
EOF
}

luks_mode_docker() {
    section "Данные Docker на зашифрованном томе"

    command -v dockerd &>/dev/null || error "Docker не установлен"
    if [[ "$(command -v docker)" == /snap/* ]] || snap list docker &>/dev/null; then
        error "Docker установлен из snap (данные в /var/snap/docker) — не поддерживается; поставьте docker.io или docker-ce"
    fi

    # ── Том ──
    local mp ctline mode
    mp=$(awk -v d="/dev/mapper/${LUKS_NAME}" '!/^[[:space:]]*#/ && $1==d {print $2; exit}' /etc/fstab)
    ctline=$(awk -v n="${LUKS_NAME}" '!/^[[:space:]]*#/ && $1==n' /etc/crypttab 2>/dev/null)
    if [[ -z "${mp}" || -z "${ctline}" ]]; then
        error "Зашифрованный том '${LUKS_NAME}' не найден. Сначала создайте его:
      bash ubuntu_hardening.sh --luks data /dev/vdb            (отдельный диск)
      bash ubuntu_hardening.sh --luks file /var/lib/secure.img 50G   (файл)
    и, если имя не securedata, укажите --name"
    fi
    mountpoint -q "${mp}" || error "Том ${LUKS_NAME} не смонтирован — выполните: sudo luks-unlock ${LUKS_NAME}"
    [[ "${ctline}" == *noauto* ]] && mode="noauto" || mode="auto"

    ensure_pkgs rsync

    # ── Что переносим ──
    local droot croot have_containerd="no" docker_was_active="no"
    droot=$(luks_docker_root)
    croot=$(luks_containerd_root)
    systemctl is-active --quiet docker.service && docker_was_active="yes"
    if systemctl cat containerd.service &>/dev/null \
       && [[ -d "${croot}" ]] && [[ -n "$(ls -A "${croot}" 2>/dev/null)" ]]; then
        have_containerd="yes"
    fi
    local dst_d="${mp}/docker" dst_c="${mp}/containerd"
    local need_d="yes" need_c="no"
    [[ "$(findmnt -no SOURCE --target "${droot}" 2>/dev/null)" == "/dev/mapper/${LUKS_NAME}"* ]] && need_d="no"
    grep -qs "^${dst_d} ${droot} none bind" /etc/fstab && need_d="no"
    if [[ "${have_containerd}" == "yes" ]]; then
        need_c="yes"
        grep -qs "^${dst_c} ${croot} none bind" /etc/fstab && need_c="no"
    fi

    # ── Отчёт об утечках: что останется НЕзашифрованным ──
    local running=() leaks=() wd
    if [[ "${docker_was_active}" == "yes" ]]; then
        mapfile -t running < <(docker ps -q 2>/dev/null)
        while read -r line; do
            [[ -n "${line}" ]] && leaks+=("${line}")
        done < <(docker ps -aq 2>/dev/null | xargs -r docker inspect \
                 -f '{{.Name}}{{range .Mounts}}{{if eq .Type "bind"}} {{.Source}}{{end}}{{end}}' 2>/dev/null \
                 | awk -v mp="${mp}" '{for(i=2;i<=NF;i++) if (index($i, mp"/")!=1 && $i!=mp && $i !~ /^\/(etc|run|var\/run|sys|proc|dev)(\/|$)/) print $1 ": " $i}')
        while read -r wd; do
            [[ -n "${wd}" && "${wd}" != "${mp}"* ]] && leaks+=("compose-проект в ${wd} (.env, конфиги)")
        done < <(docker ps -aq 2>/dev/null | xargs -r docker inspect \
                 -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null | sort -u)
        local logdrv; logdrv=$(docker info -f '{{.LoggingDriver}}' 2>/dev/null || true)
        [[ "${logdrv}" == "journald" || "${logdrv}" == "syslog" ]] && \
            leaks+=("логи контейнеров идут в ${logdrv} — на системный диск (смените на json-file или local)")
    fi

    echo ""
    echo "  Зашифрованный том : /dev/mapper/${LUKS_NAME} -> ${mp} ($( [[ ${mode} == noauto ]] && echo "открывается вручную" || echo "открывается при загрузке"))"
    if [[ "${need_d}" == "yes" ]]; then
        echo "  Docker            : ${droot} ($(du -sxh "${droot}" 2>/dev/null | cut -f1)) -> ${dst_d}"
    else
        echo "  Docker            : уже на томе"
    fi
    if [[ "${need_c}" == "yes" ]]; then
        echo "  containerd        : ${croot} ($(du -sxh "${croot}" 2>/dev/null | cut -f1)) -> ${dst_c}"
    fi
    if [[ "${need_d}" == "yes" || "${need_c}" == "yes" ]]; then
        echo "  Запущено контейнеров: ${#running[@]} — на время переноса они будут остановлены"
    fi
    if (( ${#leaks[@]} )); then
        echo ""
        warn "Останется НЕзашифрованным (перенесите на ${mp} сами):"
        printf '      %s\n' "${leaks[@]}"
    fi
    echo ""

    # ── Место ──
    local need_kb=0 avail_kb
    [[ "${need_d}" == "yes" ]] && need_kb=$(( need_kb + $(du -sxk "${droot}" | cut -f1) ))
    [[ "${need_c}" == "yes" ]] && need_kb=$(( need_kb + $(du -sxk "${croot}" | cut -f1) ))
    avail_kb=$(df --output=avail -k "${mp}" | tail -1)
    (( need_kb + need_kb / 10 + 102400 < avail_kb )) \
        || error "На ${mp} мало места: нужно ~$(( (need_kb + need_kb / 10) / 1024 + 100 )) МБ, свободно $(( avail_kb / 1024 )) МБ"

    if [[ "${need_d}" == "yes" || "${need_c}" == "yes" ]]; then
        confirm "Остановить Docker и перенести данные?" || exit 0

        info "Остановка контейнеров и Docker"
        # явная остановка: при live-restore контейнеры пережили бы остановку dockerd
        if (( ${#running[@]} )); then docker stop -t 30 "${running[@]}" >/dev/null || true; fi
        systemctl stop docker.socket docker.service 2>/dev/null || true
        [[ "${need_c}" == "yes" ]] && { systemctl stop containerd.service 2>/dev/null || true; }
        local i=0
        while pgrep -x dockerd >/dev/null && (( i < 30 )); do sleep 1; i=$((i + 1)); done
        pgrep -x dockerd >/dev/null && error "dockerd не остановился — перенос отменён"
        if pgrep -f containerd-shim >/dev/null; then
            error "Остались работающие контейнеры (containerd-shim) — остановите их и повторите"
        fi
        # остатки overlay-монтирований
        findmnt -rn -o TARGET | grep -E "^(${droot}|${croot})/" | sort -r | xargs -r umount 2>/dev/null || true

        [[ "${need_d}" == "yes" ]] && luks_docker_move_dir "${droot}" "${dst_d}" "${mp}" "${mode}"
        [[ "${need_c}" == "yes" ]] && luks_docker_move_dir "${croot}" "${dst_c}" "${mp}" "${mode}"
    fi

    # ── systemd: без тома не стартовать ──
    luks_systemd_requires docker.service "${droot}"
    [[ "${have_containerd}" == "yes" ]] && luks_systemd_requires containerd.service "${croot}"
    systemctl daemon-reload

    # ── Пустая точка монтирования самого тома тоже неизменяема ──
    luks_protect_mountpoint "${mp}"

    # ── Автозапуск ──
    if [[ "${mode}" == "noauto" ]]; then
        local svc_file="/etc/luks-unlock.d/${LUKS_NAME}.services" u
        luks_install_helpers
        touch "${svc_file}"
        for u in containerd.service docker.socket docker.service; do
            if systemctl cat "${u}" &>/dev/null; then
                grep -qx "${u}" "${svc_file}" || echo "${u}" >> "${svc_file}"
                systemctl disable "${u}" &>/dev/null || true
            fi
        done
        info "Автозапуск Docker отключён: его запускает 'sudo luks-unlock ${LUKS_NAME}'"
    fi

    # ── Запуск и проверка ──
    if [[ "${docker_was_active}" == "yes" || "${need_d}" == "yes" ]]; then
        [[ "${have_containerd}" == "yes" ]] && systemctl start containerd.service
        systemctl start docker.socket docker.service
        local newroot; newroot=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || true)
        [[ "${newroot}" == "${droot}" ]] || warn "Docker сообщает каталог данных '${newroot}', ожидался ${droot}"
        findmnt -no SOURCE "${droot}" | grep -q "^/dev/mapper/${LUKS_NAME}" \
            || error "${droot} не смонтирован с тома — Docker остановлен не будет, проверьте вручную"
        local c started=0
        for c in "${running[@]}"; do
            if [[ "$(docker inspect -f '{{.State.Running}}' "${c}" 2>/dev/null)" != "true" ]]; then
                docker start "${c}" >/dev/null 2>&1 && started=$((started + 1)) \
                    || warn "  не удалось запустить контейнер ${c}"
            fi
        done
        info "Docker работает с зашифрованного тома; запущено вручную: ${started}, всего работает: $(docker ps -q | wc -l)"
    fi

    # ── Старые открытые копии ──
    local old
    for old in "${droot}.pre-luks" "${croot}.pre-luks"; do
        [[ -d "${old}" ]] || continue
        echo ""
        warn "Старая НЕзашифрованная копия: ${old} ($(du -sxh "${old}" 2>/dev/null | cut -f1))"
        if confirm "  Проверили, что всё работает? Удалить ${old}?"; then
            rm -rf --one-file-system "${old}"
            info "  удалено: ${old}"
            command -v fstrim &>/dev/null && fstrim -v / 2>/dev/null | sed 's/^/  /' || true
            warn "  Удалённые блоки могут оставаться на диске провайдера; fstrim помогает на thin-хранилищах."
        else
            warn "  Удалите позже: sudo rm -rf --one-file-system ${old}"
        fi
    done

    luks_audit_rules
    echo ""
    info "Готово. Проверка: findmnt ${droot}; docker info -f '{{.DockerRootDir}}'"
    if [[ "${mode}" == "noauto" ]]; then
        echo "  После перезагрузки Docker не стартует, пока не выполнить:  sudo luks-unlock ${LUKS_NAME}"
        echo "  Остановить и закрыть том:                                  sudo luks-lock ${LUKS_NAME}"
    fi
    echo "  Не забудьте: бэкапы томов шифруйте отдельно (restic/borg/age) и swap — --luks swap"
}

# ──────────────────────────────────────────────────────────────────────────────
# LUKS — разбор аргументов и меню
# ──────────────────────────────────────────────────────────────────────────────
luks_main() {
    local cmd="" pos=() user_set="no"
    while (( $# )); do
        case "$1" in
            --name)          LUKS_NAME="${2:?--name: нужно значение}"; shift 2 ;;
            --mount)         LUKS_MOUNT="${2:?--mount: нужно значение}"; shift 2 ;;
            --fs)            LUKS_FS="${2:?--fs: нужно значение}"; shift 2 ;;
            --mount-opts)    LUKS_MOUNT_OPTS="${2:?--mount-opts: нужно значение}"; shift 2 ;;
            --unlock)        LUKS_UNLOCK="${2:?--unlock: нужно значение}"; shift 2 ;;
            --tang)          LUKS_TANG_URL="${2:?--tang: нужно значение}"; shift 2 ;;
            --discards)      LUKS_DISCARDS="yes"; shift ;;
            --no-perf)       LUKS_PERF="no"; shift ;;
            --prefill)       LUKS_PREFILL="yes"; shift ;;
            --cipher)        LUKS_CIPHER="${2:?--cipher: нужно значение}"; shift 2 ;;
            --key-size)      LUKS_KEY_SIZE="${2:?--key-size: нужно значение}"; shift 2 ;;
            --user)          ADMIN_USER="${2:?--user: нужно значение}"; user_set="yes"; shift 2 ;;
            --dropbear-port) LUKS_DROPBEAR_PORT="${2:?--dropbear-port: нужно значение}"; shift 2 ;;
            --prepare)       LUKS_PREPARE_ONLY="yes"; shift ;;
            -h|--help)       usage; exit 0 ;;
            -*)              error "Неизвестная опция --luks: $1" ;;
            *)               if [[ -z "${cmd}" ]]; then cmd="$1"; else pos+=("$1"); fi; shift ;;
        esac
    done

    # Администратор из прошлого полного прогона, если --user не задан
    if [[ "${user_set}" == "no" && -f "${STATE_FILE}" ]]; then
        local saved
        saved=$(awk -F= '$1=="ADMIN_USER"{print $2}' "${STATE_FILE}")
        [[ -n "${saved}" ]] && ADMIN_USER="${saved}"
    fi
    [[ "${LUKS_DROPBEAR_PORT}" =~ ^[0-9]+$ ]] || error "--dropbear-port: нужно число"
    [[ "${LUKS_NAME}" =~ ^[A-Za-z0-9_.-]+$ ]] || error "--name: только латиница, цифры, _ . -"

    case "${cmd}" in
        status)        luks_mode_status ;;
        data)          luks_mode_data "${pos[@]}" ;;
        file)          luks_mode_file "${pos[@]}" ;;
        swap)          luks_mode_swap ;;
        remote-unlock) luks_mode_remote_unlock ;;
        encrypt-root)        luks_mode_encrypt_root "${pos[@]}" ;;
        encrypt-root-auto)   luks_mode_encrypt_root_auto ;;
        encrypt-root-finish) luks_mode_encrypt_root_finish ;;
        encrypt-root-cancel) luks_mode_encrypt_root_cancel ;;
        docker)              luks_mode_docker ;;
        "")            usage; exit 1 ;;
        *)             error "Неизвестный режим --luks: ${cmd} (см. --help)" ;;
    esac
}

# luks_run — определена ниже, рядом с обработчиками ошибок

luks_menu() {
    luks_run status
    echo ""
    echo "  Шифрование (необязательно):"
    echo "    1) отдельный диск/раздел      2) файл-контейнер"
    echo "    3) защитить swap              4) сетевая разблокировка root"
    echo "    5) зашифровать весь корень (при следующей перезагрузке)"
    command -v dockerd &>/dev/null && \
    echo "    7) перенести данные Docker на зашифрованный том"
    [[ -f "${LUKS_CONVERT_DIR}/convert.conf" ]] && \
    echo -e "    6) ${YELLOW}завершить шифрование корня (задать пароль)${NC}"
    echo "  Позже то же самое: bash ubuntu_hardening.sh --luks --help"
    echo "  (Enter — пропустить)"
    local ch dev path size
    read -r -p "  Выбор: " ch
    case "${ch}" in
        1) read -r -p "  Устройство (например /dev/vdb): " dev
           luks_run data "${dev}" ;;
        2) read -r -p "  Путь (например /var/lib/secure.img): " path
           read -r -p "  Размер (например 20G): " size
           luks_run file "${path}" "${size}" ;;
        3) luks_run swap ;;
        4) luks_run remote-unlock ;;
        5) LUKS_NO_REBOOT="yes" luks_run encrypt-root-auto
           [[ -f "${LUKS_CONVERT_DIR}/convert.conf" ]] && \
               warn "Корень будет зашифрован при перезагрузке ПОСЛЕ завершения скрипта; затем --luks encrypt-root-finish" ;;
        6) luks_run encrypt-root-finish ;;
        7) luks_run docker ;;
        *) info "Шифрование пропущено" ;;
    esac
}

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНЫЙ ПРОГОН — служебные функции
# ══════════════════════════════════════════════════════════════════════════════

# Настройки, которые сохраняются между прогонами и служат умолчаниями
STATE_KEYS=(ADMIN_USER SSH_PORT EXTRA_PORTS DOCKER_ALLOW_PORTS FAIL2BAN_IGNOREIP
    NTP_SERVERS NTP_REPLACE_DEFAULTS NTP_ADD_NTS DNSSEC_MODE SSH_ADDRESS_FAMILY
    TCP_FORWARDING GATEWAY_PORTS X11_FORWARDING AGENT_FORWARDING IP_FORWARD
    DOCKER_UFW_FIX TMP_MODE HOME_NOEXEC IPV6_ACCEPT_RA LOG_MARTIANS
    APPARMOR_ENFORCE_ALL PASSWORD_CLASSES PASSWORD_MAX_DAYS ENABLE_FAILLOCK
    ENABLE_AIDE KERNEL_CMDLINE_HARDENING HIDEPID REMOTE_SYSLOG)

kv_has() { [[ -r "$1" ]] && grep -q "^$2=" "$1"; }

load_state_defaults() {
    local k
    [[ -r "${STATE_FILE}" ]] || return 0
    for k in "${STATE_KEYS[@]}"; do
        kv_has "${STATE_FILE}" "$k" && printf -v "$k" '%s' "$(kv_get "${STATE_FILE}" "$k")"
    done
    info "Умолчания взяты из прошлого прогона (${STATE_FILE})"
}

save_state() {
    local k
    track "${STATE_FILE}"
    {
        echo "# ubuntu_hardening.sh — параметры последнего прогона"
        echo "# Читается построчно (КЛЮЧ=значение), не через source"
        echo "SCRIPT_VERSION=${SCRIPT_VERSION}"
        echo "RUN_STAMP=${RUN_STAMP}"
        echo "KEY_SOURCE=${KEY_SOURCE:-$(kv_get "${STATE_FILE}" KEY_SOURCE)}"
        echo "PUBKEY_BODIES=${PUBKEY_BODIES}"
        for k in "${STATE_KEYS[@]}"; do
            case "$k" in
                ADMIN_USER) echo "ADMIN_USER=${APPLIED_ADMIN_USER}" ;;
                SSH_PORT)   echo "SSH_PORT=${APPLIED_SSH_PORT}" ;;
                *)          printf '%s=%s\n' "$k" "${!k}" ;;
            esac
        done
    } > "${STATE_FILE}.tmp"
    chmod 600 "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "${STATE_FILE}"
}

is_yes_no() { [[ "$1" == "yes" || "$1" == "no" ]]; }
validate_settings() {
    local k
    for k in TCP_FORWARDING GATEWAY_PORTS X11_FORWARDING AGENT_FORWARDING HOME_NOEXEC \
             LOG_MARTIANS APPARMOR_ENFORCE_ALL PASSWORD_CLASSES ENABLE_FAILLOCK ENABLE_AIDE \
             KERNEL_CMDLINE_HARDENING HIDEPID NTP_REPLACE_DEFAULTS NTP_ADD_NTS ALLOW_UNTESTED_OS; do
        is_yes_no "${!k}" || error "${k}='${!k}': допустимо yes или no"
    done
    [[ "${IP_FORWARD}" =~ ^(auto|yes|no)$ ]]       || error "IP_FORWARD: auto | yes | no"
    [[ "${DOCKER_UFW_FIX}" =~ ^(auto|yes|no)$ ]]   || error "DOCKER_UFW_FIX: auto | yes | no"
    [[ "${IPV6_ACCEPT_RA}" =~ ^(auto|yes|no)$ ]]   || error "IPV6_ACCEPT_RA: auto | yes | no"
    [[ "${TMP_MODE}" =~ ^(auto|tmpfs|disk)$ ]]     || error "TMP_MODE: auto | tmpfs | disk"
    [[ "${DNSSEC_MODE}" =~ ^(no|allow-downgrade|yes)$ ]] || error "DNSSEC_MODE: no | allow-downgrade | yes"
    [[ "${SSH_ADDRESS_FAMILY}" =~ ^(any|inet|inet6)$ ]]  || error "SSH_ADDRESS_FAMILY: any | inet | inet6"
    [[ "${PASSWORD_MAX_DAYS}" =~ ^[0-9]+$ ]]       || error "PASSWORD_MAX_DAYS: число дней"
    if [[ -n "${REMOTE_SYSLOG}" ]]; then
        [[ "${REMOTE_SYSLOG}" =~ ^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}$ ]] \
            || error "REMOTE_SYSLOG: host:port (IPv6 — [адрес]:порт)"
    fi
    return 0
}

step_enabled() {
    local s="$1"
    if [[ -n "${ONLY_STEPS}" && ",${ONLY_STEPS}," != *",${s},"* ]]; then return 1; fi
    [[ ",${SKIP_STEPS}," != *",${s},"* ]]
}

step_off() {   # шаг сознательно не выполняется (опция выключена)
    STEP_STATUS[${CURRENT_STEP}]="OFF"
    STEP_NOTE[${CURRENT_STEP}]="$1"
    info "Пропущено: $1"
}

run_step() {
    local s="$1"
    if ! step_enabled "$s"; then STEP_STATUS[$s]="SKIP"; return 0; fi
    section "${STEP_TITLE[$s]}"
    CURRENT_STEP="$s"
    STEP_WARNS[$s]=0
    "step_${s}"
    if [[ "${STEP_STATUS[$s]:-}" != "OFF" ]]; then
        if (( ${STEP_WARNS[$s]} > 0 )); then STEP_STATUS[$s]="WARN"; else STEP_STATUS[$s]="OK"; fi
    fi
    CURRENT_STEP=""
}

has_docker() {
    command -v dockerd &>/dev/null || [[ -x /usr/bin/dockerd || -d /etc/docker ]]
}
needs_ip_forward() {
    has_docker && return 0
    command -v podman &>/dev/null && return 0
    command -v lxd &>/dev/null && return 0
    [[ -d /var/snap/lxd ]] && return 0
    compgen -G "/etc/wireguard/*.conf" >/dev/null && return 0
    return 1
}
docker_fix_active() {
    [[ "${DOCKER_UFW_FIX}" == "yes" ]] && return 0
    [[ "${DOCKER_UFW_FIX}" == "auto" ]] && has_docker
}
# Порты контейнеров, опубликованные на всех адресах: "80/tcp 443/tcp"
docker_published_ports() {
    command -v docker &>/dev/null || return 0
    local out
    out=$(docker ps --format '{{.Ports}}' 2>/dev/null) || return 0
    grep -oE '(0\.0\.0\.0|\[?::\]?):[0-9-]+->[0-9-]+/(tcp|udp)' <<< "${out}" \
        | sed -E 's/.*->//' | sort -u | tr '\n' ' ' || true
}

valid_port_spec() {   # 80 | 443/udp | 8000:8100/tcp
    [[ "$1" =~ ^([0-9]+)(:([0-9]+))?(/(tcp|udp))?$ ]] || return 1
    (( 10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535 )) || return 1
    (( 10#${BASH_REMATCH[3]:-1} >= 1 && 10#${BASH_REMATCH[3]:-1} <= 65535 )) || return 1
    # диапазон требует явного протокола
    [[ -z "${BASH_REMATCH[2]}" || -n "${BASH_REMATCH[4]}" ]]
}

admin_home() { getent passwd "${ADMIN_USER}" | cut -d: -f6; }

# fstab_set <точка монтирования> <строка> — заменить запись (комментарии не трогает)
fstab_set() {
    local mountpoint="$1" entry="$2" tmp
    track /etc/fstab
    make_tmp tmp /etc
    awk -v mp="${mountpoint}" '/^[[:space:]]*#/ || $2 != mp' /etc/fstab > "${tmp}"
    echo "${entry}" >> "${tmp}"
    chmod 644 "${tmp}"
    mv "${tmp}" /etc/fstab
    info "fstab: ${mountpoint} настроен"
}

# set_login_def <ключ> <значение> — /etc/login.defs
set_login_def() {
    local key="$1" val="$2"
    track /etc/login.defs
    if grep -qE "^[[:space:]]*${key}[[:space:]]" /etc/login.defs; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${key}\t\t${val}|" /etc/login.defs
    else
        printf '%s\t\t%s\n' "${key}" "${val}" >> /etc/login.defs
    fi
}

# ── Контрольная точка входа ──────────────────────────────────────────────────
login_checkpoint() {
    if [[ "${ASSUME_YES}" == "yes" ]]; then
        # Человек вход не подтвердит — проверяем всё, что можно проверить локально
        local eff
        eff=$(sshd -T -C "user=${ADMIN_USER},host=localhost,addr=127.0.0.1" 2>/dev/null) \
            || error "sshd -T не выполнился — root НЕ заблокирован"
        grep -qx "authenticationmethods publickey" <<< "${eff}" || error "sshd: authenticationmethods не publickey"
        grep -qE "^allowusers( .*)? ${ADMIN_USER}( |$)" <<< "${eff}" || error "sshd: ${ADMIN_USER} не в AllowUsers"
        [[ -n "$(ss -Htln "sport = :${SSH_PORT}" 2>/dev/null)" ]] || error "Порт ${SSH_PORT} не слушается — root НЕ заблокирован"
        (( $(ssh-keygen -l -f "$(admin_home)/.ssh/authorized_keys" 2>/dev/null | wc -l) > 0 )) \
            || error "У ${ADMIN_USER} нет действующих ключей — root НЕ заблокирован"
        warn "Режим --yes: вход проверен автоматически (конфигурация, порт, ключи), но не человеком"
        return 0
    fi
    echo ""
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|  КОНТРОЛЬНАЯ ТОЧКА — проверьте вход СЕЙЧАС                 |${NC}"
    echo -e "${YELLOW}|                                                            |${NC}"
    echo -e "${YELLOW}|  В НОВОМ терминале (не закрывая этот):                     |${NC}"
    echo -e "${YELLOW}|  ssh -p ${SSH_PORT} ${ADMIN_USER}@<IP>${NC}"
    echo -e "${YELLOW}|  (сгенерированный ключ: добавьте -i ./admin_ssh_key)       |${NC}"
    echo -e "${YELLOW}|                                                            |${NC}"
    echo -e "${YELLOW}|  Следующий шаг заблокирует root — убедитесь, что вход      |${NC}"
    echo -e "${YELLOW}|  под ${ADMIN_USER} работает, и проверьте sudo -v${NC}"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo ""
    local ok
    while true; do
        read -r -p "Вход под ${ADMIN_USER} по ключу работает? [y = продолжить / n = прервать]: " ok
        case "${ok}" in
            [Yy]) return 0 ;;
            [Nn]) error "Прервано: вход не работает. Root НЕ заблокирован, исправьте проблему и перезапустите скрипт." ;;
            *)    echo "  Введите y или n." ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════════════════
#  Вопросы — задаются в начале, до изменений (кроме пароля и контрольной точки)
# ══════════════════════════════════════════════════════════════════════════════
choose_key_source() {
    local k fp
    ROOT_KEYS=(); ROOT_KEY_FPS=()
    if [[ -f /root/.ssh/authorized_keys ]]; then
        while IFS= read -r k; do
            if fp=$(check_pubkey "$k"); then
                ROOT_KEYS+=("$k"); ROOT_KEY_FPS+=("${fp}")
            elif [[ -n "${fp}" ]]; then
                warn "Ключ root пропущен: ${fp}"
            fi
        done < <(pubkeys_from_file /root/.ssh/authorized_keys)
    fi

    local def="${SSH_KEY_SOURCE}"
    if [[ -z "${def}" ]]; then
        if (( ${#ROOT_KEYS[@]} )); then def="root"
        elif [[ -n "${SSH_PUBKEY}" ]]; then def="provided"
        else def="ed25519"; fi
    fi

    if [[ "${ASSUME_YES}" == "yes" ]]; then
        case "${def}" in
            root)     (( ${#ROOT_KEYS[@]} )) || error "SSH_KEY_SOURCE=root, но в /root/.ssh/authorized_keys нет годных ключей"
                      PUBKEYS=("${ROOT_KEYS[@]}"); KEY_SOURCE="root"
                      KEY_TYPE="ключи root (${#ROOT_KEYS[@]} шт.)" ;;
            provided) fp=$(check_pubkey "${SSH_PUBKEY}") || error "SSH_PUBKEY: некорректный ключ ${fp}"
                      PUBKEYS=("${SSH_PUBKEY}"); KEY_SOURCE="provided"; KEY_TYPE="свой ($(awk '{print $NF}' <<< "${fp}"))" ;;
            ed25519|ecdsa-521)
                      error "В режиме --yes ключ нельзя сгенерировать (его некому сохранить): задайте SSH_PUBKEY или ключ root" ;;
            *)        error "SSH_KEY_SOURCE: root | provided | ed25519 | ecdsa-521" ;;
        esac
        info "SSH-ключ: ${KEY_TYPE}"
        return 0
    fi

    local defnum
    case "${def}" in root) defnum=1 ;; provided) defnum=2 ;; ecdsa-521) defnum=4 ;; *) defnum=3 ;; esac
    (( ${#ROOT_KEYS[@]} )) || [[ "${defnum}" != 1 ]] || defnum=3
    echo ""
    echo -e "  SSH-ключ для ${ADMIN_USER}:"
    if (( ${#ROOT_KEYS[@]} )); then
        echo -e "    1) ${GREEN}ключи root${NC} из /root/.ssh/authorized_keys — вы уже входите с ними:"
        for fp in "${ROOT_KEY_FPS[@]}"; do echo "         ${fp}"; done
    fi
    echo -e "    2) ${GREEN}вставить свой публичный ключ${NC} (ssh-keygen -t ed25519 у себя) — приватная часть не появится на сервере"
    echo "    3) сгенерировать ed25519 на сервере"
    echo "    4) сгенерировать ecdsa-521 на сервере (NIST P-521)"
    echo "  (Enter — ${defnum})"
    local ch pk
    while true; do
        read -r -p "  Выбор: " ch
        ch="${ch:-${defnum}}"
        case "${ch}" in
            1)  if (( ${#ROOT_KEYS[@]} )); then
                    PUBKEYS=("${ROOT_KEYS[@]}"); KEY_SOURCE="root"
                    KEY_TYPE="ключи root (${#ROOT_KEYS[@]} шт.)"; break
                fi
                echo -e "  ${RED}Годных ключей root нет.${NC}" ;;
            2)  read -r -p "  Публичный ключ (ssh-ed25519 AAAA... comment)${SSH_PUBKEY:+, Enter — из настроек}: " pk
                pk="${pk:-${SSH_PUBKEY}}"
                if fp=$(check_pubkey "${pk}"); then
                    PUBKEYS=("${pk}"); KEY_SOURCE="provided"
                    KEY_TYPE="свой ($(awk '{print $NF}' <<< "${fp}"))"
                    info "Ключ принят: ${fp}"; break
                fi
                echo -e "  ${RED}Ключ не принят${NC}${fp:+: ${fp}}" ;;
            3)  KEY_SOURCE="generated"; GEN_KEY_TYPE="ed25519";   KEY_TYPE="ed25519 (сгенерирован)"; break ;;
            4)  KEY_SOURCE="generated"; GEN_KEY_TYPE="ecdsa-521"; KEY_TYPE="ecdsa-521 (сгенерирован)"; break ;;
            *)  echo -e "  ${RED}Введите номер из списка.${NC}" ;;
        esac
    done
    info "SSH-ключ: ${KEY_TYPE}"
}

collect_answers() {
    local prev s

    if step_enabled key || step_enabled user || step_enabled ssh; then
        [[ "${ASSUME_YES}" == "yes" ]] || {
            echo ""
            echo "  Рекомендуется неочевидное имя администратора (не admin/administrator/ubuntu/user)."
        }
        prev="${ADMIN_USER}"
        while true; do
            ask ADMIN_USER "Имя администратора (Enter — ${ADMIN_USER}): "
            [[ "${ADMIN_USER}" =~ ^[a-z_][a-z0-9_-]{0,30}$ && "${ADMIN_USER}" != "root" ]] && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "ADMIN_USER='${ADMIN_USER}' некорректно"
            echo -e "  ${RED}Некорректное имя.${NC} Строчные латинские буквы, цифры, _ и -, начинается с буквы."
            ADMIN_USER="${prev}"
        done
        info "Администратор: ${ADMIN_USER}"
    fi

    if step_enabled ssh; then
        [[ "${ASSUME_YES}" == "yes" ]] || {
            echo ""
            echo "  Порт SSH: 22 или 1024–65535. Нестандартный порт лишь уменьшает шум"
            echo "  сканеров в логах; защиту дают ключи, fail2ban и UFW."
        }
        prev="${SSH_PORT}"
        while true; do
            ask SSH_PORT "Порт SSH (Enter — ${SSH_PORT}): "
            is_valid_port "${SSH_PORT}" && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "SSH_PORT='${SSH_PORT}': 22 или 1024–65535"
            echo -e "  ${RED}Некорректный порт.${NC} 22 или число от 1024 до 65535."
            SSH_PORT="${prev}"
        done
        info "Порт SSH: ${SSH_PORT}"
    fi

    if step_enabled key; then
        choose_key_source
    fi

    if step_enabled user && [[ "${ASSUME_YES}" == "yes" ]]; then
        local st=""
        id "${ADMIN_USER}" &>/dev/null && st=$(passwd -S "${ADMIN_USER}" 2>/dev/null | awk '{print $2}')
        if [[ "${st}" != "P" && -z "${ADMIN_PASSWORD_HASH}" ]]; then
            error "Режим --yes: у ${ADMIN_USER} нет пароля для sudo — задайте ADMIN_PASSWORD_HASH (openssl passwd -6)"
        fi
        [[ -z "${ADMIN_PASSWORD_HASH}" || "${ADMIN_PASSWORD_HASH}" == \$* ]] \
            || error "ADMIN_PASSWORD_HASH должен быть crypt-хешем (\$6\$..., \$y\$...)"
    fi

    if step_enabled host; then
        if [[ "${ASSUME_YES}" != "yes" ]]; then
            echo ""
            echo -e "  Текущее имя хоста: ${YELLOW}$(hostname)${NC}"
        fi
        prev="${NEW_HOSTNAME}"
        while true; do
            ask NEW_HOSTNAME "Новое имя хоста (Enter — ${NEW_HOSTNAME:-оставить текущее}): "
            [[ -z "${NEW_HOSTNAME}" || "${NEW_HOSTNAME}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "NEW_HOSTNAME='${NEW_HOSTNAME}' некорректно"
            echo -e "  ${RED}Допустимы латинские буквы, цифры и дефис.${NC}"; NEW_HOSTNAME="${prev}"
        done

        prev="${NEW_FQDN}"
        while true; do
            ask NEW_FQDN "FQDN, например $(hostname).example.com (Enter — ${NEW_FQDN:-не задавать}): "
            [[ -z "${NEW_FQDN}" ]] || is_valid_hostname_fqdn "${NEW_FQDN}" && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "NEW_FQDN='${NEW_FQDN}' некорректно"
            echo -e "  ${RED}Формат: hostname.domain.tld${NC}"; NEW_FQDN="${prev}"
        done

        local zones
        zones=$(timedatectl list-timezones 2>/dev/null || true)
        if [[ "${ASSUME_YES}" != "yes" ]]; then
            echo ""
            echo -e "  Текущий часовой пояс: ${YELLOW}$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)${NC}"
            echo "  Например: Europe/Moscow  Europe/Berlin  UTC  Asia/Dubai  America/New_York"
        fi
        prev="${TIMEZONE}"
        while true; do
            ask TIMEZONE "Часовой пояс (Enter — ${TIMEZONE:-не менять}): "
            [[ -z "${TIMEZONE}" ]] || grep -qxF -- "${TIMEZONE}" <<< "${zones}" && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "TIMEZONE='${TIMEZONE}' неизвестен (timedatectl list-timezones)"
            echo -e "  ${RED}Неизвестный часовой пояс.${NC} Список: timedatectl list-timezones"; TIMEZONE="${prev}"
        done

        if [[ "${ASSUME_YES}" != "yes" ]]; then
            echo ""
            echo "  Текущие DNS-серверы:"
            { resolvectl dns 2>/dev/null || grep "^nameserver" /etc/resolv.conf 2>/dev/null || true; } | sed 's/^/    /'
            echo "  Например: Cloudflare 1.1.1.1 1.0.0.1 | Quad9 9.9.9.9 149.112.112.112 | Google 8.8.8.8"
        fi
        prev="${DNS_SERVERS}"
        while true; do
            ask DNS_SERVERS "DNS-серверы через пробел, IPv4/IPv6 (Enter — ${DNS_SERVERS:-не менять}): "
            local bad=""
            for s in ${DNS_SERVERS}; do is_valid_ip "$s" || bad+=" $s"; done
            [[ -z "${bad}" ]] && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "DNS_SERVERS: некорректные адреса:${bad}"
            echo -e "  ${RED}Некорректные адреса:${bad}${NC}"; DNS_SERVERS="${prev}"
        done

        if [[ "${ASSUME_YES}" != "yes" ]]; then
            echo ""
            echo "  NTP: штатные серверы Ubuntu сохраняются$([[ "${NTP_ADD_NTS}" == "yes" ]] && echo ", добавляется time.cloudflare.com (NTS)")."
            echo "  Можно добавить свои (например NTP провайдера) через пробел."
        fi
        prev="${NTP_SERVERS}"
        while true; do
            ask NTP_SERVERS "Свои NTP-серверы (Enter — ${NTP_SERVERS:-нет}): "
            local badn=""
            for s in ${NTP_SERVERS}; do is_valid_ip "$s" || is_valid_hostname_fqdn "$s" || badn+=" $s"; done
            [[ -z "${badn}" ]] && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "NTP_SERVERS: некорректные значения:${badn}"
            echo -e "  ${RED}Некорректные значения:${badn}${NC}"; NTP_SERVERS="${prev}"
        done
        if [[ -n "${NTP_SERVERS}" && "${ASSUME_YES}" != "yes" && "${NTP_REPLACE_DEFAULTS}" == "no" ]]; then
            confirm "  Использовать ТОЛЬКО эти NTP-серверы (отключить штатные пулы Ubuntu)?" && NTP_REPLACE_DEFAULTS="yes"
        fi
    fi

    if step_enabled ufw; then
        if [[ "${ASSUME_YES}" != "yes" ]]; then
            echo ""
            echo "  Слушающие TCP-порты:"
            ss -Htlnp 2>/dev/null | awk '{print "    " $4 "  " $NF}' | sort -u || true
            echo "  Слушающие UDP-порты:"
            ss -Hulnp 2>/dev/null | awk '{print "    " $4 "  " $NF}' | sort -u || true
            echo ""
            echo "  UFW закроет ВСЁ входящее, кроме SSH:${SSH_PORT} и перечисленного."
            echo "  Формат: 80 443 (TCP)  или  443/udp 51820/udp  или  8000:8100/tcp  ('-' — очистить)"
        fi
        prev="${EXTRA_PORTS}"
        while true; do
            ask EXTRA_PORTS "Дополнительные порты (Enter — ${EXTRA_PORTS:-только SSH}): "
            local badp=""
            for s in ${EXTRA_PORTS}; do valid_port_spec "$s" || badp+=" $s"; done
            [[ -z "${badp}" ]] && break
            [[ "${ASSUME_YES}" == "yes" ]] && error "EXTRA_PORTS: некорректные значения:${badp}"
            echo -e "  ${RED}Некорректные значения:${badp}${NC}"; EXTRA_PORTS="${prev}"
        done

        if docker_fix_active; then
            local pub; pub=$(docker_published_ports)
            [[ "${DOCKER_ALLOW_PORTS}" == "auto" ]] && DOCKER_ALLOW_PORTS="${pub% }"
            if [[ "${ASSUME_YES}" != "yes" ]]; then
                echo ""
                echo -e "  ${YELLOW}Docker публикует порты в обход UFW.${NC} Скрипт закроет их цепочкой DOCKER-USER;"
                echo "  открытыми извне останутся только перечисленные порты КОНТЕЙНЕРОВ"
                echo "  (для -p 8080:80 это 80/tcp). Сейчас опубликовано: ${pub:-ничего}"
            fi
            prev="${DOCKER_ALLOW_PORTS}"
            while true; do
                ask DOCKER_ALLOW_PORTS "Порты контейнеров, открытые извне (Enter — ${DOCKER_ALLOW_PORTS:-никаких}): "
                local badd=""
                for s in ${DOCKER_ALLOW_PORTS}; do valid_port_spec "${s//-/:}" || badd+=" $s"; done
                [[ -z "${badd}" ]] && break
                [[ "${ASSUME_YES}" == "yes" ]] && error "DOCKER_ALLOW_PORTS: некорректные значения:${badd}"
                echo -e "  ${RED}Некорректные значения:${badd}${NC}"; DOCKER_ALLOW_PORTS="${prev}"
            done
        fi
    fi
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
#  ШАГИ
# ══════════════════════════════════════════════════════════════════════════════

# ── 0. Обновление системы и пакеты ───────────────────────────────────────────
step_packages() {
    export DEBIAN_FRONTEND=noninteractive
    "${APT_GET[@]}" update -qq
    "${APT_GET[@]}" upgrade -y -qq -o Dpkg::Options::="--force-confdef" \
                                   -o Dpkg::Options::="--force-confold"
    # rsyslog явно: минимальные образы 24.04+ могут идти без него
    "${APT_GET[@]}" install -y -qq \
        ufw fail2ban auditd audispd-plugins \
        libpam-pwquality unattended-upgrades apt-listchanges \
        acl curl wget gnupg2 chrony rsyslog needrestart apparmor apparmor-utils
    info "Пакеты установлены"
    [[ -f /var/run/reboot-required ]] && warn "Обновление требует перезагрузки (/var/run/reboot-required)"
    return 0
}

# ── 1. Имя хоста, FQDN, часовой пояс, DNS, NTP ───────────────────────────────
step_host() {
    local short; short=$(hostname)
    if [[ -n "${NEW_HOSTNAME}" && "${NEW_HOSTNAME}" != "${short}" ]]; then
        track /etc/hostname
        hostnamectl set-hostname "${NEW_HOSTNAME}"
        short="${NEW_HOSTNAME}"
        info "Имя хоста: ${short}"
    else
        info "Имя хоста оставлено: ${short}"
    fi

    track /etc/hosts
    sed -i -E '/^127\.0\.1\.1[[:space:]]/d' /etc/hosts
    if [[ -n "${NEW_FQDN}" ]]; then
        printf '127.0.1.1\t%s %s\n' "${NEW_FQDN}" "${short}" >> /etc/hosts
        info "/etc/hosts: 127.0.1.1 -> ${NEW_FQDN} ${short}"
    else
        printf '127.0.1.1\t%s\n' "${short}" >> /etc/hosts
    fi

    # cloud-init при перезагрузке вернул бы имя хоста и /etc/hosts из метаданных
    if [[ -d /etc/cloud/cloud.cfg.d ]]; then
        write_file /etc/cloud/cloud.cfg.d/99-ubuntu-hardening.cfg 644 << 'EOF'
# ubuntu_hardening.sh: не перезаписывать имя хоста и /etc/hosts при загрузке
preserve_hostname: true
manage_etc_hosts: false
EOF
        info "cloud-init: preserve_hostname, manage_etc_hosts выключен"
    fi

    if [[ -n "${TIMEZONE}" ]]; then
        timedatectl set-timezone "${TIMEZONE}"
        info "Часовой пояс: ${TIMEZONE}"
    fi

    # ── DNS ──
    if [[ -n "${DNS_SERVERS}" ]]; then
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            write_file /etc/systemd/resolved.conf.d/custom-dns.conf 644 << EOF
# ubuntu_hardening.sh
[Resolve]
DNS=${DNS_SERVERS}
FallbackDNS=
DNSOverTLS=opportunistic
DNSSEC=${DNSSEC_MODE}
EOF
            systemctl restart systemd-resolved
            info "DNS (systemd-resolved): ${DNS_SERVERS}, DNSSEC=${DNSSEC_MODE}"
            info "  DNS провайдера из DHCP остаются у интерфейса; чтобы убрать их — в netplan:"
            info "  dhcp4-overrides: { use-dns: false } (и dhcp6-overrides), затем netplan apply"
        else
            # v3 ставила chattr +i — снимаем: неизменяемый resolv.conf ломает DHCP и обновления
            if lsattr -d /etc/resolv.conf 2>/dev/null | awk '{print $1}' | grep -q i; then
                chattr -i /etc/resolv.conf
            fi
            track /etc/resolv.conf
            [[ -L /etc/resolv.conf ]] && rm -f /etc/resolv.conf
            {
                echo "# ubuntu_hardening.sh"
                for s in ${DNS_SERVERS}; do echo "nameserver ${s}"; done
                echo "options timeout:2 attempts:3"
            } > /etc/resolv.conf
            info "DNS записан в /etc/resolv.conf: ${DNS_SERVERS}"
            warn "systemd-resolved не активен: DHCP-клиент может перезаписать /etc/resolv.conf"
        fi
    else
        info "DNS не изменён"
    fi

    # ── NTP: chrony, файл дистрибутива не перезаписывается ──
    ensure_pkgs chrony
    systemctl disable --now systemd-timesyncd &>/dev/null || true
    local conf=/etc/chrony/chrony.conf
    # v3 заменяла chrony.conf целиком — возвращаем файл пакета
    if grep -qs "Сгенерировано ubuntu_hardening.sh" "${conf}"; then
        track "${conf}"
        if [[ -f /usr/share/chrony/chrony.conf ]]; then
            cp /usr/share/chrony/chrony.conf "${conf}"
            info "chrony.conf восстановлен из пакета (v3 перезаписывала его)"
        else
            warn "chrony.conf перезаписан v3, а копии из пакета нет — оставлен как есть"
        fi
    fi

    local count=0 lines="" s
    for s in ${NTP_SERVERS}; do lines+="server ${s} iburst"$'\n'; count=$(( count + 1 )); done
    if [[ "${NTP_ADD_NTS}" == "yes" ]]; then
        lines+="server time.cloudflare.com iburst nts"$'\n'; count=$(( count + 1 ))
    fi
    if [[ -n "${lines}" ]]; then
        printf '# ubuntu_hardening.sh\n%s' "${lines}" \
            | write_file /etc/chrony/sources.d/ubuntu-hardening.sources 644
    fi

    local minsources=2
    if [[ "${NTP_REPLACE_DEFAULTS}" == "yes" && -n "${NTP_SERVERS}" ]]; then
        track "${conf}"
        sed -i -E 's/^(pool|server|peer)([[:space:]])/# ubuntu_hardening: \1\2/' "${conf}"
        local f
        for f in /etc/chrony/sources.d/*.sources; do
            [[ -e "$f" && "$f" != */ubuntu-hardening.sources ]] || continue
            track "$f" "$f.disabled"; mv "$f" "$f.disabled"
            info "Отключён источник: $f"
        done
        (( count < 2 )) && minsources=1
        info "NTP: только свои серверы (${count})"
    fi
    # sourcedir для sources.d есть в chrony.conf Ubuntu; на всякий случай проверяем
    local extra=""
    grep -qsE '^[[:space:]]*sourcedir[[:space:]]+/etc/chrony/sources\.d' "${conf}" \
        || extra="sourcedir /etc/chrony/sources.d"$'\n'
    write_file /etc/chrony/conf.d/ubuntu-hardening.conf 644 << EOF
# ubuntu_hardening.sh — дополнение к ${conf} (файл пакета не изменяется)
${extra}# Минимум согласных источников, чтобы считать время синхронизированным
minsources ${minsources}
# Не принимать источник с большой задержкой (нестабильная сеть VPS)
maxdistance 1.5
# chronyc — только с localhost
bindcmdaddress 127.0.0.1
bindcmdaddress ::1
EOF
    systemctl enable chrony &>/dev/null || true
    systemctl restart chrony || warn "chrony не перезапустился: journalctl -u chrony"
    sleep 2
    chronyc makestep &>/dev/null || true
    local synced; synced=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
    if [[ "${synced}" == "yes" ]]; then info "NTP синхронизирован"
    else info "NTP: синхронизация ещё идёт (chronyc tracking)"; fi
}

# ── 2. SSH-ключ ──────────────────────────────────────────────────────────────
step_key() {
    if [[ "${KEY_SOURCE}" != "generated" ]]; then
        info "Ключ: ${KEY_TYPE} — приватная часть на сервере не создаётся"
        return 0
    fi
    rm -f "${KEY_PATH}" "${KEY_PATH}.pub"
    echo ""
    echo -e "${YELLOW}Придумайте надёжный пароль для приватного ключа — он будет${NC}"
    echo -e "${YELLOW}запрашиваться при каждом подключении по SSH.${NC}"
    echo ""
    local comment; comment="${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"
    if [[ "${GEN_KEY_TYPE}" == "ed25519" ]]; then
        ssh-keygen -t ed25519 -a 100 -f "${KEY_PATH}" -C "${comment}"
    else
        ssh-keygen -t ecdsa -b 521 -a 100 -f "${KEY_PATH}" -C "${comment}"
    fi
    chmod 600 "${KEY_PATH}"; chmod 644 "${KEY_PATH}.pub"
    PUBKEYS=("$(cat "${KEY_PATH}.pub")")

    echo ""
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|  СКАЧАЙТЕ ПРИВАТНЫЙ КЛЮЧ СЕЙЧАС!                           |${NC}"
    echo -e "${YELLOW}|  С другого терминала (root по SSH пока разрешён):          |${NC}"
    echo -e "${YELLOW}|  scp root@<IP>:${KEY_PATH} ./admin_ssh_key${NC}"
    echo -e "${YELLOW}|  Или скопируйте текст ниже — он выводится только на экран  |${NC}"
    echo -e "${YELLOW}|  и НЕ записывается в лог выполнения.                       |${NC}"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo ""
    sleep 0.3   # дать tee вывести рамку выше, прежде чем писать мимо него
    {
        echo "--- ПРИВАТНЫЙ КЛЮЧ (сохраните в безопасное место) ---"
        cat "${KEY_PATH}"
        echo "------------------------------------------------------"
    } > /dev/tty
    echo ""
    echo "--- ПУБЛИЧНЫЙ КЛЮЧ ---"
    cat "${KEY_PATH}.pub"
    echo "----------------------"
    read -r -p "Нажмите Enter, когда сохраните приватный ключ..."
}

# ── 3. Пользователь-администратор ────────────────────────────────────────────
write_pwquality() {
    ensure_pkgs libpam-pwquality
    # v3 перезаписывала pwquality.conf целиком — возвращаем файл к умолчаниям
    if grep -qs "Сгенерировано ubuntu_hardening.sh" /etc/security/pwquality.conf; then
        write_file /etc/security/pwquality.conf 644 << 'EOF'
# Настройки — в /etc/security/pwquality.conf.d/ (ubuntu_hardening.sh)
EOF
    fi
    local classes=""
    if [[ "${PASSWORD_CLASSES}" == "yes" ]]; then
        classes=$'dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1'
    fi
    # enforce_for_root обязателен: passwd запускается от root, а для root
    # pwquality по умолчанию только предупреждает
    write_file /etc/security/pwquality.conf.d/50-ubuntu-hardening.conf 644 << EOF
# ubuntu_hardening.sh
minlen = 16
${classes}
maxrepeat = 3
dictcheck = 1
usercheck = 1
gecoscheck = 1
enforce_for_root
retry = 3
EOF
}

step_user() {
    if id "${ADMIN_USER}" &>/dev/null; then
        info "Пользователь ${ADMIN_USER} уже существует"
    elif getent group "${ADMIN_USER}" &>/dev/null; then
        # группа "admin" встроена в Ubuntu — используем её как основную
        useradd -m -s /bin/bash -g "${ADMIN_USER}" "${ADMIN_USER}"
        warn "Группа '${ADMIN_USER}' уже существовала — использована как основная"
    else
        useradd -m -s /bin/bash "${ADMIN_USER}"
        info "Пользователь ${ADMIN_USER} создан"
    fi
    usermod -aG sudo "${ADMIN_USER}"
    info "${ADMIN_USER} состоит в группе sudo"

    # Политика паролей — ДО задания пароля
    write_pwquality

    local st; st=$(passwd -S "${ADMIN_USER}" 2>/dev/null | awk '{print $2}')
    if [[ -n "${ADMIN_PASSWORD_HASH}" ]]; then
        usermod -p "${ADMIN_PASSWORD_HASH}" "${ADMIN_USER}"
        info "Пароль ${ADMIN_USER} задан из ADMIN_PASSWORD_HASH"
    elif [[ "${st}" != "P" ]] || confirm "  У ${ADMIN_USER} уже есть пароль. Сменить?"; then
        warn "Задайте пароль для ${ADMIN_USER} (нужен для sudo, не для SSH):"
        # 3 ошибки ввода дают код ≠0 — без цикла set -e уронил бы скрипт
        until passwd "${ADMIN_USER}"; do
            echo "  Пароль не задан (несовпадение или слабый) — попробуйте ещё раз"
        done
    fi

    local home; home=$(admin_home)
    local ssh_dir="${home}/.ssh" ak="${home}/.ssh/authorized_keys"
    mkdir -p "${ssh_dir}"
    track "${ak}"
    touch "${ak}"

    if (( ${#PUBKEYS[@]} )); then
        local new_bodies="" k body old
        for k in "${PUBKEYS[@]}"; do new_bodies+="${new_bodies:+ }$(awk '{print $2}' <<< "$k")"; done
        # Ключи, поставленные прошлым прогоном и больше не выбранные, убираем
        # (ключи, добавленные вручную, не трогаем)
        local old_bodies; old_bodies="$(kv_get "${STATE_FILE}" PUBKEY_BODIES) $(kv_get "${STATE_FILE}" PUBKEY_BODY)"
        for old in ${old_bodies}; do
            [[ " ${new_bodies} " == *" ${old} "* ]] && continue
            if grep -qF -- "${old}" "${ak}"; then
                grep -vF -- "${old}" "${ak}" > "${ak}.tmp" || true
                mv "${ak}.tmp" "${ak}"
                info "Убран ключ прошлого прогона: ${old:0:24}…"
            fi
        done
        for k in "${PUBKEYS[@]}"; do
            body=$(awk '{print $2}' <<< "$k")
            if grep -qF -- "${body}" "${ak}"; then
                info "Ключ уже установлен: ${body:0:24}…"
            else
                printf '%s\n' "$k" >> "${ak}"
                info "Ключ добавлен: ${body:0:24}…"
            fi
        done
        PUBKEY_BODIES="${new_bodies}"
    else
        PUBKEY_BODIES="$(kv_get "${STATE_FILE}" PUBKEY_BODIES)"
        [[ -n "${PUBKEY_BODIES}" ]] || PUBKEY_BODIES="$(kv_get "${STATE_FILE}" PUBKEY_BODY)"
        info "Шаг key не выполнялся — authorized_keys не меняется"
    fi

    chown -R "${ADMIN_USER}:$(id -gn "${ADMIN_USER}")" "${ssh_dir}"
    chmod 700 "${ssh_dir}"; chmod 600 "${ak}"
    local nkeys; nkeys=$(ssh-keygen -l -f "${ak}" 2>/dev/null | wc -l)
    (( nkeys > 0 )) || error "В ${ak} нет ни одного действующего ключа"
    info "${ak}: ключей ${nkeys}"

    APPLIED_ADMIN_USER="${ADMIN_USER}"
    save_state
}

# ── 4. SSH ───────────────────────────────────────────────────────────────────
step_ssh() {
    id "${ADMIN_USER}" &>/dev/null || error "Пользователя ${ADMIN_USER} нет — сначала шаг user"
    local ak; ak="$(admin_home)/.ssh/authorized_keys"
    (( $(ssh-keygen -l -f "${ak}" 2>/dev/null | wc -l) > 0 )) \
        || error "В ${ak} нет действующих ключей — sshd не трогаем"

    write_file /etc/ssh/my_banner 644 << 'EOF'
*******************************************************************
*  WARNING: Unauthorized access is strictly prohibited.           *
*  All sessions are monitored and logged.                         *
*  Disconnect immediately if you are not an authorized user.      *
*******************************************************************
EOF
    track /etc/ssh/sshd_config
    # /etc/ssh — 755 (иначе ломается ssh-клиент у обычных пользователей)
    chmod 755 /etc/ssh
    find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key"     -exec chmod 600 {} \;
    find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*_key.pub" -exec chmod 644 {} \;

    # KEX: постквантовые гибриды первыми, только то, что знает этот OpenSSH
    local supported kex_list="" k
    supported=$(ssh -Q kex 2>/dev/null || true)
    for k in mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
             curve25519-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp521; do
        grep -qxF -- "$k" <<< "${supported}" && kex_list+="${kex_list:+,}$k"
    done
    [[ -n "${kex_list}" ]] || kex_list="curve25519-sha256,curve25519-sha256@libssh.org"
    info "SSH KEX: ${kex_list}"

    local tmp; make_tmp tmp /etc/ssh
    cat > "${tmp}" << EOF
# Generated by ubuntu_hardening.sh v${SCRIPT_VERSION}
# sshd берёт ПЕРВОЕ значение директивы: наши настройки стоят выше Include
# и не перебиваются drop-in файлами (cloud-init и т.п.).

Port ${SSH_PORT}
AddressFamily ${SSH_ADDRESS_FAMILY}

# Криптография — только современные алгоритмы
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
KexAlgorithms ${kex_list}
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Аутентификация
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes
AuthenticationMethods publickey
PermitUserEnvironment no

# Тайм-ауты и лимиты
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
MaxStartups 5:30:20
ClientAliveInterval 300
ClientAliveCountMax 2

AllowUsers ${ADMIN_USER}

# Форвардинг (настраивается переменными в начале скрипта / --config)
AllowTcpForwarding ${TCP_FORWARDING}
AllowAgentForwarding ${AGENT_FORWARDING}
GatewayPorts ${GATEWAY_PORTS}
X11Forwarding ${X11_FORWARDING}
PermitTunnel no

PrintMotd no
PrintLastLog yes
Banner /etc/ssh/my_banner
AcceptEnv LANG LC_*
# internal-sftp: без отдельного бинарника, работает и в chroot
Subsystem sftp internal-sftp

DebianBanner no
VersionAddendum none

SyslogFacility AUTH
LogLevel VERBOSE

# Drop-in — В КОНЦЕ: добавляют только то, что не задано выше
Include /etc/ssh/sshd_config.d/*.conf
EOF

    # Port и ListenAddress НАКАПЛИВАЮТСЯ — drop-in с ними открыл бы второй порт
    local f
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            track "$f"
            mkdir -p "${BACKUP_DIR}/moved"
            mv "$f" "${BACKUP_DIR}/moved/"
            warn "Drop-in с Port/ListenAddress убран (копия в ${BACKUP_DIR}): $(basename "$f")"
        done < <(grep -rlsE '^[[:space:]]*(Port|ListenAddress)[[:space:]]' /etc/ssh/sshd_config.d/ || true)
    fi

    # Проверка ДО установки: битый конфиг не должен попасть на место
    mkdir -p /run/sshd
    if sshd -t -f "${tmp}"; then
        chmod 600 "${tmp}"
        mv "${tmp}" /etc/ssh/sshd_config
        info "sshd_config прошёл проверку и установлен"
    else
        error "Ошибка в сгенерированном sshd_config — текущая конфигурация не тронута"
    fi

    local eff ports
    eff=$(sshd -T 2>/dev/null || true)
    ports=$(awk '$1=="port"{print $2}' <<< "${eff}" | sort -u | tr '\n' ' ')
    [[ "${ports}" == "${SSH_PORT} " ]] || warn "sshd слушает порты: ${ports}— ожидался только ${SSH_PORT}"
    grep -qx "passwordauthentication no" <<< "${eff}" \
        || error "PasswordAuthentication не выключен в итоговой конфигурации sshd"

    # UFW уже включён (бывает в образах провайдеров) — открываем порт ДО рестарта
    local ufw_state; ufw_state=$(ufw status 2>/dev/null || true)
    if grep -q "^Status: active" <<< "${ufw_state}"; then
        ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited" >/dev/null
        info "UFW активен — порт ${SSH_PORT}/tcp открыт заранее"
    fi

    # Ubuntu 22.10+: socket-активация, при ней Port в sshd_config игнорируется
    if systemctl is-enabled ssh.socket &>/dev/null; then
        warn "Обнаружена socket-активация SSH (ssh.socket) — отключаем"
        systemctl disable --now ssh.socket
        track_action unit-enable ssh.socket
        systemctl enable ssh.service &>/dev/null || true
        systemctl daemon-reload
    fi

    local svc="ssh"
    systemctl cat ssh.service &>/dev/null || svc="sshd"
    systemctl restart "${svc}"
    systemctl is-active --quiet "${svc}" || error "SSH не запустился! journalctl -xe -u ${svc}"
    sleep 1
    if [[ -n "$(ss -Htln "sport = :${SSH_PORT}" 2>/dev/null)" ]]; then
        info "SSH (${svc}) слушает порт ${SSH_PORT}"
    else
        warn "Порт ${SSH_PORT} не найден в ss — journalctl -xe -u ${svc}"
    fi
    APPLIED_SSH_PORT="${SSH_PORT}"
    save_state
    SSH_CHECKPOINT_DONE="yes"
    STEP_NOTE[ssh]="порт ${SSH_PORT}, только ключи, PQ-KEX"
    # Проверка входа — ДО блокировки root
    login_checkpoint
}

# ── 5. root ──────────────────────────────────────────────────────────────────
step_root() {
    [[ "${SSH_CHECKPOINT_DONE}" == "yes" ]] || login_checkpoint
    passwd -l root >/dev/null
    info "Пароль root заблокирован (откат: passwd root — задать новый пароль)"

    # su — только для группы sudo. В Ubuntu строка закомментирована как
    # "# auth       required   pam_wheel.so"; без group=sudo проверялась бы группа root
    local pam_su=/etc/pam.d/su
    [[ -f "${pam_su}" ]] || return 0
    track "${pam_su}"
    if grep -qE '^\s*auth\s+required\s+pam_wheel\.so' "${pam_su}"; then
        grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' "${pam_su}" \
            || sed -i -E 's/^(\s*auth\s+required\s+pam_wheel\.so)(.*)$/\1\2 group=sudo/' "${pam_su}"
    elif grep -qE '^#\s*auth\s+required\s+pam_wheel\.so\s*$' "${pam_su}"; then
        sed -i -E 's/^#\s*auth\s+required\s+pam_wheel\.so\s*$/auth       required   pam_wheel.so group=sudo/' "${pam_su}"
    else
        sed -i '0,/^@include common-auth/s//auth       required   pam_wheel.so group=sudo\n&/' "${pam_su}"
    fi
    if grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' "${pam_su}"; then
        info "su ограничен группой sudo"
    else
        warn "Не удалось включить pam_wheel в ${pam_su} — проверьте вручную"
    fi
}

# ── 6. UFW ───────────────────────────────────────────────────────────────────
docker_ufw_rules() {
    cat << 'EOF'

# BEGIN UBUNTU_HARDENING DOCKER-USER
# Docker публикует порты через собственные цепочки iptables, минуя правила UFW.
# Новые входящие соединения из внешней сети к контейнерам блокируются здесь;
# открыть порт контейнера: ufw route allow proto tcp from any to any port <порт>
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j RETURN
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
COMMIT
# END UBUNTU_HARDENING DOCKER-USER
EOF
}

step_ufw() {
    ensure_pkgs ufw
    local f
    for f in /etc/ufw/user.rules /etc/ufw/user6.rules /etc/ufw/before.rules /etc/ufw/before6.rules \
             /etc/ufw/after.rules /etc/ufw/after6.rules /etc/ufw/ufw.conf /etc/default/ufw; do
        track "$f"
    done
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed

    # limit = встроенный rate-limit UFW: 6 попыток за 30 секунд -> блок
    ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited"

    local p rule
    for p in ${EXTRA_PORTS}; do
        rule="${p}"; [[ "${p}" == */* ]] || rule="${p}/tcp"
        if ufw allow "${rule}" comment "user-defined" >/dev/null; then info "UFW: открыт ${rule}"
        else warn "UFW отклонил правило ${rule}"; fi
    done

    if docker_fix_active; then
        if ! grep -q "BEGIN UBUNTU_HARDENING DOCKER-USER" /etc/ufw/after.rules; then
            docker_ufw_rules >> /etc/ufw/after.rules
        fi
        info "Docker: опубликованные порты закрыты извне (цепочка DOCKER-USER)"
        local port proto
        for p in ${DOCKER_ALLOW_PORTS}; do
            port="${p%/*}"; proto="tcp"; [[ "${p}" == */* ]] && proto="${p#*/}"
            if ufw route allow proto "${proto}" from any to any port "${port//-/:}" comment "docker" >/dev/null; then
                info "UFW: открыт порт контейнера ${port}/${proto}"
            else
                warn "UFW отклонил правило для порта контейнера ${p}"
            fi
        done
        STEP_NOTE[ufw]="Docker закрыт DOCKER-USER${DOCKER_ALLOW_PORTS:+, открыто: ${DOCKER_ALLOW_PORTS}}"
    elif has_docker; then
        warn "Docker найден, DOCKER_UFW_FIX=no: опубликованные порты контейнеров доступны в обход UFW"
    fi

    ufw --force enable
    ufw status verbose
}

# ── 7. Fail2ban ──────────────────────────────────────────────────────────────
step_fail2ban() {
    ensure_pkgs fail2ban
    write_file /etc/fail2ban/jail.local 644 << EOF
# ubuntu_hardening.sh
[DEFAULT]
bantime   = 1h
findtime  = 10m
maxretry  = 3
backend   = systemd
banaction = ufw
# Свои адреса (офис, VPN) задаются FAIL2BAN_IGNOREIP
ignoreip  = 127.0.0.1/8 ::1 ${FAIL2BAN_IGNOREIP}

[sshd]
enabled  = true
port     = ${SSH_PORT}
# aggressive: ловит и перебор ключами, и обрывы до аутентификации (сканеры)
mode     = aggressive
maxretry = 3
bantime  = 24h

# Повторные нарушители: 3 бана за сутки -> бан на неделю
[recidive]
enabled  = true
backend  = auto
logpath  = /var/log/fail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
    systemctl enable fail2ban &>/dev/null || true
    systemctl restart fail2ban || warn "fail2ban не перезапустился: journalctl -u fail2ban"
    info "Fail2ban: 3 неудачные попытки -> бан 24 ч, повторно -> неделя"
}

# ── 8. cron/at ───────────────────────────────────────────────────────────────
step_cron() {
    local path
    for path in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
        [[ -e "${path}" ]] || continue
        chown root:root "${path}"
        chmod og-rwx "${path}"
    done
    track /etc/cron.allow /etc/cron.deny
    echo "root" > /etc/cron.allow; chmod 600 /etc/cron.allow
    rm -f /etc/cron.deny
    if command -v at &>/dev/null; then
        track /etc/at.allow /etc/at.deny
        echo "root" > /etc/at.allow; chmod 600 /etc/at.allow
        rm -f /etc/at.deny
    fi
    info "cron/at: доступ только у root (своим пользователям — допишите в /etc/cron.allow)"
}

# ── 9. Разделы ───────────────────────────────────────────────────────────────
step_mounts() {
    local mode="${TMP_MODE}"
    if [[ "${mode}" == "auto" ]]; then
        if (( TOTAL_RAM_KB >= 2 * 1024 * 1024 )); then mode="tmpfs"; else mode="disk"; fi
    fi
    if [[ "${mode}" == "tmpfs" ]]; then
        # без size= tmpfs может занять до 50% RAM
        local size=$(( TOTAL_RAM_KB / 1024 / 4 ))
        (( size < 256 ))  && size=256
        (( size > 2048 )) && size=2048
        fstab_set /tmp "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,mode=1777,size=${size}m 0 0"
        STEP_NOTE[mounts]="/tmp: tmpfs ${size} МБ"
    else
        # мало RAM: /tmp остаётся на диске, флаги — через bind на себя
        fstab_set /tmp "/tmp /tmp none bind,nosuid,nodev,noexec 0 0"
        STEP_NOTE[mounts]="/tmp: на диске (RAM < 2 ГБ или TMP_MODE=disk)"
    fi
    fstab_set /dev/shm "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0"
    # /var/tmp по FHS переживает перезагрузку — bind на себя
    fstab_set /var/tmp "/var/tmp /var/tmp none bind,nosuid,nodev,noexec 0 0"

    local cur_tmp; cur_tmp=$(findmnt -no FSTYPE /tmp 2>/dev/null || true)
    if [[ "${mode}" == "tmpfs" && "${cur_tmp}" == "tmpfs" ]] || [[ "${mode}" == "disk" && -n "${cur_tmp}" && "${cur_tmp}" != "tmpfs" ]]; then
        mount -o remount /tmp 2>/dev/null && info "  /tmp перемонтирован" || warn "/tmp: применится после reboot"
    elif [[ -z "${cur_tmp}" ]] && mount /tmp 2>/dev/null; then
        info "  /tmp смонтирован"
    else
        warn "/tmp: тип монтирования меняется — применится после reboot"
    fi
    mount -o remount /dev/shm 2>/dev/null && info "  /dev/shm перемонтирован" || warn "/dev/shm: применится после reboot"
    if mountpoint -q /var/tmp; then
        mount -o remount,bind,nosuid,nodev,noexec /var/tmp 2>/dev/null || warn "/var/tmp: применится после reboot"
    elif mount /var/tmp 2>/dev/null; then
        info "  /var/tmp смонтирован (bind, noexec)"
    else
        warn "/var/tmp: применится после reboot"
    fi

    # noexec /tmp ломает часть maintainer-скриптов dpkg — свой каталог для apt
    mkdir -p /var/lib/apt/tmp
    write_file /etc/apt/apt.conf.d/99tempdir 644 << 'EOF'
// /tmp смонтирован с noexec — apt использует отдельный каталог
APT::ExtractTemplates::TempDir "/var/lib/apt/tmp";
EOF

    # /home
    local hopts="nosuid,nodev"
    [[ "${HOME_NOEXEC}" == "yes" ]] && hopts+=",noexec"
    if awk '!/^[[:space:]]*#/ && $2=="/home" && $3!="none"' /etc/fstab | grep -q .; then
        track /etc/fstab
        local tmp; make_tmp tmp /etc
        awk -v add="${hopts}" 'BEGIN{OFS="\t"}
             !/^[[:space:]]*#/ && $2=="/home" {
                 n = split(add, a, ",")
                 for (i = 1; i <= n; i++) if ($4 !~ "(^|,)" a[i] "(,|$)") $4 = $4 "," a[i]
             } {print}' /etc/fstab > "${tmp}"
        chmod 644 "${tmp}"; mv "${tmp}" /etc/fstab
        mount -o remount /home 2>/dev/null || warn "/home: применится после reboot"
        info "fstab: /home (отдельный раздел): ${hopts}"
    else
        if [[ -f /etc/systemd/system/remount-home.service ]]; then
            systemctl disable remount-home.service &>/dev/null || true
            track /etc/systemd/system/remount-home.service
            rm -f /etc/systemd/system/remount-home.service
            info "Удалён неработающий remount-home.service (v2)"
        fi
        fstab_set /home "/home /home none bind,${hopts} 0 0"
        systemctl daemon-reload
        if mountpoint -q /home; then
            mount -o "remount,bind,${hopts}" /home 2>/dev/null || warn "/home: применится после reboot"
        elif mount /home 2>/dev/null; then
            info "  /home смонтирован (bind, ${hopts})"
        else
            warn "/home: применится после reboot"
        fi
    fi
    [[ "${HOME_NOEXEC}" == "yes" ]] && info "  /home: noexec (~/.local/bin, VS Code Remote, nvm не запустятся; HOME_NOEXEC=no)"

    if [[ "${HIDEPID}" == "yes" ]]; then
        getent group proc &>/dev/null || groupadd -r proc
        fstab_set /proc "proc /proc proc defaults,hidepid=invisible,gid=proc 0 0"
        write_file /etc/systemd/system/systemd-logind.service.d/hidepid.conf 644 << 'EOF'
[Service]
SupplementaryGroups=proc
EOF
        id polkitd &>/dev/null && usermod -aG proc polkitd
        systemctl daemon-reload
        warn "hidepid применится после reboot; мониторинг, которому нужны все процессы, добавьте в группу proc"
    fi
}

# ── 10. sysctl ───────────────────────────────────────────────────────────────
step_sysctl() {
    # rp_filter: строгий режим (1) ломает асимметричную маршрутизацию (публичная
    # + приватная сеть провайдера). Несколько интерфейсов -> свободный режим (2)
    local ifaces count rp=1
    ifaces=$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2}' || true)
    count=$(grep -cvE '^(docker|br-|veth|virbr|tun|tap|wg|lxdbr|cni|flannel)' <<< "${ifaces}" || true)
    (( count > 1 )) && rp=2
    info "Сетевых интерфейсов: ${count} -> rp_filter=${rp}"

    local fwd="${IP_FORWARD}"
    if [[ "${fwd}" == "auto" ]]; then
        if needs_ip_forward; then fwd="yes"; else fwd="no"; fi
    fi
    [[ "${fwd}" == "yes" ]] && info "IP-форвардинг включён (Docker/Podman/LXD/WireGuard или IP_FORWARD=yes)"

    local ra="${IPV6_ACCEPT_RA}" v6
    if [[ "${ra}" == "auto" ]]; then
        v6=$(ip -6 addr show scope global 2>/dev/null || true)
        if [[ -n "${v6}" ]]; then ra="yes"; else ra="no"; fi
    fi

    local f=/etc/sysctl.d/99-hardening.conf
    track "$f"
    {
        cat << EOF
# ubuntu_hardening.sh v${SCRIPT_VERSION}
# ============================================================
#  Сеть
# ============================================================
# Анти-спуфинг: 1 = строго, 2 = свободно (несколько интерфейсов)
net.ipv4.conf.all.rp_filter = ${rp}
net.ipv4.conf.default.rp_filter = ${rp}

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

EOF
        if [[ "${fwd}" == "yes" ]]; then
            echo "# Форвардинг нужен контейнерам/VPN (IP_FORWARD=${IP_FORWARD})"
            echo "net.ipv4.ip_forward = 1"
        else
            echo "# Сервер — не маршрутизатор"
            echo "net.ipv4.ip_forward = 0"
            echo "net.ipv6.conf.all.forwarding = 0"
        fi
        cat << 'EOF'

# SYN-flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# ICMP-редиректы (MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
EOF
        if [[ "${LOG_MARTIANS}" == "yes" ]]; then
            echo ""
            echo "net.ipv4.conf.all.log_martians = 1"
            echo "net.ipv4.conf.default.log_martians = 1"
        fi
        echo ""
        if [[ "${ra}" == "no" ]]; then
            echo "# Глобального IPv6 нет (или IPV6_ACCEPT_RA=no) — RA не принимаем"
            echo "net.ipv6.conf.all.accept_ra = 0"
            echo "net.ipv6.conf.default.accept_ra = 0"
        else
            echo "# accept_ra не меняется: у сервера есть глобальный IPv6 (маршрут по умолчанию из RA)"
        fi
        cat << 'EOF'

# ============================================================
#  Ядро
# ============================================================
# ptrace: только родитель (2 ломает strace/gdb)
kernel.yama.ptrace_scope = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.randomize_va_space = 2

fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Запрет kexec (необратимо до reboot)
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
EOF
        # Ядра Ubuntu поддерживают perf_event_paranoid=4 и обычно уже так настроены —
        # повышаем только если текущее значение ниже 3
        local pep; pep=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 4)
        if (( pep < 3 )); then echo "kernel.perf_event_paranoid = 3"; fi

        echo ""
        echo "# User namespaces (rootless Docker/Podman потребуют отключить)"
        [[ -f /proc/sys/kernel/unprivileged_userns_clone ]] && echo "kernel.unprivileged_userns_clone = 0"
        [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] && echo "kernel.apparmor_restrict_unprivileged_userns = 1"
        true
    } > "$f"

    sysctl --system -q || warn "sysctl: часть параметров не применилась (см. вывод выше)"
    STEP_NOTE[sysctl]="rp_filter=${rp}, forward=${fwd}, accept_ra=${ra}"
}

# ── 11. Модули ядра и параметры загрузки ─────────────────────────────────────
step_modules() {
    local mods=(cramfs freevxfs jffs2 hfs hfsplus udf
                dccp sctp rds tipc
                ax25 netrom rose x25 appletalk ipx can atm n_hdlc)
    # squashfs нужен snap — блокируем только без snapd
    if ! command -v snap &>/dev/null && ! dpkg -s snapd &>/dev/null; then mods+=(squashfs); fi

    local f=/etc/modprobe.d/hardening-blacklist.conf m
    track "$f"
    mkdir -p /etc/modprobe.d
    {
        echo "# ubuntu_hardening.sh: редкие ФС и сетевые протоколы с историей CVE"
        echo "# (USB/Firewire не трогаем: на VPS их нет; virtio не трогаем)"
        for m in "${mods[@]}"; do echo "blacklist ${m}"; echo "install ${m} /bin/false"; done
    } > "$f"
    for m in "${mods[@]}"; do
        if [[ -d "/sys/module/${m}" ]]; then
            modprobe -r "${m}" 2>/dev/null && info "Выгружен модуль ${m}" \
                || warn "Модуль ${m} загружен и не выгружается — после reboot"
        fi
    done
    local out
    if ! out=$(luks_regen_initramfs "" 2>&1); then
        warn "Пересборка initramfs не удалась:"; tail -5 <<< "${out}"
    fi
    info "Blacklist: ${#mods[@]} модулей"

    if [[ "${KERNEL_CMDLINE_HARDENING}" == "yes" ]]; then
        if command -v update-grub &>/dev/null; then
            write_file /etc/default/grub.d/99-ubuntu-hardening.cfg 644 << 'EOF'
# ubuntu_hardening.sh: усиление ядра на этапе загрузки
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} slab_nomerge init_on_alloc=1 page_alloc.shuffle=1 vsyscall=none"
EOF
            update-grub &>/dev/null && info "Параметры ядра добавлены в GRUB (после reboot)" \
                || warn "update-grub не выполнился"
        else
            warn "GRUB не найден — параметры загрузки ядра не изменены"
        fi
    fi
}

# ── 12. Core dump ────────────────────────────────────────────────────────────
step_coredump() {
    # v3 дописывала строки в limits.conf при каждом запуске — убираем их
    local lc=/etc/security/limits.conf
    if grep -qE '^(\*|root)[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]+0[[:space:]]*$' "${lc}" 2>/dev/null; then
        track "${lc}"
        sed -i -E '/^(\*|root)[[:space:]]+(hard|soft)[[:space:]]+core[[:space:]]+0[[:space:]]*$/d' "${lc}"
        info "Из limits.conf убраны строки core (теперь — limits.d)"
    fi
    write_file /etc/security/limits.d/99-ubuntu-hardening-core.conf 644 << 'EOF'
# ubuntu_hardening.sh
*    hard    core    0
*    soft    core    0
root hard    core    0
EOF
    write_file /etc/systemd/coredump.conf.d/disable.conf 644 << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
    info "Core dump отключён"
}

# ── 13. auditd ───────────────────────────────────────────────────────────────
step_auditd() {
    ensure_pkgs auditd audispd-plugins
    local immutable="no" st
    st=$(auditctl -s 2>/dev/null || true)
    grep -q "enabled 2" <<< "${st}" && immutable="yes"

    write_file /etc/audit/auditd.conf 640 << EOF
# ubuntu_hardening.sh
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = root
# Ротация: ${AUDIT_NUM_LOGS} файлов по ${AUDIT_MAX_FILE_MB} МБ (не более 10% свободного места)
max_log_file = ${AUDIT_MAX_FILE_MB}
num_logs = ${AUDIT_NUM_LOGS}
max_log_file_action = ROTATE
# При нехватке места — не останавливать систему (VPS без физического доступа)
space_left = $(( AUDIT_MAX_FILE_MB * 2 ))
space_left_action = SYSLOG
admin_space_left = ${AUDIT_MAX_FILE_MB}
admin_space_left_action = ROTATE
disk_full_action = ROTATE
disk_error_action = SYSLOG
name_format = HOSTNAME
flush = INCREMENTAL_ASYNC
freq = 50
EOF

    local home; home=$(admin_home); home="${home:-/home/${ADMIN_USER}}"
    write_file /etc/audit/rules.d/99-hardening.rules 640 << EOF
# ubuntu_hardening.sh v${SCRIPT_VERSION}
# -b, -f и -e вынесены в zz-hardening-finalize.rules: augenrules оставляет
# ПОСЛЕДНИЕ из них, а audit.rules дистрибутива читается после файлов 99-*
# -i: не прерывать загрузку, если syscall/пути нет в этой версии ядра
-i

# Идентификация
-w /etc/passwd    -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/gshadow   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/sudo.log -p wa -k sudo_log

# PAM и политики входа
-w /etc/pam.d/        -p wa -k pam
-w /etc/security/     -p wa -k pam
-w /etc/login.defs    -p wa -k pam

# SSH
-w /etc/ssh/sshd_config          -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/       -p wa -k sshd_config
-w ${home}/.ssh/     -p wa -k ssh_keys
-w /root/.ssh/                   -p wa -k ssh_keys

# Входы и сессии
-w /var/log/lastlog   -p wa -k logins
-w /var/log/faillog   -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp      -p wa -k session
-w /var/log/wtmp      -p wa -k session
-w /var/log/btmp      -p wa -k session

# Cron
-w /etc/crontab       -p wa -k cron
-w /etc/cron.d/       -p wa -k cron
-w /etc/cron.daily/   -p wa -k cron
-w /etc/cron.hourly/  -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/  -p wa -k cron
-w /var/spool/cron/   -p wa -k cron

# Автозагрузка и предзагрузка библиотек
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload   -p wa -k preload
-w /etc/ld.so.conf.d/   -p wa -k preload

# Время (auid-фильтр отсекает chronyd)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F auid>=1000 -F auid!=unset -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -F auid>=1000 -F auid!=unset -k time_change
-w /etc/localtime -p wa -k time_change

# Имя хоста и сеть
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system_locale
-w /etc/hosts       -p wa -k system_locale
-w /etc/hostname    -p wa -k system_locale
-w /etc/netplan/    -p wa -k system_locale
-w /etc/resolv.conf -p wa -k system_locale

# Мандатный контроль доступа
-w /etc/apparmor/   -p wa -k mac_policy
-w /etc/apparmor.d/ -p wa -k mac_policy

# Монтирование пользователями
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount,umount,umount2 -F auid>=1000 -F auid!=unset -k mounts

# Права и владельцы (b64 + b32 — иначе 32-битные вызовы не аудируются)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k file_perm
# fchmodat2 (ядро 6.6+) — отдельным правилом: неизвестный syscall отбросил бы всё правило
-a always,exit -F arch=b64 -S fchmodat2 -F auid>=1000 -F auid!=unset -k file_perm

# Привилегии
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec

# Неудачные попытки доступа к файлам (признак разведки)
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S openat2,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S openat2,open_by_handle_at -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access

# Удаление и переименование файлов пользователями
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S renameat2 -F auid>=1000 -F auid!=unset -k delete

# Модули ядра
-w /usr/bin/kmod -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k kernel_modules

# Сеть: только bind реальных пользователей (socket/connect — источник backlog exceeded)
-a always,exit -F arch=b64 -S bind -F auid>=1000 -F auid!=unset -k net_bind
-a always,exit -F arch=b32 -S bind -F auid>=1000 -F auid!=unset -k net_bind

# Загрузчик и kexec
-w /boot/ -p wa -k boot
-a always,exit -F arch=b64 -S kexec_load,kexec_file_load -k kexec
-a always,exit -F arch=b32 -S kexec_load -k kexec
EOF

    # Запуск SUID/SGID-программ (CIS 4.1.3.6) — список строится на этом сервере
    local bin n=0
    {
        echo "# ubuntu_hardening.sh: запуск привилегированных программ, $(date +%F)"
        while IFS= read -r bin; do
            echo "-a always,exit -F path=${bin} -F perm=x -F auid>=1000 -F auid!=unset -k privileged"
        done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort || true)
    } | write_file /etc/audit/rules.d/70-privileged.rules 640
    n=$(grep -c '^-a' /etc/audit/rules.d/70-privileged.rules || true)

    write_file /etc/audit/rules.d/zz-hardening-finalize.rules 640 << EOF
# ubuntu_hardening.sh — читается последним (ls -v): эти значения побеждают
# -b 8192 из audit.rules дистрибутива
-b ${AUDIT_BACKLOG}
# Режим сбоя 1 = syslog (не 2/паника — VPS без физического доступа)
-f 1
# Неизменяемые правила до перезагрузки
-e 2
EOF

    # auditd ротирует сам (max_log_file_action = ROTATE)
    track /etc/logrotate.d/audit
    rm -f /etc/logrotate.d/audit
    mkdir -p /var/log/audit

    if [[ "${immutable}" == "yes" ]]; then
        warn "Правила auditd неизменяемы (enabled 2) — новые файлы записаны и применятся после reboot"
    else
        augenrules --load &>/dev/null || warn "augenrules --load завершился с ошибкой — проверьте: augenrules --check"
        systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null \
            || warn "auditd не перезапустился"
    fi
    STEP_NOTE[auditd]="backlog ${AUDIT_BACKLOG}, ${AUDIT_NUM_LOGS}×${AUDIT_MAX_FILE_MB} МБ, SUID/SGID: ${n}"
}

# ── 14. AppArmor ─────────────────────────────────────────────────────────────
step_apparmor() {
    ensure_pkgs apparmor apparmor-utils
    systemctl enable --now apparmor &>/dev/null || true
    if aa-status --enabled 2>/dev/null; then
        local enf cmp
        enf=$(aa-status --profiled 2>/dev/null || echo "?")
        cmp=$(aa-status --complaining 2>/dev/null || echo "?")
        info "AppArmor активен: профилей ${enf}, в complain ${cmp}"
        if [[ "${APPARMOR_ENFORCE_ALL}" == "yes" ]]; then
            local profile
            while IFS= read -r profile; do
                if aa-enforce "${profile}" &>/dev/null; then info "  enforce: $(basename "${profile}")"
                else warn "  не удалось: $(basename "${profile}")"; fi
            done < <(grep -lE 'flags=\([^)]*complain' /etc/apparmor.d/* 2>/dev/null \
                        | xargs -r grep -LE 'flags=\([^)]*unconfined' || true)
        elif [[ "${cmp}" != "0" && "${cmp}" != "?" ]]; then
            info "  Перевести выборочно: aa-enforce /etc/apparmor.d/<профиль>"
        fi
    else
        warn "AppArmor не активен (параметры ядра apparmor=1 security=apparmor)"
    fi
}

# ── 15. sudo ─────────────────────────────────────────────────────────────────
step_sudo() {
    if sudo --version 2>/dev/null | head -1 | grep -qi "sudo-rs"; then
        info "Обнаружен sudo-rs — используются только общие с ним Defaults"
    fi
    # root заблокирован — битый sudoers означал бы полную потерю доступа
    local tmp; make_tmp tmp
    cat > "${tmp}" << 'EOF'
# ubuntu_hardening.sh
Defaults    timestamp_timeout=5
Defaults    use_pty
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
    chmod 440 "${tmp}"
    if visudo -c -f "${tmp}" &>/dev/null; then
        track /etc/sudoers.d/99-hardening
        mv "${tmp}" /etc/sudoers.d/99-hardening
        chown root:root /etc/sudoers.d/99-hardening
        if ! visudo -c &>/dev/null; then
            rm -f /etc/sudoers.d/99-hardening
            warn "sudoers в целом не прошёл проверку — наш файл убран (visudo -c)"
        fi
    else
        warn "Настройки sudo не прошли visudo — НЕ установлены"
    fi

    # Отдельный лог sudo. rsyslog в Ubuntu пишет от имени syslog:adm — файл
    # должен принадлежать ему (в v3 был root:root 600, и rsyslog не мог в него писать).
    # Строки sudo остаются и в auth.log (без "& stop").
    ensure_pkgs rsyslog
    write_file /etc/rsyslog.d/50-sudo.conf 644 << 'EOF'
# ubuntu_hardening.sh: копия событий sudo в отдельный файл
:programname, isequal, "sudo" /var/log/sudo.log
EOF
    local owner="root:adm"
    id syslog &>/dev/null && owner="syslog:adm"
    install -o "${owner%:*}" -g "${owner#*:}" -m 640 /dev/null /var/log/sudo.log.new
    if [[ -f /var/log/sudo.log ]]; then
        chown "${owner}" /var/log/sudo.log; chmod 640 /var/log/sudo.log; rm -f /var/log/sudo.log.new
    else
        mv /var/log/sudo.log.new /var/log/sudo.log
    fi
    write_file /etc/logrotate.d/sudo-log 644 << EOF
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 ${owner/:/ }
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
EOF
    systemctl restart rsyslog 2>/dev/null || warn "rsyslog не перезапустился"
    info "sudo: тайм-аут 5 мин, use_pty, secure_path; лог /var/log/sudo.log (${owner}, ротация)"
}

# ── 16. Пароли, login.defs, faillock ─────────────────────────────────────────
faillock_enable() {
    local ca=/etc/pam.d/common-auth cc=/etc/pam.d/common-account
    track "${ca}" "${cc}" /etc/security/faillock.conf \
          /usr/share/pam-configs/ubuntu-hardening-faillock \
          /usr/share/pam-configs/ubuntu-hardening-faillock-notify
    cat > /etc/security/faillock.conf << 'EOF'
# ubuntu_hardening.sh: 5 неверных паролей за 15 минут -> блок на 15 минут.
# root не блокируется (even_deny_root не задан). Снять: faillock --user <имя> --reset
deny = 5
fail_interval = 900
unlock_time = 900
audit
EOF
    cat > /usr/share/pam-configs/ubuntu-hardening-faillock << 'EOF'
Name: Lockout after failed attempts (ubuntu_hardening.sh)
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
EOF
    cat > /usr/share/pam-configs/ubuntu-hardening-faillock-notify << 'EOF'
Name: Check and reset failed-attempt counter (ubuntu_hardening.sh)
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
    pam-auth-update --package --enable ubuntu-hardening-faillock ubuntu-hardening-faillock-notify

    # Проверка порядка: preauth до pam_unix, authfail после, pam_unix на месте.
    # Ошибка здесь сломала бы sudo при заблокированном root — тогда откатываем.
    local order
    order=$(grep -nE 'pam_(faillock|unix)\.so' "${ca}" | sed -E 's/^([0-9]+):.*pam_(faillock|unix)\.so ?([a-z]*).*/\2\3/' | tr '\n' ' ')
    if [[ "${order}" == "faillockpreauth unixnullok faillockauthfail " || "${order}" == "faillockpreauth unix faillockauthfail " ]] \
       && grep -qE '^account\s+required\s+pam_faillock\.so' "${cc}"; then
        info "faillock: 5 неверных паролей -> блок 15 мин (faillock --user <имя> --reset)"
    else
        warn "faillock: неожиданный порядок модулей в ${ca} (${order}) — откатываю"
        pam-auth-update --package --remove ubuntu-hardening-faillock ubuntu-hardening-faillock-notify || true
        cp -a "${BACKUP_DIR}/files${ca}" "${ca}" 2>/dev/null || true
        cp -a "${BACKUP_DIR}/files${cc}" "${cc}" 2>/dev/null || true
        rm -f /usr/share/pam-configs/ubuntu-hardening-faillock /usr/share/pam-configs/ubuntu-hardening-faillock-notify
    fi
}

step_accounts() {
    write_pwquality
    info "Политика паролей: от 16 символов$([[ "${PASSWORD_CLASSES}" == "yes" ]] && echo ", все классы символов"), словарь, enforce_for_root"

    set_login_def UMASK 027
    set_login_def PASS_MAX_DAYS "${PASSWORD_MAX_DAYS}"
    set_login_def PASS_MIN_DAYS 1
    set_login_def PASS_WARN_AGE 7
    # shadow 4.8 (22.04) не знает YESCRYPT; passwd там и так пишет yescrypt через PAM
    if [[ "${UBUNTU_VERSION}" != "22.04" ]]; then set_login_def ENCRYPT_METHOD YESCRYPT; fi
    info "login.defs: UMASK 027, срок пароля ${PASSWORD_MAX_DAYS} дн."
    if id "${ADMIN_USER}" &>/dev/null; then
        chage --maxdays "${PASSWORD_MAX_DAYS}" --mindays 1 --warndays 7 "${ADMIN_USER}"
        info "Срок пароля ${ADMIN_USER} (для sudo): ${PASSWORD_MAX_DAYS} дн."
    fi

    if [[ "${ENABLE_FAILLOCK}" == "yes" ]]; then
        faillock_enable
    else
        info "faillock выключен (ENABLE_FAILLOCK=yes — блокировка после 5 неверных паролей sudo/su)"
    fi
}

# ── 17. Права ────────────────────────────────────────────────────────────────
step_perms() {
    # 640 root:shadow: при 600 unix_chkpwd не проверит пароль для непривилегированных процессов
    chown root:shadow /etc/shadow /etc/gshadow
    chmod 640 /etc/shadow /etc/gshadow
    chmod 644 /etc/passwd /etc/group
    chmod 700 /boot 2>/dev/null || true
    # Снять SUID через dpkg-statoverride — иначе обновление пакета passwd вернёт его
    local bin
    for bin in /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp; do
        [[ -e "${bin}" ]] || continue
        if ! dpkg-statoverride --list "${bin}" &>/dev/null; then
            dpkg-statoverride --update --add root root 0755 "${bin}"
            track_action statoverride-remove "${bin}"
            info "SUID снят (dpkg-statoverride): ${bin}"
        fi
    done
}

# ── 18. Телеметрия ───────────────────────────────────────────────────────────
step_telemetry() {
    local pkg
    for pkg in ubuntu-report popularity-contest apport whoopsie; do
        if dpkg -s "${pkg}" &>/dev/null; then
            if "${APT_GET[@]}" purge -y -qq "${pkg}"; then info "Удалён: ${pkg}"; else warn "Не удалось удалить: ${pkg}"; fi
        fi
    done
    "${APT_GET[@]}" autoremove -y -qq
    "${APT_GET[@]}" autoclean -qq
    if command -v snap &>/dev/null; then
        snap set system metrics.status=disabled 2>/dev/null || true
    fi
    if [[ -f /etc/default/motd-news ]]; then
        track /etc/default/motd-news
        sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
        systemctl disable --now motd-news.timer &>/dev/null || true
    fi
    if command -v pro &>/dev/null; then pro config set apt_news=false &>/dev/null || true; fi
    info "Телеметрия удалена"
}

# ── 19. Автообновления ───────────────────────────────────────────────────────
step_updates() {
    ensure_pkgs unattended-upgrades needrestart
    # Свой файл 52-… (файл пакета 50-… не трогаем); #clear заменяет списки целиком.
    # Package-Blacklist — регулярные выражения от начала имени (re.match):
    # "mysql" задерживает mysql-server*, но не libmysqlclient*
    write_file /etc/apt/apt.conf.d/52unattended-upgrades-hardening 644 << 'EOF'
// ubuntu_hardening.sh — переопределяет 50unattended-upgrades
#clear Unattended-Upgrade::Allowed-Origins;
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    "${distro_id}:${distro_codename}-updates";
};

// Сервисы с данными / оркестрация — вручную, чтобы контролировать простой
#clear Unattended-Upgrade::Package-Blacklist;
Unattended-Upgrade::Package-Blacklist {
    "docker";
    "containerd";
    "kube";
    "postgresql";
    "mysql";
    "mariadb";
    "redis";
    "mongodb";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// Без автоперезагрузки: нужна ли она — /var/run/reboot-required (и --audit)
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
EOF
    if [[ -d /etc/needrestart ]]; then
        write_file /etc/needrestart/conf.d/50-hardening.conf 644 << 'EOF'
# ubuntu_hardening.sh: перезапускать сервисы после обновления библиотек
$nrconf{restart} = 'a';
EOF
    fi
    write_file /etc/apt/apt.conf.d/20auto-upgrades 644 << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    write_file /etc/systemd/system/apt-daily.timer.d/override.conf 644 << 'EOF'
[Timer]
OnBootSec=
OnCalendar=
OnUnitActiveSec=
OnCalendar=*-*-* 03:00
RandomizedDelaySec=10m
EOF
    write_file /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf 644 << 'EOF'
[Timer]
OnBootSec=
OnCalendar=
OnUnitActiveSec=
OnCalendar=*-*-* 03:30
RandomizedDelaySec=10m
EOF
    systemctl daemon-reload
    systemctl restart apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || warn "Таймеры apt не перезапустились"
    info "Автообновления: списки 03:00, установка 03:30 (±10 мин); СУБД, Docker, kube — вручную"
    info "Письма об ошибках идут root — без MTA смотрите /var/log/unattended-upgrades/ и --audit"
}

# ── 19.1 journald и пересылка ────────────────────────────────────────────────
step_journald() {
    write_file /etc/systemd/journald.conf.d/50-ubuntu-hardening.conf 644 << EOF
# ubuntu_hardening.sh: журнал переживает перезагрузку, но не больше квоты
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=${LOG_QUOTA_MB}M
SystemKeepFree=$(( LOG_QUOTA_MB / 2 ))M
EOF
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal &>/dev/null || true
    systemctl restart systemd-journald 2>/dev/null || warn "systemd-journald не перезапустился"
    info "journald: persistent, не более ${LOG_QUOTA_MB} МБ"

    if [[ -n "${REMOTE_SYSLOG}" ]]; then
        local host="${REMOTE_SYSLOG%:*}" port="${REMOTE_SYSLOG##*:}"
        host="${host#[}"; host="${host%]}"
        ensure_pkgs rsyslog audispd-plugins
        # Файл 45-… раньше 50-default.conf: события auditd уходят наружу,
        # но не дублируются в /var/log/syslog (они уже есть в audit.log)
        write_file /etc/rsyslog.d/45-ubuntu-hardening-remote.conf 644 << EOF
# ubuntu_hardening.sh: пересылка всех журналов на ${REMOTE_SYSLOG} по TCP.
# Канал НЕ шифруется — используйте VPN/WireGuard или настройте TLS (gtls).
*.* action(type="omfwd" target="${host}" port="${port}" protocol="tcp"
           queue.type="LinkedList" queue.filename="uh_fwd" queue.maxDiskSpace="256m"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1")
:programname, isequal, "audisp-syslog" stop
EOF
        local plug=/etc/audit/plugins.d/syslog.conf
        if [[ -f "${plug}" ]]; then
            track "${plug}"
            sed -i -E 's/^(\s*active\s*=\s*).*/\1yes/' "${plug}"
            systemctl restart auditd 2>/dev/null || true
        else
            warn "${plug} не найден — события auditd пересылаться не будут"
        fi
        systemctl restart rsyslog 2>/dev/null || warn "rsyslog не перезапустился"
        STEP_NOTE[journald]="пересылка на ${REMOTE_SYSLOG} (TCP, без TLS)"
        warn "Логи уходят на ${REMOTE_SYSLOG} без шифрования — только через доверенную сеть/VPN"
    fi
}

# ── 19.2 AIDE ────────────────────────────────────────────────────────────────
step_aide() {
    if [[ "${ENABLE_AIDE}" != "yes" ]]; then
        step_off "AIDE выключен (ENABLE_AIDE=yes)"
        return 0
    fi
    ensure_pkgs aide aide-common
    info "Построение базы AIDE (несколько минут)…"
    if aideinit -y -f >/dev/null 2>&1; then
        info "База AIDE создана; ежедневная проверка — dailyaidecheck / cron.daily"
        systemctl enable --now dailyaidecheck.timer &>/dev/null || true
    else
        warn "aideinit завершился с ошибкой"
    fi
}

# ── 19.5 LUKS ────────────────────────────────────────────────────────────────
step_luks() {
    if [[ "${ASSUME_YES}" == "yes" ]]; then
        step_off "в режиме --yes не выполняется: bash ubuntu_hardening.sh --luks <режим>"
        return 0
    fi
    luks_menu
    if grep -qsE '^[^#[:space:]]' /etc/crypttab; then STEP_NOTE[luks]="настроено (--luks status)"
    else STEP_NOTE[luks]="не настроено"; fi
}

# ── 20. Итог: ключ, старые логи, лишние службы ───────────────────────────────
step_finish() {
    # Логи v2 содержали приватный ключ в открытом виде
    local log
    for log in /root/hardening_*.log; do
        [[ -f "${log}" && "${log}" != "${RUN_LOG}" ]] || continue
        if grep -q "PRIVATE KEY-----" "${log}" 2>/dev/null; then
            shred -uz "${log}" 2>/dev/null || rm -f "${log}"
            warn "Удалён старый лог с приватным ключом: ${log}"
        fi
    done

    if [[ "${KEY_SOURCE:-}" == "generated" && -f "${KEY_PATH}" ]]; then
        echo ""
        echo -e "${RED}+------------------------------------------------------------+${NC}"
        echo -e "${RED}|  УДАЛЕНИЕ ПРИВАТНОГО КЛЮЧА С СЕРВЕРА                       |${NC}"
        echo -e "${RED}|  Root по SSH уже запрещён — scp под root не сработает.     |${NC}"
        echo -e "${RED}|  Если ключ не сохранён, его можно показать ещё раз здесь.  |${NC}"
        echo -e "${RED}+------------------------------------------------------------+${NC}"
        if confirm "Показать приватный ключ ещё раз?"; then
            sleep 0.3
            { echo ""; cat "${KEY_PATH}"; echo ""; } > /dev/tty
        fi
        if confirm "Ключ сохранён и вход под ${ADMIN_USER} работает? Удалить ключ с сервера?"; then
            shred -uz "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
            info "Приватный ключ удалён с сервера"
        else
            warn "Ключ оставлен: ${KEY_PATH} — удалите после сохранения: sudo shred -uz ${KEY_PATH}"
        fi
    elif [[ -f "${KEY_PATH}" && "${KEY_SOURCE:-}" != "generated" ]]; then
        shred -uz "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
        info "Удалён приватный ключ прошлого прогона: ${KEY_PATH}"
    fi

    # Лишние службы, которые часто остаются в образах
    local svc found=()
    for svc in rpcbind.service rpcbind.socket avahi-daemon.service avahi-daemon.socket \
               cups.service cups.socket cups-browsed.service ModemManager.service bluetooth.service; do
        systemctl is-enabled "${svc}" &>/dev/null && found+=("${svc}")
    done
    if (( ${#found[@]} )); then
        echo ""
        info "Включены службы, обычно ненужные на сервере: ${found[*]}"
        for svc in "${found[@]}"; do
            if [[ " ${DISABLE_SERVICES} " == *" ${svc%.*} "* || " ${DISABLE_SERVICES} " == *" ${svc} "* ]] \
               || confirm "  Отключить ${svc}?"; then
                systemctl disable --now "${svc}" &>/dev/null && track_action unit-enable "${svc}" \
                    && info "  Отключена: ${svc}"
            fi
        done
    fi

    echo ""
    info "Слушают не только localhost:"
    ss -Htlnu 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|::1)/ {print "    " $1 "  " $5}' | sort -u || true

    save_state
}

# ══════════════════════════════════════════════════════════════════════════════
#  --audit: проверка состояния без изменений
# ══════════════════════════════════════════════════════════════════════════════
A_PASS=0; A_FAIL=0; A_WARN=0
a_pass() { A_PASS=$(( A_PASS + 1 )); echo -e "  ${GREEN}PASS${NC}  $*"; }
a_fail() { A_FAIL=$(( A_FAIL + 1 )); echo -e "  ${RED}FAIL${NC}  $*"; }
a_warn() { A_WARN=$(( A_WARN + 1 )); echo -e "  ${YELLOW}WARN${NC}  $*"; }
a_check() {   # a_check <описание> <команда...>
    local d="$1"; shift
    if "$@" &>/dev/null; then a_pass "$d"; else a_fail "$d"; fi
}
a_eff() {   # a_eff <ключ sshd -T> <ожидаемое значение>
    if grep -qx "$1 $2" <<< "${A_SSHD}"; then a_pass "sshd: $1 $2"
    else a_fail "sshd: $1 = $(awk -v k="$1" '$1==k{$1=""; print substr($0,2)}' <<< "${A_SSHD}" | head -1) (ожидалось $2)"; fi
}
a_mount_opts() {   # a_mount_opts <точка> <опция>...
    local mp="$1" opts o miss=""; shift
    opts=$(findmnt -no OPTIONS "${mp}" 2>/dev/null | head -1)
    if [[ -z "${opts}" ]]; then a_fail "${mp}: не смонтирован отдельно (нужен reboot?)"; return; fi
    for o in "$@"; do [[ ",${opts}," == *",${o},"* ]] || miss+=" ${o}"; done
    if [[ -z "${miss}" ]]; then a_pass "${mp}: $*"; else a_fail "${mp}: нет${miss}"; fi
}

run_audit() {
    local user port
    user=$(kv_get "${STATE_FILE}" ADMIN_USER); user="${user:-${ADMIN_USER}}"
    port=$(kv_get "${STATE_FILE}" SSH_PORT);   port="${port:-${SSH_PORT}}"
    local home_noexec; home_noexec=$(kv_get "${STATE_FILE}" HOME_NOEXEC); home_noexec="${home_noexec:-yes}"
    echo ""
    echo "ubuntu_hardening.sh ${SCRIPT_VERSION} — проверка ($(hostname), $(date '+%F %T'))"
    echo "Администратор: ${user}, порт SSH: ${port}"

    section "SSH"
    A_SSHD=$(sshd -T -C "user=${user},host=localhost,addr=127.0.0.1" 2>/dev/null || true)
    if [[ -z "${A_SSHD}" ]]; then
        a_fail "sshd -T не выполнился"
    else
        a_eff port "${port}"
        a_eff permitrootlogin no
        a_eff passwordauthentication no
        a_eff kbdinteractiveauthentication no
        a_eff authenticationmethods publickey
        a_eff allowagentforwarding no
        a_eff x11forwarding no
        a_eff permittunnel no
        a_eff permituserenvironment no
        a_eff maxauthtries 3
        if grep -qE "^allowusers( .*)? ${user}( |$)" <<< "${A_SSHD}"; then a_pass "sshd: ${user} в AllowUsers"
        else a_fail "sshd: ${user} не в AllowUsers"; fi
    fi
    if systemctl is-enabled ssh.socket &>/dev/null; then a_fail "ssh.socket включён (Port из sshd_config игнорируется)"
    else a_pass "ssh.socket выключен"; fi
    local ak; ak="$(getent passwd "${user}" | cut -d: -f6)/.ssh/authorized_keys"
    local nk; nk=$(ssh-keygen -l -f "${ak}" 2>/dev/null | wc -l)
    if (( nk > 0 )); then a_pass "${ak}: ключей ${nk}"; else a_fail "${ak}: нет ключей"; fi

    section "Учётные записи"
    local rs; rs=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [[ "${rs}" == "L" || "${rs}" == "NP" ]]; then a_pass "root: пароль заблокирован"; else a_fail "root: пароль не заблокирован (${rs})"; fi
    if grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' /etc/pam.d/su 2>/dev/null; then a_pass "su только для группы sudo"
    else a_fail "su не ограничен (pam_wheel)"; fi
    if grep -qs '^enforce_for_root' /etc/security/pwquality.conf.d/*.conf /etc/security/pwquality.conf; then a_pass "pwquality: enforce_for_root"
    else a_fail "pwquality: enforce_for_root не задан"; fi
    a_check "sudoers: visudo -c" visudo -c
    a_check "sudoers: use_pty" grep -qs 'use_pty' /etc/sudoers.d/99-hardening
    local sl; sl=$(stat -c '%U:%G %a' /var/log/sudo.log 2>/dev/null || echo "нет")
    if [[ "${sl}" == "syslog:adm 640" || "${sl}" == "root:adm 640" ]]; then a_pass "/var/log/sudo.log: ${sl}"
    else a_fail "/var/log/sudo.log: ${sl} (rsyslog не сможет писать)"; fi
    local sh; sh=$(stat -c '%U:%G %a' /etc/shadow)
    if [[ "${sh}" == "root:shadow 640" || "${sh}" == "root:shadow 600" ]]; then a_pass "/etc/shadow: ${sh}"; else a_fail "/etc/shadow: ${sh}"; fi

    section "Сеть"
    local ufw_out; ufw_out=$(ufw status verbose 2>/dev/null || true)
    if grep -q "^Status: active" <<< "${ufw_out}"; then a_pass "UFW активен"; else a_fail "UFW не активен"; fi
    if grep -q "deny (incoming)" <<< "${ufw_out}"; then a_pass "UFW: deny incoming"; else a_fail "UFW: входящие не запрещены по умолчанию"; fi
    if grep -qE "^${port}/tcp" <<< "${ufw_out}"; then a_pass "UFW: правило для SSH ${port}"; else a_fail "UFW: нет правила для ${port}/tcp"; fi
    if has_docker; then
        if grep -qs "BEGIN UBUNTU_HARDENING DOCKER-USER" /etc/ufw/after.rules; then a_pass "Docker: DOCKER-USER закрывает опубликованные порты"
        else a_warn "Docker: опубликованные порты доступны в обход UFW"; fi
    fi
    local f2b; f2b=$(fail2ban-client status sshd 2>/dev/null || true)
    if [[ -n "${f2b}" ]]; then a_pass "fail2ban: jail sshd активен"; else a_fail "fail2ban: jail sshd не работает"; fi

    section "Ядро (sysctl: файл против текущих значений)"
    local key val cur drift=0 total=0
    while IFS='=' read -r key val; do
        key="${key//[[:space:]]/}"; val="${val#"${val%%[![:space:]]*}"}"
        [[ -z "${key}" || "${key}" == \#* ]] && continue
        total=$(( total + 1 ))
        cur=$(sysctl -n "${key}" 2>/dev/null || echo "?")
        if [[ "${cur}" != "${val}" ]]; then
            drift=$(( drift + 1 )); a_fail "sysctl ${key} = ${cur} (в файле ${val})"
        fi
    done < <(grep -vE '^\s*(#|$)' /etc/sysctl.d/99-hardening.conf 2>/dev/null || true)
    if (( total == 0 )); then a_fail "/etc/sysctl.d/99-hardening.conf не найден"
    elif (( drift == 0 )); then a_pass "sysctl: все ${total} параметров совпадают"; fi

    local m bad=""
    while read -r _ m _; do
        [[ -d "/sys/module/${m}" ]] && bad+=" ${m}"
    done < <(grep -E '^install ' /etc/modprobe.d/hardening-blacklist.conf 2>/dev/null || true)
    if [[ ! -f /etc/modprobe.d/hardening-blacklist.conf ]]; then a_fail "Blacklist модулей не установлен"
    elif [[ -z "${bad}" ]]; then a_pass "Заблокированные модули не загружены"; else a_fail "Загружены:${bad}"; fi

    section "Разделы"
    a_mount_opts /tmp nosuid nodev noexec
    a_mount_opts /dev/shm nosuid nodev noexec
    a_mount_opts /var/tmp nosuid nodev noexec
    if [[ "${home_noexec}" == "yes" ]]; then a_mount_opts /home nosuid nodev noexec
    else a_mount_opts /home nosuid nodev; fi

    section "Аудит и журналы"
    a_check "auditd активен" systemctl is-active --quiet auditd
    local ast; ast=$(auditctl -s 2>/dev/null || true)
    if grep -q "enabled 2" <<< "${ast}"; then a_pass "auditd: правила неизменяемы (enabled 2)"; else a_warn "auditd: правила изменяемы (нужен reboot?)"; fi
    local nr; nr=$(auditctl -l 2>/dev/null | grep -vc "^No rules" || true)
    if (( nr > 50 )); then a_pass "auditd: загружено правил ${nr}"; else a_fail "auditd: загружено правил ${nr}"; fi
    local lost; lost=$(awk '$1=="lost"{print $2}' <<< "${ast}")
    if [[ -n "${lost}" && "${lost}" != "0" ]]; then a_warn "auditd: потеряно событий ${lost} (backlog мал или поток велик)"; fi
    local bl; bl=$(awk '$1=="backlog_limit"{print $2}' <<< "${ast}")
    [[ -n "${bl}" ]] && echo "        backlog_limit ${bl}"
    if aa-status --enabled 2>/dev/null; then a_pass "AppArmor активен"; else a_fail "AppArmor не активен"; fi
    a_check "journald: drop-in с квотой" test -f /etc/systemd/journald.conf.d/50-ubuntu-hardening.conf
    a_check "core dump: limits.d" test -f /etc/security/limits.d/99-ubuntu-hardening-core.conf

    section "Обновления"
    a_check "unattended-upgrades включены" grep -qs 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades
    a_check "таймер apt-daily-upgrade активен" systemctl is-active --quiet apt-daily-upgrade.timer
    if [[ -f /var/run/reboot-required ]]; then a_warn "Требуется перезагрузка ($(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null | cut -c1-80))"
    else a_pass "Перезагрузка не требуется"; fi
    local up; up=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ' || true)
    if (( up > 0 )); then a_warn "Ожидают установки пакетов: ${up} (часть — из Package-Blacklist)"; else a_pass "Все пакеты обновлены"; fi
    local pkg tel=""
    for pkg in ubuntu-report popularity-contest apport whoopsie; do dpkg -s "${pkg}" &>/dev/null && tel+=" ${pkg}"; done
    if [[ -z "${tel}" ]]; then a_pass "Телеметрия удалена"; else a_fail "Установлены:${tel}"; fi

    echo ""
    echo -e "Итого: ${GREEN}PASS ${A_PASS}${NC}  ${RED}FAIL ${A_FAIL}${NC}  ${YELLOW}WARN ${A_WARN}${NC}"
    (( A_FAIL == 0 ))
}

# ══════════════════════════════════════════════════════════════════════════════
#  --rollback: восстановление файлов прогона
# ══════════════════════════════════════════════════════════════════════════════
run_rollback() {
    if [[ -z "${ROLLBACK_STAMP}" ]]; then
        echo "Резервные копии прогонов (${BACKUP_ROOT}):"
        local d
        for d in "${BACKUP_ROOT}"/*/; do
            [[ -f "${d}manifest" ]] || continue
            printf '  %s  изменений: %s\n' "$(basename "${d}")" "$(wc -l < "${d}manifest")"
        done
        echo "Откат: bash ubuntu_hardening.sh --rollback <метка>"
        return 0
    fi
    local dir="${BACKUP_ROOT}/${ROLLBACK_STAMP}" man
    man="${dir}/manifest"
    [[ "${ROLLBACK_STAMP}" =~ ^[0-9_]+$ && -f "${man}" ]] || error "Нет прогона ${ROLLBACK_STAMP} (список: --rollback)"
    echo "Будет восстановлено из ${dir}:"
    sed 's/^/  /' "${man}"
    echo ""
    warn "Не откатываются: пользователи и пароли (в т.ч. блокировка root — passwd root),"
    warn "удалённые пакеты, неизменяемые правила auditd (до reboot), LUKS."
    [[ "${ASSUME_YES}" == "yes" ]] || confirm "Выполнить откат?" || exit 0

    local kind path line restored=0
    while IFS= read -r line; do
        kind="${line%% *}"; path="${line#* }"
        case "${kind}" in
            saved)  if [[ -e "${dir}/files${path}" || -L "${dir}/files${path}" ]]; then
                        mkdir -p "$(dirname "${path}")"
                        rm -f "${path}"
                        cp -a "${dir}/files${path}" "${path}"
                        restored=$(( restored + 1 ))
                    fi ;;
            new)    rm -f "${path}" ;;
            unit-enable)  systemctl enable "${path}" &>/dev/null || warn "Не удалось включить ${path}" ;;
            unit-disable) systemctl disable "${path}" &>/dev/null || true ;;
            statoverride-remove)
                    dpkg-statoverride --remove "${path}" &>/dev/null || true
                    chmod u+s "${path}" 2>/dev/null || true ;;
            *)      warn "Неизвестная запись: ${line}" ;;
        esac
    done < <(tac "${man}")
    info "Восстановлено файлов: ${restored}"

    systemctl daemon-reload || true
    sysctl --system -q || true
    if grep -q "^saved /etc/ssh/sshd_config$" "${man}"; then
        if sshd -t; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
            systemctl is-enabled ssh.socket &>/dev/null && systemctl restart ssh.socket || true
            info "sshd перезапущен со старой конфигурацией"
        else
            warn "Восстановленный sshd_config не проходит sshd -t — sshd НЕ перезапущен"
        fi
    fi
    if grep -q "^saved /etc/ufw/" "${man}"; then
        if grep -qs '^ENABLED=yes' /etc/ufw/ufw.conf; then ufw reload >/dev/null || true
        else ufw --force disable >/dev/null || true; fi
        info "UFW: правила восстановлены"
    fi
    systemctl restart rsyslog chrony fail2ban 2>/dev/null || true
    augenrules --load &>/dev/null || true
    warn "Изменения fstab, модулей и auditd вступят в силу после перезагрузки"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
[[ $EUID -eq 0 ]] || error "Запускайте скрипт от root"

on_err() { echo -e "${RED}[x]${NC} Ошибка на строке $1: $2${RUN_LOG:+ (см. ${RUN_LOG})}"; }
on_exit() {
    local rc=$? h
    set +e
    for h in "${EXIT_HOOKS[@]}"; do "$h"; done
    (( ${#TMP_FILES[@]} )) && rm -f "${TMP_FILES[@]}"
    if (( rc != 0 )) && [[ "${RUN_MODE}" == "harden" && -n "${CURRENT_STEP}" ]]; then
        local s rest="" seen="no"
        for s in "${STEPS_ALL[@]}"; do
            [[ "$s" == "${CURRENT_STEP}" ]] && seen="yes"
            [[ "${seen}" == "yes" ]] && step_enabled "$s" && rest+="${rest:+,}$s"
        done
        echo -e "${RED}[x]${NC} Остановлено на шаге '${CURRENT_STEP}' (${STEP_TITLE[${CURRENT_STEP}]})."
        echo "    После исправления продолжить: bash $0 --only ${rest}"
        echo "    Откатить изменённые файлы:    bash $0 --rollback ${RUN_STAMP}"
    fi
    if [[ -n "${TEE_PID:-}" ]]; then
        exec 1>&- 2>&-
        wait "${TEE_PID}" 2>/dev/null
    fi
    return "${rc}"
}
trap on_exit EXIT
trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR

# luks_run из блока LUKS: ERR-trap внутри подоболочки, без ложного сообщения снаружи
luks_run() {
    local rc
    trap - ERR
    set +e
    ( trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR; set -e; luks_main "$@" )
    rc=$?
    set -e
    trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR
    (( rc == 0 )) || warn "LUKS: режим не завершён (код ${rc}) — харденинг продолжается"
    return 0
}

if [[ "${RUN_MODE}" == "audit" ]]; then
    if run_audit; then exit 0; else exit 1; fi
fi

if [[ "${RUN_MODE}" == "harden" && "${ASSUME_YES}" != "yes" && ! -t 0 ]]; then
    error "Без терминала запускайте с --yes и --config (интерактивный режим требует TTY)"
fi

# ── Лог выполнения ───────────────────────────────────────────────────────────
# Секреты (приватный ключ) пишутся напрямую в /dev/tty и в лог не попадают.
RUN_LOG="/root/hardening_${RUN_MODE}_${RUN_STAMP}.log"
( umask 077; : > "${RUN_LOG}" )
exec > >(tee -a "${RUN_LOG}") 2>&1
TEE_PID=$!
info "ubuntu_hardening.sh ${SCRIPT_VERSION}; лог: ${RUN_LOG}"

if [[ "${RUN_MODE}" == "luks" ]]; then
    luks_main "${LUKS_ARGS[@]}"
    exit 0
fi
if [[ "${RUN_MODE}" == "rollback" ]]; then
    run_rollback
    exit 0
fi

# ── Версия ОС ────────────────────────────────────────────────────────────────
[[ -f /etc/os-release ]] || error "Не удалось определить ОС (/etc/os-release не найден)"
OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)
UBUNTU_VERSION=$(awk -F= '$1=="VERSION_ID"{gsub(/"/,"",$2); print $2}' /etc/os-release)
UBUNTU_VERSION="${UBUNTU_VERSION:-unknown}"

# ── Настройки: умолчания < прошлый прогон < --config < UH_* ──────────────────
load_state_defaults
[[ -n "${CONFIG_FILE}" ]] && load_kv_file "${CONFIG_FILE}"
load_env_overrides
validate_settings
APPLIED_ADMIN_USER="${ADMIN_USER}"
APPLIED_SSH_PORT="${SSH_PORT}"
# Шаги, которые сами не спрашивают порт/пользователя, работают с применёнными значениями
if ! step_enabled ssh && kv_has "${STATE_FILE}" SSH_PORT; then
    SSH_PORT=$(kv_get "${STATE_FILE}" SSH_PORT); APPLIED_SSH_PORT="${SSH_PORT}"
fi
if ! step_enabled user && ! step_enabled key && ! step_enabled ssh && kv_has "${STATE_FILE}" ADMIN_USER; then
    ADMIN_USER=$(kv_get "${STATE_FILE}" ADMIN_USER); APPLIED_ADMIN_USER="${ADMIN_USER}"
fi

if [[ "${OS_ID}" != "ubuntu" ]]; then
    [[ "${ALLOW_UNTESTED_OS}" == "yes" ]] || error "ОС '${OS_ID}' — не Ubuntu. Скрипт рассчитан на Ubuntu (ALLOW_UNTESTED_OS=yes — на свой риск)"
    warn "ОС '${OS_ID}' — не Ubuntu, ALLOW_UNTESTED_OS=yes"
fi
case "${UBUNTU_VERSION}" in
    22.04|24.04|26.04) info "Ubuntu ${UBUNTU_VERSION} — поддерживается" ;;
    *)  warn "Ubuntu ${UBUNTU_VERSION} — не тестировалась (рассчитано на 22.04 / 24.04 / 26.04)"
        if [[ "${ALLOW_UNTESTED_OS}" != "yes" ]]; then
            confirm "Продолжить?" || error "Прервано по версии ОС"
        fi ;;
esac

# ── Первые минуты VPS: дождаться cloud-init (он держит apt и пишет конфиги) ──
if command -v cloud-init &>/dev/null; then
    info "Ожидание завершения cloud-init…"
    timeout 600 cloud-init status --wait &>/dev/null || warn "cloud-init не завершился за 10 мин — продолжаем"
fi

HYPERVISOR=$(systemd-detect-virt 2>/dev/null || echo "unknown")
info "Виртуализация: ${HYPERVISOR}"
TOTAL_RAM_KB=$(awk '/^MemTotal/{print $2}' /proc/meminfo)

# ── Квоты логов: не более 10% свободного места ───────────────────────────────
LOG_PARTITION=$(df --output=target /var/log 2>/dev/null | tail -1)
FREE_KB=$(df -k "${LOG_PARTITION}" | awk 'NR==2{print $4}')
LOG_QUOTA_MB=$(( FREE_KB / 10 / 1024 ))
(( LOG_QUOTA_MB < 50 ))   && LOG_QUOTA_MB=50
(( LOG_QUOTA_MB > 2048 )) && LOG_QUOTA_MB=2048
AUDIT_NUM_LOGS=5
AUDIT_MAX_FILE_MB=$(( LOG_QUOTA_MB / AUDIT_NUM_LOGS ))
(( AUDIT_MAX_FILE_MB < 10 )) && AUDIT_MAX_FILE_MB=10
# audit backlog — буфер в памяти ядра, из объёма RAM
AUDIT_BACKLOG=$(( TOTAL_RAM_KB / 1024 * 8 ))
(( AUDIT_BACKLOG < 8192 ))  && AUDIT_BACKLOG=8192
(( AUDIT_BACKLOG > 65536 )) && AUDIT_BACKLOG=65536
info "Квота логов: ${LOG_QUOTA_MB} МБ (раздел ${LOG_PARTITION}); audit backlog: ${AUDIT_BACKLOG}"

KEY_SOURCE=""; KEY_TYPE="не менялся"; GEN_KEY_TYPE=""
PUBKEYS=(); PUBKEY_BODIES=""
SSH_CHECKPOINT_DONE="no"
[[ "${ASSUME_YES}" == "yes" ]] && info "Режим --yes: вопросы не задаются"
[[ -n "${ONLY_STEPS}" ]] && info "Только шаги: ${ONLY_STEPS}"
[[ -n "${SKIP_STEPS}" ]] && info "Пропуск шагов: ${SKIP_STEPS}"

collect_answers

for _s in "${STEPS_ALL[@]}"; do run_step "${_s}"; done
CURRENT_STEP=""
# Настройки прогона — для --luks, --audit и следующего запуска
if [[ -f "${STATE_FILE}" ]] || id "${APPLIED_ADMIN_USER}" &>/dev/null; then save_state; fi

# ══════════════════════════════════════════════════════════════════════════════
#  ИТОГ
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}+============================================================+${NC}"
echo -e "${GREEN}|                 HARDENING: ИТОГ ПРОГОНА                    |${NC}"
echo -e "${GREEN}+============================================================+${NC}"
# Статус — первым столбцом: printf выравнивает по байтам, а заголовки кириллические
for _s in "${STEPS_ALL[@]}"; do
    case "${STEP_STATUS[${_s}]:-SKIP}" in
        OK)   _st="${GREEN}[OK]  ${NC}" ;;
        WARN) _st="${YELLOW}$(printf '[!%-3s]' "${STEP_WARNS[${_s}]}")${NC}" ;;
        OFF)  _st="[--]  " ;;
        *)    _st="[skip]" ;;
    esac
    echo -e "  ${_st}  ${STEP_TITLE[${_s}]}${STEP_NOTE[${_s}]:+ — ${STEP_NOTE[${_s}]}}"
done
echo ""
echo "  [OK] выполнено  [!N] N предупреждений (см. выше и лог)"
echo "  [--] выключено настройкой  [skip] не выбран (--only/--skip)"
echo ""
echo -e "  ${YELLOW}Лог:${NC} ${RUN_LOG}"
echo -e "  ${YELLOW}Откат файлов:${NC} bash $0 --rollback ${RUN_STAMP}"
echo ""
echo -e "  ${YELLOW}Перезагрузка нужна для:${NC} blacklist модулей, /tmp и /home (если не применились),"
echo "    kexec_load_disabled, неизменяемых правил auditd, hidepid и параметров GRUB"
echo ""
echo -e "  ${CYAN}Подключение:${NC} ssh -p ${APPLIED_SSH_PORT} ${APPLIED_ADMIN_USER}@<IP>"
echo -e "  ${CYAN}Проверка в любой момент:${NC} sudo bash $0 --audit"
echo ""
