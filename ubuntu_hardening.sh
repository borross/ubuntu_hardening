#!/usr/bin/env bash
# =============================================================================
#  Ubuntu Hardening Script — VPS/VDS Edition  (v3.1)
#  Целевая платформа: Ubuntu 22.04 / 24.04 / 26.04 на виртуальном сервере
#  Запускать от root сразу после получения сервера
#
#  Использование:
#    bash ubuntu_hardening.sh                      # полный харденинг (интерактивно)
#    bash ubuntu_hardening.sh --luks <режим> ...   # шифрование LUKS2 (см. --help)
#    bash ubuntu_hardening.sh --help
#
#  Изменения v3 / v3.1:
#    - приватный ключ выводится только на терминал (/dev/tty) и больше
#      не попадает в лог выполнения; можно указать свой публичный ключ
#    - имя администратора спрашивается (по умолчанию admin)
#    - SSH: постквантовый обмен ключами (mlkem768x25519 / sntrup761x25519),
#      список KEX строится из того, что поддерживает установленный OpenSSH;
#      убраны устаревшие Protocol / ChallengeResponseAuthentication;
#      если UFW уже активен — новый порт открывается ДО перезапуска sshd
#    - su действительно ограничен группой sudo (старое регулярное выражение
#      не находило строку "# auth required pam_wheel.so")
#    - политика паролей (enforce_for_root) применяется ДО задания пароля
#    - sudoers проверяется visudo -cf до установки (root уже заблокирован —
#      битый sudoers означал бы потерю доступа)
#    - /home без отдельного раздела: bind-монтирование через fstab вместо
#      remount-home.service, который падал при каждой загрузке
#    - /var/tmp — собственный bind с noexec (остаётся постоянным), /tmp — с size=
#    - AppArmor: массовый aa-enforce убран (ломал профили, намеренно
#      оставленные в complain/unconfined); выводится отчёт
#    - sysctl: rp_filter подбирается по числу интерфейсов, добавлены
#      kexec_load_disabled, unprivileged_bpf_disabled, bpf_jit_harden,
#      ldisc_autoload, accept_source_route
#    - auditd: время, mount, hostname/сеть, PAM, AppArmor, входы в систему;
#      b32-правила для модулей и bind; kmod вместо симлинков /sbin/*
#    - unattended-upgrades: свой файл 52-… с #clear вместо перезаписи 50-…,
#      nginx/apache больше не исключены из security-обновлений, needrestart
#    - chrony: сохранены rtcsync, leapsectz, NTP от провайдера (DHCP)
#    - fail2ban: ignoreip, режим aggressive; /etc/shadow 640 root:shadow
#    - шаг 20: исправлена инструкция (root по SSH к этому моменту запрещён)
#    - новый режим --luks: data / file / swap / remote-unlock / status
#      и необязательная секция 19.5 в полном прогоне
#    - шифрование всего корня: --luks encrypt-root (из rescue-системы,
#      при необходимости создаёт раздел /boot) и --luks encrypt-root-auto
#      (с работающей системы, шифрование при следующей загрузке) + finish
#    - Ubuntu 26.04 (dracut): сетевая разблокировка через Tang/clevis-dracut
#    - --luks docker: данные Docker/containerd на зашифрованном томе
#
#  ВАЖНО для VPS:
#    Убедитесь, что у вас есть доступ к VNC/консоли провайдера
#    на случай потери SSH-доступа во время настройки!
# =============================================================================

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКИ — измените под себя
# ──────────────────────────────────────────────────────────────────────────────
ADMIN_USER="admin"                   # значение по умолчанию, будет переспрошено
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

# AppArmor: yes — перевести ВСЕ профили в enforce (как в v2). Может сломать
# программы, чьи профили дистрибутив намеренно держит в complain.
APPARMOR_ENFORCE_ALL="no"

# Сохранённые параметры прогона (используются режимом --luks)
STATE_FILE="/etc/ubuntu_hardening.conf"

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

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}===================================================${NC}";
            echo -e "${CYAN}  $*${NC}";
            echo -e "${CYAN}===================================================${NC}"; }

usage() {
    cat << 'EOF'
Использование:
  bash ubuntu_hardening.sh                    полный харденинг (интерактивно)
  bash ubuntu_hardening.sh --luks <режим> [аргументы] [опции]

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

# ── Разбор аргументов ─────────────────────────────────────────────────────────
RUN_MODE="harden"
LUKS_ARGS=()
while (( $# )); do
    case "$1" in
        --luks)    RUN_MODE="luks"; shift; LUKS_ARGS=("$@"); break ;;
        -h|--help) usage; exit 0 ;;
        *)         echo "Неизвестный аргумент: $1"; echo; usage; exit 1 ;;
    esac
done

# ──────────────────────────────────────────────────────────────────────────────
# LUKS — функции режима --luks (и секции 19.5 полного прогона)
# ──────────────────────────────────────────────────────────────────────────────

ensure_pkgs() {
    local missing=()
    for p in "$@"; do dpkg -s "$p" &>/dev/null || missing+=("$p"); done
    if (( ${#missing[@]} )); then
        info "Установка пакетов: ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
    fi
}

confirm() {   # confirm "вопрос" -> 0 если y
    local ans
    read -r -p "$1 [y/N]: " ans
    [[ "${ans}" =~ ^[Yy]$ ]]
}

backup_file() {
    mkdir -p "${LUKS_BACKUP_DIR}"; chmod 700 "${LUKS_BACKUP_DIR}"
    [[ -f "$1" ]] && cp -a "$1" "${LUKS_BACKUP_DIR}/$(basename "$1").${LUKS_STAMP}"
    return 0
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

    trap 'luks_chroot_umount' EXIT

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

    trap - EXIT
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

# Запуск режима в подоболочке: ошибка внутри не обрывает полный прогон,
# а set -e продолжает действовать (в контексте || он бы отключился)
luks_run() {
    local rc
    set +e
    ( set -e; luks_main "$@" )
    rc=$?
    set -e
    (( rc == 0 )) || warn "LUKS: режим не завершён (код ${rc}) — харденинг продолжается"
    return 0
}

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

# ──────────────────────────────────────────────────────────────────────────────
# 0. Предстартовые проверки
# ──────────────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запускайте скрипт от root"
if [[ "${RUN_MODE}" == "harden" && ! -t 0 ]]; then
    error "Полный прогон интерактивный — запускайте в терминале (не через пайп)"
fi

# ── Лог выполнения: весь вывод дублируется в файл ─────────────────────────────
# Секреты (приватный ключ) пишутся напрямую в /dev/tty и в лог не попадают.
RUN_LOG="/root/hardening_${RUN_MODE}_$(date +%Y%m%d_%H%M%S).log"
( umask 077; : > "${RUN_LOG}" )
exec > >(tee -a "${RUN_LOG}") 2>&1
info "Лог выполнения: ${RUN_LOG}"

# ── Trap: при аварийном завершении показываем строку ──────────────────────────
trap 'echo -e "${RED}[x]${NC} Скрипт аварийно остановлен на строке ${LINENO} (см. ${RUN_LOG})"' ERR

# ── Режим --luks: только шифрование, без харденинга ──────────────────────────
if [[ "${RUN_MODE}" == "luks" ]]; then
    luks_main "${LUKS_ARGS[@]}"
    exit 0
fi

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

# ── Имя администратора ────────────────────────────────────────────────────────
# "admin" — одно из первых имён в словарях перебора; к тому же в sudoers
# Ubuntu по историческим причинам есть строка "%admin ALL=(ALL) ALL"
echo ""
echo -e "  Имя пользователя-администратора по умолчанию: ${YELLOW}${ADMIN_USER}${NC}"
echo "  Рекомендуется неочевидное имя (не admin/administrator/ubuntu/user)."
echo "  (Enter — оставить ${ADMIN_USER})"
while true; do
    read -r -p "  Имя администратора: " _admin_name
    if [[ -z "${_admin_name}" ]]; then
        break
    elif [[ "${_admin_name}" =~ ^[a-z_][a-z0-9_-]{0,30}$ && "${_admin_name}" != "root" ]]; then
        ADMIN_USER="${_admin_name}"
        break
    else
        echo -e "  ${RED}Некорректное имя.${NC} Строчные латинские буквы, цифры, _ и -, начинается с буквы."
    fi
done
info "Администратор: ${ADMIN_USER}"

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
# Лучший вариант — свой ключ: приватная часть никогда не появляется на сервере.
echo -e "  SSH-ключ для ${ADMIN_USER}:"
echo -e "    1) ${GREEN}сгенерировать ed25519${NC} — современный, быстрый"
echo "    2) сгенерировать ecdsa-521 — NIST P-521 (совместимость со старыми требованиями)"
echo -e "    3) ${GREEN}вставить свой публичный ключ${NC} — рекомендуется (ssh-keygen -t ed25519 у себя)"
echo "  (Enter — 1)"
KEY_TYPE="ed25519"
KEY_SOURCE="generated"
USER_PUBKEY=""
while true; do
    read -r -p "  Выбор [1/2/3]: " _key_choice
    case "${_key_choice}" in
        ""|1) KEY_TYPE="ed25519";   break ;;
        2)    KEY_TYPE="ecdsa-521"; break ;;
        3)    read -r -p "  Вставьте строку публичного ключа (ssh-ed25519 AAAA... comment): " USER_PUBKEY
              _pk_tmp=$(mktemp)
              printf '%s\n' "${USER_PUBKEY}" > "${_pk_tmp}"
              if [[ "${USER_PUBKEY}" =~ ^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa)\  ]] \
                 && _pk_fp=$(ssh-keygen -l -f "${_pk_tmp}" 2>/dev/null); then
                  rm -f "${_pk_tmp}"
                  if [[ "${USER_PUBKEY}" == ssh-rsa* ]] && (( $(awk '{print $1}' <<< "${_pk_fp}") < 3072 )); then
                      echo -e "  ${RED}RSA короче 3072 бит не принимается.${NC}"
                      continue
                  fi
                  KEY_SOURCE="provided"
                  KEY_TYPE="свой ($(awk '{print $NF}' <<< "${_pk_fp}"))"
                  info "Ключ принят: ${_pk_fp}"
                  break
              fi
              rm -f "${_pk_tmp}"
              echo -e "  ${RED}Это не похоже на корректный публичный ключ OpenSSH.${NC}" ;;
        *)    echo -e "  ${RED}Введите 1, 2 или 3.${NC}" ;;
    esac
done
info "SSH-ключ: ${KEY_TYPE}"
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
    acl curl wget gnupg2 chrony rsyslog needrestart
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

[[ -f /etc/chrony/chrony.conf ]] && cp /etc/chrony/chrony.conf "/etc/chrony/chrony.conf.bak.$(date +%Y%m%d%H%M%S)"
mkdir -p /etc/chrony/conf.d /etc/chrony/sources.d
cat > /etc/chrony/chrony.conf << EOF
# Сгенерировано ubuntu_hardening.sh
${NTP_LINES}

# Дополнительные конфиги и источники (в т.ч. NTP провайдера, полученные по DHCP)
confdir /etc/chrony/conf.d
sourcedir /run/chrony-dhcp
sourcedir /etc/chrony/sources.d

# Drift-файл: хранит погрешность часов между перезапусками
driftfile /var/lib/chrony/drift
# Кэш NTS-cookie (time.cloudflare.com nts) — быстрее старт после перезагрузки
ntsdumpdir /var/lib/chrony
keyfile /etc/chrony/chrony.keys

# Корректная обработка високосной секунды и синхронизация RTC ядром
leapsectz right/UTC
rtcsync

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
# 2. SSH-ключ администратора
# ──────────────────────────────────────────────────────────────────────────────
section "2. SSH-ключ администратора (${KEY_TYPE})"

if [[ "${KEY_SOURCE}" == "provided" ]]; then
    # Приватная часть ключа на сервере не появляется вообще
    rm -f "${KEY_PATH}"
    printf '%s\n' "${USER_PUBKEY}" > "${KEY_PATH}.pub"
    chmod 644 "${KEY_PATH}.pub"
    info "Используется ваш публичный ключ (${KEY_PATH}.pub)"
else
    rm -f "${KEY_PATH}" "${KEY_PATH}.pub"

    echo ""
    echo -e "${YELLOW}Придумайте надёжный пароль для приватного ключа.${NC}"
    echo -e "${YELLOW}Он будет запрашиваться при каждом подключении по SSH.${NC}"
    echo ""
    if [[ "${KEY_TYPE}" == "ed25519" ]]; then
        ssh-keygen -t ed25519 -a 100 \
                   -f "${KEY_PATH}" \
                   -C "${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"
    else
        ssh-keygen -t ecdsa -b 521 -a 100 \
                   -f "${KEY_PATH}" \
                   -C "${ADMIN_USER}@$(hostname)-$(date +%Y%m%d)"
    fi

    chmod 600 "${KEY_PATH}"
    chmod 644 "${KEY_PATH}.pub"

    info "Ключевая пара создана:"
    info "  Приватный ключ : ${KEY_PATH}"
    info "  Публичный ключ : ${KEY_PATH}.pub"

    echo ""
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo -e "${YELLOW}|  СКАЧАЙТЕ ПРИВАТНЫЙ КЛЮЧ СЕЙЧАС!                           |${NC}"
    echo -e "${YELLOW}|                                                            |${NC}"
    echo -e "${YELLOW}|  С другого терминала (root по SSH пока разрешён):          |${NC}"
    echo -e "${YELLOW}|  scp root@<IP>:${KEY_PATH} ./admin_ssh_key${NC}"
    echo -e "${YELLOW}|                                                            |${NC}"
    echo -e "${YELLOW}|  Или скопируйте текст ниже — он выводится только на экран  |${NC}"
    echo -e "${YELLOW}|  и НЕ записывается в лог выполнения.                       |${NC}"
    echo -e "${YELLOW}+------------------------------------------------------------+${NC}"
    echo ""
    # Ключ — мимо tee: в лог /root/hardening_*.log он попасть не должен
    sleep 0.3   # дать tee вывести рамку выше, чтобы порядок на экране не сбился
    {
        echo "--- ПРИВАТНЫЙ КЛЮЧ (сохраните в безопасное место) ---"
        cat "${KEY_PATH}"
        echo "------------------------------------------------------"
    } > /dev/tty
    echo ""
    echo "--- ПУБЛИЧНЫЙ КЛЮЧ ---"
    cat "${KEY_PATH}.pub"
    echo "----------------------"
    echo ""

    read -r -p "Нажмите Enter, когда сохраните приватный ключ..."
fi

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

# ИСПРАВЛЕНО: политика паролей применяется ДО задания пароля (раньше
# секция 16 шла после passwd и на пароль администратора не влияла).
# enforce_for_root обязателен: passwd запускается от root, а для root
# pwquality по умолчанию только предупреждает и принимает слабый пароль.
cat > /etc/security/pwquality.conf << 'EOF'
# Сгенерировано ubuntu_hardening.sh
minlen = 16
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
dictcheck = 1
usercheck = 1
gecoscheck = 1
enforce_for_root
retry = 3
EOF
info "Политика паролей: минимум 16 символов, все классы символов"

# passwd в цикле: 3 ошибки ввода возвращают ≠0 и при set -e
# раньше роняли весь скрипт на середине
warn "Задайте пароль для ${ADMIN_USER} (нужен только для sudo, не для SSH):"
until passwd "${ADMIN_USER}"; do
    warn "Пароль не задан (несовпадение или слабый) — попробуйте ещё раз"
done

SSH_DIR="/home/${ADMIN_USER}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"
mkdir -p "${SSH_DIR}"
touch "${AUTH_KEYS}"
# Ключ прошлого прогона этого скрипта больше не нужен — убираем его
# (ключи, добавленные вручную, не трогаем)
if [[ -f "${STATE_FILE}" ]]; then
    _old_pub=$(awk -F= '$1=="PUBKEY_BODY"{print $2}' "${STATE_FILE}")
    if [[ -n "${_old_pub}" ]]; then
        grep -vF -- "${_old_pub}" "${AUTH_KEYS}" > "${AUTH_KEYS}.tmp" || true
        mv "${AUTH_KEYS}.tmp" "${AUTH_KEYS}"
    fi
fi
cat "${KEY_PATH}.pub" >> "${AUTH_KEYS}"
sort -u "${AUTH_KEYS}" -o "${AUTH_KEYS}"
chown -R "${ADMIN_USER}:$(id -gn "${ADMIN_USER}")" "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chmod 600 "${AUTH_KEYS}"
info "Публичный ключ установлен для ${ADMIN_USER}"

# Параметры прогона — для режима --luks и следующего запуска
cat > "${STATE_FILE}" << EOF
# ubuntu_hardening.sh — параметры последнего прогона
ADMIN_USER=${ADMIN_USER}
SSH_PORT=${SSH_PORT}
PUBKEY_BODY=$(awk '{print $2}' "${KEY_PATH}.pub")
EOF
chmod 600 "${STATE_FILE}"

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

# ── KEX: постквантовые гибриды первыми, только то, что знает этот OpenSSH ────
# ИСПРАВЛЕНО: v2 оставляла лишь curve25519/nistp521 и тем самым ОТКЛЮЧАЛА
# постквантовый обмен ключами, включённый в OpenSSH по умолчанию
# (sntrup761x25519 с 9.0, mlkem768x25519 с 9.9; 24.04 = 9.6, 26.04 = 10.x).
# Защищает записанный сегодня трафик от расшифровки в будущем.
SUPPORTED_KEX=$(ssh -Q kex 2>/dev/null || true)
KEX_LIST=""
for _kex in mlkem768x25519-sha256 \
            sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
            curve25519-sha256 curve25519-sha256@libssh.org \
            ecdh-sha2-nistp521; do
    if grep -qx "${_kex}" <<< "${SUPPORTED_KEX}"; then
        KEX_LIST+="${KEX_LIST:+,}${_kex}"
    fi
done
[[ -n "${KEX_LIST}" ]] || KEX_LIST="curve25519-sha256,curve25519-sha256@libssh.org"
info "SSH KEX: ${KEX_LIST}"

SSHD_TMP=$(mktemp /etc/ssh/sshd_config.XXXXXX)
cat > "${SSHD_TMP}" << EOF
# Generated by ubuntu_hardening.sh (VPS edition, v3)
# sshd берёт ПЕРВОЕ встреченное значение директивы, поэтому наши настройки
# стоят выше Include и не перебиваются drop-in файлами (cloud-init и т.п.).

# Порт и адреса
Port ${SSH_PORT}
# any = IPv4+IPv6; inet = только IPv4 (настраивается переменной в скрипте)
AddressFamily ${SSH_ADDRESS_FAMILY}

# Криптография — только современные алгоритмы
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
KexAlgorithms ${KEX_LIST}
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Аутентификация
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
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

# Drop-in файлы — В КОНЦЕ: добавляют только то, что не задано выше
Include /etc/ssh/sshd_config.d/*.conf
EOF

# Port и ListenAddress, в отличие от остальных директив, НАКАПЛИВАЮТСЯ —
# drop-in с ними открыл бы второй порт. Такие drop-in убираем.
if [[ -d /etc/ssh/sshd_config.d ]]; then
    if grep -rqsE "^\s*(Port|ListenAddress)\s" /etc/ssh/sshd_config.d/ 2>/dev/null; then
        mkdir -p /root/sshd_config.d.bak
        grep -rlsE "^\s*(Port|ListenAddress)\s" /etc/ssh/sshd_config.d/ | while read -r f; do
            mv "$f" /root/sshd_config.d.bak/
            warn "Drop-in с Port/ListenAddress перемещён в /root/sshd_config.d.bak: $(basename "$f")"
        done
    fi
fi

# ИСПРАВЛЕНО: проверяем конфиг ДО установки — раньше битый файл оставался
# на месте, и следующий рестарт sshd (например, при обновлении) ронял SSH
mkdir -p /run/sshd
if sshd -t -f "${SSHD_TMP}"; then
    chmod 600 "${SSHD_TMP}"
    mv "${SSHD_TMP}" /etc/ssh/sshd_config
    info "sshd_config прошёл валидацию и установлен"
else
    rm -f "${SSHD_TMP}"
    error "Ошибка в сгенерированном sshd_config — текущая конфигурация не тронута"
fi

# Итоговая (эффективная) конфигурация: порт ровно один, пароли выключены
SSHD_EFFECTIVE=$(sshd -T 2>/dev/null || true)
_ports=$(awk '$1=="port"{print $2}' <<< "${SSHD_EFFECTIVE}" | sort -u | tr '\n' ' ')
[[ "${_ports}" == "${SSH_PORT} " ]] || warn "sshd слушает порты: ${_ports}— ожидался только ${SSH_PORT}"
grep -qx "passwordauthentication no" <<< "${SSHD_EFFECTIVE}" \
    || error "PasswordAuthentication не выключен в итоговой конфигурации sshd"

# Если UFW уже включён (бывает в образах провайдеров) — открываем новый порт
# ДО перезапуска sshd, иначе контрольная точка входа не пройдёт
if ufw status 2>/dev/null | grep -q "^Status: active"; then
    ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited" >/dev/null
    info "UFW активен — порт ${SSH_PORT}/tcp открыт заранее"
fi

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
# ИСПРАВЛЕНО: в Ubuntu строка выглядит как "# auth       required   pam_wheel.so"
# (пробел после #). Старый grep "^#auth" её не находил, а проверка
# "pam_wheel.so есть в файле" срабатывала на ЗАКОММЕНТИРОВАННУЮ строку —
# в итоге su не ограничивался вообще. Без group=sudo pam_wheel проверял бы
# группу root, а не sudo.
PAM_SU=/etc/pam.d/su
if [[ -f "${PAM_SU}" ]]; then
    cp "${PAM_SU}" "${PAM_SU}.bak.$(date +%Y%m%d%H%M%S)"
    if grep -qE '^\s*auth\s+required\s+pam_wheel\.so' "${PAM_SU}"; then
        # уже активна — гарантируем group=sudo
        grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' "${PAM_SU}" \
            || sed -i -E 's/^(\s*auth\s+required\s+pam_wheel\.so)(.*)$/\1\2 group=sudo/' "${PAM_SU}"
    elif grep -qE '^#\s*auth\s+required\s+pam_wheel\.so\s*$' "${PAM_SU}"; then
        sed -i -E 's/^#\s*auth\s+required\s+pam_wheel\.so\s*$/auth       required   pam_wheel.so group=sudo/' "${PAM_SU}"
    else
        # строки нет вовсе — вставляем перед @include common-auth
        sed -i '0,/^@include common-auth/s//auth       required   pam_wheel.so group=sudo\n&/' "${PAM_SU}"
    fi
    if grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' "${PAM_SU}"; then
        info "su ограничен группой sudo"
    else
        warn "Не удалось включить pam_wheel в ${PAM_SU} — проверьте вручную"
    fi
fi

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
echo "  Слушающие UDP-порты:"
ss -ulnp 2>/dev/null | awk 'NR>1 {print "    " $4 "  " $NF}' | sort -u || true
echo ""
echo "  UFW закроет ВСЁ входящее, кроме SSH:${SSH_PORT}."
echo "  Если нужны другие порты — перечислите через пробел."
echo "  Формат: 80 443 (TCP)  или  443/udp 51820/udp  или  8000:8100/tcp"
echo "  (Enter — открыть только SSH)"
read -r -p "  Дополнительные порты: " EXTRA_PORTS

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# limit = встроенный rate-limit UFW: 6 попыток за 30 сек -> блок
ufw limit "${SSH_PORT}/tcp" comment "SSH rate-limited"

if [[ -n "${EXTRA_PORTS:-}" ]]; then
    for p in ${EXTRA_PORTS}; do
        if [[ "${p}" =~ ^([0-9]+)(:([0-9]+))?(/(tcp|udp))?$ ]] \
           && (( BASH_REMATCH[1] >= 1 && BASH_REMATCH[1] <= 65535 )) \
           && (( ${BASH_REMATCH[3]:-1} >= 1 && ${BASH_REMATCH[3]:-1} <= 65535 )); then
            _rule="${p}"
            # диапазон требует явного протокола; одиночный порт без него — TCP
            [[ "${p}" == */* ]] || _rule="${p}/tcp"
            ufw allow "${_rule}" comment "user-defined" || { warn "UFW отклонил правило ${_rule}"; continue; }
            info "UFW: открыт ${_rule}"
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
# Свои адреса не баним; добавьте сюда IP своего офиса/VPN через пробел
ignoreip  = 127.0.0.1/8 ::1

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

# Заменяет запись с точкой монтирования $1 (поле 2) на $2; комментарии не трогает.
# (v2 удаляла по подстроке — это было хрупко)
fstab_set() {
    local mountpoint="$1"
    local entry="$2"
    awk -v mp="${mountpoint}" '/^[[:space:]]*#/ || $2 != mp' "${FSTAB}" > "${FSTAB}.tmp"
    echo "${entry}" >> "${FSTAB}.tmp"
    mv "${FSTAB}.tmp" "${FSTAB}"
    info "fstab: ${mountpoint} настроен"
}

# /tmp в RAM — с ограничением размера: без size= tmpfs может занять до 50% RAM,
# и любой пользователь, заполнив /tmp, выдавит из памяти сервисы
TMP_SIZE_MB=$(( TOTAL_RAM_KB / 1024 / 4 ))
(( TMP_SIZE_MB < 256  )) && TMP_SIZE_MB=256
(( TMP_SIZE_MB > 2048 )) && TMP_SIZE_MB=2048
fstab_set "/tmp" \
    "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,mode=1777,size=${TMP_SIZE_MB}m 0 0"
info "  /tmp: tmpfs ${TMP_SIZE_MB} МБ"

# /dev/shm  (seclabel убрана — только для SELinux, Ubuntu использует AppArmor)
fstab_set "/dev/shm" \
    "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0"

# ИСПРАВЛЕНО: v2 привязывала /var/tmp к tmpfs /tmp, и он очищался при каждой
# перезагрузке — а /var/tmp по FHS обязан переживать reboot (на это рассчитывают
# systemd, редакторы, установщики). Теперь /var/tmp привязан сам к себе с теми
# же защитными флагами. Старая запись "/tmp /var/tmp none bind" заменяется.
fstab_set "/var/tmp" \
    "/var/tmp /var/tmp none bind,nosuid,nodev,noexec 0 0"

# Применяем без перезагрузки
mount -o remount /tmp     2>/dev/null && info "  /tmp перемонтирован"     || warn "/tmp: применится после reboot"
mount -o remount /dev/shm 2>/dev/null && info "  /dev/shm перемонтирован" || warn "/dev/shm: применится после reboot"
if mountpoint -q /var/tmp; then
    warn "/var/tmp уже смонтирован (возможно, старый bind на /tmp) — новая схема после reboot"
elif mount /var/tmp 2>/dev/null; then
    info "  /var/tmp смонтирован (bind на себя, noexec)"
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

# /home — на VPS чаще не отдельный раздел.
# ВНИМАНИЕ: noexec на /home запрещает запуск ~/bin, ~/.local/bin и т.п.
if awk '!/^[[:space:]]*#/ && $2=="/home" && $3!="none"' "${FSTAB}" | grep -q .; then
    # Отдельный раздел: добавляем недостающие опции (повторный запуск не дублирует)
    awk 'BEGIN{OFS="\t"}
         !/^[[:space:]]*#/ && $2=="/home" {
             n=split("nosuid,nodev,noexec", add, ",")
             for (i=1; i<=n; i++) if ($4 !~ "(^|,)" add[i] "(,|$)") $4=$4 "," add[i]
         } {print}' "${FSTAB}" > "${FSTAB}.tmp" && mv "${FSTAB}.tmp" "${FSTAB}"
    mount -o remount /home 2>/dev/null || warn "/home: применится после reboot"
    info "fstab: /home защищён (отдельный раздел)"
else
    # ИСПРАВЛЕНО: v2 ставила remount-home.service с "mount -o remount /home",
    # но /home не точка монтирования — команда падала при каждой загрузке.
    # Правильно: bind-монтирование каталога на себя с нужными флагами.
    if [[ -f /etc/systemd/system/remount-home.service ]]; then
        systemctl disable remount-home.service 2>/dev/null || true
        rm -f /etc/systemd/system/remount-home.service
        info "Удалён неработающий remount-home.service (v2)"
    fi
    fstab_set "/home" "/home /home none bind,nosuid,nodev,noexec 0 0"
    systemctl daemon-reload
    if mountpoint -q /home; then
        mount -o remount,bind,nosuid,nodev,noexec /home 2>/dev/null \
            || warn "/home: применится после reboot"
    elif mount /home 2>/dev/null; then
        info "  /home смонтирован (bind на себя, noexec,nosuid,nodev)"
    else
        warn "/home: применится после reboot"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# 10. Kernel / sysctl hardening
# ──────────────────────────────────────────────────────────────────────────────
section "10. Параметры ядра (sysctl)"

# rp_filter: строгий режим (1) ломает асимметричную маршрутизацию — типичный
# случай VPS с публичным интерфейсом и приватной сетью провайдера.
# Несколько интерфейсов -> свободный режим (2): защита от спуфинга остаётся.
IFACE_COUNT=$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2}' \
              | grep -cvE '^(docker|br-|veth|virbr|tun|tap|wg)' || true)
RP_FILTER=1
(( IFACE_COUNT > 1 )) && RP_FILTER=2
info "Сетевых интерфейсов: ${IFACE_COUNT} -> rp_filter=${RP_FILTER}"

cat > /etc/sysctl.d/99-hardening.conf << EOF
# ============================================================
#  Сетевая безопасность
# ============================================================

# Обратная проверка пути (анти-спуфинг): 1 = строго, 2 = свободно (multi-NIC)
net.ipv4.conf.all.rp_filter = ${RP_FILTER}
net.ipv4.conf.default.rp_filter = ${RP_FILTER}

# Не принимать пакеты с маршрутом источника
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# VPS — не роутер, отключить форвардинг
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Защита от SYN-flood
net.ipv4.tcp_syncookies = 1
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

# Запрет kexec: нельзя подменить ядро без перезагрузки (необратимо до reboot)
kernel.kexec_load_disabled = 1

# eBPF: только для root + усиление JIT (меньше поверхность для эксплойтов ядра)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Не подгружать TTY line discipline по запросу пользователя (класс CVE в n_hdlc и др.)
dev.tty.ldisc_autoload = 0

# userfaultfd только для привилегированных (используется в эксплойтах гонок)
vm.unprivileged_userfaultfd = 0
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

sysctl --system -q || warn "sysctl: часть параметров не применилась (например, IPv6 отключён) — см. вывод выше"
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
# v3: добавлены время, mount, hostname/сеть, PAM, AppArmor, входы в систему;
#     b32 для модулей и bind; вместо -w /sbin/insmod (это симлинки, exec
#     через них не ловится) — наблюдение за самим /usr/bin/kmod.
#     -i: не прерывать загрузку правил, если какого-то syscall/пути нет
#     в этой версии ядра или ОС (например, b32 без IA32-эмуляции).
cat > /etc/audit/rules.d/99-hardening.rules << EOF
-D
-i
# backlog рассчитан из RAM: ${AUDIT_BACKLOG} записей
-b ${AUDIT_BACKLOG}
# Режим сбоя 1 = писать в syslog (не 2/паника — VPS без физического доступа!)
-f 1

# Идентификация
-w /etc/passwd    -p wa -k identity
-w /etc/shadow    -p wa -k identity
-w /etc/group     -p wa -k identity
-w /etc/gshadow   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers   -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# PAM и политики входа
-w /etc/pam.d/        -p wa -k pam
-w /etc/security/     -p wa -k pam
-w /etc/login.defs    -p wa -k pam

# SSH
-w /etc/ssh/sshd_config          -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/       -p wa -k sshd_config
-w /home/${ADMIN_USER}/.ssh/     -p wa -k ssh_keys
-w /root/.ssh/                   -p wa -k ssh_keys

# Входы в систему и сессии
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

# systemd-юниты и автозагрузка (типичное место закрепления)
-w /etc/systemd/system/       -p wa -k systemd

-w /etc/ld.so.preload         -p wa -k preload
-w /etc/ld.so.conf.d/         -p wa -k preload

# Изменение времени (auid-фильтр отсекает chronyd, который крутит часы постоянно)
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

# Управление привилегиями (b64 + b32 — иначе 32-битные вызовы не аудируются)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat           -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown    -F auid>=1000 -F auid!=unset -k file_perm
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid -F auid>=1000 -F auid!=unset -k priv_esc
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k priv_exec

# Неудачные попытки доступа к файлам (признак разведки)
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=unset -k access

# Модули ядра
-w /usr/bin/kmod   -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k kernel_modules

# Сеть: только bind реальных пользователей (новый слушающий сокет — редкое
# и значимое событие). socket/connect НЕ аудируем — источник backlog exceeded.
-a always,exit -F arch=b64 -S bind -F auid>=1000 -F auid!=unset -k net_bind
-a always,exit -F arch=b32 -S bind -F auid>=1000 -F auid!=unset -k net_bind

# Загрузчик и ядро
-w /boot/ -p wa -k boot
-a always,exit -F arch=b64 -S kexec_load,kexec_file_load -k kexec

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

# ИСПРАВЛЕНО: v2 переводила в enforce ВСЕ файлы /etc/apparmor.d. Но часть
# профилей дистрибутив держит в complain или flags=(unconfined) намеренно
# (на 24.04 — десятки профилей для userns), принудительный enforce ломал
# эти программы. Теперь — отчёт и, по желанию, enforce для complain-профилей.
if aa-status --enabled 2>/dev/null; then
    _aa_enf=$(aa-status --profiled 2>/dev/null || echo "?")
    _aa_cmp=$(aa-status --complaining 2>/dev/null || echo "?")
    info "AppArmor активен: профилей загружено ${_aa_enf}, в режиме complain ${_aa_cmp}"
    if [[ "${APPARMOR_ENFORCE_ALL}" == "yes" ]]; then
        # Только профили, которые сейчас в complain, и не помеченные unconfined
        grep -lE 'flags=\([^)]*complain' /etc/apparmor.d/* 2>/dev/null \
            | xargs -r grep -LE 'flags=\([^)]*unconfined' \
            | while read -r profile; do
                  aa-enforce "${profile}" &>/dev/null \
                      && info "  enforce: $(basename "${profile}")" \
                      || warn "  не удалось: $(basename "${profile}")"
              done
    elif [[ "${_aa_cmp}" != "0" && "${_aa_cmp}" != "?" ]]; then
        info "  Профили в complain: aa-status | sed -n '/complain mode/,/^[0-9]/p'"
        info "  Перевести выборочно: aa-enforce /etc/apparmor.d/<профиль>"
    fi
else
    warn "AppArmor не активен (проверьте параметры ядра apparmor=1 security=apparmor)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 15. sudo hardening
# ──────────────────────────────────────────────────────────────────────────────
section "15. Настройка sudo"

# Ubuntu 25.10+ / 26.04: по умолчанию sudo-rs. Он поддерживает не все Defaults —
# используем только общие для sudo и sudo-rs.
if sudo --version 2>/dev/null | head -1 | grep -qi "sudo-rs"; then
    info "Обнаружен sudo-rs"
fi

# ИСПРАВЛЕНО: root к этому моменту заблокирован, а битый файл в sudoers.d
# ломает sudo целиком — это полная потеря доступа (только VNC + recovery).
# Поэтому файл сначала проверяется отдельно и только потом устанавливается.
SUDOERS_TMP=$(mktemp)
cat > "${SUDOERS_TMP}" << 'EOF'
# Тайм-аут sudo-сессии — 5 минут
Defaults    timestamp_timeout=5
# Команды в отдельном псевдотерминале: фоновый процесс не перехватит ввод
Defaults    use_pty
# Фиксированный безопасный PATH — защита от подмены системных утилит
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 "${SUDOERS_TMP}"
if visudo -c -f "${SUDOERS_TMP}" &>/dev/null; then
    mv "${SUDOERS_TMP}" /etc/sudoers.d/99-hardening
    chown root:root /etc/sudoers.d/99-hardening
    if visudo -c &>/dev/null; then
        info "sudo: конфигурация корректна"
    else
        rm -f /etc/sudoers.d/99-hardening
        warn "sudoers в целом не прошёл проверку — наш файл убран, проверьте: visudo -c"
    fi
else
    rm -f "${SUDOERS_TMP}"
    warn "Настройки sudo не прошли проверку visudo — НЕ установлены (sudo работает как раньше)"
fi

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

info "sudo настроен: тайм-аут 5 мин, use_pty, secure_path, лог -> /var/log/sudo.log"

# ──────────────────────────────────────────────────────────────────────────────
# 16. Политика паролей (PAM / pwquality)
# ──────────────────────────────────────────────────────────────────────────────
section "16. Политика паролей"

# Конфигурация pwquality записана в секции 3 — ДО задания пароля администратора
if grep -q "^enforce_for_root" /etc/security/pwquality.conf 2>/dev/null; then
    info "Политика паролей активна: минимум 16 символов, все классы, enforce_for_root"
else
    warn "/etc/security/pwquality.conf изменён вручную — проверьте политику"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 17. Права на системные файлы
# ──────────────────────────────────────────────────────────────────────────────
section "17. Права на системные файлы"

# 640 root:shadow (как в Ubuntu и CIS): при 600 setgid-утилита unix_chkpwd
# не может проверять пароли для непривилегированных процессов
chown root:shadow /etc/shadow /etc/gshadow
chmod 640 /etc/shadow /etc/gshadow
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

# motd-news и рекламные apt-news ходят на серверы Canonical при каждом входе
if [[ -f /etc/default/motd-news ]]; then
    sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
    systemctl disable --now motd-news.timer 2>/dev/null || true
fi
command -v pro &>/dev/null && pro config set apt_news=false &>/dev/null || true

info "Телеметрия удалена"

# ──────────────────────────────────────────────────────────────────────────────
# 19. Автоматические security-обновления
# ──────────────────────────────────────────────────────────────────────────────
section "19. Автоматические security-обновления"

# ИСПРАВЛЕНО: v2 перезаписывала 50unattended-upgrades (файл пакета) — при
# обновлении пакета новые умолчания терялись. Теперь свой файл 52-…, а #clear
# заменяет списки целиком (без него apt ДОПИСАЛ бы наши значения к умолчаниям).
# nginx/apache больше не исключены: это самые открытые наружу сервисы, их
# security-исправления важнее короткого перезапуска.
cat > /etc/apt/apt.conf.d/52unattended-upgrades-hardening << 'EOF'
// ubuntu_hardening.sh — переопределяет 50unattended-upgrades
#clear Unattended-Upgrade::Allowed-Origins;
Unattended-Upgrade::Allowed-Origins {
    // Security-патчи
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
    // Стабильные обновления (bugfix, не только security)
    "${distro_id}:${distro_codename}-updates";
};

// Сервисы с данными / оркестрация — вручную, чтобы контролировать даунтайм
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

// На VPS не включаем авто-reboot — делайте сами в удобное время
// (необходимость видна по файлу /var/run/reboot-required)
Unattended-Upgrade::Automatic-Reboot "false";

// Писать письмо root только при ошибках (нужен MTA, иначе см. журнал:
// /var/log/unattended-upgrades/)
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
EOF

# Если v2 перезаписала файл пакета — 52-… всё равно имеет приоритет (#clear)
if grep -q "Разрешённые источники обновлений" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
    info "50unattended-upgrades был изменён v2 — переопределён файлом 52-…"
fi

# needrestart: после обновления библиотек автоматически перезапускать сервисы,
# иначе уязвимая версия остаётся загруженной в память до перезагрузки
if [[ -d /etc/needrestart ]]; then
    mkdir -p /etc/needrestart/conf.d
    cat > /etc/needrestart/conf.d/50-hardening.conf << 'EOF'
# ubuntu_hardening.sh: перезапускать сервисы автоматически
$nrconf{restart} = 'a';
EOF
    info "needrestart: автоматический перезапуск сервисов после обновлений"
fi

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
info "  Вручную: docker, containerd, kube, СУБД (nginx/apache обновляются)"
info "  Письмо root: только при ошибках"

echo ""
systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager 2>/dev/null \
    | sed 's/^/  /' || true

# ──────────────────────────────────────────────────────────────────────────────
# 19.5 Шифрование LUKS (необязательно)
#      До шага 20: для SSH-разблокировки нужны authorized_keys администратора.
#      То же самое позже: bash ubuntu_hardening.sh --luks <режим>
# ──────────────────────────────────────────────────────────────────────────────
section "19.5 Шифрование LUKS (необязательно)"
LUKS_DONE="пропущено"
luks_menu
grep -qsE '^[^#[:space:]]' /etc/crypttab && LUKS_DONE="настроено (см. --luks status)"

# ──────────────────────────────────────────────────────────────────────────────
# 20. Удаление приватного ключа с сервера
# ──────────────────────────────────────────────────────────────────────────────
section "20. Финальный шаг — приватный ключ и логи"

# Логи v2 содержали приватный ключ в открытом виде — затираем такие файлы
for _log in /root/hardening_*.log; do
    [[ -f "${_log}" && "${_log}" != "${RUN_LOG}" ]] || continue
    if grep -q "PRIVATE KEY-----" "${_log}" 2>/dev/null; then
        shred -uz "${_log}" 2>/dev/null || rm -f "${_log}"
        warn "Удалён старый лог с приватным ключом: ${_log}"
    fi
done

if [[ "${KEY_SOURCE}" == "provided" ]]; then
    info "Использовался ваш публичный ключ — приватного ключа на сервере нет"
    if [[ -f "${KEY_PATH}" ]]; then
        shred -uz "${KEY_PATH}" 2>/dev/null || rm -f "${KEY_PATH}"
        info "Удалён приватный ключ прошлого прогона: ${KEY_PATH}"
    fi
else
    # ИСПРАВЛЕНО: v2 советовала здесь "scp -P 22 root@…", но root по SSH уже
    # запрещён, а порт сменён — скачать так невозможно. Если ключ не сохранён,
    # единственный путь — показать его ещё раз на этом терминале.
    echo ""
    echo -e "${RED}+------------------------------------------------------------+${NC}"
    echo -e "${RED}|  ПОСЛЕДНИЙ ШАГ: УДАЛЕНИЕ ПРИВАТНОГО КЛЮЧА С СЕРВЕРА        |${NC}"
    echo -e "${RED}|                                                            |${NC}"
    echo -e "${RED}|  Root по SSH уже запрещён — scp под root не сработает.     |${NC}"
    echo -e "${RED}|  Если ключ не сохранён, его можно показать ещё раз здесь.  |${NC}"
    echo -e "${RED}+------------------------------------------------------------+${NC}"
    echo ""
    read -r -p "Показать приватный ключ ещё раз? [y/N]: " _show_key
    if [[ "${_show_key}" =~ ^[Yy]$ ]]; then
        sleep 0.3
        { echo ""; cat "${KEY_PATH}"; echo ""; } > /dev/tty
    fi
    read -r -p "Ключ сохранён и вход под ${ADMIN_USER} работает? Удалить ключ с сервера? [y/N]: " confirm

    if [[ "${confirm}" =~ ^[Yy]$ ]]; then
        if command -v shred &>/dev/null; then
            shred -uz "${KEY_PATH}"
        else
            rm -f "${KEY_PATH}"
        fi
        info "Приватный ключ надёжно удалён с сервера"
        info "Публичный ключ оставлен: ${KEY_PATH}.pub"
    else
        warn "Ключ оставлен по адресу: ${KEY_PATH}"
        warn "Удалите после сохранения: sudo shred -uz ${KEY_PATH}"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# ИТОГ
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}+============================================================+${NC}"
echo -e "${GREEN}|             HARDENING ЗАВЕРШЁН УСПЕШНО                    |${NC}"
echo -e "${GREEN}+============================================================+${NC}"
echo ""
printf "  %-48s %s\n" "SSH-ключ: ${KEY_TYPE}"                  "[OK]"
printf "  %-48s %s\n" "Пользователь '${ADMIN_USER}' создан"    "[OK]"
printf "  %-48s %s\n" "SSH: порт ${SSH_PORT}, только ключи, PQ-KEX" "[OK]"
printf "  %-48s %s\n" "ssh.socket отключён (Port применяется)" "[OK]"
printf "  %-48s %s\n" "Root заблокирован, su только для sudo"  "[OK]"
printf "  %-48s %s\n" "UFW: разрешён только SSH:${SSH_PORT}${EXTRA_PORTS:+ + свои}" "[OK]"
printf "  %-48s %s\n" "Fail2ban: 3 попытки -> бан 24ч, recidive" "[OK]"
printf "  %-48s %s\n" "sysctl: сеть + ядро (rp_filter=${RP_FILTER})" "[OK]"
printf "  %-48s %s\n" "Blacklist: опасные ФС/протоколы"        "[OK]"
printf "  %-48s %s\n" "/tmp /dev/shm /var/tmp /home: noexec"   "[OK]"
printf "  %-48s %s\n" "Cron: только root"                      "[OK]"
printf "  %-48s %s\n" "Auditd: расширенные правила, immutable" "[OK]"
printf "  %-48s %s\n" "Core dump отключён"                     "[OK]"
printf "  %-48s %s\n" "AppArmor: активен (отчёт выше)"         "[OK]"
printf "  %-48s %s\n" "sudo: проверен visudo, use_pty, лог"    "[OK]"
printf "  %-48s %s\n" "Политика паролей: 16+ символов"         "[OK]"
printf "  %-48s %s\n" "Телеметрия удалена"                     "[OK]"
printf "  %-48s %s\n" "Автообновления + needrestart"           "[OK]"
printf "  %-48s %s\n" "LUKS: ${LUKS_DONE}"                     "[--]"
echo ""
echo -e "  ${YELLOW}Лог выполнения:${NC} ${RUN_LOG}"
echo ""
echo -e "  ${YELLOW}Требуется перезагрузка для:${NC}"
echo "    - blacklist модулей ядра (DCCP, SCTP, редкие ФС)"
echo "    - /var/tmp и /home bind-mount (если не применились)"
echo "    - kexec_load_disabled, правила auditd (immutable)"
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
echo "    bash ubuntu_hardening.sh --luks status   # шифрование"
echo ""
