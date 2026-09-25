#!/bin/bash
# ==========================================
#         🚀 PAINEL NETSIMON 🚀
# ==========================================
# Atualização de CPU/RAM/Hora: feita via "read -r -t 1" com timeout.
# Quando o timer expira sem input, atualiza só as linhas dinâmicas
# (sem clear, sem background process, sem interferência no cursor).
# Input: read -r aguarda Enter — Delete/Backspace/Ctrl+C funcionam.
#
# Menu principal com 6 opções. Submenus:
#   01) Gerenciar Usuários  -> menu_usuarios()
#   02) Gerenciar Conexões  -> menu_conexoes()
#   05) EXTRAS              -> menu_extras()

BASE="/etc/painel"
USERDB="/etc/painel/usuarios.db"
BLOCKED="/etc/xray-manager/blocked.db"
DEVICES_DB="/etc/painel/netsimon_devices.db"
PAINEL_CFG="/etc/painel/painel_config.json"
XRAY_CONF="/usr/local/etc/xray/config.json"
NS_CACHE_IP="/tmp/ns_cached_ip"
NS_CACHE_XP="/tmp/ns_xp"

# Posições das linhas dinâmicas (1-indexadas, contadas após o clear):
readonly ROW_HORA=5
readonly ROW_CPU=9
readonly ROW_RAM=10
readonly ROW_PROMPT=20

P=$'\033[1;35m'; G=$'\033[1;32m'; GD=$'\033[0;32m'; R=$'\033[1;31m'
Y=$'\033[1;33m'; W=$'\033[1;37m'; C=$'\033[1;36m'; B=$'\033[1;34m'
O=$'\033[38;5;208m'; NC=$'\033[0m'
# Azul turquesa #00FFEF (true color) — cor de todas as opções numeradas do menu
T=$'\033[38;2;0;255;239m'

source "$BASE/online.sh" 2>/dev/null

# ── Ctrl+C: restaura terminal e sai para o prompt da VPS ─────────
trap 'tput cnorm 2>/dev/null; echo ""; exit 130' INT TERM
trap 'tput cnorm 2>/dev/null' EXIT

# ── Coleta de dados ───────────────────────────────────────────────
get_cpu()  { top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2+$4)}'; }
get_ram()  { free 2>/dev/null | awk '/Mem:/ {printf "%d", $3/$2*100}'; }
get_disk() { df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%'; }
get_total()        { [ -f "$USERDB"  ] && wc -l < "$USERDB"  || echo 0; }

# "Block" no cabeçalho deveria refletir usuários REALMENTE bloqueados
# agora (Limiter ou Bloqueio por Dispositivo) — mas estava fazendo
# "SELECT COUNT(*) FROM devices", que é a tabela de aparelhos que só
# CONECTARAM com sucesso (registro, não bloqueio; ver dispositivos.html
# "Dispositivos registrados"). Por isso o menu SSH mostrava 29 (total de
# aparelhos já vistos) enquanto o painel web mostrava outro número —
# nenhum dos dois batia com a realidade. Corrigido pra somar as duas
# fontes de bloqueio de verdade, mesmo critério do painel_api.py:
#   - Limiter: linhas de blocked.db cujo motivo é do limit.sh (mesmos
#     prefixos de _is_limiter_block no painel_api.py) — não conta
#     expirado nem suspensão manual, que têm motivo próprio.
#   - Dispositivo: tentativas REAIS recusadas por device_hash nas
#     últimas 48h (device_log, ação=BLOCKED) — mesma janela usada pela
#     tela "Tentativas bloqueadas" do painel web.
# OBS: soma simples das duas fontes — blocked.db guarda login e
# device_log guarda uuid, então no raríssimo caso do mesmo usuário
# estar nas duas ao mesmo tempo ele pode contar 2x aqui (o painel web,
# que tem acesso ao mapa uuid<->login, não tem essa limitação). Se não
# houver nem blocked.db nem o banco de dispositivos, mostra "N/A" em
# vez de 0 — 0 sugeriria bloqueio ativo e ninguém pego, o que engana.
get_blocked_count() {
    local limiter_count=0 device_count=0 have_source=0

    if [ -f "$BLOCKED" ]; then
        have_source=1
        limiter_count=$(awk -F'|' \
            '$3 ~ /^(SSH duplicado|UUID compartilhado|SSH\+Xray simultâneos)/ {print $1}' \
            "$BLOCKED" 2>/dev/null | sort -u | wc -l)
    fi

    if [ -f "$DEVICES_DB" ] && command -v sqlite3 &>/dev/null; then
        have_source=1
        device_count=$(sqlite3 "$DEVICES_DB" \
            "SELECT COUNT(DISTINCT username) FROM device_log WHERE action='BLOCKED' AND created_at >= datetime('now','-48 hours');" \
            2>/dev/null)
        [ -z "$device_count" ] && device_count=0
    fi

    [ "$have_source" -eq 0 ] && { echo "N/A"; return; }
    echo $((limiter_count + device_count))
}

# Fonte única de verdade para "online" (definida em online.sh) — o
# mesmo número aparece aqui, no submenu de usuários e no Xray Manager.
get_online() { netsimon_online_count 2>/dev/null || echo 0; }

get_expired() {
    local hoje cont=0
    hoje=$(date +%s)
    [ ! -f "$USERDB" ] && echo 0 && return
    while IFS='|' read -r _ _ exp _; do
        local s; s=$(date -d "$exp" +%s 2>/dev/null)
        [[ $? -eq 0 && -n "$s" && $s -lt $hoje ]] && ((cont++))
    done < "$USERDB"
    echo "$cont"
}

check_proto() {
    pgrep -f "$1" >/dev/null 2>&1 || systemctl is-active --quiet "$1" 2>/dev/null \
        && printf "${G}ON${NC}" || printf "${R}OFF${NC}"
}

# ── Barra de progresso ────────────────────────────────────────────
bar() {
    local p=$1 size=20
    [[ -z "$p" || ! "$p" =~ ^[0-9]+$ ]] && p=0
    [[ $p -gt 100 ]] && p=100
    local filled=$((p * size / 100)) empty=$((size - filled))
    local color=$G
    [ "$p" -gt 70 ] && color=$O
    [ "$p" -gt 85 ] && color=$R
    local i s="${color}["
    for ((i=0; i<filled; i++)); do s+="#"; done
    for ((i=0; i<empty; i++)); do s+="-"; done
    s+="] ${p}%${NC}"
    printf "%s" "$s"
}

# ── Atualiza SOMENTE as linhas dinâmicas (sem clear, sem mover o cursor do usuário)
# Salva posição do cursor com \0337 e restaura com \0338 (VT100, suportado em todos
# os clientes SSH modernos: PuTTY, OpenSSH, Termux, etc.)
do_update() {
    local ip xp hora cpu ram
    ip=$(cat "$NS_CACHE_IP" 2>/dev/null); [ -z "$ip" ] && ip="..."
    xp=$(cat "$NS_CACHE_XP" 2>/dev/null); [ -z "$xp" ] && xp="--"
    hora=$(date +"%H:%M:%S")
    cpu=$(get_cpu);  [ -z "$cpu" ] && cpu=0
    ram=$(get_ram);  [ -z "$ram" ] && ram=0

    printf "\0337"  # salva posição atual do cursor (onde usuário está digitando)

    # Linha ROW_HORA — apaga e reimprima
    printf "\033[%d;1H\033[2K" "$ROW_HORA"
    printf "${P}║${NC} ${B}IP:${W} %-15s ${P}│${B} Port:${W} %-8s ${P}│${B} Hora:${W} %-10s${NC}" \
        "$ip" "$xp" "$hora"

    # Linha ROW_CPU
    printf "\033[%d;1H\033[2K${P}║${NC} CPU  " "$ROW_CPU"
    bar "$cpu"

    # Linha ROW_RAM
    printf "\033[%d;1H\033[2K${P}║${NC} RAM  " "$ROW_RAM"
    bar "$ram"

    printf "\0338"  # restaura o cursor exatamente onde estava antes da atualização
}

# ── Desenho completo da tela principal (executado 1x por ciclo de input) ─
draw_full() {
    clear
    local cpu ram disk hora ip xp lmt

    cpu=$(get_cpu);   [ -z "$cpu"  ] && cpu=0
    ram=$(get_ram);   [ -z "$ram"  ] && ram=0
    disk=$(get_disk); [ -z "$disk" ] && disk=0
    hora=$(date +"%H:%M:%S")
    ip=$(cat "$NS_CACHE_IP" 2>/dev/null);  [ -z "$ip" ] && ip="..."
    xp=$(cat "$NS_CACHE_XP" 2>/dev/null);  [ -z "$xp" ] && xp="--"
    lmt=$(pgrep -f limit.sh >/dev/null && printf "${G}ON${NC}" || printf "${R}OFF${NC}")

    # ROW 1
    echo -e "${P}╔══════════════════════════════════════════════════════════════${NC}"
    # ROW 2
    echo -e "${P}║${C}                🚀 PAINEL NETSIMON 🚀                    ${NC}"
    # ROW 3
    echo -e "${P}╠══════════════════════════════════════════════════════════════${NC}"
    # ROW 4
    printf "${P}║${NC} ${C}Users:${O} %-4s ${P}│${C} Online:${G} %-4s ${P}│${C} Expired:${R} %-4s ${P}│${C} Block:${R} %-4s${NC}\n" \
        "$(get_total)" "$(get_online)" "$(get_expired)" "$(get_blocked_count)"
    # ROW 5  ← ROW_HORA (atualizado pelo do_update)
    printf "${P}║${NC} ${B}IP:${W} %-15s ${P}│${B} Port:${W} %-8s ${P}│${B} Hora:${W} %-10s${NC}\n" \
        "$ip" "$xp" "$hora"
    # ROW 6
    echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
    # ROW 7
    printf "${P}║${NC} ${O}XRAY:${NC} $(check_proto xray)  ${P}│${O} SLOWDNS:${NC} $(check_proto slowdns)  ${P}│${O} WS:${NC} $(check_proto proxy.py)  ${P}│${O} LIMITER:${NC} ${lmt}${NC}\n"
    # ROW 8
    echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
    # ROW 9  ← ROW_CPU
    printf "${P}║${NC} CPU  "; bar "$cpu"; echo
    # ROW 10 ← ROW_RAM
    printf "${P}║${NC} RAM  "; bar "$ram"; echo
    # ROW 11
    printf "${P}║${NC} DISK "; bar "$disk"; echo
    # ROW 12
    echo -e "${P}╠══════════════════════════════════════════════════════════════${NC}"
    # ROWS 13-18 — menu principal
    printf "${P}║${T} 01) Gerenciar Usuários${NC}\n"
    printf "${P}║${T} 02) Gerenciar Conexões${NC}\n"
    printf "${P}║${T} 03) Status VPS${NC}\n"
    printf "${P}║${T} 04) Teste Velocidade${NC}\n"
    printf "${P}║${T} 05) EXTRAS${NC}\n"
    printf "${P}║${T} 06) Reparar Sistema${NC}\n"
    # ROW 19
    echo -e "${P}╚══════════════════════════════════════════════════════════════${NC}"
    # ROW 20 — sem newline; cursor fica aqui para o read
    printf "${O}✨ Opção: ${NC}"
}

# ── Cache do IP público e portas abertas ─────────────────────────
# "Port:" no cabeçalho mostra as portas de tráfego relevantes pro
# cliente final — WebSocket (80/8080, se estiverem de fato em LISTEN)
# e a(s) porta(s) de tráfego real do Xray (443 por padrão, ou outra
# se tiver sido alterada no Xray Manager). A porta 2000 é só a API
# interna do Xray e nunca aparece aqui — mostrar 2000 confundiria o
# cliente achando que é uma porta de conexão.
refresh_cache() {
    local new_ip
    new_ip=$(wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null | tr -d '\n')
    [ -n "$new_ip" ] && echo "$new_ip" > "$NS_CACHE_IP" || echo "offline" > "$NS_CACHE_IP"

    local portas=()
    for p in 80 8080; do
        ss -tln 2>/dev/null | grep -q ":$p " && portas+=("$p")
    done
    if [ -f "$XRAY_CONF" ]; then
        while read -r xp; do
            [ -n "$xp" ] && [ "$xp" != "2000" ] && portas+=("$xp")
        done < <(jq -r '.inbounds[]? | select(.protocol != "dokodemo-door") | .port' "$XRAY_CONF" 2>/dev/null)
    fi

    if [ "${#portas[@]}" -gt 0 ]; then
        (IFS=/; echo "${portas[*]}") > "$NS_CACHE_XP"
    else
        echo "--" > "$NS_CACHE_XP"
    fi
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: GERENCIAR USUÁRIOS
# ══════════════════════════════════════════════════════════════════
menu_usuarios() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                 👤 GERENCIAR USUÁRIOS                        ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        printf "${P}║${NC} ${C}Users:${O} %-4s ${P}│${C} Online:${G} %-4s ${P}│${C} Expirados:${R} %-4s ${P}│${C} Block:${R} %-4s${NC}\n" \
            "$(get_total)" "$(get_online)" "$(get_expired)" "$(get_blocked_count)"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T}  1)${NC} Criar Usuário"
        echo -e "${P}║${T}  2)${NC} Criar Teste"
        echo -e "${P}║${T}  3)${NC} Excluir Expirados"
        echo -e "${P}║${T}  4)${NC} Remover Usuário"
        echo -e "${P}║${T}  5)${NC} Listar Usuários"
        echo -e "${P}║${T}  6)${NC} Usuários Online"
        echo -e "${P}║${T}  7)${NC} Block Dispositivos"
        echo -e "${P}║${R}  0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r uop

        case "$uop" in
            1) bash "$BASE/adduser.sh" ;;
            2) bash "$BASE/addtest.sh" ;;
            3)
                clear
                echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${P}║${W}            🗑️  EXCLUIR USUÁRIOS EXPIRADOS                    ${P}║${NC}"
                echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

                if [ ! -s "$USERDB" ]; then
                    echo -e "\n${Y}Banco de dados vazio.${NC}"
                    read -rp "ENTER para voltar..."; continue
                fi

                hoje=$(date +%s)
                expirados=()
                printf "\n${W}%-15s %-20s${NC}\n" "USUÁRIO" "VENCEU EM"
                echo -e "${P}──────────────────────────────────────────────${NC}"
                while IFS='|' read -r eu _ eexp _ _; do
                    [ -z "$eu" ] && continue
                    es=$(date -d "$eexp" +%s 2>/dev/null)
                    if [[ -n "$es" && "$es" -lt "$hoje" ]]; then
                        expirados+=("$eu")
                        printf "${R}%-15s${NC} ${Y}%-20s${NC}\n" "$eu" "$eexp"
                    fi
                done < "$USERDB"

                if [ "${#expirados[@]}" -eq 0 ]; then
                    echo -e "\n${G}Nenhum usuário expirado no momento.${NC}"
                    read -rp "ENTER para voltar..."; continue
                fi

                echo -e "${P}──────────────────────────────────────────────${NC}"
                echo -e "${W}Total de expirados: ${R}${#expirados[@]}${NC}"
                echo -ne "\n${R}⚠️  Excluir TODOS os usuários listados acima? (s/n): ${NC}"
                read -r uconf
                if [[ "$uconf" != "s" ]]; then
                    echo -e "${Y}Operação cancelada.${NC}"; sleep 2; continue
                fi

                for eu in "${expirados[@]}"; do
                    echo -ne "${W} -> Removendo: ${C}$eu... ${NC}"
                    bash "$BASE/deluser.sh" "$eu" --auto
                    echo -e "${G}OK${NC}"
                done
                echo -e "\n${G}✅ ${#expirados[@]} usuário(s) expirado(s) removido(s)!${NC}"
                read -rp "ENTER para voltar..." ;;
            4) bash "$BASE/deluser.sh" ;;
            5)
                clear
                echo -e "${P}╔══════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${P}║${NC} ${O} #   USUÁRIO    SENHA       UUID             DATA          LIM.${NC}"
                echo -e "${P}╠══════════════════════════════════════════════════════════════════╣${NC}"
                if [ -s "$USERDB" ]; then
                    local num=0
                    # Lê na ordem exata do arquivo (= ordem de criação, sem sort)
                    while IFS='|' read -r luser luuid lexp lpass llim; do
                        ((num++))
                        ldata_fmt=$(date -d "$lexp" +"%d/%m/%y %H:%M" 2>/dev/null || echo "--/--")
                        luuid_curto="${luuid:0:8}..."
                        printf "${P}║${W} %-3s %-10s %-11s %-16s %-13s %-4s${NC}\n" \
                            "$num" "$luser" "$lpass" "$luuid_curto" "$ldata_fmt" "$llim"
                    done < "$USERDB"
                else
                    echo -e "${P}║${R}                  NENHUM USUÁRIO ENCONTRADO!                        ${NC}"
                fi
                echo -e "${P}╚══════════════════════════════════════════════════════════════════╝${NC}"
                read -rp "Pressione ENTER para voltar..." ;;
            6) bash "$BASE/online.sh" ;;
            7) menu_block_dispositivos ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$uop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: GERENCIAR CONEXÕES
# ══════════════════════════════════════════════════════════════════
menu_conexoes() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                🔌 GERENCIAR CONEXÕES                         ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} WebSocket Manager"
        echo -e "${P}║${T} 2)${NC} SlowDNS Manager"
        echo -e "${P}║${T} 3)${NC} Xray Manager"
        echo -e "${P}║${T} 4)${NC} CheckUser API"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r cop

        case "$cop" in
            1) bash "$BASE/websocket.sh" ;;
            2) bash "$BASE/slowdns-server.sh" ;;
            3) bash "$BASE/xray.sh" ;;
            4) bash "$BASE/checkuser.sh" ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$cop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  OTIMIZAR SERVIDOR — limpeza de cache/logs antigos (menu EXTRAS)
# ══════════════════════════════════════════════════════════════════
otimizar_servidor() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                  🧹 OTIMIZAR SERVIDOR                        ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${Y}Isso vai:${NC}"
    echo -e "  • Limpar cache de pacotes do apt (apt clean/autoremove)"
    echo -e "  • Limpar logs do systemd (journalctl) com mais de 7 dias"
    echo -e "  • Apagar arquivos temporários em /tmp com mais de 7 dias"
    echo -e "  • Apagar logs rotacionados antigos (*.gz, *.log.N) com mais de 30 dias em /var/log"
    echo -e "  • Liberar cache de página/inode da RAM (não afeta dados, só cache reaproveitável)"
    echo -e "${Y}Nada disso apaga usuário, config, ou qualquer dado do painel.${NC}"
    echo -ne "${Y}Confirma? (s/N): ${NC}"; read -r conf
    if [[ ! "$conf" =~ ^[sS]$ ]]; then
        echo -e "${R}Cancelado.${NC}"; sleep 1; return
    fi

    echo -e "${C}Antes:${NC}"
    df -h / | tail -1 | awk '{print "  Disco / :  usado "$3" de "$2" ("$5")"}'
    free -h | awk '/Mem:/ {print "  RAM     :  usado "$3" de "$2}'
    echo ""

    if command -v apt-get &>/dev/null; then
        echo -e "${T}→ Limpando cache do apt...${NC}"
        apt-get clean -y &>/dev/null
        apt-get autoremove -y &>/dev/null
    fi

    if command -v journalctl &>/dev/null; then
        echo -e "${T}→ Limpando journal com mais de 7 dias...${NC}"
        journalctl --vacuum-time=7d &>/dev/null
    fi

    echo -e "${T}→ Limpando /tmp (arquivos com mais de 7 dias)...${NC}"
    find /tmp -maxdepth 1 -type f -mtime +7 -delete 2>/dev/null

    echo -e "${T}→ Limpando logs rotacionados antigos em /var/log...${NC}"
    find /var/log -type f \( -name "*.gz" -o -name "*.log.*" -o -name "*.[0-9]" \) -mtime +30 -delete 2>/dev/null

    echo -e "${T}→ Liberando cache de página/inode da RAM...${NC}"
    sync
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

    echo ""
    echo -e "${C}Depois:${NC}"
    df -h / | tail -1 | awk '{print "  Disco / :  usado "$3" de "$2" ("$5")"}'
    free -h | awk '/Mem:/ {print "  RAM     :  usado "$3" de "$2}'
    echo ""
    echo -e "${G}✅ Otimização concluída.${NC}"
    read -rp "ENTER para voltar..."
}

# ══════════════════════════════════════════════════════════════════
#  MEMÓRIA SWAP — criar/remover swapfile (menu EXTRAS)
# ══════════════════════════════════════════════════════════════════
SWAPFILE="/swapfile_netsimon"

_swap_status() {
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q "^${SWAPFILE}$"; then
        local tam
        tam=$(free -h | awk '/Swap:/ {print $2}')
        echo -e "${G}Ativa${NC} — tamanho: ${W}${tam}${NC} (arquivo: $SWAPFILE)"
    elif swapon --show 2>/dev/null | grep -q .; then
        echo -e "${Y}Existe swap ativa, mas não foi criada por este menu${NC}"
        swapon --show
    else
        echo -e "${R}Nenhuma swap ativa${NC}"
    fi
}

_swap_criar() {
    local tamanho="$1"   # ex: 512M, 1G, 2G
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q "^${SWAPFILE}$"; then
        echo -e "${Y}Já existe uma swap ativa criada por este menu. Remova antes de criar outra (opção 2).${NC}"
        sleep 2; return
    fi
    echo -e "${T}→ Criando arquivo de swap de ${tamanho}...${NC}"

    if ! fallocate -l "$tamanho" "$SWAPFILE" 2>/dev/null; then
        # fallocate não funciona em alguns filesystems (ex: alguns overlay/btrfs) —
        # dd é mais lento mas funciona em qualquer lugar.
        echo -e "${Y}fallocate não disponível aqui, usando dd (pode demorar mais)...${NC}"
        local mb
        mb=$(numfmt --from=iec "$tamanho")
        mb=$((mb / 1024 / 1024))
        dd if=/dev/zero of="$SWAPFILE" bs=1M count="$mb" status=progress 2>/dev/null
    fi

    chmod 600 "$SWAPFILE"
    if ! mkswap "$SWAPFILE" &>/dev/null; then
        echo -e "${R}Falha ao formatar o arquivo de swap.${NC}"
        rm -f "$SWAPFILE"
        sleep 2; return
    fi
    swapon "$SWAPFILE"

    # Persiste após reboot — só adiciona se ainda não estiver no fstab.
    if ! grep -q "^${SWAPFILE} " /etc/fstab 2>/dev/null; then
        echo "${SWAPFILE} none swap sw 0 0" >> /etc/fstab
    fi

    echo -e "${G}✅ Swap de ${tamanho} ativada e persistente após reboot.${NC}"
    free -h
    read -rp "ENTER para voltar..."
}

_swap_remover() {
    if ! swapon --show=NAME --noheadings 2>/dev/null | grep -q "^${SWAPFILE}$"; then
        echo -e "${Y}Não há swap criada por este menu pra remover.${NC}"
        sleep 2; return
    fi
    echo -ne "${Y}Confirma remover a swap de $SWAPFILE? (s/N): ${NC}"; read -r conf
    if [[ ! "$conf" =~ ^[sS]$ ]]; then
        echo -e "${R}Cancelado.${NC}"; sleep 1; return
    fi
    swapoff "$SWAPFILE" 2>/dev/null
    rm -f "$SWAPFILE"
    sed -i "\\#^${SWAPFILE} #d" /etc/fstab
    echo -e "${G}✅ Swap removida.${NC}"
    sleep 2
}

menu_swap() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                     💽 MEMÓRIA SWAP                          ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -ne "${P}║${NC} Status atual: "; _swap_status
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Ativar/Criar swap"
        echo -e "${P}║${T} 2)${NC} Remover swap (criada por este menu)"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r sop

        case "$sop" in
            1)
                clear
                echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${P}║${W}              Escolha o tamanho da swap                       ${P}║${NC}"
                echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
                echo -e "${P}║${T} 1)${NC} 512 MB"
                echo -e "${P}║${T} 2)${NC} 1 GB"
                echo -e "${P}║${T} 3)${NC} 2 GB"
                echo -e "${P}║${T} 4)${NC} 4 GB"
                echo -e "${P}║${T} 5)${NC} Personalizado"
                echo -e "${P}║${R} 0)${NC} Cancelar"
                echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
                echo -ne "${Y} Escolha: ${NC}"; read -r top
                case "$top" in
                    1) _swap_criar "512M" ;;
                    2) _swap_criar "1G" ;;
                    3) _swap_criar "2G" ;;
                    4) _swap_criar "4G" ;;
                    5)
                        echo -ne "${Y}Tamanho (ex: 1500M ou 3G): ${NC}"; read -r custom
                        if [[ "$custom" =~ ^[0-9]+[MG]$ ]]; then
                            _swap_criar "$custom"
                        else
                            echo -e "${R}Formato inválido — use algo como 512M ou 2G.${NC}"; sleep 2
                        fi
                        ;;
                    0) ;;
                    *) echo -e "${R}Opção inválida.${NC}"; sleep 1 ;;
                esac
                ;;
            2) _swap_remover ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida.${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: EXTRAS
# ══════════════════════════════════════════════════════════════════
menu_extras() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                     ⚙️  EXTRAS                               ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Ver Bloqueios do Limiter (IP/SSH)"
        echo -e "${P}║${T} 2)${NC} Ativar Limiter (IP/SSH)"
        echo -e "${P}║${T} 3)${NC} Parar Limiter (IP/SSH)"
        echo -e "${P}║${T} 4)${NC} Backup Config"
        echo -e "${P}║${T} 5)${NC} Ver Logs"
        echo -e "${P}║${T} 6)${NC} Limpar Bloqueios do Limiter"
        echo -e "${P}║${T} 7)${NC} Otimizar Servidor (limpar cache/logs antigos)"
        echo -e "${P}║${T} 8)${NC} Memória SWAP"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r xop

        case "$xop" in
            1)
                clear
                echo -e "${P}╔═══════════════════════════════╗${NC}"
                echo -e "${P}║${W}    BLOQUEIOS DO LIMITER        ${P}║${NC}"
                echo -e "${P}╚═══════════════════════════════╝${NC}"
                if [ -s "$BLOCKED" ]; then
                    printf "${W}%-20s %-18s %s${NC}\n" "USUÁRIO" "DATA" "MOTIVO"
                    echo -e "${P}──────────────────────────────────────────────${NC}"
                    while IFS='|' read -r bu bd bm; do
                        printf "${R}%-20s ${Y}%-18s ${C}%s${NC}\n" "$bu" "$bd" "$bm"
                    done < "$BLOCKED"
                else
                    echo -e "${Y}Nenhum bloqueio do limiter registrado.${NC}"
                fi
                read -rp "ENTER para voltar..." ;;
            2)
                systemctl restart limiter 2>/dev/null
                echo -e "${G}✅ Limiter ativado!${NC}"; sleep 1 ;;
            3)
                systemctl stop limiter 2>/dev/null
                echo -e "${R}⛔ Limiter parado!${NC}"; sleep 1 ;;
            4)
                clear
                BKP="/root/backup_netsimon_$(date +%d%m%y_%H%M).tar.gz"
                tar -czf "$BKP" "$BASE" "/usr/local/etc/xray" "/etc/xray-manager" 2>/dev/null
                echo -e "${G}✅ Backup: $BKP${NC}"; sleep 3 ;;
            5)
                clear
                echo -e "${P}══════════════ LOGS DO SISTEMA ══════════════${NC}"
                if [ -s /var/log/xray/access.log ]; then
                    echo -e "${W}Xray (últimas 15 entradas):${NC}"
                    tail -n 15 /var/log/xray/access.log \
                        | sed "s/accepted/${G}accepted${NC}/g" \
                        | sed "s/failed/${R}failed${NC}/g"
                fi
                echo -e "${P}──────────────────────────────────────────────${NC}"
                if [ -s /var/log/netsimon_limit.log ]; then
                    echo -e "${W}Limiter (últimas 10 entradas):${NC}"
                    tail -n 10 /var/log/netsimon_limit.log
                fi
                read -rp "ENTER para voltar..." ;;
            6)
                : > "$BLOCKED"
                echo -e "${G}✅ Bloqueios do limiter removidos!${NC}"; sleep 2 ;;
            7) otimizar_servidor ;;
            8) menu_swap ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$xop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  RESET_USER — remove dispositivo(s) registrados no bloqueio por
#  aparelho. Aceita:
#    - um rowid numérico (remove só aquele dispositivo específico)
#    - um login ou uuid (remove TODOS os dispositivos daquele usuário)
#  A tabela devices guarda o UUID na coluna "username", então login
#  precisa ser resolvido via usuarios.db antes do DELETE (mesma lógica
#  usada pelo painel_api.py em /api/device/reset/<login>).
# ══════════════════════════════════════════════════════════════════
reset_user() {
    local input="$1"
    local removed=0

    if [[ -z "$input" ]]; then
        echo -e "${R}Entrada inválida.${NC}"
        return 1
    fi
    if ! command -v sqlite3 &>/dev/null || [ ! -f "$DEVICES_DB" ]; then
        echo -e "${R}Banco de dispositivos não encontrado.${NC}"
        return 1
    fi

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        # Entrada numérica: trata como rowid de um dispositivo específico
        removed=$(sqlite3 "$DEVICES_DB" "DELETE FROM devices WHERE rowid=$input; SELECT changes();" 2>/dev/null)
        removed=${removed:-0}
        if [ "$removed" -gt 0 ] 2>/dev/null; then
            echo -e "${G}✅ Dispositivo ID $input removido.${NC}"
        else
            echo -e "${R}Nenhum dispositivo encontrado com esse ID.${NC}"
        fi
        return 0
    fi

    # Entrada é login ou uuid: resolve o uuid real do usuário
    local uuid_val=""
    if [ -f "$USERDB" ]; then
        while IFS='|' read -r u_login u_uuid _u_rest; do
            if [[ "${u_login,,}" == "${input,,}" || "${u_uuid,,}" == "${input,,}" ]]; then
                uuid_val="$u_uuid"
                break
            fi
        done < "$USERDB"
    fi
    [ -z "$uuid_val" ] && uuid_val="$input"

    # Escapa aspas simples pra não quebrar o comando SQL
    local uuid_esc="${uuid_val//\'/\'\'}"
    removed=$(sqlite3 "$DEVICES_DB" "DELETE FROM devices WHERE username='$uuid_esc'; SELECT changes();" 2>/dev/null)
    removed=${removed:-0}
    if [ "$removed" -gt 0 ] 2>/dev/null; then
        echo -e "${G}✅ $removed dispositivo(s) removido(s) para: $input${NC}"
    else
        echo -e "${Y}Nenhum dispositivo registrado para esse usuário/ID.${NC}"
    fi
}

# ══════════════════════════════════════════════════════════════════
#  INTERRUPTOR: Bloqueio por Dispositivo (device_hash)
#  Lê/grava a MESMA chave que o painel web usa (painel_config.json ->
#  device_block.enabled), então ligar/desligar aqui ou pela tela web
#  dá o resultado idêntico — um interruptor só, dois jeitos de mexer
#  nele. Sistema 100% separado do Limiter (limit.sh): esse aqui nunca
#  liga/desliga processo nenhum, só a flag que _device_check_core()
#  no painel_api.py consulta a cada checagem de device_hash.
# ══════════════════════════════════════════════════════════════════
device_block_is_on() {
    if [ ! -f "$PAINEL_CFG" ]; then
        echo "1"; return   # sem config ainda = comportamento padrão (ligado)
    fi
    if ! command -v jq &>/dev/null; then
        echo "1"; return   # sem jq pra ler = mesmo padrão de antes (ligado)
    fi
    local v rc
    v=$(jq -r '.device_block.enabled' "$PAINEL_CFG" 2>/dev/null)
    rc=$?
    # BUGFIX: a versão anterior usava `// true` dentro do próprio filtro
    # jq E ainda tinha um `|| echo 1` de fallback — então QUALQUER falha
    # de leitura (jq travou, exit code != 0, saída vazia) virava "1"
    # (ATIVO) do mesmo jeito que "chave ausente" (que É pra ser ATIVO por
    # padrão). Resultado: se o jq falhasse bem no instante em que o admin
    # tinha acabado de DESATIVAR pelo painel web, o menu SSH mostrava
    # ATIVO mesmo com painel_config.json já gravado com "enabled": false
    # — o interruptor "mentia" pro admin. Agora só cai no padrão ligado
    # quando a chave realmente não existe (v vazio ou "null"); se o jq
    # rodou e leu "false" de verdade, é "false" sempre, sem cair em
    # fallback nenhum.
    if [ $rc -ne 0 ] || [ -z "$v" ] || [ "$v" = "null" ]; then
        echo "1"; return
    fi
    [[ "$v" == "false" ]] && echo "0" || echo "1"
}

device_block_set() {
    local newval="$1"   # "true" ou "false"
    if [ ! -f "$PAINEL_CFG" ]; then
        echo -e "${R}painel_config.json ainda não existe — abra o painel web pelo menos uma vez antes.${NC}"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        echo -e "${R}jq não está instalado.${NC}"
        return 1
    fi
    jq --argjson v "$newval" '.device_block.enabled = $v' "$PAINEL_CFG" > "${PAINEL_CFG}.tmp" \
        && mv "${PAINEL_CFG}.tmp" "$PAINEL_CFG"
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: BLOCK DISPOSITIVOS
# ══════════════════════════════════════════════════════════════════
menu_block_dispositivos() {
    while true; do
        clear
        local bd_on bd_on_label
        bd_on=$(device_block_is_on)
        bd_on_label=$([ "$bd_on" = "1" ] && printf "${G}● ATIVO${NC}" || printf "${R}● DESATIVADO${NC}")

        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                  📵 BLOCK DISPOSITIVOS                      ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        printf "${P}║${NC}  Interruptor: %-52b${P}║${NC}\n" "$bd_on_label"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

        if [ ! -f "$DEVICES_DB" ] || ! command -v sqlite3 &>/dev/null; then
            echo -e "${P}║${Y}  Nenhum dispositivo registrado ainda.                        ${P}║${NC}"
            echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
            echo -e "${P}║${T}  3)${NC} $([ "$bd_on" = "1" ] && echo "Desativar" || echo "Ativar") bloqueio por dispositivo"
            echo -e "${P}║${R}  0)${NC} Voltar"
            echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
            echo -ne "${Y} Escolha: ${NC}"; read -r _bop
            case "$_bop" in
                3)
                    if [ "$bd_on" = "1" ]; then device_block_set "false" && echo -e "\n${R}⛔ Bloqueio por dispositivo desativado!${NC}"
                    else device_block_set "true" && echo -e "\n${G}✅ Bloqueio por dispositivo ativado!${NC}"; fi
                    sleep 2 ;;
                *) return ;;
            esac
            continue
        fi

        local bd_count
        bd_count=$(sqlite3 "$DEVICES_DB" "SELECT COUNT(*) FROM devices;" 2>/dev/null || echo 0)

        if [ "$bd_count" -eq 0 ] 2>/dev/null; then
            echo -e "${P}║${Y}  Nenhum dispositivo bloqueado no momento.                    ${P}║${NC}"
        else
            # A coluna "username" da tabela devices guarda o UUID do usuário
            # (não o login). Monta um mapa uuid->login a partir do usuarios.db
            # pra exibir algo legível em vez do UUID cru.
            declare -A bd_uuid2login
            if [ -f "$USERDB" ]; then
                while IFS='|' read -r u_login u_uuid _u_rest; do
                    [ -n "$u_uuid" ] && bd_uuid2login["$u_uuid"]="$u_login"
                done < "$USERDB"
            fi

            printf "${P}║${NC}  ${C}%-6s${NC} ${W}%-30s${NC}\n" "ID" "USUÁRIO"
            echo -e "${P}╟──────────────────────────────────────────────────────────────${NC}"
            while IFS='|' read -r bd_id bd_uuid; do
                bd_login="${bd_uuid2login[$bd_uuid]:-$bd_uuid}"
                printf "${P}║${NC}  ${C}%-6s${NC} ${W}%s${NC}\n" "$bd_id" "$bd_login"
            done < <(sqlite3 "$DEVICES_DB" "SELECT rowid, username FROM devices ORDER BY rowid;" 2>/dev/null)
            unset bd_uuid2login
        fi

        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T}  1)${NC} Desbloquear 1 ID"
        echo -e "${P}║${T}  2)${NC} Desbloquear todos os IDs"
        echo -e "${P}║${T}  3)${NC} $([ "$bd_on" = "1" ] && echo "Desativar" || echo "Ativar") bloqueio por dispositivo"
        echo -e "${P}║${R}  0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r bop

        case "$bop" in
            1)
                echo -ne "\n${Y} Informe o ID (da lista acima) ou Login/UUID do usuário: ${NC}"
                read -r bd_input
                if [[ -n "$bd_input" ]]; then
                    reset_user "$bd_input"
                else
                    echo -e "\n${R}Entrada inválida.${NC}"
                fi
                sleep 2 ;;
            2)
                echo -ne "\n${R}⚠️  Isso desbloqueia TODOS os dispositivos. Confirma? (s/n): ${NC}"
                read -r bd_conf
                if [[ "$bd_conf" == "s" ]]; then
                    sqlite3 "$DEVICES_DB" "DELETE FROM devices;"
                    echo -e "\n${G}✅ Todos os IDs foram desbloqueados!${NC}"
                else
                    echo -e "\n${Y}Operação cancelada.${NC}"
                fi
                sleep 2 ;;
            3)
                if [ "$bd_on" = "1" ]; then device_block_set "false" && echo -e "\n${R}⛔ Bloqueio por dispositivo desativado!${NC}"
                else device_block_set "true" && echo -e "\n${G}✅ Bloqueio por dispositivo ativado!${NC}"; fi
                sleep 2 ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$bop'${NC}"; sleep 1 ;;
        esac
    done
}

# ── LOOP PRINCIPAL ────────────────────────────────────────────────
ip_timer=0
refresh_cache &   # busca IP/portas em background para não travar o primeiro desenho

while true; do
    # Refresca cache do IP/portas a cada 30 ciclos
    if [ "$ip_timer" -le 0 ]; then
        refresh_cache &
        ip_timer=30
    fi
    ((ip_timer--))

    draw_full   # limpa tela e desenha tudo 1x; cursor fica em ROW_PROMPT após "Opção: "

    # Aguarda input com timeout de 1 segundo.
    # ret=0   → usuário pressionou Enter (input recebido)
    # ret>128 → timeout expirou (1s sem Enter) → atualiza CPU/RAM/Hora e volta a aguardar
    op=""
    while true; do
        IFS= read -r -t 1 op
        ret=$?
        if [ "$ret" -eq 0 ]; then
            break          # Enter recebido — sai do loop de input
        elif [ "$ret" -gt 128 ]; then
            do_update      # timeout — atualiza linhas dinâmicas sem tocar no cursor
        fi
        # ret 1-128 = EOF ou erro — continuamos aguardando
    done

    echo ""   # desce uma linha antes de processar

    case "$op" in
        1|01) menu_usuarios ;;
        2|02) menu_conexoes ;;
        3|03) bash "$BASE/monitor.sh" ;;
        4|04)
            clear
            which speedtest-cli >/dev/null 2>&1 || apt-get install -y speedtest-cli >/dev/null 2>&1
            speedtest-cli --simple 2>&1
            read -rp "ENTER para voltar..." ;;
        5|05) menu_extras ;;
        6|06) bash "$BASE/repair.sh" ;;
        "")  ;;   # Enter em branco — apenas redesenha
        *) echo -e "${R}Opção inválida: '$op'${NC}"; sleep 1 ;;
    esac
done