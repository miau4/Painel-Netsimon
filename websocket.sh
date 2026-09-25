#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - WEBSOCKET MANAGER
#   4 sistemas independentes, cada um com seu próprio código,
#   nenhum mesclado com outro:
#     1) WS PROXY    (proxy.py, porta 80, sem TLS)
#     2) WSS TLS      (wss.py, porta 8443, TLS real)
#     3) WSS SSH      (wss_security.py, porta 8888, sem TLS)
#     4) STUNNEL SSL  (netsimon-stunnel, porta 2053, TLS "cru")
#
#   WSS TLS e WSS SSH são protocolos DIFERENTES e INDEPENDENTES, cada
#   um desenvolvido/testado separadamente — não compartilham código,
#   nem service, nem porta. Todos os 4 são serviços systemd de verdade
#   (Restart=always) — nenhum sobe via screen/kill -9; sempre systemctl.
# ==========================================

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; B=$'\033[1;34m'; NC=$'\033[0m'
T=$'\033[38;2;0;255;239m'

BASE="/etc/painel"

WSS_DIR="/etc/painel/wss"
WSS_CONF="$WSS_DIR/wss.conf"
WSS_CERT="$WSS_DIR/cert.pem"
WSS_KEY="$WSS_DIR/key.pem"
WSS_DEFAULT_PORT=8443

WSSSEC_DIR="/etc/painel/wss-security"
WSSSEC_CONF="$WSSSEC_DIR/wss-security.conf"
WSSSEC_DEFAULT_PORT=8888

STUNNEL_DIR="/etc/painel/stunnel"
STUNNEL_SETTINGS="$STUNNEL_DIR/stunnel_settings.conf"
STUNNEL_CONF="$STUNNEL_DIR/stunnel.conf"
STUNNEL_CERT="$STUNNEL_DIR/stunnel.pem"
STUNNEL_UNIT="netsimon-stunnel"
STUNNEL_DEFAULT_PORT=2053

# ── Helpers de status ────────────────────────────────────────────

# Identifica o que está rodando em uma porta e retorna label colorido
check_proto() {
    local porta=$1
    local pid cmd
    pid=$(lsof -t -i :"$porta" -sTCP:LISTEN 2>/dev/null | head -n1)
    if [ -z "$pid" ]; then
        echo -e "${R}OFF${NC}"
        return
    fi
    cmd=$(ps -fp "$pid" -o args= 2>/dev/null)
    if [[ "$cmd" == *"proxy.py"* ]]; then
        echo -e "${G}WS PROXY ●${NC}"
    elif [[ "$cmd" == *"/wss.py"* ]]; then
        echo -e "${C}WSS TLS ●${NC}"
    elif [[ "$cmd" == *"wss_security.py"* ]]; then
        echo -e "${C}WSS SSH ●${NC}"
    elif [[ "$cmd" == *"stunnel"* ]]; then
        echo -e "${B}STUNNEL SSL ●${NC}"
    else
        echo -e "${Y}OUTRO ●${NC}"
    fi
}

# ── 1. WS PROXY (proxy.py) ───────────────────────────────────────
# Roda como serviço systemd de verdade (proxy@<porta>, Restart=always)
# — igual ao xray. O menu só liga/desliga a unit.
start_proxy() {
    local porta=$1
    systemctl stop "wss@${porta}" "wss-security@${porta}" 2>/dev/null
    sleep 1
    systemctl start "proxy@${porta}" 2>/dev/null
    sleep 1
    if systemctl is-active --quiet "proxy@${porta}"; then
        echo -e "${G}[OK] WS PROXY iniciado na porta $porta!${NC}"
    else
        echo -e "${R}[ERRO] Falha na porta $porta. Verifique: systemctl status proxy@${porta}${NC}"
    fi
}

stop_proxy_port() {
    systemctl stop "proxy@${1}" 2>/dev/null
}

# ── 2. WSS TLS (wss.py — TLS real) ───────────────────────────────

check_wss_bin() {
    if [ ! -f "$BASE/wss.py" ]; then
        echo -e "${R}[ERRO] Script não encontrado: $BASE/wss.py${NC}"
        echo -e "${Y}       Reinstale/atualize o painel — o wss.py deve vir junto.${NC}"
        return 1
    fi
    if [ ! -f "$WSS_CERT" ] || [ ! -f "$WSS_KEY" ]; then
        echo -e "${R}[ERRO] Certificado/chave ausentes em $WSS_DIR${NC}"
        echo -e "${Y}       Reinstale/atualize o painel pra gerar o certificado autoassinado.${NC}"
        return 1
    fi
    return 0
}

get_wss_dest() {
    [ -f "$WSS_CONF" ] && grep -oP 'WSS_DEST=\K.*' "$WSS_CONF" 2>/dev/null || echo "127.0.0.1:22"
}

check_wss_any() {
    if systemctl list-units --type=service --all --no-legend "wss@*" 2>/dev/null \
        | awk '{print $1}' | xargs -r -n1 systemctl is-active --quiet 2>/dev/null; then
        echo -e "${C}ATIVO${NC}"
    else
        echo -e "${R}PARADO${NC}"
    fi
}

wss_active_ports() {
    local ports
    ports=$(systemctl list-units --type=service --state=running --no-legend "wss@*" 2>/dev/null \
        | awk '{print $1}' | sed -E "s/^wss@([0-9]+)\.service\$/\1/" | tr '\n' '/')
    [ -n "$ports" ] && echo "${ports%/}" || echo "--"
}

start_wss() {
    local porta=$1
    check_wss_bin || { sleep 2; return; }
    systemctl stop "proxy@${porta}" "wss-security@${porta}" 2>/dev/null
    sleep 1
    systemctl enable --now "wss@${porta}" 2>/dev/null
    sleep 1
    if systemctl is-active --quiet "wss@${porta}"; then
        echo -e "${G}[OK] WSS TLS ativo na porta $porta!${NC}"
        echo -e "${W}     Destino: ${C}$(get_wss_dest)${NC}"
    else
        echo -e "${R}[ERRO] wss@${porta} não subiu. Verifique: systemctl status wss@${porta}${NC}"
    fi
}

stop_wss_port() {
    systemctl stop "wss@${1}" 2>/dev/null
    echo -e "${G}Parado na porta $1.${NC}"
}

stop_wss_all() {
    local units
    units=$(systemctl list-units --type=service --all --no-legend "wss@*" 2>/dev/null | awk '{print $1}')
    for u in $units; do systemctl stop "$u" 2>/dev/null; done
    sleep 1
}

configure_wss() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}          ⚙️  CONFIGURAR DESTINO — WSS TLS                      ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local atual; atual=$(get_wss_dest)
    echo -e "${W}Destino atual : ${C}$atual${NC}"
    echo ""
    echo -ne "${W}Novo destino — formato 127.0.0.1:22 (Enter para manter ${C}$atual${W}): ${NC}"
    read -r novo
    [ -z "$novo" ] && novo="$atual"

    mkdir -p "$WSS_DIR"
    echo "WSS_DEST=${novo}" > "$WSS_CONF"

    echo ""
    echo -e "${G}✅ Configuração salva!${NC}"

    local portas_ativas; portas_ativas=$(wss_active_ports)
    if [ "$portas_ativas" != "--" ]; then
        echo -ne "${Y}Já está ativo. Reiniciar agora pra aplicar o novo destino? (s/n): ${NC}"
        read -r restart_now
        if [[ "$restart_now" == "s" ]]; then
            for p in ${portas_ativas//\// }; do systemctl restart "wss@${p}" 2>/dev/null; done
            echo -e "${G}Reiniciado.${NC}"
        fi
    fi
    read -rp "ENTER para voltar..."
}

# ── 3. WSS SSH (wss_security.py — sem TLS) ───────────────────────
# Protocolo independente do WSS TLS acima — código próprio, sem
# nenhuma linha alterada.

check_wsssec_bin() {
    if [ ! -f "$BASE/wss_security.py" ]; then
        echo -e "${R}[ERRO] Script não encontrado: $BASE/wss_security.py${NC}"
        echo -e "${Y}       Reinstale/atualize o painel — o wss_security.py deve vir junto.${NC}"
        return 1
    fi
    return 0
}

get_wsssec_dest() {
    [ -f "$WSSSEC_CONF" ] && grep -oP 'WSSSEC_DEST=\K.*' "$WSSSEC_CONF" 2>/dev/null || echo "127.0.0.1:22"
}

check_wsssec_any() {
    if systemctl list-units --type=service --all --no-legend "wss-security@*" 2>/dev/null \
        | awk '{print $1}' | xargs -r -n1 systemctl is-active --quiet 2>/dev/null; then
        echo -e "${C}ATIVO${NC}"
    else
        echo -e "${R}PARADO${NC}"
    fi
}

wsssec_active_ports() {
    local ports
    ports=$(systemctl list-units --type=service --state=running --no-legend "wss-security@*" 2>/dev/null \
        | awk '{print $1}' | sed -E "s/^wss-security@([0-9]+)\.service\$/\1/" | tr '\n' '/')
    [ -n "$ports" ] && echo "${ports%/}" || echo "--"
}

start_wsssec() {
    local porta=$1
    check_wsssec_bin || { sleep 2; return; }
    systemctl stop "proxy@${porta}" "wss@${porta}" 2>/dev/null
    sleep 1
    systemctl enable --now "wss-security@${porta}" 2>/dev/null
    sleep 1
    if systemctl is-active --quiet "wss-security@${porta}"; then
        echo -e "${G}[OK] WSS SSH ativo na porta $porta!${NC}"
        echo -e "${W}     Destino: ${C}$(get_wsssec_dest)${NC}"
    else
        echo -e "${R}[ERRO] wss-security@${porta} não subiu. Verifique: systemctl status wss-security@${porta}${NC}"
    fi
}

stop_wsssec_port() {
    systemctl stop "wss-security@${1}" 2>/dev/null
    echo -e "${G}Parado na porta $1.${NC}"
}

stop_wsssec_all() {
    local units
    units=$(systemctl list-units --type=service --all --no-legend "wss-security@*" 2>/dev/null | awk '{print $1}')
    for u in $units; do systemctl stop "$u" 2>/dev/null; done
    sleep 1
}

configure_wsssec() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}          ⚙️  CONFIGURAR DESTINO — WSS SSH                      ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local atual; atual=$(get_wsssec_dest)
    echo -e "${W}Destino atual : ${C}$atual${NC}"
    echo ""
    echo -ne "${W}Novo destino — formato 127.0.0.1:22 (Enter para manter ${C}$atual${W}): ${NC}"
    read -r novo
    [ -z "$novo" ] && novo="$atual"

    mkdir -p "$WSSSEC_DIR"
    echo "WSSSEC_DEST=${novo}" > "$WSSSEC_CONF"

    echo ""
    echo -e "${G}✅ Configuração salva!${NC}"

    local portas_ativas; portas_ativas=$(wsssec_active_ports)
    if [ "$portas_ativas" != "--" ]; then
        echo -ne "${Y}Já está ativo. Reiniciar agora pra aplicar o novo destino? (s/n): ${NC}"
        read -r restart_now
        if [[ "$restart_now" == "s" ]]; then
            for p in ${portas_ativas//\// }; do systemctl restart "wss-security@${p}" 2>/dev/null; done
            echo -e "${G}Reiniciado.${NC}"
        fi
    fi
    read -rp "ENTER para voltar..."
}

# ── 4. STUNNEL SSL (SSH sobre TLS "cru") ─────────────────────────

stunnel_bin() { command -v stunnel4 || command -v stunnel; }

ensure_stunnel_bin() {
    local bin; bin=$(stunnel_bin)
    if [ -n "$bin" ]; then echo "$bin"; return 0; fi
    apt-get update -y &>/dev/null; apt-get install -y stunnel4 &>/dev/null
    stunnel_bin
}

ensure_stunnel_cert() {
    [ -f "$STUNNEL_CERT" ] && return 0
    mkdir -p "$STUNNEL_DIR"
    openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -sha256 \
        -subj "/CN=Painel Netsimon" -keyout "$STUNNEL_CERT" -out "$STUNNEL_CERT" &>/dev/null
    chmod 600 "$STUNNEL_CERT"
}

get_stunnel_settings() {
    local port="$STUNNEL_DEFAULT_PORT" dest="127.0.0.1:22"
    if [ -f "$STUNNEL_SETTINGS" ]; then
        port=$(grep -oP 'STUNNEL_PORT=\K.*' "$STUNNEL_SETTINGS" 2>/dev/null); port=${port:-$STUNNEL_DEFAULT_PORT}
        dest=$(grep -oP 'STUNNEL_DEST=\K.*' "$STUNNEL_SETTINGS" 2>/dev/null); dest=${dest:-127.0.0.1:22}
    fi
    echo "$port|$dest"
}

write_stunnel_conf() {
    local port=$1 dest=$2
    mkdir -p "$STUNNEL_DIR"
    printf 'STUNNEL_PORT=%s\nSTUNNEL_DEST=%s\n' "$port" "$dest" > "$STUNNEL_SETTINGS"
    cat > "$STUNNEL_CONF" <<EOF
pid = /var/run/${STUNNEL_UNIT}.pid
cert = ${STUNNEL_CERT}
client = no
foreground = yes
output = /var/log/netsimon_stunnel.log
socket = a:SO_REUSEADDR=1

[${STUNNEL_UNIT}]
accept = ${port}
connect = ${dest}
EOF
}

write_stunnel_unit() {
    local bin=$1
    local unit_path="/etc/systemd/system/${STUNNEL_UNIT}.service"
    [ -f "$unit_path" ] && return 0
    cat > "$unit_path" <<EOF
[Unit]
Description=Painel Netsimon - STUNNEL SSL (SSH sobre TLS "cru")
After=network.target

[Service]
Type=simple
ExecStart=${bin} ${STUNNEL_CONF}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

start_stunnel() {
    local porta=$1 destino=$2
    local bin; bin=$(ensure_stunnel_bin)
    if [ -z "$bin" ]; then
        echo -e "${R}[ERRO] Não foi possível instalar o stunnel — verifique a conexão com a internet.${NC}"
        return
    fi
    ensure_stunnel_cert
    write_stunnel_conf "$porta" "$destino"
    write_stunnel_unit "$bin"

    systemctl stop "proxy@${porta}" "wss@${porta}" "wss-security@${porta}" 2>/dev/null
    sleep 1
    systemctl enable --now "$STUNNEL_UNIT" &>/dev/null
    sleep 1
    if systemctl is-active --quiet "$STUNNEL_UNIT"; then
        echo -e "${G}[OK] STUNNEL SSL ativo — porta ${porta} -> ${destino}${NC}"
    else
        echo -e "${R}[ERRO] $STUNNEL_UNIT não subiu. Verifique: systemctl status $STUNNEL_UNIT${NC}"
    fi
}

stop_stunnel() {
    systemctl stop "$STUNNEL_UNIT" 2>/dev/null
    echo -e "${G}STUNNEL SSL parado.${NC}"
}

configure_stunnel() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                ⚙️  CONFIGURAR STUNNEL SSL (portas)             ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    IFS='|' read -r porta_atual dest_atual <<< "$(get_stunnel_settings)"
    echo -e "${W}Porta de entrada atual        : ${C}$porta_atual${NC}"
    echo -e "${W}Porta de direcionamento atual : ${C}$dest_atual${NC}"
    echo ""

    echo -ne "${W}Nova porta de entrada (Enter para manter ${C}$porta_atual${W}): ${NC}"
    read -r nova_porta
    [ -z "$nova_porta" ] && nova_porta="$porta_atual"
    if ! [[ "$nova_porta" =~ ^[0-9]+$ ]] || [ "$nova_porta" -lt 1 ] || [ "$nova_porta" -gt 65535 ]; then
        echo -e "${R}Porta inválida.${NC}"; sleep 2; return
    fi

    echo -ne "${W}Novo destino — formato 127.0.0.1:22 (Enter para manter ${C}$dest_atual${W}): ${NC}"
    read -r novo_destino
    [ -z "$novo_destino" ] && novo_destino="$dest_atual"
    if ! [[ "$novo_destino" =~ ^[A-Za-z0-9_.-]+:[0-9]{1,5}$ ]]; then
        echo -e "${R}Destino inválido.${NC}"; sleep 2; return
    fi

    start_stunnel "$nova_porta" "$novo_destino"
    read -rp "ENTER para voltar..."
}

# Relatório completo de WebSocket (4 sistemas)
relatorio_portas() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                📊 RELATÓRIO DE PORTAS WEBSOCKET               ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    IFS='|' read -r stunnel_port _ <<< "$(get_stunnel_settings)"

    echo -e "${W}── PORTAS EM LISTEN ─────────────────────────────────────────${NC}"
    lsof -i :80,8443,8888,"${stunnel_port}" -sTCP:LISTEN 2>/dev/null || echo "  nenhuma porta relevante em listen"

    echo ""
    echo -e "${W}── PROCESSOS WEBSOCKET ATIVOS ───────────────────────────────${NC}"
    ps aux 2>/dev/null | grep -E "proxy\.py|wss\.py|wss_security\.py|stunnel" | grep -v grep \
        | awk '{printf "  PID %-7s %s\n", $2, substr($0, index($0,$11))}'

    echo ""
    echo -e "${W}── CONEXÕES ATIVAS NAS PORTAS WS (top 20) ───────────────────${NC}"
    ss -tnp 2>/dev/null | grep -E ":80 |:8443 |:8888 |:${stunnel_port} " | grep ESTAB | head -20 \
        || echo "  nenhuma conexão ativa no momento"

    echo ""
    read -rp "ENTER para voltar..."
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: WSS TLS
# ══════════════════════════════════════════════════════════════════
menu_wss() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                🔒 WSS TLS MANAGER (TLS real)                   ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

        local status_bin
        if check_wss_bin &>/dev/null; then status_bin="${G}Disponível${NC}"; else status_bin="${R}Incompleto — reinstale o painel${NC}"; fi
        local dest_conf; dest_conf=$(get_wss_dest)

        printf "${P}║${NC} ${W}Binário  :${NC} %-40b\n" "$status_bin"
        printf "${P}║${NC} ${W}Status   :${NC} %-40b\n" "$(check_wss_any)"
        printf "${P}║${NC} ${W}Portas   : ${C}%-38s${NC}\n" "$(wss_active_ports)"
        printf "${P}║${NC} ${W}Destino  : ${Y}%-38s${NC}\n" "$dest_conf"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Iniciar na porta padrão ${C}${WSS_DEFAULT_PORT}${NC}"
        echo -e "${P}║${T} 2)${NC} Iniciar em porta personalizada"
        echo -e "${P}║${T} 3)${NC} Parar porta padrão"
        echo -e "${P}║${T} 4)${NC} Parar porta personalizada"
        echo -e "${P}║${T} 5)${NC} Parar TODAS as instâncias"
        echo -e "${P}║${T} 6)${NC} ⚙️  Configurar Destino"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r sop

        case "$sop" in
            1) start_wss "$WSS_DEFAULT_PORT"; sleep 2 ;;
            2)
                echo -ne "${W}Digite a porta: ${NC}"; read -r porta_custom
                if [[ "$porta_custom" =~ ^[0-9]+$ ]] && [ "$porta_custom" -ge 1 ] && [ "$porta_custom" -le 65535 ]; then
                    start_wss "$porta_custom"
                else
                    echo -e "${R}Porta inválida.${NC}"
                fi
                sleep 2 ;;
            3) stop_wss_port "$WSS_DEFAULT_PORT"; sleep 2 ;;
            4)
                echo -ne "${W}Digite a porta para parar: ${NC}"; read -r porta_stop
                [[ "$porta_stop" =~ ^[0-9]+$ ]] && stop_wss_port "$porta_stop" || echo -e "${R}Porta inválida.${NC}"
                sleep 2 ;;
            5)
                echo -ne "${R}Parar TODAS as instâncias? (s/n): ${NC}"; read -r conf_all
                [[ "$conf_all" == "s" ]] && { stop_wss_all; echo -e "${G}Encerradas.${NC}"; }
                sleep 2 ;;
            6) configure_wss ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$sop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: WSS SSH
# ══════════════════════════════════════════════════════════════════
menu_wsssec() {
    while true; do
        clear
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}                🔐 WSS SSH MANAGER (sem TLS)                    ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

        local status_bin
        if check_wsssec_bin &>/dev/null; then status_bin="${G}Disponível${NC}"; else status_bin="${R}Incompleto — reinstale o painel${NC}"; fi
        local dest_conf; dest_conf=$(get_wsssec_dest)

        printf "${P}║${NC} ${W}Binário  :${NC} %-40b\n" "$status_bin"
        printf "${P}║${NC} ${W}Status   :${NC} %-40b\n" "$(check_wsssec_any)"
        printf "${P}║${NC} ${W}Portas   : ${C}%-38s${NC}\n" "$(wsssec_active_ports)"
        printf "${P}║${NC} ${W}Destino  : ${Y}%-38s${NC}\n" "$dest_conf"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Iniciar na porta padrão ${C}${WSSSEC_DEFAULT_PORT}${NC}"
        echo -e "${P}║${T} 2)${NC} Iniciar em porta personalizada"
        echo -e "${P}║${T} 3)${NC} Parar porta padrão"
        echo -e "${P}║${T} 4)${NC} Parar porta personalizada"
        echo -e "${P}║${T} 5)${NC} Parar TODAS as instâncias"
        echo -e "${P}║${T} 6)${NC} ⚙️  Configurar Destino"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r sop

        case "$sop" in
            1) start_wsssec "$WSSSEC_DEFAULT_PORT"; sleep 2 ;;
            2)
                echo -ne "${W}Digite a porta: ${NC}"; read -r porta_custom
                if [[ "$porta_custom" =~ ^[0-9]+$ ]] && [ "$porta_custom" -ge 1 ] && [ "$porta_custom" -le 65535 ]; then
                    start_wsssec "$porta_custom"
                else
                    echo -e "${R}Porta inválida.${NC}"
                fi
                sleep 2 ;;
            3) stop_wsssec_port "$WSSSEC_DEFAULT_PORT"; sleep 2 ;;
            4)
                echo -ne "${W}Digite a porta para parar: ${NC}"; read -r porta_stop
                [[ "$porta_stop" =~ ^[0-9]+$ ]] && stop_wsssec_port "$porta_stop" || echo -e "${R}Porta inválida.${NC}"
                sleep 2 ;;
            5)
                echo -ne "${R}Parar TODAS as instâncias? (s/n): ${NC}"; read -r conf_all
                [[ "$conf_all" == "s" ]] && { stop_wsssec_all; echo -e "${G}Encerradas.${NC}"; }
                sleep 2 ;;
            6) configure_wsssec ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Opção inválida: '$sop'${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  SUBMENU: STUNNEL SSL
# ══════════════════════════════════════════════════════════════════
menu_stunnel() {
    while true; do
        clear
        IFS='|' read -r porta_atual dest_atual <<< "$(get_stunnel_settings)"
        echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${P}║${W}          🛡️  STUNNEL SSL MANAGER — SSH sobre TLS \"cru\"          ${P}║${NC}"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        printf "${P}║${NC} ${W}Status  :${NC} %-40b\n" "$(systemctl is-active --quiet "$STUNNEL_UNIT" && echo -e "${G}● ATIVO${NC}" || echo -e "${R}○ PARADO${NC}")"
        printf "${P}║${NC} ${W}Entrada : ${C}%-38s${NC}\n" "$porta_atual"
        printf "${P}║${NC} ${W}Destino : ${Y}%-38s${NC}\n" "$dest_atual"
        echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${P}║${T} 1)${NC} Iniciar / Aplicar na porta padrão ${C}2053${NC}"
        echo -e "${P}║${T} 2)${NC} ⚙️  Configurar portas (entrada + destino)"
        echo -e "${P}║${T} 3)${NC} Parar STUNNEL SSL"
        echo -e "${P}║${T} 4)${NC} ↺ Reiniciar STUNNEL SSL"
        echo -e "${P}║${R} 0)${NC} Voltar"
        echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo -ne "${Y} Escolha: ${NC}"; read -r sop

        case "$sop" in
            1) start_stunnel "$STUNNEL_DEFAULT_PORT" "$dest_atual"; sleep 2 ;;
            2) configure_stunnel ;;
            3) stop_stunnel; sleep 2 ;;
            4) systemctl restart "$STUNNEL_UNIT" 2>/dev/null && echo -e "${G}Reiniciado!${NC}" || echo -e "${R}Falha.${NC}"; sleep 2 ;;
            0) return ;;
            "") ;;
            *) echo -e "${R}Inválido!${NC}"; sleep 1 ;;
        esac
    done
}

# ══════════════════════════════════════════════════════════════════
#  MENU PRINCIPAL DO WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════════
while true; do
    clear
    IFS='|' read -r stunnel_port stunnel_dest <<< "$(get_stunnel_settings)"
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}             🌐 PAINEL NETSIMON — WEBSOCKET MANAGER              ${P}║${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  1. WS PROXY (porta 80, sem TLS) ───────────────────────────${P}║${NC}"
    printf "${P}║${NC}  ${W}PORTA  80  :${NC} %-38b\n" "$(check_proto 80)"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  2. WSS TLS (porta 8443, TLS real) ──────────────────────────${P}║${NC}"
    printf "${P}║${NC}  ${W}PORTA 8443 :${NC} %-38b\n" "$(check_proto "$WSS_DEFAULT_PORT")"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  3. WSS SSH (porta 8888, sem TLS) ───────────────────────────${P}║${NC}"
    printf "${P}║${NC}  ${W}PORTA 8888 :${NC} %-38b\n" "$(check_proto "$WSSSEC_DEFAULT_PORT")"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${W}  4. STUNNEL SSL — SSH sobre TLS \"cru\" (porta ${stunnel_port}) ─────${NC}${P}  ║${NC}"
    printf "${P}║${NC}  ${W}PORTA %-5s:${NC} %-38b\n" "$stunnel_port" "$(check_proto "$stunnel_port")"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 1)${NC} Iniciar WS PROXY ${C}(Porta 80)${NC}"
    echo -e "${P}║${T} 2)${NC} Parar Porta 80"
    echo -e "${P}║${T} 3)${NC} 🔒 Gerenciar WSS TLS"
    echo -e "${P}║${T} 4)${NC} 🔐 Gerenciar WSS SSH"
    echo -e "${P}║${T} 5)${NC} 🛡️  Gerenciar STUNNEL SSL"
    echo -e "${P}║${T} 6)${NC} ↺ Reiniciar os 4 sistemas (portas padrão)"
    echo -e "${P}║${T} 7)${NC} 📊 Relatório de portas"
    echo -e "${P}║${R} 0)${NC} Voltar"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -ne "${Y} Escolha: ${NC}"; read -r opt

    case "$opt" in
        1) start_proxy 80; sleep 2 ;;
        2)
            stop_proxy_port 80 \
                && echo -e "${G}Porta 80 encerrada.${NC}" \
                || echo -e "${Y}Nada rodando na 80.${NC}"
            sleep 2 ;;
        3) menu_wss ;;
        4) menu_wsssec ;;
        5) menu_stunnel ;;
        6)
            systemctl restart proxy@80 "wss@${WSS_DEFAULT_PORT}" \
                "wss-security@${WSSSEC_DEFAULT_PORT}" "$STUNNEL_UNIT" 2>/dev/null
            echo -e "${G}Os 4 sistemas foram reiniciados.${NC}"
            sleep 2 ;;
        7) relatorio_portas ;;
        0) exit 0 ;;
        "") ;;
        *) echo -e "${R}Inválido!${NC}"; sleep 1 ;;
    esac
done
