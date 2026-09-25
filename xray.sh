#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - XRAY MANAGER
# ==========================================

BASE="/etc/painel"
USERDB="$BASE/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
SSL_DIR="/etc/xray-manager/ssl"

C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'
Y=$'\033[1;33m'; W=$'\033[1;37m'; M=$'\033[1;35m'; NC=$'\033[0m'
BG_G=$'\033[42m'; BG_R=$'\033[41m'
# Azul turquesa #00FFEF (true color) — cor de todas as opções deste menu
T=$'\033[38;2;0;255;239m'

source "$BASE/xray_lib.sh" 2>/dev/null || {
    echo -e "${R}ERRO: xray_lib.sh não encontrado em $BASE. Reinstale o painel.${NC}"
    sleep 3; exit 1
}
source "$BASE/online.sh" 2>/dev/null

# ------------------------------------------------------------------
# STATUS / PORTAS
# Ignora o inbound "dokodemo-door" (api, porta 2000) e mostra TODAS
# as portas de tráfego real, cruzando com o que está de fato em
# LISTEN, pra refletir a realidade do servidor.
# ------------------------------------------------------------------
draw_status() {
    if systemctl is-active --quiet xray; then
        status_text="${BG_G}${W} ONLINE ${NC}"
    else
        status_text="${BG_R}${W} OFFLINE ${NC}"
    fi
    local host; host=$(jq -r '[.inbounds[] | select(.protocol != "dokodemo-door")][0].streamSettings.xhttpSettings.host // "N/A"' "$XRAY_CONF" 2>/dev/null)

    local portas_fmt=""
    while IFS='|' read -r porta proto pstatus; do
        [ -z "$porta" ] && continue
        local cor="$Y"
        [ "$pstatus" = "ATIVA" ] && cor="$G"
        [ "$pstatus" = "INATIVA" ] && cor="$R"
        portas_fmt+="${cor}${porta}${NC}${W}/${Y}${proto}${NC} "
    done < <(xray_list_active_ports)
    [ -z "$portas_fmt" ] && portas_fmt="${R}nenhuma${NC}"

    local xray_online; xray_online=$(command -v netsimon_online_count_xray &>/dev/null && netsimon_online_count_xray || echo 0)

    echo -e "${M}────────────────────────────────────────────────────────────${NC}"
    echo -e " STATUS: $status_text  ${W}|${NC} PORTAS: $portas_fmt"
    echo -e " CLIENTES XRAY ONLINE AGORA: ${G}${xray_online}${NC}"
    echo -e " HOST: ${Y}${host:0:40}${NC}"
    echo -e "${M}────────────────────────────────────────────────────────────${NC}"
}

# ------------------------------------------------------------------
# INSTALAR / RECONFIGURAR XRAY
# CORREÇÃO: antes desta função escrevia direto em $XRAY_CONF sem
# garantir que o Xray (binário + diretório /usr/local/etc/xray/)
# estivesse instalado. Se o Xray ainda não tivesse sido instalado
# neste servidor, o "cat > $XRAY_CONF" falhava com:
#   line 77: /usr/local/etc/xray/config.json: No such file or directory
# Agora a ordem correta é sempre respeitada:
#   1) instala o binário/serviço do Xray (se ainda não existir)
#   2) cria os diretórios necessários (config, SSL, log)
#   3) só então escreve o config.json
# ------------------------------------------------------------------
setup_xray() {
    clear
    echo -e "${C}⚙️  Configurando Xray xHTTP TLS...${NC}"
    # [PATCH] Evita qualquer prompt interativo do apt/dpkg, já que este
    # script roda numa sessão própria e não herda o DEBIAN_FRONTEND
    # definido no instalador principal (install.sh).
    export DEBIAN_FRONTEND=noninteractive
    apt update -qq && apt install -y jq openssl curl ufw &>/dev/null

    # 1. Garante que o binário do Xray existe ANTES de mexer no config
    if [ ! -f /usr/local/bin/xray ]; then
        echo -e "${Y}[+] Xray não encontrado neste servidor — instalando binário...${NC}"
        bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) &>/dev/null
        setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray 2>/dev/null
    fi

    # 2. Garante os diretórios (config.json, SSL e log) antes do cat >
    mkdir -p "$SSL_DIR" "$(dirname "$XRAY_CONF")" /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chmod -R 777 /var/log/xray

    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -subj "/C=BR/ST=SP/L=SaoPaulo/O=Painel Netsimon/CN=www.tim.com.br" \
        -keyout "$SSL_DIR/privkey.pem" -out "$SSL_DIR/fullchain.pem" &>/dev/null
    chmod 644 "$SSL_DIR/privkey.pem" "$SSL_DIR/fullchain.pem"

    # Preserva clientes existentes
    local existing_clients="[]"
    if [ -f "$XRAY_CONF" ]; then
        existing_clients=$(jq -r '.inbounds[0].settings.clients // []' "$XRAY_CONF" 2>/dev/null || echo "[]")
    fi

    # 3. Só agora escreve o config.json
    cat > "$XRAY_CONF" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "api": {
    "services": ["HandlerService","LoggerService","StatsService"],
    "tag": "api"
  },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserDownlink": true, "statsUserOnline": true, "statsUserUplink": true } },
    "system": { "statsInboundDownlink": true, "statsInboundUplink": true }
  },
  "inbounds": [
    {
      "tag": "api",
      "port": 2000,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "listen": "127.0.0.1"
    },
    {
      "tag": "inbound-netsimon",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": $existing_clients, "decryption": "none" },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "xhttpSettings": {
          "path": "/",
          "host": "",
          "mode": "",
          "noSSEHeader": false,
          "scMaxBufferedPosts": 30,
          "scMaxEachPostBytes": "1000000",
          "scStreamUpServerSecs": "20-80",
          "xPaddingBytes": "100-1000"
        },
        "tlsSettings": {
          "certificates": [{ "certificateFile": "$SSL_DIR/fullchain.pem", "keyFile": "$SSL_DIR/privkey.pem" }],
          "alpn": ["http/1.1"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": { "domainStrategy": "UseIP" }, "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "inboundTag": ["api"], "outboundTag": "api", "type": "field" },
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
    ]
  }
}
EOF

    # Watchdog
    echo "* * * * * root if ! systemctl is-active --quiet xray; then systemctl restart xray; fi" \
        > /etc/cron.d/xray_watchdog

    # Garante o serviço systemd — cobre o caso do binário já existir mas
    # o service ter sido removido (ex: via "Desinstalar Xray" deste menu)
    if [ ! -f /etc/systemd/system/xray.service ]; then
        cat > /etc/systemd/system/xray.service <<'EOFSVC'
[Unit]
Description=Xray Service - Painel Netsimon
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOFSVC
        systemctl enable xray &>/dev/null
    fi

    systemctl daemon-reload
    systemctl restart xray
    echo -e "${G}✅ Xray configurado! Clientes preservados.${NC}"
    sleep 2
}

# ------------------------------------------------------------------
# CRIAR USUÁRIO XRAY — em sincronia com adduser.sh (mesmo fluxo local:
# sistema Linux + usuarios.db + Xray com lock/dedup)
# ------------------------------------------------------------------
add_user_xray() {
    clear
    draw_status
    echo -ne "${W}👤 Nome do Usuário: ${NC}"; read nick
    [ -z "$nick" ] && return

    # Mesmo critério de duplicidade usado em adduser.sh/addtest.sh
    if grep -qw "^$nick|" "$USERDB" 2>/dev/null || id "$nick" &>/dev/null; then
        echo -e "\n${R}Erro: já existe um usuário com esse nome (local ou Linux)!${NC}"
        read -p "ENTER..."
        return
    fi

    echo -ne "${W}🔑 Senha (Enter p/ padrão): ${NC}"; read pass
    [ -z "$pass" ] && pass="netsimon"
    echo -ne "${W}📅 Dias de Validade: ${NC}"; read dias
    [ -z "$dias" ] && dias=30
    echo -ne "${W}🔢 Limite de Conexões: ${NC}"; read limite
    [ -z "$limite" ] && limite=1

    uuid=$(cat /proc/sys/kernel/random/uuid)
    exp=$(date -d "+$dias days" +"%Y-%m-%d 23:59:59")
    exp_date=$(date -d "+$dias days" +%d/%m/%Y)

    # ---- Sistema Linux (igual adduser.sh, pra funcionar com SSH/limiter) ----
    useradd -M -s /bin/false "$nick" &>/dev/null
    echo "$nick:$pass" | chpasswd &>/dev/null
    chage -E "$(date -d "+$dias days" +%Y-%m-%d)" "$nick" 2>/dev/null

    # ---- Xray (com lock + checagem de duplicidade real) ----
    xray_add_client_safe "$nick" "$uuid" 443
    xray_rc=$?

    if [ "$xray_rc" -eq 1 ]; then
        echo -e "${R}❌ Erro ao salvar no Xray.${NC}"
        userdel -f "$nick" &>/dev/null
        read -p "ENTER..."
        return
    fi
    [ "$xray_rc" -eq 2 ] && echo -e "${Y}⚠ Já existia esse email no Xray, reaproveitado.${NC}"

    systemctl restart xray

    # ---- Banco Local (pra aparecer em "Listar Usuários" e no limiter) ----
    echo "$nick|$uuid|$exp|$pass|$limite" >> "$USERDB"

    local host; host=$(jq -r '[.inbounds[] | select(.protocol != "dokodemo-door")][0].streamSettings.xhttpSettings.host // "HOST"' "$XRAY_CONF")
    local porta; porta=$(jq -r '[.inbounds[] | select(.protocol != "dokodemo-door")][0].port' "$XRAY_CONF")

    echo -e "${G}✅ USUÁRIO XRAY CRIADO!${NC}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${W}Validade: ${Y}$exp_date${NC}  ${W}Limite: ${Y}$limite${NC}"
    echo -e "${Y}VLESS LINK:${NC}"
    echo -e "${C}vless://$uuid@m.ofertas.tim.com.br:$porta?encryption=none&flow=none&type=xhttp&host=$host&path=%2F&security=tls&sni=www.tim.com.br#$nick${NC}"
    read -p "ENTER..."
}

# ------------------------------------------------------------------
# LISTA COMPLETA DE USUÁRIOS — UUID sem cortar
# Na tela inicial (menu.sh, opção 01 -> 5) o UUID aparece cortado
# ("${uuid:0:8}...") pra caber na tabela. Aqui mostra o UUID inteiro.
# ------------------------------------------------------------------
list_users_full() {
    clear
    echo -e "${C}  🛰️  XRAY MANAGER — USUÁRIOS (UUID COMPLETO)${NC}"
    draw_status
    local total=0
    while IFS='|' read -r email uuid porta; do
        [ -z "$email" ] && continue
        ((total++))
        printf "${W}%-20s${NC} ${M}porta %-5s${NC}\n  ${C}%s${NC}\n\n" "$email" "$porta" "$uuid"
    done < <(xray_list_users_full)

    if [ "$total" -eq 0 ]; then
        echo -e "${Y}Nenhum usuário cadastrado no Xray no momento.${NC}"
    else
        echo -e "${M}────────────────────────────────────────────────────────────${NC}"
        echo -e "${W}Total: ${G}$total${NC} usuário(s)"
    fi
    read -p "ENTER para voltar..."
}

# ------------------------------------------------------------------
# DESINSTALAR XRAY COMPLETAMENTE — confirmação apenas com ENTER
# ------------------------------------------------------------------
uninstall_xray() {
    clear
    echo -e "${R}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${R}║${W}          ⚠️   DESINSTALAR XRAY COMPLETAMENTE   ⚠️            ${R}║${NC}"
    echo -e "${R}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${Y}Isso vai remover:${NC}"
    echo -e "  ${W}- O binário e serviço do Xray (systemd)${NC}"
    echo -e "  ${W}- $XRAY_CONF (config e TODOS os clientes/UUIDs)${NC}"
    echo -e "  ${W}- Certificados SSL em $SSL_DIR${NC}"
    echo -e "  ${W}- O watchdog do cron (/etc/cron.d/xray_watchdog)${NC}"
    echo -e "${R}Os usuários continuam cadastrados em $USERDB,${NC}"
    echo -e "${R}mas perdem acesso via Xray até reinstalar (opção 1 deste menu).${NC}"
    echo ""
    echo -ne "${W}Pressione ${T}ENTER${W} para confirmar a desinstalação, ou ${C}CTRL+C${W} para cancelar: ${NC}"
    read -r _confirm

    echo -e "${Y}Removendo Xray...${NC}"
    systemctl stop xray &>/dev/null
    systemctl disable xray &>/dev/null

    # Desinstalador oficial do XTLS (remove binário + serviço systemd)
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove --purge &>/dev/null

    rm -f /etc/systemd/system/xray.service
    rm -f /etc/cron.d/xray_watchdog
    rm -rf "$SSL_DIR"
    rm -f "$XRAY_CONF"
    systemctl daemon-reload

    echo -e "${G}✅ Xray desinstalado completamente.${NC}"
    echo -e "${W}Use a opção ${T}[1] Instalar / Reconfigurar Xray${W} pra reinstalar quando quiser.${NC}"
    read -p "ENTER..."
}

while true; do
    clear
    echo -e "${C}  🛰️  PAINEL NETSIMON - XRAY MANAGER${NC}"
    draw_status
    echo -e " ${T}[1]${NC} Instalar / Reconfigurar Xray"
    echo -e " ${T}[2]${NC} Criar Usuário Xray"
    echo -e " ${T}[3]${NC} 📋 Ver Lista de Usuários (UUID completo)"
    echo -e " ${M}────────────────────────────────────────────────────────────${NC}"
    echo -e " ${T}[4]${NC} 🔄 Reiniciar"
    echo -e " ${T}[5]${NC} 🛑 Parar"
    echo -e " ${T}[6]${NC} 🌐 Mudar Host"
    echo -e " ${T}[7]${NC} 🔌 Mudar Porta"
    echo -e " ${M}────────────────────────────────────────────────────────────${NC}"
    echo -e " ${T}[8]${NC} 🗑️  Desinstalar Xray Completamente"
    echo -e " ${R}[0]${NC} Sair"
    echo -e "${M}────────────────────────────────────────────────────────────${NC}"
    echo -ne " Escolha: "; read opt
    case $opt in
        1) setup_xray ;;
        2) add_user_xray ;;
        3) list_users_full ;;
        4) systemctl restart xray && echo -e "${G}OK!${NC}" && sleep 1 ;;
        5) systemctl stop xray && echo -e "${R}OK!${NC}" && sleep 1 ;;
        6)
            echo -ne "Novo Host: "; read nhost
            jq --arg h "$nhost" \
                '(.inbounds[] | select(.port==443)).streamSettings.xhttpSettings.host = $h' \
                "$XRAY_CONF" > /tmp/xc.tmp && mv /tmp/xc.tmp "$XRAY_CONF"
            systemctl restart xray ;;
        7)
            echo -ne "Nova Porta: "; read nport
            jq --argjson p "$nport" '(.inbounds[] | select(.port==443)).port = $p' \
                "$XRAY_CONF" > /tmp/xc.tmp && mv /tmp/xc.tmp "$XRAY_CONF"
            ufw allow "$nport"/tcp &>/dev/null
            systemctl restart xray ;;
        8) uninstall_xray ;;
        0) exit 0 ;;
    esac
done