#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - REPAIR SYSTEM
# ==========================================

BASE="/etc/painel"
WEBROOT="/var/www/html"
REPO="https://raw.githubusercontent.com/miau4/Painel-Netsimon/main"
C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'

clear
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${C}║${W}            🛠️  REPARANDO SISTEMA PAINEL NETSIMON                ${C}║${NC}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${NC}"

arquivos=(
    "menu.sh" "adduser.sh" "addtest.sh" "deluser.sh"
    "online.sh" "limit.sh" "unblock.sh" "websocket.sh"
    "xray.sh" "xray_lib.sh" "slowdns-server.sh" "monitor.sh" "proxy.py" "wss.py" "wss_security.py"
    "boot_check.sh" "repair.sh" "checkuser.py" "checkuser.sh"
    "painel_api.py" "bot_telegram.py" "migrate_ssh_xhttp.sh" "setup_https_domain.sh"
)

for file in "${arquivos[@]}"; do
    printf "${W}[+] Restaurando: ${Y}%-20s${NC}" "$file"
    wget -q -O "$BASE/$file" "$REPO/$file?$(date +%s)"
    if [ -s "$BASE/$file" ]; then
        chmod +x "$BASE/$file"
        dos2unix "$BASE/$file" &>/dev/null
        echo -e "${G}[ OK ]${NC}"
    else
        echo -e "${R}[ FALHA ]${NC}"
    fi
done

# Item: binário do dnstt-server (SlowDNS) -- fica FORA do loop acima de
# propósito, porque ele roda "dos2unix" em tudo, e isso corromperia um
# binário. Só baixa se ainda não existir (nunca sobrescreve uma cópia
# já funcionando à toa).
if [ ! -s "$BASE/dnstt-server" ]; then
    printf "${W}[+] Restaurando: ${Y}%-20s${NC}" "dnstt-server"
    wget -q -O "$BASE/dnstt-server" "$REPO/dnstt-server?$(date +%s)"
    if [ -s "$BASE/dnstt-server" ]; then
        chmod +x "$BASE/dnstt-server"
        echo -e "${G}[ OK ]${NC}"
    else
        echo -e "${R}[ FALHA ]${NC}"
    fi
fi

echo -e "${Y}[!] Restaurando Painel Web (frontend)...${NC}"
frontend_files=(
    "index.html" "login.html" "dashboard.html" "usuarios.html" "todos-usuarios.html"
    "dispositivos.html" "xray.html" "websocket.html" "slowdns.html"
    "revendedores.html" "servidores.html" "diagnostico.html" "whatsapp.html"
    "app.html" "backup.html" "campanhas.html"
    "bot.html" "logs.html" "ia.html" "configuracoes.html"
)
for file in "${frontend_files[@]}"; do
    printf "${W}  -> %-20s ${NC}" "$file"
    wget -q -O "$WEBROOT/$file" "$REPO/$file?$(date +%s)"
    [ -s "$WEBROOT/$file" ] && echo -e "${G}[OK]${NC}" || echo -e "${R}[FALHA]${NC}"
done
mkdir -p "$WEBROOT/css" "$WEBROOT/js"
wget -q -O "$WEBROOT/css/painel.css" "$REPO/painel.css?$(date +%s)"
wget -q -O "$WEBROOT/js/painel.js" "$REPO/painel.js?$(date +%s)"
wget -q -O "$WEBROOT/img/logo.png" "$REPO/logo.png?$(date +%s)"
wget -q -O "$WEBROOT/img/painel_bg.mp4" "$REPO/painel_bg.mp4?$(date +%s)"

# Reset de permissões
chmod -R 777 /var/log/xray
setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray 2>/dev/null
systemctl daemon-reload
# v45: xray e proxy@80 só são reiniciados aqui se o admin JÁ tiver
# ativado manualmente cada um pelo painel (systemctl enable) — repair.sh
# conserta o que está quebrado, mas não reativa protocolo que o admin
# deixou desligado de propósito.
systemctl is-enabled --quiet xray 2>/dev/null && systemctl restart xray
systemctl restart netsimon-painel 2>/dev/null
systemctl restart nginx 2>/dev/null
# Item: checkuser, proxy (80) e limiter viraram serviços systemd
# próprios nesta versão (antes rodavam via screen/nohup) — faltava
# reiniciar os 3 aqui, então um "repair" não pegava problema neles.
systemctl restart checkuser 2>/dev/null
systemctl is-enabled --quiet proxy@80 2>/dev/null && systemctl restart proxy@80 2>/dev/null
systemctl restart limiter 2>/dev/null

# v40: wss@8443 (TLS real) — o repair não baixa unit files (nenhum
# .service vem do REPO — todos são gerados via heredoc no install),
# então recria a unit e o certificado aqui se estiverem faltando, e
# sempre reinicia o serviço.
mkdir -p /etc/painel/wss
if [ ! -f /etc/painel/wss/cert.pem ] || [ ! -f /etc/painel/wss/key.pem ]; then
    IP_ATUAL=$(curl -s -4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/painel/wss/key.pem -out /etc/painel/wss/cert.pem \
        -days 3650 -nodes -subj "/CN=${IP_ATUAL:-localhost}" >/dev/null 2>&1
    chmod 600 /etc/painel/wss/key.pem
fi
if [ ! -f /etc/painel/wss/wss.conf ]; then
    echo "WSS_DEST=127.0.0.1:22" > /etc/painel/wss/wss.conf
fi
if [ ! -f /etc/systemd/system/wss@.service ]; then
cat > /etc/systemd/system/wss@.service <<EOF
[Unit]
Description=Painel Netsimon WSS - WebSocket Security (TLS real) - porta %i
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/painel/wss/wss.conf
ExecStart=/usr/bin/python3 $BASE/wss.py %i --dest \${WSS_DEST} --cert /etc/painel/wss/cert.pem --key /etc/painel/wss/key.pem
Restart=always
RestartSec=3
StandardOutput=append:/var/log/netsimon_wss.log
StandardError=append:/var/log/netsimon_wss.log

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi
# v45: só reinicia se já estava ativado antes (não reativa protocolo
# que o admin deixou desligado de propósito).
systemctl is-enabled --quiet wss@8443 2>/dev/null && systemctl restart wss@8443 2>/dev/null

# v41: wss-security@8888 (sem TLS) — protocolo NOVO e independente do
# wss@ acima (wss_security.py, desenvolvido e testado separadamente).
# Mesmo raciocínio: recria unit/config se estiverem faltando, e sempre
# reinicia o serviço.
mkdir -p /etc/painel/wss-security
[ -f /etc/painel/wss-security/wss-security.conf ] || echo "WSSSEC_DEST=127.0.0.1:22" > /etc/painel/wss-security/wss-security.conf

if [ ! -f /etc/systemd/system/wss-security@.service ]; then
cat > /etc/systemd/system/wss-security@.service <<EOF
[Unit]
Description=Painel Netsimon - Websocket Security sem TLS - porta %i
After=network.target sshd.service
Wants=sshd.service

[Service]
Type=simple
EnvironmentFile=/etc/painel/wss-security/wss-security.conf
ExecStart=/usr/bin/python3 $BASE/wss_security.py --port %i --target \${WSSSEC_DEST}
Restart=always
RestartSec=2
StandardOutput=append:/var/log/netsimon_wss_security.log
StandardError=append:/var/log/netsimon_wss_security.log

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
fi
# v45: idem — só reinicia se já estava ativado antes.
systemctl is-enabled --quiet wss-security@8888 2>/dev/null && systemctl restart wss-security@8888 2>/dev/null

# v41: netsimon-stunnel (Stunnel — 4º modo do menu WebSocket) — mesmo
# raciocínio acima: recria diretório/cert/unit se estiverem faltando,
# e só reinicia se já houver config salva (Stunnel é opcional — pode
# nunca ter sido configurado nesse servidor).
if [ -f /etc/painel/stunnel/stunnel_settings.conf ]; then
    mkdir -p /etc/painel/stunnel
    if [ ! -f /etc/painel/stunnel/stunnel.pem ]; then
        openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -sha256 \
            -subj "/CN=Painel Netsimon" \
            -keyout /etc/painel/stunnel/stunnel.pem -out /etc/painel/stunnel/stunnel.pem >/dev/null 2>&1
        chmod 600 /etc/painel/stunnel/stunnel.pem
    fi
    STUNNEL_PORT_ATUAL=$(grep -oP 'STUNNEL_PORT=\K.*' /etc/painel/stunnel/stunnel_settings.conf 2>/dev/null); STUNNEL_PORT_ATUAL=${STUNNEL_PORT_ATUAL:-2053}
    STUNNEL_DEST_ATUAL=$(grep -oP 'STUNNEL_DEST=\K.*' /etc/painel/stunnel/stunnel_settings.conf 2>/dev/null); STUNNEL_DEST_ATUAL=${STUNNEL_DEST_ATUAL:-127.0.0.1:22}
    cat > /etc/painel/stunnel/stunnel.conf <<EOF
pid = /var/run/netsimon-stunnel.pid
cert = /etc/painel/stunnel/stunnel.pem
client = no
foreground = yes
output = /var/log/netsimon_stunnel.log
socket = a:SO_REUSEADDR=1

[netsimon-stunnel]
accept = ${STUNNEL_PORT_ATUAL}
connect = ${STUNNEL_DEST_ATUAL}
EOF
    if [ ! -f /etc/systemd/system/netsimon-stunnel.service ]; then
        STUNNEL_BIN=$(command -v stunnel4 || command -v stunnel)
        cat > /etc/systemd/system/netsimon-stunnel.service <<EOF
[Unit]
Description=Painel Netsimon - Stunnel (SSH sobre TLS "cru")
After=network.target

[Service]
Type=simple
ExecStart=${STUNNEL_BIN} /etc/painel/stunnel/stunnel.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    # v45: idem — só reinicia se já estava ativado antes.
    systemctl is-enabled --quiet netsimon-stunnel 2>/dev/null && systemctl restart netsimon-stunnel 2>/dev/null
fi

echo -e "\n${G}✅ SISTEMA PAINEL NETSIMON REPARADO!${NC}"
echo -e "${Y}usuarios.db e configurações não foram alteradas.${NC}"
sleep 2