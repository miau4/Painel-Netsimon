#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - SLOWDNS MANAGER
# ==========================================

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'
T=$'\033[38;2;0;255;239m'

DIR="/etc/slowdns"
BIN="$DIR/dnstt-server"

show_status() {
    if pgrep -f "dnstt-server" > /dev/null; then
        echo -e "${G}● ATIVO${NC}"
    else
        echo -e "${R}○ PARADO${NC}"
    fi
}

# Garante o binário do dnstt-server: usa o já existente, ou copia do
# binário embutido no projeto (/etc/painel/dnstt-server) -- v42: o
# binário já vem PRONTO junto com o painel (compilado a partir do fonte
# oficial), sem depender de baixar/compilar nada na hora. Antes (v41),
# faltando o binário, tentava compilar via 'go install' -- que nem
# funcionava de verdade, porque o dnstt não é publicado como módulo
# versionado no proxy do Go (proxy.golang.org devolve 404 pra ele).
ensure_dnstt_binary() {
    if [[ -f "$BIN" ]]; then
        return 0
    fi
    mkdir -p "$DIR"

    local EMBEDDED="/etc/painel/dnstt-server"
    if [[ -f "$EMBEDDED" ]]; then
        cp "$EMBEDDED" "$BIN"
        chmod +x "$BIN"
        return 0
    fi

    # Compatibilidade com quem já tinha o hábito antigo de compilar na
    # mão e deixar em /root.
    local BIN_SRC
    BIN_SRC=$(find /root -maxdepth 2 -name "dnstt-server" -type f 2>/dev/null | head -n1)
    if [ -n "$BIN_SRC" ]; then
        cp "$BIN_SRC" "$BIN"
        chmod +x "$BIN"
        return 0
    fi

    echo -e "${R}ERRO: binário do dnstt-server não encontrado em $EMBEDDED.${NC}"
    echo -e "${W}Reinstale/atualize o painel — esse arquivo deve vir junto com o projeto.${NC}"
    return 1
}

install_slowdns() {
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                📡 INSTALADOR SLOWDNS 10                     ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

    echo -ne "${W}Digite seu NameServer (NS): ${NC}"; read NS_DOMAIN
    [[ -z "$NS_DOMAIN" ]] && return

    if ! ensure_dnstt_binary; then
        read -p "ENTER..."; return
    fi

    echo -e "${Y}[2/3] Gerando par de chaves...${NC}"
    cd "$DIR"
    rm -f priv.key pub.key
    "$BIN" -gen-key -privkey-file priv.key -pubkey-file pub.key > /dev/null 2>&1

    local PUB_KEY; PUB_KEY=$(cat pub.key 2>/dev/null)
    if [[ -z "$PUB_KEY" ]]; then
        echo -e "${R}ERRO: Falha ao gerar chaves.${NC}"; read -p "ENTER..."; return
    fi
    echo "$NS_DOMAIN" > "$DIR/domain"

    echo -e "${Y}[3/3] Configurando firewall e serviço systemd...${NC}"
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
    iptables -I INPUT -p udp --dport 53 -j ACCEPT
    iptables -I INPUT -p udp --dport 5353 -j ACCEPT

    cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Painel Netsimon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$DIR
ExecStart=$BIN -udp :5353 -privkey-file $DIR/priv.key $NS_DOMAIN 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slowdns > /dev/null 2>&1
    systemctl restart slowdns
    sleep 2

    clear
    echo -e "${G}✅ SLOWDNS CONFIGURADO!${NC}"
    echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${W} NameServer : ${Y}$NS_DOMAIN${NC}"
    echo -e "${W} Chave Pública:${NC}"
    echo -e "${G}$PUB_KEY${NC}"
    echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${W}Copie a chave pública acima para o seu aplicativo injetor.${NC}"
    read -p "ENTER para voltar..."
}

while true; do
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                📡 GERENCIADOR SLOWDNS 10                    ${P}║${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e " STATUS : $(show_status)"
    [ -f "$DIR/domain" ] && echo -e " NS     : ${Y}$(cat $DIR/domain)${NC}" || echo -e " NS     : ${R}não configurado${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 1)${NC} Instalar / Reconfigurar SlowDNS"
    echo -e "${P}║${T} 2)${NC} Ver Chave Pública (PUB KEY)"
    echo -e "${P}║${T} 3)${NC} Reiniciar serviço"
    echo -e "${P}║${T} 4)${NC} Parar e Desinstalar SlowDNS"
    echo -e "${P}║${R} 0)${NC} Voltar"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -ne "${Y} Escolha: ${NC}"; read opc

    case $opc in
        1) install_slowdns ;;
        2)
            clear
            if [ -f "$DIR/pub.key" ]; then
                echo -e "${P}══════════ SUA CHAVE PÚBLICA ══════════════${NC}"
                echo -e "${G}$(cat $DIR/pub.key)${NC}"
                echo -e "${P}═══════════════════════════════════════════${NC}"
            else
                echo -e "${R}SlowDNS não instalado.${NC}"
            fi
            read -p "ENTER..." ;;
        3)
            systemctl restart slowdns && echo -e "${G}Reiniciado!${NC}" || echo -e "${R}Falha.${NC}"
            sleep 2 ;;
        4)
            echo -ne "${R}Confirma remoção? (s/n): ${NC}"; read c
            if [[ "$c" == "s" ]]; then
                systemctl stop slowdns &>/dev/null
                systemctl disable slowdns &>/dev/null
                rm -f /etc/systemd/system/slowdns.service
                systemctl daemon-reload
                iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
                rm -rf "$DIR"
                echo -e "${G}SlowDNS removido!${NC}"; sleep 2
            fi ;;
        0) exit 0 ;;
        *) echo -e "${R}Inválido!${NC}"; sleep 1 ;;
    esac
done
