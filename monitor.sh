#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - STATUS VPS
#   Recursos do servidor + portas abertas
#   Pressione ENTER para voltar ao menu
# ==========================================

# Descarta qualquer caractere residual no buffer de entrada
# (proteção contra "Enter" que vazou do menu principal)
read -t 0.1 -r -d '' _discard 2>/dev/null || true

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; O=$'\033[38;5;208m'; NC=$'\033[0m'

clear

CPU=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2 + $4)}')
[ -z "$CPU" ] && CPU=0
RAM=$(free -h 2>/dev/null | awk '/Mem:/ {print $3 "/" $2}')
DISK=$(df -h / 2>/dev/null | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
UP=$(uptime -p 2>/dev/null | sed 's/up //')
HORA=$(date '+%d/%m/%Y %H:%M:%S')
IP=$(wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null || echo "offline")

echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${P}║${W}                  🖥️  STATUS DA VPS — PAINEL NETSIMON             ${P}║${NC}"
echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
printf "${P}║${NC} ${C}IP:${W} %-18s ${C}CPU:${W} %-6s ${C}RAM:${W} %-15s${NC}\n" "$IP" "${CPU}%" "$RAM"
printf "${P}║${NC} ${C}DISCO:${W} %-16s ${C}UPTIME:${W} %-20s${NC}\n" "$DISK" "$UP"
printf "${P}║${NC} ${C}HORA:${W} %-20s${NC}\n" "$HORA"
echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${P}║${W}               📋 SERVIÇOS PAINEL NETSIMON (PORTAS-CHAVE)             ${P}║${NC}"
echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"

check_port() {
    local porta=$1 nome=$2
    if ss -tuln 2>/dev/null | grep -q ":$porta "; then
        printf "${P}║${NC}  %-8s %-26s ${G}● ABERTA${NC}\n" "$porta" "$nome"
    else
        printf "${P}║${NC}  %-8s %-26s ${R}○ FECHADA${NC}\n" "$porta" "$nome"
    fi
}

check_port 22   "SSH"
check_port 80   "WebSocket"
check_port 81   "Web (Nginx)"
check_port 443  "Xray VLESS"
check_port 2000 "Xray API interna"
check_port 5000 "CheckUser API"
check_port 5353 "SlowDNS"
check_port 6969 "Módulo do Painel Web"
check_port 8080 "WebSocket Security (com token)"
check_port 8443 "SSH via Stunnel"

echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${P}║${W}                 🔌 TODAS AS PORTAS EM LISTEN                  ${P}║${NC}"
echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
printf "${W}  %-6s %-24s %-30s${NC}\n" "PROTO" "ENDEREÇO:PORTA" "PROCESSO"
echo -e "${P}  ──────────────────────────────────────────────────────────────${NC}"

ss -tulnp 2>/dev/null | tail -n +2 | awk '{printf "  %-6s %-24s %-30s\n", $1, $5, $NF}'

echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
echo -e "${Y} Pressione ENTER para voltar ao menu principal...${NC}"
read -r
