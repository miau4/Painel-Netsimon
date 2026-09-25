#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - CHECKUSER MANAGER
# ==========================================

C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'
P=$'\033[1;35m'; NC=$'\033[0m'
T=$'\033[38;2;0;255;239m'
BASE="/etc/painel"

install_deps() {
    command -v pip3 &>/dev/null || apt install python3-pip -y &>/dev/null
    python3 -c "import flask" 2>/dev/null || pip3 install flask --break-system-packages &>/dev/null
}

api_status() {
    pgrep -f "checkuser.py" > /dev/null && echo -e "${G}● ATIVO${NC}" || echo -e "${R}○ PARADO${NC}"
}

IP=$(wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null || echo "SEU-IP")

while true; do
    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                🆔 CHECKUSER API 10                          ${P}║${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${NC} Status: $(api_status)"
    echo -e "${P}║${NC} ${W}Endpoints disponíveis:${NC}"
    echo -e "${P}║${NC}   ${C}http://$IP:5000/check/USUARIO${NC}"
    echo -e "${P}║${NC}   ${C}http://$IP:5000/check/uuid/UUID${NC}"
    echo -e "${P}║${NC}   ${C}http://$IP:5000/users${NC}"
    echo -e "${P}║${NC}   ${C}http://$IP:5000/ping${NC}"
    echo -e "${P}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${P}║${T} 1)${NC} Instalar dependências (Flask)"
    echo -e "${P}║${T} 2)${NC} Iniciar API (porta 5000)"
    echo -e "${P}║${T} 3)${NC} Parar API"
    echo -e "${P}║${T} 4)${NC} Ver conexões na porta 5000"
    echo -e "${P}║${R} 0)${NC} Voltar"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -ne "${Y} Escolha: ${NC}"; read opt

    case $opt in
        1) install_deps; echo -e "${G}Dependências instaladas!${NC}"; sleep 2 ;;
        2)
            install_deps
            if pgrep -f "checkuser.py" > /dev/null; then
                echo -e "${Y}API já está rodando.${NC}"
            else
                nohup python3 "$BASE/checkuser.py" > /var/log/checkuser.log 2>&1 &
                sleep 1
                pgrep -f "checkuser.py" > /dev/null && \
                    echo -e "${G}✅ API iniciada na porta 5000!${NC}" || \
                    echo -e "${R}❌ Falha ao iniciar. Verifique /var/log/checkuser.log${NC}"
            fi
            sleep 2 ;;
        3)
            pkill -f "checkuser.py" 2>/dev/null
            echo -e "${R}API parada.${NC}"; sleep 1 ;;
        4)
            clear
            echo -e "${Y}Conexões ativas na porta 5000:${NC}"
            ss -tnp | grep :5000
            read -p "ENTER..." ;;
        0) exit 0 ;;
        *) echo -e "${R}Opção inválida!${NC}"; sleep 1 ;;
    esac
done
