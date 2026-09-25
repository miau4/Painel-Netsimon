#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - RESTAURAR ACESSO
#   (usuário bloqueado pelo LIMITER, não pelo
#    bloqueio por dispositivo do app)
# ==========================================
# Este script não está mais ligado a nenhuma opção do menu principal
# (a opção "Desbloquear Usuário" foi substituída por "Liberar
# Todos/1 Usuário" do bloqueio por dispositivo, ver menu.sh). Continua
# disponível para chamar manualmente: bash /etc/painel/unblock.sh —
# útil se um usuário foi expulso pelo limit.sh por engano e você quer
# devolver o acesso dele sem esperar o próximo ciclo.

USERDB="/etc/painel/usuarios.db"
BLOCKED="/etc/xray-manager/blocked.db"
XRAY_CONF="/usr/local/etc/xray/config.json"

G=$'\033[1;32m'; R=$'\033[1;31m'; C=$'\033[1;36m'
Y=$'\033[1;33m'; W=$'\033[1;37m'; P=$'\033[1;35m'; NC=$'\033[0m'

source "/etc/painel/xray_lib.sh" 2>/dev/null

clear
echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${P}║${W}          🔓 RESTAURAR ACESSO (BLOQUEIO DO LIMITER) 10       ${P}║${NC}"
echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ ! -f "$BLOCKED" ] || [ ! -s "$BLOCKED" ]; then
    echo -e "\n${Y}Nenhum usuário bloqueado no momento.${NC}"
    read -p "ENTER..."; exit 0
fi

mapfile -t bloqueados < <(cut -d'|' -f1 "$BLOCKED")

echo -e "\n${W}Usuários bloqueados:${NC}\n"
for i in "${!bloqueados[@]}"; do
    local_user="${bloqueados[$i]}"
    motivo=$(grep "^$local_user|" "$BLOCKED" | cut -d'|' -f3)
    printf "${C}%02d)${NC} %-20s ${Y}%s${NC}\n" "$((i+1))" "$local_user" "$motivo"
done

echo -e "\n${C}00)${NC} Voltar"
echo -e "${P}──────────────────────────────────────────────────────${NC}"
read -p " Escolha: " op

[[ "$op" == "0" || "$op" == "00" ]] && exit

user="${bloqueados[$((op-1))]}"
if [[ -z "$user" ]]; then
    echo -e "${R}Opção inválida!${NC}"; sleep 2; exit
fi

echo -e "\n${Y}Restaurando acesso para: $user ...${NC}"

# 1. Desbloqueia conta Linux
passwd -u "$user" &>/dev/null
echo -e "${G}[OK]${NC} Linux/SSH restaurado"

# 2. Verifica se o UUID já está no Xray; se não estiver, readiciona
uuid=$(grep "^$user|" "$USERDB" | cut -d'|' -f2)
if [ -n "$uuid" ] && [ -f "$XRAY_CONF" ]; then
    xray_add_client_safe "$user" "$uuid" 443
    xray_rc=$?
    if [ "$xray_rc" -eq 0 ]; then
        systemctl restart xray &>/dev/null
        echo -e "${G}[OK]${NC} Xray UUID restaurado"
    elif [ "$xray_rc" -eq 2 ]; then
        echo -e "${G}[OK]${NC} UUID já presente no Xray"
    else
        echo -e "${Y}[AVISO]${NC} Não foi possível reinserir UUID no Xray"
    fi
fi

# 3. Remove da lista de bloqueados
sed -i "/^$user|/d" "$BLOCKED"

echo -e "\n${G}✅ $user está liberado!${NC}"
read -p "ENTER..."
