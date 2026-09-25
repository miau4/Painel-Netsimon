#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - TESTE TEMPORÁRIO
# ==========================================

BASE="/etc/painel"
USERDB="/etc/painel/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
LOG_LIMIT="/var/log/netsimon_limit.log"

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'

source "$BASE/xray_lib.sh" 2>/dev/null || {
    echo -e "${R}ERRO: xray_lib.sh não encontrado${NC}"; sleep 2; exit 1
}

clear
echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${P}║${W}                ⚡ GERAR TESTE TEMPORÁRIO 10                 ${P}║${NC}"
echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

read -p " Nome do Teste (Enter para aleatório): " user
if [[ -z "$user" ]]; then
    user="teste$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4)"
fi

if grep -q "^$user|" "$USERDB" 2>/dev/null || id "$user" &>/dev/null; then
    echo -e "\n${R}Erro: Usuário '$user' já existe!${NC}"; sleep 2; exit 1
fi

read -p " Senha (Padrão 123): " pass
[[ -z "$pass" ]] && pass="123"

echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Duração do teste:${NC}"
echo -e "${C}  1)${NC} 60 minutos  (1 hora)"
echo -e "${C}  2)${NC} 120 minutos (2 horas)"
echo -e "${C}  3)${NC} 180 minutos (3 horas)"
echo -e "${C}  4)${NC} Personalizado (em minutos)"
echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
read -p " Escolha [1-4]: " opcao_tempo

case "$opcao_tempo" in
    1) minutos=60 ;;
    2) minutos=120 ;;
    3) minutos=180 ;;
    4)
        read -p " Digite a duração em minutos: " minutos
        if ! [[ "$minutos" =~ ^[0-9]+$ ]] || [ "$minutos" -lt 1 ]; then
            echo -e "\n${R}Valor inválido. Usando 60 minutos como padrão.${NC}"
            minutos=60
        fi
        ;;
    *)
        echo -e "\n${Y}Opção inválida. Usando 60 minutos como padrão.${NC}"
        minutos=60
        ;;
esac

# Converte para o formato que date/at entendem corretamente
tempo="${minutos} minutes"
tempo_label="${minutos} minutos"

# ---- Sistema Linux ----
# BUG1 FIX: usar /bin/bash em vez de /bin/false (false bloqueia SSH)
# BUG2 FIX: usar -m em vez de -M para criar o diretório home
useradd -m -s /bin/bash "$user" &>/dev/null
echo "$user:$pass" | chpasswd &>/dev/null

# Garante estrutura .ssh com permissões corretas
mkdir -p "/home/$user/.ssh"
chmod 700 "/home/$user/.ssh"
chown -R "$user:$user" "/home/$user"

# ---- Xray ----
uuid=$(cat /proc/sys/kernel/random/uuid)
if [ -f "$XRAY_CONF" ]; then
    xray_add_client_safe "$user" "$uuid" 443
    xray_rc=$?
    if [ "$xray_rc" -eq 0 ]; then
        systemctl restart xray >/dev/null 2>&1
    elif [ "$xray_rc" -eq 2 ]; then
        echo -e "${Y}⚠ Já existia um cliente Xray com esse nome, não duplicado.${NC}"
    fi
fi

# ---- Banco Local + expiração real no sistema Linux ----
# NOTA: chage -E NÃO é usado aqui intencionalmente.
# Testes têm duração em minutos/horas — o chage só trabalha com
# granularidade de dia, então qualquer teste < 24h resultaria em
# exp_chage = hoje, fazendo o PAM bloquear o login imediatamente
# na criação. A remoção do usuário é responsabilidade exclusiva
# do 'at' agendado abaixo, que tem precisão de minuto.
exp=$(date -d "now + $tempo" +"%Y-%m-%d %H:%M:%S")
echo "$user|$uuid|$exp|$pass|1" >> "$USERDB"

# ---- Auto-Destruição via 'at' ----
if ! command -v at &>/dev/null; then
    apt install at -y &>/dev/null
    systemctl enable --now atd &>/dev/null
fi
echo "bash $BASE/deluser.sh $user --auto" | at "now + $tempo" &>/dev/null
AVISO_AUTO="${G}AUTO-REMOÇÃO EM: ${Y}${tempo_label}${NC}"

echo "$(date '+%d/%m/%Y %H:%M:%S') - TESTE CRIADO: $user por $tempo_label" >> "$LOG_LIMIT"

clear
echo -e "${G}✅ CONTA DE TESTE CRIADA!${NC}"
echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
printf "${W} Usuário : ${Y}%-20s ${W} Senha  : ${Y}%-10s${NC}\n" "$user" "$pass"
printf "${W} Duração : ${Y}%-20s ${W} Limite : ${Y}%-10s${NC}\n" "$tempo_label" "1"
echo -e "${W} UUID    : ${C}$uuid${NC}"
echo -e " ${AVISO_AUTO}"
echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
read -p "Pressione ENTER para voltar..."
