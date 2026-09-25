#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - CRIAR USUÁRIO
# ==========================================

BASE="/etc/painel"
USERDB="/etc/painel/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'

# Carrega lib compartilhada de escrita segura no Xray (dedup + lock)
source "$BASE/xray_lib.sh" 2>/dev/null || {
    echo -e "${R}ERRO: xray_lib.sh não encontrado em $BASE${NC}"
    sleep 2; exit 1
}

[[ ! -f "$USERDB" ]] && touch "$USERDB"

clear
echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${P}║${W}                 🚀 CRIAR NOVO USUÁRIO 10                    ${P}║${NC}"
echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

read -p " Nome do Usuário: " user
[[ -z "$user" ]] && exit 1

# FIX (trava de nome duplicado, case-insensitive): antes o grep era
# case-sensitive, então "yndaiara" e "Yndaiara" passavam como usuários
# diferentes por aqui -- mas o Xray rejeita os dois como o mesmo "email"
# internamente, e o segundo nunca carregava de fato. Agora bate igual o
# Xray (sem diferenciar maiúsculas/minúsculas).
if grep -qiw "^$user|" "$USERDB" || id "$user" &>/dev/null; then
    echo -e "\n${R}Erro: Usuário já existe! (nomes não diferenciam maiúsculas/minúsculas)${NC}"; sleep 2; exit 1
fi

read -p " Senha: " pass
[[ -z "$pass" ]] && pass="1234"

read -p " Dias de Validade: " dias
[[ -z "$dias" ]] && dias=30

read -p " Limite de Conexões: " limite
[[ -z "$limite" ]] && limite=1

# ---- Sistema Linux ----
# BUG1 FIX: usar /bin/bash em vez de /bin/false (false bloqueia SSH)
# BUG2 FIX: usar -m em vez de -M para criar o diretório home
useradd -m -s /bin/bash "$user" &>/dev/null
echo "$user:$pass" | chpasswd &>/dev/null

# Garante estrutura .ssh com permissões corretas
mkdir -p "/home/$user/.ssh"
chmod 700 "/home/$user/.ssh"
chown -R "$user:$user" "/home/$user"

exp=$(date -d "+$dias days" +"%Y-%m-%d 23:59:59")
exp_chage=$(date -d "+$dias days" +"%Y-%m-%d")
chage -E "$exp_chage" "$user"

# ---- Xray ----
uuid=$(cat /proc/sys/kernel/random/uuid)
if [ -f "$XRAY_CONF" ]; then
    xray_add_client_safe "$user" "$uuid" 443
    xray_rc=$?
    if [ "$xray_rc" -eq 0 ]; then
        systemctl restart xray >/dev/null 2>&1
    elif [ "$xray_rc" -eq 2 ]; then
        echo -e "${Y}⚠ Aviso: já existia um cliente Xray com esse nome, não duplicado.${NC}"
    else
        echo -e "${Y}⚠ Aviso: falha ao injetar UUID no Xray. Config preservada.${NC}"
    fi
fi

# ---- Banco Local ----
echo "$user|$uuid|$exp|$pass|$limite" >> "$USERDB"

clear
echo -e "${G}✅ USUÁRIO CRIADO COM SUCESSO!${NC}"
echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
printf "${W} Usuário : ${Y}%-20s ${W} Senha  : ${Y}%-10s${NC}\n" "$user" "$pass"
printf "${W} Validade: ${Y}%-20s ${W} Limite : ${Y}%-10s${NC}\n" "$exp_chage" "$limite"
echo -e "${W} UUID    : ${C}$uuid${NC}"
echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
read -p "Pressione ENTER para voltar..."
