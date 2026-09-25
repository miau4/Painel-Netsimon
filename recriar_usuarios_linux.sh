#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - RECRIAR USUÁRIOS LINUX
#   Recria no sistema operacional todo usuário
#   que existe em /etc/painel/usuarios.db mas
#   não existe como usuário Linux (perdido na
#   reconstrução do servidor).
# ==========================================

USERDB="/etc/painel/usuarios.db"

G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; C=$'\033[1;36m'; NC=$'\033[0m'

if [[ ! -f "$USERDB" ]]; then
    echo -e "${R}ERRO: $USERDB não encontrado.${NC}"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${R}ERRO: rode este script como root (ou com sudo).${NC}"
    exit 1
fi

criados=0
existentes=0
falhas=0

echo -e "${C}Lendo $USERDB e recriando usuários Linux ausentes...${NC}"
echo "----------------------------------------------------------------"

while IFS='|' read -r user uuid exp pass limite; do
    # Ignora linhas vazias ou malformadas
    [[ -z "$user" ]] && continue

    if id "$user" &>/dev/null; then
        echo -e "${Y}JÁ EXISTE${NC}  $user"
        existentes=$((existentes+1))
        continue
    fi

    # ---- Cria o usuário Linux (mesmo padrão do adduser.sh) ----
    useradd -m -s /bin/bash "$user" &>/dev/null
    if [[ $? -ne 0 ]]; then
        echo -e "${R}FALHA${NC}      $user (useradd retornou erro)"
        falhas=$((falhas+1))
        continue
    fi

    echo "$user:$pass" | chpasswd &>/dev/null

    mkdir -p "/home/$user/.ssh"
    chmod 700 "/home/$user/.ssh"
    chown -R "$user:$user" "/home/$user"

    # Converte a data de expiração do banco (YYYY-MM-DD HH:MM:SS ou YYYY-MM-DD)
    # para o formato aceito pelo chage (YYYY-MM-DD)
    exp_chage=$(date -d "${exp%% *}" +"%Y-%m-%d" 2>/dev/null)
    if [[ -n "$exp_chage" ]]; then
        chage -E "$exp_chage" "$user" &>/dev/null
    fi

    echo -e "${G}CRIADO${NC}     $user  (validade: ${exp_chage:-n/a})"
    criados=$((criados+1))

done < "$USERDB"

echo "----------------------------------------------------------------"
echo -e "${G}Criados: $criados${NC}   ${Y}Já existiam: $existentes${NC}   ${R}Falhas: $falhas${NC}"
