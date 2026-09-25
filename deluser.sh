#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - REMOVER USUÁRIO
# ==========================================

BASE="/etc/painel"
USERDB="/etc/painel/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
LOG_LIMIT="/var/log/netsimon_limit.log"

P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'

# -------------------------------------------------------
# Função central de limpeza
# -------------------------------------------------------
fun_limpar_user() {
    local user_to_del="$1"
    # captura o uuid ANTES de apagar a linha do usuarios.db no passo 3 —
    # a tabela devices guarda o uuid (não o login) na coluna username
    local uuid_del
    uuid_del=$(awk -F'|' -v u="$user_to_del" '$1==u{print $2; exit}' "$USERDB" 2>/dev/null)

    # 1. Encerra processos e remove do sistema
    pkill -KILL -u "$user_to_del" 2>/dev/null
    pkill -KILL -u "$user_to_del" -f sshd 2>/dev/null
    userdel -f "$user_to_del" &>/dev/null
    rm -rf "/home/$user_to_del" &>/dev/null

    # 2. Remove do Xray
    if [ -f "$XRAY_CONF" ]; then
        local tmp; tmp=$(mktemp)
        jq --arg u "$user_to_del" \
            '(.inbounds[] | select(.port == 443)).settings.clients |= map(select(.email != $u))' \
            "$XRAY_CONF" > "$tmp" 2>/dev/null
        if jq . "$tmp" >/dev/null 2>&1; then
            mv "$tmp" "$XRAY_CONF"
        else
            rm -f "$tmp"
        fi
    fi

    # 3. Remove do banco local de usuários
    sed -i "/^$user_to_del|/d" "$USERDB"

    # 4. Libera a cota do revendedor dono (item 2): remove o login de
    #    qualquer lista "users" em painel_config.json — inclusive quando
    #    a remoção é automática (teste vencido via 'at'), que não passa
    #    pela API e antes deixava a cota "presa".
    python3 - "$user_to_del" <<'PYEOF' 2>/dev/null
import json, sys
CFG = "/etc/painel/painel_config.json"
login = sys.argv[1]
try:
    with open(CFG) as f:
        cfg = json.load(f)
    changed = False
    for r in cfg.get("resellers", {}).values():
        if login in r.get("users", []):
            r["users"].remove(login)
            changed = True
    if changed:
        with open(CFG, "w") as f:
            json.dump(cfg, f, indent=2)
except Exception:
    pass
PYEOF

    # 5. Limpa o registro de dispositivos (bloqueio por device_hash) desse
    #    usuário — sem isso, o registro ficava "órfão" pra sempre na lista
    #    de Dispositivos do painel (mostrando o UUID cru em vez do nome, e
    #    sem forma de resetar/limpar pela tela, já que o usuário some do
    #    usuarios.db mas o dispositivo continuava lá).
    DEVICES_DB="/etc/painel/netsimon_devices.db"
    if [ -n "$uuid_del" ] && [ -f "$DEVICES_DB" ] && command -v sqlite3 &>/dev/null; then
        sqlite3 "$DEVICES_DB" "DELETE FROM devices WHERE username='$uuid_del'; DELETE FROM device_log WHERE username='$uuid_del';" 2>/dev/null
    fi
}

# -------------------------------------------------------
# Modo automático (chamado pelo addtest.sh via 'at')
# -------------------------------------------------------
if [[ "$2" == "--auto" ]]; then
    user="$1"
    fun_limpar_user "$user"
    if [[ "$3" != "--no-restart" ]]; then
        systemctl restart xray &>/dev/null
    fi
    echo "$(date '+%d/%m/%Y %H:%M:%S') - AUTO: Teste $user EXPIRADO e REMOVIDO." >> "$LOG_LIMIT"
    exit 0
fi

# -------------------------------------------------------
# Interface manual
# -------------------------------------------------------
clear
echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${P}║${W}                💀 REMOÇÃO DE CONTA 10                       ${P}║${NC}"
echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ ! -s "$USERDB" ]; then
    echo -e "${R}Banco de dados vazio.${NC}"
    read -p "ENTER..."; exit 1
fi

printf "\n${W}%-4s | %-15s | %-20s | %-6s${NC}\n" "ID" "USUÁRIO" "EXPIRAÇÃO" "LIMITE"
echo -e "${P}──────────────────────────────────────────────────────${NC}"

declare -A lista_users
i=1
while IFS='|' read -r u id exp p lim; do
    printf "${C}%-4s${NC} | ${W}%-15s${NC} | %-20s | %-6s\n" "$i" "$u" "$exp" "$lim"
    lista_users[$i]=$u
    ((i++))
done < "$USERDB"

echo -e "${P}──────────────────────────────────────────────────────${NC}"
echo -e " ${G}[0]${W} REMOVER TODOS"
echo -e " ${R}[x]${W} VOLTAR"
echo -e "${P}──────────────────────────────────────────────────────${NC}"
read -p " Escolha o ID ou Nome: " escolha

[[ "$escolha" == "x" ]] && exit

if [[ "$escolha" == "0" ]]; then
    echo -ne "\n${R}⚠️  Deletar TODOS? (s/n): ${NC}"; read confirmar
    [[ "$confirmar" != "s" ]] && exit
    for u in "${lista_users[@]}"; do
        echo -ne "${W} -> Removendo: ${C}$u... ${NC}"
        fun_limpar_user "$u"
        echo -e "${G}OK${NC}"
    done
    systemctl restart xray &>/dev/null
    echo "$(date '+%d/%m/%Y %H:%M:%S') - ADMIN: LIMPEZA TOTAL." >> "$LOG_LIMIT"
    echo -e "\n${G}✅ TODOS REMOVIDOS!${NC}"; sleep 2; exit
fi

if [[ ${lista_users[$escolha]} ]]; then
    user=${lista_users[$escolha]}
else
    user=$escolha
fi

if ! grep -q "^$user|" "$USERDB"; then
    echo -e "${R}Usuário '$user' não encontrado!${NC}"; sleep 2; exit 1
fi

echo -e "\n${Y}[+] Removendo $user...${NC}"

echo -ne "${W}[1/3] Sistema Linux + Xray... ${NC}"
fun_limpar_user "$user"
echo -e "${G}OK${NC}"

echo -ne "${W}[2/3] Reiniciando Xray... ${NC}"
systemctl restart xray &>/dev/null
echo -e "${G}OK${NC}"

echo -ne "${W}[3/3] Log de auditoria... ${NC}"
echo "$(date '+%d/%m/%Y %H:%M:%S') - ADMIN: $user REMOVIDO." >> "$LOG_LIMIT"
echo -e "${G}OK${NC}"

echo -e "\n${G}✅ USUÁRIO REMOVIDO!${NC}"
echo -e "${P}════════════════════════════════════════════════════════════════${NC}"
read -p "ENTER para voltar..."