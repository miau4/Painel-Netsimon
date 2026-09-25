#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - USUÁRIOS ONLINE
#   SSH / WebSocket / Xray VLESS
# ==========================================
# Este arquivo funciona em dois modos:
#   1) Executado diretamente (bash online.sh): mostra a tela
#      interativa de "Usuários Conectados Agora".
#   2) "Sourced" por outro script (menu.sh, xray.sh): expõe as
#      funções netsimon_online_count() / netsimon_online_count_xray()
#      / netsimon_online_count_ssh(), usadas para os contadores de
#      "Online" no cabeçalho do menu principal, no submenu de
#      usuários e no Xray Manager — SEMPRE com o mesmo resultado,
#      porque é a mesma função calculando em todos os lugares (fonte
#      única de verdade, sem duas contagens divergentes).
#
# 9.0: detecção Xray migrada para API em tempo real
# (xray api statsgetallonlineusers / statsonlineiplist) — elimina
# a dependência do access.log e a janela de 90s que causava
# subcontagem de usuários conectados há mais tempo.
#
# NOTA: o painel WEB (painel_api.py) não faz "source" deste arquivo —
# ele tem sua própria get_online_users() em Python, que soma processos
# sshd (pra pegar túnel sem pty) e agora valida cada um contra `ss`
# (socket TCP ESTABLISHED de verdade), pra não divergir deste script
# quando um processo sshd fica pendurado após queda de rede.

USERDB="${USERDB:-/etc/painel/usuarios.db}"
XRAY_API="${XRAY_API:-127.0.0.1:2000}"

# ── Linhas formatadas de sessões SSH/WebSocket ativas ─────────────
# Considera apenas logins que existem no usuarios.db (evita contar
# sessões SSH de administração, ex.: o próprio root gerenciando o
# painel, como se fossem clientes do serviço).
_netsimon_online_ssh_rows() {
    [ ! -s "$USERDB" ] && return
    while read -r user; do
        [[ -z "$user" ]] && continue
        grep -q "^$user|" "$USERDB" 2>/dev/null || continue

        local ip_conn dur dur_str mins
        ip_conn=$(ss -tnp 2>/dev/null | awk -v u="sshd" '$NF ~ u' | grep ESTAB | \
            awk '{print $5}' | cut -d: -f1 | grep -v "127.0.0.1" | head -n1)
        [[ -z "$ip_conn" ]] && ip_conn="WebSocket"

        dur=$(ps -u "$user" -o etimes= 2>/dev/null | sort -n | head -n1)
        if [ -n "$dur" ]; then
            mins=$(( dur / 60 ))
            dur_str="${mins}min"
        else
            dur_str="--"
        fi

        printf "%s\x1f%s\x1f%s\x1f%s\n" "$user" "$ip_conn" "SSH/WS" "$dur_str"
    done < <(who 2>/dev/null | awk '{print $1}' | sort -u)
}

# ── Linhas formatadas de sessões Xray/VLESS ativas — via API ──────
# 9.0: usa xray api statsgetallonlineusers para listar quem está
# online agora em tempo real, depois statsonlineiplist para obter
# o IP de cada um. Sem janela de tempo, sem depender do access.log.
_netsimon_online_xray_rows() {
    [ ! -s "$USERDB" ] && return

    # Lista todos os emails com sessão ativa agora
    local online_raw
    online_raw=$(xray api statsgetallonlineusers --server="$XRAY_API" 2>/dev/null)
    [ -z "$online_raw" ] && return

    # Extrai emails da resposta JSON (formato: "user>>>EMAIL>>>online")
    local emails
    emails=$(echo "$online_raw" | grep -oP 'user>>>\K[^>]+(?=>>>online)' 2>/dev/null)
    [ -z "$emails" ] && return

    while read -r user; do
        [[ -z "$user" ]] && continue
        # Só mostra quem está no banco local
        grep -q "^$user|" "$USERDB" 2>/dev/null || continue

        # Busca IP via API
        local ip_x
        ip_x=$(xray api statsonlineiplist --server="$XRAY_API" -email "$user" 2>/dev/null \
            | grep -oP '"(\d{1,3}\.){3}\d{1,3}"' | head -1 | tr -d '"')
        [[ -z "$ip_x" || "$ip_x" == "127.0.0.1" ]] && ip_x="tunnel"

        printf "%s\x1f%s\x1f%s\x1f%s\n" "$user" "$ip_x" "XRAY/VLESS" "--"
    done <<< "$emails"
}

# ── Contadores (fonte única usada em todo o painel) ────────────────
netsimon_online_count_ssh()  { _netsimon_online_ssh_rows  | sort -u | wc -l; }
netsimon_online_count_xray() { _netsimon_online_xray_rows | sort -u | wc -l; }
netsimon_online_count() {
    { _netsimon_online_ssh_rows; _netsimon_online_xray_rows; } | sort -u | wc -l
}

# ── Tela interativa ──────────────────────────────────────────────
_netsimon_online_screen() {
    P=$'\033[1;35m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'
    W=$'\033[1;37m'; C=$'\033[1;36m'; NC=$'\033[0m'

    clear
    echo -e "${P}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${P}║${W}                👥 USUÁRIOS CONECTADOS AGORA                  ${P}║${NC}"
    echo -e "${P}╚══════════════════════════════════════════════════════════════╝${NC}"
    printf " ${W}%-15s | %-20s | %-12s | %-6s${NC}\n" "USUÁRIO" "IP DE CONEXÃO" "PROTOCOLO" "DURAÇÃO"
    echo -e "${P}────────────────────────────────────────────────────────────────${NC}"

    local rows
    rows=$( { _netsimon_online_ssh_rows; _netsimon_online_xray_rows; } | sort -u )

    if [ -n "$rows" ]; then
        while IFS=$'\x1f' read -r ru rip rproto rdur; do
            [ -z "$ru" ] && continue
            printf " ${G}%-15s${NC} | ${C}%-20s${NC} | ${Y}%-12s${NC} | ${W}%-6s${NC}\n" \
                "$ru" "$rip" "$rproto" "$rdur"
        done <<< "$rows"
    else
        echo -e "             ${R}Nenhum usuário logado no momento.${NC}"
    fi

    echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
    local total
    if [ -z "$rows" ]; then
        total=0
    else
        total=$(echo "$rows" | grep -c '.')
    fi
    echo -e " ${W}TOTAL DE CONEXÕES: ${G}$total${NC}"
    echo -e "${P}────────────────────────────────────────────────────────────────${NC}"
    read -p " Pressione ENTER para voltar..."
}

# Só roda a tela se o arquivo foi chamado diretamente (bash online.sh),
# nunca quando é "sourced" por outro script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _netsimon_online_screen
fi
