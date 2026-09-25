#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - XRAY LIB (helpers compartilhados)
# ==========================================
# Este arquivo centraliza toda escrita no config.json do Xray.
#
# CAUSA RAIZ HISTÓRICA DO BUG "User X already exists" (Xray morrendo
# em loop): scripts diferentes (adduser.sh, addtest.sh, xray.sh)
# escreviam direto no clients[] com jq, cada um por conta própria,
# sem checar duplicidade e sem lock entre processos concorrentes.
#
# A correção é estrutural: toda escrita passa a usar
# xray_add_client_safe(), que faz flock (serializa qualquer escrita
# concorrente de qualquer script) e SEMPRE checa duplicidade antes
# de dar append, não importa quem chamou.

XRAY_CONF="${XRAY_CONF:-/usr/local/etc/xray/config.json}"
XRAY_LOCK="/tmp/netsimon_xray_conf.lock"

# Adiciona um cliente ao inbound da porta informada (default 443)
# somente se ainda não existir. Sempre serializado via flock.
# Retorno: 0 = adicionado | 2 = já existia (ignorado, sem duplicar)
#          1 = falha (config ausente/inválido ou porta inexistente)
xray_add_client_safe() {
    local email="$1" id="$2" port="${3:-443}"
    [ -z "$email" ] || [ -z "$id" ] && return 1
    [ -f "$XRAY_CONF" ] || return 1

    local lockfd
    exec {lockfd}>"$XRAY_LOCK"
    flock -x -w 10 "$lockfd" || { exec {lockfd}>&-; return 1; }

    local existe
    existe=$(jq --argjson p "$port" --arg u "$email" \
        '[.inbounds[]? | select(.port == $p) | .settings.clients[]? | select(.email == $u)] | length' \
        "$XRAY_CONF" 2>/dev/null)

    if [ -n "$existe" ] && [ "$existe" != "0" ]; then
        exec {lockfd}>&-
        return 2
    fi

    local tmp; tmp=$(mktemp)
    jq --argjson p "$port" --arg id "$id" --arg u "$email" \
        '(.inbounds[]? | select(.port == $p)).settings.clients += [{"id": $id, "email": $u}]' \
        "$XRAY_CONF" > "$tmp" 2>/dev/null

    if [ -s "$tmp" ] && jq . "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$XRAY_CONF"
        exec {lockfd}>&-
        return 0
    else
        rm -f "$tmp"
        exec {lockfd}>&-
        return 1
    fi
}

# Remove um cliente pelo email, em qualquer inbound, com o mesmo lock.
xray_remove_client_safe() {
    local email="$1"
    [ -z "$email" ] && return 1
    [ -f "$XRAY_CONF" ] || return 1

    local lockfd
    exec {lockfd}>"$XRAY_LOCK"
    flock -x -w 10 "$lockfd" || { exec {lockfd}>&-; return 1; }

    local tmp; tmp=$(mktemp)
    jq --arg u "$email" \
        '(.inbounds[]?).settings.clients |= (if . == null then . else map(select(.email != $u)) end)' \
        "$XRAY_CONF" > "$tmp" 2>/dev/null

    if [ -s "$tmp" ] && jq . "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$XRAY_CONF"
        exec {lockfd}>&-
        return 0
    else
        rm -f "$tmp"
        exec {lockfd}>&-
        return 1
    fi
}

# Retorna, um por linha, "porta protocolo" de todo inbound com clients
# (ou seja, portas de tráfego real, ignorando a porta interna da api).
xray_list_ports() {
    [ -f "$XRAY_CONF" ] || return 1
    jq -r '.inbounds[]? | select(.protocol != "dokodemo-door") | "\(.port) \(.protocol)"' \
        "$XRAY_CONF" 2>/dev/null
}

# Mesma coisa, mas cruzando com o que está REALMENTE em LISTEN no
# processo do xray (ss), pra refletir a realidade do servidor e não
# só o que está escrito no json (que pode estar desatualizado se o
# serviço não recarregou depois de uma edição manual).
xray_list_active_ports() {
    local xray_pid
    xray_pid=$(pgrep -x xray | head -n1)
    local listening=""
    if [ -n "$xray_pid" ]; then
        listening=$(ss -tlnp 2>/dev/null | grep "pid=$xray_pid" | awk '{print $4}' | sed 's/.*://' | sort -un)
    fi

    while read -r porta proto; do
        [ -z "$porta" ] && continue
        if [ -n "$listening" ] && echo "$listening" | grep -qx "$porta"; then
            echo "$porta|$proto|ATIVA"
        elif systemctl is-active --quiet xray; then
            echo "$porta|$proto|?"
        else
            echo "$porta|$proto|INATIVA"
        fi
    done < <(xray_list_ports)
}

# Lista completa de usuários do Xray com UUID sem cortar.
xray_list_users_full() {
    [ -f "$XRAY_CONF" ] || return 1
    jq -r '.inbounds[]? | select(.protocol != "dokodemo-door") as $ib
        | ($ib.settings.clients // [])[]? | "\(.email)|\(.id)|\($ib.port)"' \
        "$XRAY_CONF" 2>/dev/null
}

# Conta quantos clientes únicos do Xray tiveram uma conexão "accepted"
# registrada no access.log dentro da janela de tempo informada (default
# 90s). Mesmo critério de "online" usado em online.sh/limit.sh, exposto
# aqui como contador simples para uso em telas de status (xray.sh).
xray_count_online() {
    local xray_log="${XRAY_LOG:-/var/log/xray/access.log}"
    local janela="${1:-90}"
    [ -f "$xray_log" ] || { echo 0; return; }

    local now_epoch; now_epoch=$(date +%s)
    tail -n 500 "$xray_log" 2>/dev/null | grep "accepted" | grep "email: " | \
    while read -r line; do
        local ts line_epoch diff email
        ts=$(echo "$line" | awk '{print $1 " " $2}')
        line_epoch=$(date -d "$ts" +%s 2>/dev/null || echo 0)
        diff=$(( now_epoch - line_epoch ))
        [ "$diff" -gt "$janela" ] && continue
        email=$(echo "$line" | sed -n 's/.*email: //p')
        [ -n "$email" ] && echo "$email"
    done | sort -u | wc -l
}
