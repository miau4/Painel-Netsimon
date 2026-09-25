#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - LIMITER HÍBRIDO AVANÇADO
#   Controle preciso: SSH/WebSocket + UUID Xray
#   Detecta e expulsa duplicatas em tempo real
# ==========================================
# Responsabilidade única: limitar o número de conexões simultâneas
# por usuário (SSH e Xray) e registrar quem foi expulso por isso em
# /etc/xray-manager/blocked.db. Este script NÃO lê nem grava em
# /root/usuarios.db, não sincroniza nada com o módulo do painel e
# não decide se um usuário existe ou não — só consome
# /etc/painel/usuarios.db (já sincronizado por sync_usuarios.sh) para
# saber login/UUID/limite. Pode ficar ligado ou desligado sem afetar
# criação, remoção ou sincronização de usuários.
#
# DETECÇÃO XRAY: usa exclusivamente a API interna do Xray (porta 2000)
# via "xray api statsonline" e "xray api statsonlineiplist" — dados
# em tempo real, sem depender do access.log nem de janela de tempo.
#
# TOLERÂNCIA: o excesso precisa ser confirmado em XRAY_CONFIRM_CYCLES
# ciclos consecutivos antes do bloqueio, para evitar falsos positivos
# causados por troca de IP (4G/5G) ou reconexão rápida.
#
# KICK XRAY: usa "xray api rmu" + "xray api adu" — cirúrgico, sem
# reiniciar o Xray nem afetar outros usuários conectados.
#
# BLOQUEIO: após o kick, o usuário é removido do Xray e NÃO
# readicionado até que o admin limpe o blocked.db manualmente
# (menu 01 > opção 10). O registro permanece em blocked.db mesmo
# após o desbloqueio, para auditoria.
# ==========================================

USERDB="/etc/painel/usuarios.db"
XRAY_CONF="/usr/local/etc/xray/config.json"
LOG_LIMIT="/var/log/netsimon_limit.log"
BLOCKED="/etc/xray-manager/blocked.db"
XRAY_API="127.0.0.1:2000"
XRAY_TAG="inbound-netsimon"

# Número de ciclos consecutivos com excesso antes de bloquear.
# Cada ciclo = 8s. 3 ciclos = ~24s de excesso confirmado.
XRAY_CONFIRM_CYCLES=3

# Diretório de estado — rastreia ciclos consecutivos por usuário
STATE_DIR="/tmp/netsimon_limiter"

RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YEL=$'\033[1;33m'
CYA=$'\033[1;36m'; W=$'\033[1;37m'; NC=$'\033[0m'

source "/etc/painel/xray_lib.sh" 2>/dev/null

# -------------------------------------------------------
# Garante estrutura de diretórios e arquivos
# -------------------------------------------------------
mkdir -p "$STATE_DIR"
touch "$LOG_LIMIT"
chmod 666 "$LOG_LIMIT"
[ ! -f "$BLOCKED" ] && touch "$BLOCKED"

log() {
    echo "$(date '+%d/%m/%Y %H:%M:%S') $1" >> "$LOG_LIMIT"
    [ "${DEBUG:-0}" = "1" ] && echo -e "$1"
}

# -------------------------------------------------------
# Conta conexões SSH ativas de um usuário
# -------------------------------------------------------
count_ssh() {
    local user="$1"
    local n n2
    n=$(who | awk -v u="$user" '$1 == u' | wc -l)
    n2=$(ps -u "$user" -o comm= 2>/dev/null | grep -c "sshd" || true)
    echo $(( n > n2 ? n : n2 ))
}

# -------------------------------------------------------
# Conta sessões Xray ativas via API em tempo real
# Retorna 0 se a API falhar (fail-safe: não bloqueia por erro)
# -------------------------------------------------------
count_xray_online() {
    local user="$1"
    local val
    val=$(xray api statsonline --server="$XRAY_API" -email "$user" 2>/dev/null \
        | grep '"value"' | grep -oP '\d+' | head -1)
    echo "${val:-0}"
}

# -------------------------------------------------------
# Conta IPs únicos conectados ao Xray via API em tempo real
# Retorna 0 se a API falhar (fail-safe: não bloqueia por erro)
# -------------------------------------------------------
count_xray_unique_ips() {
    local user="$1"
    local count
    count=$(xray api statsonlineiplist --server="$XRAY_API" -email "$user" 2>/dev/null \
        | grep -oP '"[\d\.:]+":\s*\d+' | wc -l)
    echo "${count:-0}"
}

# -------------------------------------------------------
# Mata todas as conexões SSH de um usuário
# -------------------------------------------------------
kick_ssh() {
    local user="$1"
    pkill -KILL -u "$user" -f sshd 2>/dev/null
    pkill -KILL -u "$user" 2>/dev/null
    log "- SSH KICK: $user"
}

# -------------------------------------------------------
# Bloqueia usuário Xray via API — sem reiniciar o Xray,
# sem afetar outros usuários. Não readiciona após o kick:
# o acesso só volta quando o admin limpar o blocked.db.
# O UUID é preservado no config.json — só a sessão ativa
# é derrubada via API. Para impedir reconexão, remove do
# config.json via xray_remove_client_safe.
# -------------------------------------------------------
kick_xray_block() {
    local user="$1"
    local uuid="$2"

    # 1. Remove via API (derruba sessão ativa imediatamente)
    xray api rmu --server="$XRAY_API" -tag="$XRAY_TAG" "$user" 2>/dev/null
    log "- XRAY API RMU: $user"

    # 2. Remove do config.json (impede reconexão)
    xray_remove_client_safe "$user"
    log "- XRAY CONFIG REMOVIDO: $user ($uuid)"
}

# -------------------------------------------------------
# Registra bloqueio — sempre append, para auditoria completa.
# Se o usuário já estava bloqueado, atualiza o registro.
# -------------------------------------------------------
register_block() {
    local user="$1"
    local reason="$2"
    # Remove entrada anterior do mesmo usuário (se existir)
    sed -i "/^$user|/d" "$BLOCKED" 2>/dev/null
    # Registra com timestamp atual
    echo "$user|$(date '+%d/%m/%Y %H:%M')|$reason" >> "$BLOCKED"

    # BUGFIX CRÍTICO: até aqui, "bloquear" só derrubava a sessão ATIVA
    # (kick_ssh/kick_xray_block) e tirava o UUID do Xray — a conta Linux
    # em si (senha em /etc/shadow) NUNCA era travada. Resultado: SSH
    # continuava aceitando login normalmente pra qualquer usuário
    # "bloqueado", bastando reconectar (e reconectar de vários
    # dispositivos ao mesmo tempo, já que nada no SO impedia). Isso é
    # exatamente o que unblock.sh sempre esperou reverter com
    # "passwd -u" — só que o lado do bloqueio nunca fazia o "passwd -l"
    # correspondente. Agora faz, fechando a porta SSH de verdade,
    # independente do Xray/limiter.
    passwd -l "$user" &>/dev/null
}

# -------------------------------------------------------
# Gerencia contador de ciclos consecutivos de excesso
# Retorna o número atual de ciclos para este usuário
# -------------------------------------------------------
get_excess_cycles() {
    local user="$1"
    local f="$STATE_DIR/xray_excess_$user"
    [ -f "$f" ] && cat "$f" || echo 0
}

increment_excess_cycles() {
    local user="$1"
    local current; current=$(get_excess_cycles "$user")
    echo $(( current + 1 )) > "$STATE_DIR/xray_excess_$user"
}

reset_excess_cycles() {
    local user="$1"
    rm -f "$STATE_DIR/xray_excess_$user"
}

# -------------------------------------------------------
# Contador de ciclos consecutivos de excesso COMBINADO
# (SSH + Xray simultâneos, protocolos diferentes contando
# pro mesmo limite). Separado do contador acima porque mede
# uma coisa diferente: aqui não importa se cada protocolo
# sozinho está dentro do limite, importa a SOMA dos dois ao
# mesmo tempo. Mesma tolerância de ciclos do Xray — evita
# marcar como violação uma simples troca rápida de protocolo
# (usuário sai do SSH e entra no Xray em poucos segundos).
# -------------------------------------------------------
get_combined_excess_cycles() {
    local user="$1"
    local f="$STATE_DIR/combined_excess_$user"
    [ -f "$f" ] && cat "$f" || echo 0
}

increment_combined_excess_cycles() {
    local user="$1"
    local current; current=$(get_combined_excess_cycles "$user")
    echo $(( current + 1 )) > "$STATE_DIR/combined_excess_$user"
}

reset_combined_excess_cycles() {
    local user="$1"
    rm -f "$STATE_DIR/combined_excess_$user"
}

# -------------------------------------------------------
# LOOP PRINCIPAL DO LIMITER
# -------------------------------------------------------
echo -e "${GREEN}[+] LIMITER PAINEL NETSIMON INICIADO — monitorando a cada 8s...${NC}"
log "=== LIMITER 10 INICIADO ==="

while true; do
    if [ ! -f "$USERDB" ] || [ ! -s "$USERDB" ]; then
        sleep 10
        continue
    fi

    while IFS='|' read -r user uuid exp pass limit; do
        [[ -z "$user" || "$user" =~ ^# ]] && continue
        [[ -z "$limit" ]] && limit=1

        # Usuário já bloqueado nesta rodada de bloqueios — não reavalia
        # nada pra ele até o admin liberar (evita reprocessar e também
        # evita os contadores de ciclo ficarem contando à toa).
        if grep -q "^$user|" "$BLOCKED" 2>/dev/null; then
            reset_excess_cycles "$user"
            reset_combined_excess_cycles "$user"
            continue
        fi

        ssh_count=$(count_ssh "$user")

        xray_sessions=0; xray_ips=0; xray_count=0
        if [ -n "$uuid" ] && [ "$uuid" != "NULL" ]; then
            xray_sessions=$(count_xray_online "$user")
            xray_ips=$(count_xray_unique_ips "$user")
            # -----------------------------------------------------------
            # BUGFIX: bloqueio errôneo ao trocar de rede (wifi <-> dados
            # móveis). Antes usava sempre o MAIOR valor entre sessões e
            # IPs únicos. Só que quando o celular do cliente troca de
            # rede, o Xray reconecta na hora com o IP novo, mas a API
            # "statsonlineiplist" às vezes ainda lista o IP antigo por
            # alguns segundos (entrada não expirou ainda) — mesmo já não
            # havendo sessão real nele. Resultado: xray_ips contava 2
            # (IP velho fantasma + IP novo real) enquanto xray_sessions
            # continuava mostrando 1 (a contagem de sessão em si é mais
            # confiável pra saber quantas conexões estão REALMENTE
            # abertas agora, porque cai junto com a conexão).
            #
            # Regra nova: só confiar no contador de IPs quando ele bate
            # (ou fica abaixo) do contador de sessões. Se IPs > sessões,
            # é sinal clássico de IP fantasma de uma troca de rede
            # recente — nesse caso usa o número de sessões, que é o dado
            # mais confiável sobre quantas conexões existem de verdade
            # neste exato momento. Um compartilhamento de UUID real (2
            # dispositivos diferentes ao mesmo tempo) sempre aparece com
            # sessions E ips igualmente altos, então continua detectado
            # normalmente.
            if [[ "$xray_ips" -gt "$xray_sessions" ]]; then
                xray_count=$xray_sessions
                log "ℹ️  IP extra ignorado (possível troca de rede): $user | Sessões=$xray_sessions | IPs=$xray_ips"
            else
                xray_count=$(( xray_sessions > xray_ips ? xray_sessions : xray_ips ))
            fi
        fi

        # ===================================================
        # BLOCO 1: SSH SOZINHO acima do limite (duplicação
        # dentro do mesmo protocolo) — ação imediata, sem
        # tolerância de ciclos: 2 SSH ao mesmo tempo já é uma
        # violação óbvia, não é o caso de falso positivo por
        # troca de IP que a tolerância existe pra cobrir.
        # ===================================================
        if [[ "$ssh_count" -gt "$limit" ]]; then
            log "🔴 SSH EXCEDIDO: $user | Limite=$limit | Ativo=$ssh_count"
            kick_ssh "$user"
            # BUG5 FIX: bloquear Xray junto com SSH para fechar todas as portas de acesso
            if [ -n "$uuid" ] && [ "$uuid" != "NULL" ]; then
                kick_xray_block "$user" "$uuid"
                log "- XRAY BLOQUEADO JUNTO COM SSH: $user"
            fi
            register_block "$user" "SSH duplicado ($ssh_count/$limit)"
            reset_excess_cycles "$user"
            reset_combined_excess_cycles "$user"
            continue
        fi

        # ===================================================
        # BLOCO 2: XRAY SOZINHO acima do limite — tolerância de
        # XRAY_CONFIRM_CYCLES ciclos consecutivos (evita falso
        # positivo por troca de IP em 4G/5G).
        # ===================================================
        if [ -n "$uuid" ] && [ "$uuid" != "NULL" ] && [[ "$xray_count" -gt "$limit" ]]; then
            increment_excess_cycles "$user"
            cycles=$(get_excess_cycles "$user")

            log "⚠️  XRAY EXCESSO: $user | IPs=$xray_ips | Sessões=$xray_sessions | Limite=$limit | Ciclo=$cycles/$XRAY_CONFIRM_CYCLES"

            if [[ "$cycles" -ge "$XRAY_CONFIRM_CYCLES" ]]; then
                log "🔴 XRAY BLOQUEADO: $user | UUID=$uuid | IPs=$xray_ips | Sessões=$xray_sessions"
                kick_xray_block "$user" "$uuid"
                register_block "$user" "UUID compartilhado (${xray_ips} IPs / ${xray_sessions} sessões / limite=${limit})"
                reset_excess_cycles "$user"
                reset_combined_excess_cycles "$user"
                continue
            fi
        else
            reset_excess_cycles "$user"
        fi

        # ===================================================
        # BLOCO 3: TOTAL COMBINADO (SSH + Xray SIMULTÂNEOS) acima
        # do limite. Cada protocolo sozinho pode estar dentro do
        # limite (ex: 1 SSH + 1 Xray, limite=1) e mesmo assim ser
        # um acesso simultâneo real de duas origens diferentes —
        # é exatamente esse caso que os Blocos 1 e 2, sozinhos,
        # deixavam passar. Mesma tolerância de ciclos do Xray: uma
        # troca rápida de protocolo (desconecta SSH, conecta Xray
        # segundos depois) não fica presa nessa janela de ~24s por
        # coincidir num único ciclo de 8s.
        # ===================================================
        total_count=$(( ssh_count + xray_count ))

        if [[ "$total_count" -gt "$limit" ]]; then
            increment_combined_excess_cycles "$user"
            ccycles=$(get_combined_excess_cycles "$user")

            log "⚠️  COMBINADO EXCESSO: $user | SSH=$ssh_count | Xray=$xray_count | Total=$total_count | Limite=$limit | Ciclo=$ccycles/$XRAY_CONFIRM_CYCLES"

            if [[ "$ccycles" -ge "$XRAY_CONFIRM_CYCLES" ]]; then
                log "🔴 BLOQUEADO (SSH+XRAY SIMULTÂNEOS): $user | SSH=$ssh_count | Xray=$xray_count"
                [[ "$ssh_count" -gt 0 ]] && kick_ssh "$user"
                if [ -n "$uuid" ] && [ "$uuid" != "NULL" ] && [[ "$xray_count" -gt 0 ]]; then
                    kick_xray_block "$user" "$uuid"
                fi
                register_block "$user" "SSH+Xray simultâneos (${ssh_count}+${xray_count}=${total_count}/limite=${limit})"
                reset_combined_excess_cycles "$user"
                continue
            fi
        else
            reset_combined_excess_cycles "$user"
        fi

        # ===================================================
        # BLOCO 4 (EXPIRAÇÃO) FOI REMOVIDO DAQUI DE PROPÓSITO.
        #
        # Bloquear por expiração passou a ser responsabilidade EXCLUSIVA
        # de um watchdog independente dentro do painel_api.py
        # (expired_user_kick_scheduler_loop, serviço netsimon-painel) —
        # não do limit.sh. Motivo: o limiter é uma feature OPCIONAL que
        # o admin liga/desliga (inclusive fica desligado por padrão hoje
        # neste servidor), enquanto bloqueio de usuário vencido precisa
        # ser um sistema primordial, sempre ativo, sem nenhuma
        # dependência do limiter estar rodando ou não — mesmo critério
        # já usado pelo bloqueio por dispositivo (_device_check_core).
        # Manter os dois sistemas escrevendo a mesma lógica em paralelo
        # só criaria duplicidade sem necessidade.
        # ===================================================

    done < "$USERDB"

    sleep 8
done