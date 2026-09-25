#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - MIGRAÇÃO SSH → XHTTP
#   Move o SSH para dentro do túnel VLESS/XHTTP
#   (mesmo escudo anti-DPI que o VLESS já usa)
# ==========================================
# O QUE ESTE SCRIPT FAZ:
#
# 1. Adiciona uma exceção de roteamento no Xray: o destino
#    127.0.0.1:22 passa a ser permitido através de um outbound
#    dedicado ("ssh-local"), mesmo com a regra geral que bloqueia
#    IPs privados (geoip:private) continuando ativa para qualquer
#    OUTRO destino interno.
#
# 2. Fecha as portas 80 e 8080 para conexões EXTERNAS via iptables.
#    A porta 22 NÃO é mais bloqueada por padrão (ver nota de
#    segurança abaixo) — fica disponível como acesso de emergência.
#
# 3. Encerra o proxy.py (WebSocket) — não é mais necessário.
#
# ── 🛡️ CINTO DE SEGURANÇA (rollback automático) ────────────────────
# Depois de aplicar as mudanças, este script agenda uma REVERSÃO
# AUTOMÁTICA em 5 minutos via 'at'. Se você confirmar que a nova
# conexão (VLESS + port-forward pro app) está funcionando, rode:
#
#   bash /etc/painel/migrate_ssh_xhttp.sh --confirm
#
# Isso cancela a reversão agendada. Se você NÃO confirmar a tempo
# (por exemplo, porque ficou sem acesso nenhum ao servidor), o
# script desfaz tudo sozinho — sem precisar de console/VNC do
# provedor. Pra reverter manualmente a qualquer momento:
#
#   bash /etc/painel/migrate_ssh_xhttp.sh --revert
#
# Este script é IDEMPOTENTE — pode rodar de novo sem duplicar regras.
# ==========================================

BASE="/etc/painel"
XRAY_CONF="/usr/local/etc/xray/config.json"
PENDING_FLAG="/etc/painel/.xhttp_migration_pending"
ATJOB_FILE="/etc/painel/.xhttp_migration_atjob"
C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'

do_revert() {
    echo -e "${Y}[+] Revertendo migração SSH → XHTTP...${NC}"

    # Firewall: reabre 22/80/8080
    iptables -D INPUT -p tcp --dport 22 -j DROP 2>/dev/null
    iptables -D INPUT -p tcp --dport 22 -i lo -j ACCEPT 2>/dev/null
    iptables -D INPUT -p tcp --dport 80 -j DROP 2>/dev/null
    iptables -D INPUT -p tcp --dport 8080 -j DROP 2>/dev/null
    netfilter-persistent save &>/dev/null || true

    # Restaura o backup mais recente do config.json do Xray, se existir
    LATEST_BAK=$(ls -t "$XRAY_CONF".bak_pre_xhttp_migration_* 2>/dev/null | head -n1)
    if [ -n "$LATEST_BAK" ]; then
        cp "$LATEST_BAK" "$XRAY_CONF"
        echo -e "${G}[OK]${NC} config.json restaurado de $LATEST_BAK"
    else
        # Sem backup — remove a regra manualmente via jq
        TMP=$(mktemp)
        jq 'del(.outbounds[] | select(.tag=="ssh-local")) |
            .routing.rules |= map(select(.outboundTag != "ssh-local"))' \
            "$XRAY_CONF" > "$TMP" 2>/dev/null
        [ -s "$TMP" ] && mv "$TMP" "$XRAY_CONF"
        echo -e "${Y}[!] Backup não encontrado — regra removida manualmente via jq.${NC}"
    fi

    systemctl restart xray

    # Religa o WebSocket nas portas 80 (proxy@80, simples) e 8443
    # (wss@8443, TLS real) — ambos serviços systemd
    # independentes (igual ao xray), não sobem mais via screen.
    systemctl restart proxy@80 wss@8443

    rm -f "$PENDING_FLAG" "$ATJOB_FILE"
    sleep 2

    echo -e "${G}✅ Reversão concluída — servidor de volta ao modo tradicional.${NC}"
    echo -e "${W}Portas ativas agora:${NC}"
    ss -tlnp | grep -E ":22 |:80 |:8080 |:443 "
}

# ── Modo --revert: desfaz tudo imediatamente ───────────────────────
if [[ "$1" == "--revert" ]]; then
    clear
    do_revert
    exit 0
fi

# ── Modo --confirm: cancela o rollback automático agendado ─────────
if [[ "$1" == "--confirm" ]]; then
    if [ -f "$ATJOB_FILE" ]; then
        JOBID=$(cat "$ATJOB_FILE")
        atrm "$JOBID" 2>/dev/null
        rm -f "$PENDING_FLAG" "$ATJOB_FILE"
        echo -e "${G}✅ Confirmado! Reversão automática cancelada. Migração mantida.${NC}"
    else
        echo -e "${Y}Nenhuma reversão agendada no momento (nada a confirmar).${NC}"
    fi
    exit 0
fi

# ── Modo --revert --auto: chamado pelo próprio 'at' agendado ───────
if [[ "$1" == "--revert" && "$2" == "--auto" ]]; then
    do_revert
    exit 0
fi

clear
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${C}║${W}     🛡️  MIGRAÇÃO SSH → XHTTP (ESCUDO ANTI-DPI TOTAL)         ${C}║${NC}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ ! -f "$XRAY_CONF" ]; then
    echo -e "${R}ERRO: config.json do Xray não encontrado em $XRAY_CONF.${NC}"
    echo -e "${Y}Instale/configure o Xray primeiro (Xray Manager > Instalar/Reconfigurar).${NC}"
    exit 1
fi

command -v jq >/dev/null 2>&1 || { apt-get install -y jq &>/dev/null; }
command -v at >/dev/null 2>&1 || { apt-get install -y at &>/dev/null; systemctl enable --now atd &>/dev/null; }

echo -e "${Y}Isso vai:${NC}"
echo -e "  ${W}- Encerrar o WebSocket (WS PROXY 80, WSS TLS 8443, WSS SSH 8888, STUNNEL SSL 2053)${NC}"
echo -e "  ${W}- Bloquear acesso EXTERNO às portas 80 e 8080 no firewall${NC}"
echo -e "  ${W}- Todo SSH passará a entrar SOMENTE via VLESS/XHTTP na porta 443${NC}"
echo -e "${R}⚠️  Certifique-se de que o app cliente já suporta port-forward via Xray${NC}"
echo -e "${R}   antes de continuar, ou seus usuários perderão acesso SSH.${NC}"
echo ""
echo -e "${G}🛡️  Segurança: se você não confirmar em 5 minutos, o servidor${NC}"
echo -e "${G}   desfaz tudo sozinho — mesmo sem console do provedor.${NC}"
echo ""
read -p "Digite 'sim' para confirmar e continuar: " confirm
if [[ "$confirm" != "sim" ]]; then
    echo -e "${Y}Cancelado. Nenhuma alteração foi feita.${NC}"
    exit 0
fi

# ── 1. Backup do config.json ──────────────────────────────────────
cp "$XRAY_CONF" "$XRAY_CONF.bak_pre_xhttp_migration_$(date +%s)"
echo -e "${G}[OK]${NC} Backup do config.json salvo."

# ── 2. Adiciona outbound + regra de roteamento (idempotente) ──────
echo -ne "${W}[2/5] Aplicando exceção de roteamento SSH local no Xray... ${NC}"
TMP=$(mktemp)
jq '
  (.outbounds) |= (
    map(select(.tag != "ssh-local")) +
    [{"protocol":"freedom","tag":"ssh-local","settings":{}}]
  ) |
  (.routing.rules) |= (
    (map(select(.outboundTag != "ssh-local"))) as $rest |
    ($rest[0:1]) +
    [{"type":"field","outboundTag":"ssh-local","port":"22","ip":["127.0.0.1"]}] +
    ($rest[1:])
  )
' "$XRAY_CONF" > "$TMP" 2>/dev/null

if [ -s "$TMP" ] && jq . "$TMP" >/dev/null 2>&1; then
    mv "$TMP" "$XRAY_CONF"
    echo -e "${G}OK${NC}"
else
    rm -f "$TMP"
    echo -e "${R}FALHA${NC} — config.json não foi modificado (verifique erros do jq acima)."
    exit 1
fi

# ── 3. Firewall: bloqueia acesso externo a 80/8080 (22 fica livre) ─
# NOTA DE SEGURANÇA: diferente de versões anteriores deste script,
# a porta 22 NÃO é mais bloqueada aqui — ela continua como acesso
# de emergência (SSH direto, fora do túnel) até você mesmo decidir
# fechá-la manualmente depois de validar que tudo funciona. Isso
# evita o cenário de ficar 100% sem acesso ao servidor.
echo -ne "${W}[3/5] Bloqueando acesso externo às portas 80 e 8080... ${NC}"
iptables -C INPUT -p tcp --dport 80 -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 80 -j DROP
iptables -C INPUT -p tcp --dport 8080 -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 8080 -j DROP
netfilter-persistent save &>/dev/null || true
echo -e "${G}OK${NC}"

# ── 4. Encerra o WebSocket (não é mais necessário) ─────────────────
# Os 4 modos rodam como serviço systemd (Restart=always) — um "pkill"
# cru não resolveria, o systemd religaria sozinho em segundos. Precisa
# ser "systemctl stop" mesmo.
echo -ne "${W}[4/5] Encerrando WebSocket (WS PROXY + WSS TLS + WSS SSH + STUNNEL SSL)... ${NC}"
systemctl stop proxy@80 wss@8443 wss-security@8888 netsimon-stunnel 2>/dev/null
echo -e "${G}OK${NC}"

systemctl restart xray
sleep 1

# ── 5. Agenda o rollback automático de segurança (5 minutos) ──────
echo -ne "${W}[5/5] Agendando rollback automático de segurança (5 min)... ${NC}"
touch "$PENDING_FLAG"
ATOUT=$(echo "bash $BASE/migrate_ssh_xhttp.sh --revert --auto" | at now + 5 minutes 2>&1)
JOBID=$(echo "$ATOUT" | grep -oP 'job \K[0-9]+')
if [ -n "$JOBID" ]; then
    echo "$JOBID" > "$ATJOB_FILE"
    echo -e "${G}OK${NC} (job at #$JOBID)"
else
    echo -e "${Y}AVISO${NC} — não foi possível confirmar o agendamento do rollback (serviço 'at' ok?)."
fi

echo ""
echo -e "${G}✅ MIGRAÇÃO APLICADA (provisória por 5 minutos)!${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} O SSH agora entra pelo túnel VLESS/XHTTP (443). Portas 80/8080${NC}"
echo -e "${W} bloqueadas externamente. A porta 22 direta ${G}continua aberta${NC}${W}${NC}"
echo -e "${W} como acesso de emergência.${NC}"
echo -e "${R}────────────────────────────────────────────────────────────────${NC}"
echo -e "${R} 🛡️  TESTE A NOVA CONEXÃO AGORA (app cliente + port-forward).${NC}"
echo -e "${R} Se funcionar, confirme em até 5 minutos:${NC}"
echo -e "${C}   bash /etc/painel/migrate_ssh_xhttp.sh --confirm${NC}"
echo -e "${R} Se você NÃO confirmar, o servidor desfaz tudo sozinho.${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${Y} Pra reverter manualmente a qualquer momento:${NC}"
echo -e "${C}   bash /etc/painel/migrate_ssh_xhttp.sh --revert${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
