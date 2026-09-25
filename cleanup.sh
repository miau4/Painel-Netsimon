#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - LIMPEZA DE INSTALAÇÃO ANTERIOR
# ==========================================
# Encerra processos e remove crons de versões/instalações antigas do
# Painel Netsimon (incluindo o antigo sistema de sincronização Atlas em
# bash, hoje descontinuado) para que uma reinstalação comece limpa.
#
# NÃO apaga usuarios.db, blocked.db, atlas.key ou qualquer dado —
# apenas processos em execução e agendamentos de cron. Os arquivos de
# script em si são sobrescritos normalmente pelo instalador.
# ==========================================

C=$'\033[1;36m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'

echo -e "${C}[+] Parando processos antigos do Painel Netsimon...${NC}"
pkill -f "limit.sh" 2>/dev/null
pkill -f "proxy.py" 2>/dev/null
pkill -f "checkuser.py" 2>/dev/null
pkill -f "monitor_usuarios.sh" 2>/dev/null
pkill -f "atlas_sync_cron.sh" 2>/dev/null
pkill -f "delete_watcher.sh" 2>/dev/null
pkill -f "dragon_hook.sh" 2>/dev/null
screen -wipe >/dev/null 2>&1

echo -e "${C}[+] Removendo crons antigos...${NC}"
rm -f /etc/cron.d/atlas_sync
rm -f /etc/cron.d/xray_watchdog
rm -f /etc/cron.d/sync_usuarios
rm -f /etc/cron.d/delete_watcher_watchdog
rm -f /etc/cron.d/dragon_hook

(crontab -l 2>/dev/null | grep -vE "limit\.sh|boot_check\.sh") | crontab - 2>/dev/null

echo -e "${C}[+] Removendo scripts descontinuados (Atlas bash)...${NC}"
rm -f /etc/painel/atlas.sh
rm -f /etc/painel/atlas_sync_cron.sh
rm -f /etc/painel/atlas.key
rm -f /etc/painel/monitor_usuarios.sh

echo ""
echo -e "${G}✅ Limpeza concluída.${NC}"
echo -e "${W}Usuários e configuração (usuarios.db, blocked.db) foram preservados.${NC}"
echo -e "${Y}Rode o instalador do Painel Netsimon em seguida para reinstalar os módulos atualizados.${NC}"
