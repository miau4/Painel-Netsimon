#!/usr/bin/env python3
# ==========================================
#   PAINEL NETSIMON - API PRINCIPAL
#   Porta 5001 — Admin + Revendedor
# ==========================================

from flask import Flask, jsonify, request, session, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
import subprocess
import datetime
import os
import json
import hashlib
import base64
import secrets
import time
import re
import shlex
import traceback
import threading
import sqlite3
import uuid as uuidlib
import requests
import tarfile
import io
import tempfile
import shutil
import glob
import unicodedata
import csv
import random
import string
import pwd

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)
# Item de segurança: o Nginx já manda X-Real-IP/X-Forwarded-For (ver
# install.sh), mas sem isso o Flask ignorava e request.remote_addr sempre
# mostrava 127.0.0.1 pra QUALQUER requisição pública (porque quem conecta
# no Flask é sempre o próprio Nginx local) — o que também deixava inútil
# qualquer checagem futura de "bloquear por IP" (ex.: força bruta no
# login). x_for=1/x_proto=1 porque só o Nginx local fica na frente do
# Flask (um único "salto" confiável).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE          = "/etc/painel"
USERDB        = "/etc/painel/usuarios.db"
BLOCKED       = "/etc/xray-manager/blocked.db"
# Janela de "bloqueio ativo" por device_hash — não existe uma flag
# persistente de "usuário X está bloqueado por dispositivo" (é só o
# registro de cada tentativa recusada em device_log). Usamos as últimas
# 48h como corte de "ainda conta como bloqueado agora", mesma janela já
# usada por /api/device/blocked-attempts (ver DEVICE_BLOCK_WINDOW_HOURS).
DEVICE_BLOCK_WINDOW_HOURS = 48

# Item: banco (separado do usuarios.db) alimentado pelo log_watcher.py,
# que le o access.log do Xray em tempo real e grava tentativas de
# conexao e sessoes por usuario. So leitura aqui -- quem escreve e o
# log_watcher.py (processo/serviço systemd a parte).
LOGS_DB_PATH  = "/opt/netsimon/netsimon_logs.db"

def get_logs_db():
    conn = sqlite3.connect(LOGS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ══════════════════════════════════════════════════════════════════
#  LICENCIAMENTO — cliente do license_server.py
#
#  Este bloco só CONSOME o servidor de licenças (que fica em outra
#  máquina, fora do alcance do cliente). Guarda aqui só a chave
#  PÚBLICA Ed25519 — expor ela não é problema (é assim que assinatura
#  assimétrica funciona: só a privada, que nunca sai do seu license
#  server, consegue gerar uma assinatura que essa pública aceita).
#
#  TODO ao gerar um build pra vender: troque o valor abaixo pelo
#  retornado por GET /admin/public-key no seu license_server.py.
# ══════════════════════════════════════════════════════════════════
LICENSE_PUBLIC_KEY_B64 = "COLE_AQUI_A_CHAVE_PUBLICA_DO_SEU_LICENSE_SERVER"
LICENSE_CACHE_PATH     = "/etc/painel/license_cache.json"
LICENSE_FINGERPRINT_PATH = "/etc/painel/license_fingerprint"
LICENSE_CHECKIN_HOURS  = 6     # intervalo do check-in periódico
LICENSE_GRACE_HOURS    = 72    # tolerância offline antes de considerar inválida
PLANO_RECURSOS = {
    "essencial":   set(),
    "pro":         {"ia", "bot"},
    "white_label": {"ia", "bot", "white_label"},
}

def _license_fingerprint():
    """Identificador estável deste servidor — não muda em reboot, mas
    muda se o disco for clonado pra outra máquina (é o que amarra a
    key a ESTE servidor). Usa /etc/machine-id quando existe (padrão em
    toda distro systemd); cai pra um UUID salvo em arquivo senão."""
    for src in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(src):
            with open(src) as f:
                v = f.read().strip()
                if v:
                    return hashlib.sha256(v.encode()).hexdigest()
    if os.path.exists(LICENSE_FINGERPRINT_PATH):
        with open(LICENSE_FINGERPRINT_PATH) as f:
            return f.read().strip()
    fp = hashlib.sha256(uuidlib.uuid4().bytes).hexdigest()
    with open(LICENSE_FINGERPRINT_PATH, "w") as f:
        f.write(fp)
    return fp

def _license_verify(payload_json, assinatura_b64):
    """Confere a assinatura Ed25519 do license_server. Retorna o
    payload (dict) se bater, ou None se a assinatura for inválida —
    NUNCA confia num payload sem verificar antes, mesmo vindo do
    próprio cache local (o cache é um JSON comum no disco; sem checar
    assinatura, bastaria editar o arquivo pra "liberar" qualquer
    plano)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(LICENSE_PUBLIC_KEY_B64))
        pub.verify(base64.b64decode(assinatura_b64), payload_json.encode())
        return json.loads(payload_json)
    except Exception:
        return None

def _license_cache_load():
    if not os.path.exists(LICENSE_CACHE_PATH):
        return None
    try:
        with open(LICENSE_CACHE_PATH) as f:
            raw = json.load(f)
        payload = _license_verify(raw["payload"], raw["assinatura"])
        if not payload:
            return None
        payload["_verificado_localmente_em"] = raw.get("_salvo_em")
        return payload
    except Exception:
        return None

def _license_cache_save(payload_json, assinatura_b64):
    os.makedirs(os.path.dirname(LICENSE_CACHE_PATH), exist_ok=True)
    with open(LICENSE_CACHE_PATH, "w") as f:
        json.dump({
            "payload": payload_json,
            "assinatura": assinatura_b64,
            "_salvo_em": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }, f)

def license_config():
    cfg = load_config()
    return cfg.get("license", {"key": "", "server_url": ""})

def license_ativar(key, server_url):
    """Chamado UMA vez, quando o admin cola a key pela primeira vez
    (ver rota /api/license/ativar). Se o license_server já negar aqui
    (key usada em outro lugar, revogada etc), não grava nada local."""
    fp = _license_fingerprint()
    r = requests.post(f"{server_url.rstrip('/')}/ativar",
                       json={"key": key, "fingerprint": fp, "hostname": os.uname().nodename},
                       timeout=10)
    data = r.json()
    if not data.get("valido"):
        return False, data.get("erro", "ativação recusada")
    payload = _license_verify(data["payload"], data["assinatura"])
    if not payload:
        return False, "resposta do license server com assinatura inválida"
    _license_cache_save(data["payload"], data["assinatura"])
    cfg = load_config()
    cfg["license"] = {"key": key, "server_url": server_url}
    save_config(cfg)
    return True, payload

def license_checkin():
    """Check-in periódico — roda em background (ver _license_loop).
    Falha de rede NÃO apaga o cache válido anterior; só não atualiza
    o timestamp de "última confirmação online" (é isso que sustenta a
    janela de tolerância LICENSE_GRACE_HOURS)."""
    lic = license_config()
    if not lic.get("key") or not lic.get("server_url"):
        return
    try:
        r = requests.post(f"{lic['server_url'].rstrip('/')}/validar",
                           json={"key": lic["key"], "fingerprint": _license_fingerprint()},
                           timeout=10)
        data = r.json()
        if data.get("valido"):
            payload = _license_verify(data["payload"], data["assinatura"])
            if payload:
                _license_cache_save(data["payload"], data["assinatura"])
        # valido=False explícito (revogada/fingerprint não bate) também
        # NÃO apaga o cache aqui de propósito — license_status() é quem
        # decide invalidar, comparando a idade do cache; isso evita que
        # um único erro transitório da rede derrube o painel na hora.
    except requests.RequestException:
        pass  # sem internet agora — cache velho ainda vale, dentro da folga

def license_status():
    """Fonte única de verdade sobre a licença pra qualquer rota
    consultar. Nunca lança exceção — pior caso, devolve inválido."""
    payload = _license_cache_load()
    if not payload:
        return {"valido": False, "plano": None, "motivo": "sem ativação local"}
    salvo_em = payload.get("_verificado_localmente_em")
    if salvo_em:
        idade = datetime.datetime.now() - datetime.datetime.strptime(salvo_em, "%Y-%m-%d %H:%M:%S")
        if idade > datetime.timedelta(hours=LICENSE_GRACE_HOURS):
            return {"valido": False, "plano": payload.get("plano"),
                    "motivo": f"sem contato com o license server há mais de {LICENSE_GRACE_HOURS}h"}
    return {"valido": True, "plano": payload.get("plano"),
            "updates_until": payload.get("updates_until")}

def license_allows(feature):
    st = license_status()
    if not st["valido"]:
        return False
    return feature in PLANO_RECURSOS.get(st["plano"], set())

def _license_loop():
    while True:
        try:
            license_checkin()
        except Exception:
            pass
        time.sleep(LICENSE_CHECKIN_HOURS * 3600)

threading.Thread(target=_license_loop, daemon=True).start()

# Rotas de licença ficam de fora do allowlist abaixo de propósito —
# são elas que permitem o admin ativar/consultar mesmo sem licença
# válida ainda. auth/login também fica de fora (senão ninguém entra
# nem pra configurar a key).
_LICENSE_ALLOWLIST_PREFIXES = ("/api/auth/", "/api/license/", "/ping")

@app.before_request
def _bloquear_sem_licenca():
    """Trava dura: sem licença válida (nunca ativada, revogada, ou
    passou da janela de tolerância offline), qualquer rota /api/* que
    não seja login/licença/ping devolve 402 em vez de processar. Não
    é bonito, mas é o freio de mão de verdade — sem ele, todo o resto
    dessa proteção (fingerprint, assinatura etc) é só decoração."""
    if not request.path.startswith("/api/"):
        return
    if request.path.startswith(_LICENSE_ALLOWLIST_PREFIXES):
        return
    lic = license_config()
    if not lic.get("server_url"):
        # Licenciamento ainda não configurado NESTE servidor (nenhum
        # server_url definido) — não bloqueia. A trava só passa a valer
        # depois que o admin de fato configurar um license server pra
        # essa instalação (POST /api/license/ativar). Isso evita que um
        # servidor recém-instalado, sem licenciamento configurado ainda,
        # fique travado com 402 em tudo por padrão.
        return
    st = license_status()
    if not st["valido"]:
        return jsonify({"erro": "licença inválida ou não ativada",
                         "motivo": st.get("motivo")}), 402

XRAY_CONF     = "/usr/local/etc/xray/config.json"
PAINEL_CFG    = "/etc/painel/painel_config.json"
LOG_LIMIT     = "/var/log/netsimon_limit.log"
XRAY_LOG      = "/var/log/xray/access.log"
XRAY_API      = "127.0.0.1:2000"
XRAY_TAG      = "inbound-netsimon"

# ── Fotos de usuário (armazenamento local) — portado do NetSimon 7.0,
# funcionalidade perdida na reescrita pra 8.0/9.0. Servido como estático
# pelo nginx direto de /var/www/html (mesma pasta do frontend).
FOTOS_DIR = "/var/www/html/fotos"
FOTOS_DB  = "/etc/painel/fotos.db"
MAX_PHOTO_SIZE = 2 * 1024 * 1024  # 2 MB

# ── Device Check (bloqueio por dispositivo, 100% local) ──────────
DEVICE_DB       = "/etc/painel/netsimon_devices.db"
DEVICE_LOG      = "/var/log/netsimon_device.log"
# Log SISTÊMICO — serviços (subiu/caiu/reiniciou), config corrompido,
# exceções não tratadas, etc. Separado do DEVICE_LOG de propósito: antes
# tudo isso (incluindo cada evento do autodiagnóstico) caía junto com o
# log de device-check, e a aba "Device Check" da tela de Logs virava uma
# bagunça de mensagens "DIAG [...]" sem nenhuma relação com dispositivo
# nenhum. Agora cada coisa fica na sua aba.
SYSTEM_LOG      = "/var/log/netsimon_system.log"
DEVICE_TOKEN_F  = "/etc/painel/device_check.token"
CHECKUSER_TOKEN_F = "/etc/painel/checkuser.token"

# ── Gerenciamento de versões do aplicativo ────────────────────────
APP_DIR         = "/etc/painel/app_releases"
APP_META        = "/etc/painel/app_releases/releases.json"
APP_PUBLIC_URL  = "/downloads"   # servido estaticamente pelo Nginx

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO TÉCNICO (item novo) — intercepta erros 4xx/5xx e
#  exceções do painel, classifica a causa por padrões conhecidos (isso
#  é reconhecimento de padrões determinístico, NÃO é uma IA generativa
#  tentando adivinhar) e aplica a correção sozinho quando existe uma
#  correção catalogada, sempre criando um backup antes e registrando
#  tudo pra permitir reverter depois pela tela de Diagnóstico.
# ══════════════════════════════════════════════════════════════════
DIAG_REPO           = "https://raw.githubusercontent.com/miau4/Painel-Netsimon/main"
DIAG_WEBROOT        = "/var/www/html"
DIAG_BACKUP_DIR     = "/etc/painel/diag_backups"
DIAG_INCIDENTS_F    = "/etc/painel/diag_incidents.json"
DIAG_CONFIG_HIST    = "/etc/painel/diag_backups/config_history"
DIAG_LOCK           = threading.Lock()

# Só arquivos de CÓDIGO (script/página estática) entram aqui — nunca um
# arquivo de DADO (usuarios.db, painel_config.json, config.json do Xray,
# logs, bancos de dispositivo). Dado corrompido/perdido tem um tratamento
# próprio (restaurar de backup), nunca é "baixado de novo do repositório"
# porque o repositório não tem os dados de ninguém, só o código.
DIAG_FRONTEND_FILES = {
    "index.html", "login.html", "dashboard.html", "usuarios.html", "todos-usuarios.html",
    "dispositivos.html", "xray.html", "websocket.html", "slowdns.html",
    "revendedores.html", "servidores.html", "diagnostico.html", "whatsapp.html",
    "app.html", "backup.html", "campanhas.html",
    "bot.html", "logs.html", "configuracoes.html",
    "painel.css", "painel.js",
}
DIAG_BACKEND_FILES = {
    "addtest.sh", "adduser.sh", "boot_check.sh", "checkuser.py", "checkuser.sh",
    "cleanup.sh", "deluser.sh", "limit.sh", "menu.sh", "migrate_ssh_xhttp.sh",
    "monitor.sh", "online.sh", "proxy.py", "repair.sh", "setup_https_domain.sh",
    "slowdns-server.sh", "unblock.sh", "uninstall.sh", "websocket.sh", "xray.sh",
    "xray_lib.sh", "bot_telegram.py", "whatsapp_bot.js", "install.sh",
    "whatsapp-bot.service", "wss.py", "wss_security.py",
    # painel_api.py de propósito NÃO entra aqui: se ele estiver faltando/quebrado
    # o próprio processo que faria essa correção não estaria rodando.
}

# Comandos de reinício por serviço — reaproveita exatamente os mesmos
# comandos já usados manualmente em /api/services e nos scripts de
# instalação, pra nunca ter dois jeitos diferentes de subir a mesma coisa.
DIAG_SERVICE_RESTART_CMDS = {
    "xray":         "systemctl restart xray",
    "proxy":        "systemctl restart proxy@80",
    "wss":          "systemctl restart wss@8443",
    "wsssec":       "systemctl restart wss-security@8888",
    "limiter":      "systemctl restart limiter",
    "checkuser":    "systemctl restart checkuser",
    "badvpn":       "systemctl restart badvpn",
    "slowdns":      "systemctl restart slowdns",
    "nginx":        "systemctl restart nginx",
    "whatsapp-bot": "systemctl restart whatsapp-bot",
    "stunnel":      "systemctl restart netsimon-stunnel",
    # netsimon-painel de propósito NÃO entra aqui: o unit já tem
    # "Restart=on-failure" no systemd (install.sh linha ~663), então se
    # o próprio painel cair, o systemd já resolve sozinho — não tem como
    # o processo se reiniciar por dentro de si mesmo de forma confiável.
}

# ── Interruptor de automação (item novo, a pedido do admin) ───────
# "manual"     -> nunca aplica nada sozinho; tudo vira "pendente_aprovacao"
#                 até o admin clicar em Aprovar. É o kill-switch: se algo
#                 na automação se comportar mal, trocar pra manual já
#                 desliga toda ação automática na hora.
# "parcial"    -> só reinício de serviço parado é autônomo (é a categoria
#                 mais segura/reversível: o serviço já está fora do ar,
#                 então reiniciar só pode melhorar, nunca piorar). Tudo o
#                 mais (arquivo, permissão) fica pendente de aprovação.
# "automatico" -> aplica tudo sozinho (comportamento padrão combinado).
# Fica num arquivo PRÓPRIO, separado do painel_config.json de propósito:
# assim a configuração do autodiagnóstico nunca depende do próprio
# painel_config.json (que é justamente um dos arquivos que o diagnóstico
# monitora) — evita qualquer risco de dependência circular.
DIAG_SETTINGS_F = "/etc/painel/diag_settings.json"
DIAG_MODES = ("manual", "parcial", "automatico")



# ── Sessões em memória ────────────────────────────────────────────
_sessions = {}  # token -> {user, role, expires}

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — armazenamento de incidentes
# ══════════════════════════════════════════════════════════════════
def _diag_load_incidents():
    if not os.path.exists(DIAG_INCIDENTS_F):
        return []
    try:
        with open(DIAG_INCIDENTS_F) as f:
            items = json.load(f)
    except Exception:
        return []

    # Item CORREÇÃO: a lista de incidentes técnicos (tela Diagnóstico >
    # Incidentes técnicos e o sininho de notificações, que lê daqui) só
    # crescia — um incidente antigo, já resolvido ou não, ficava exibido
    # pra sempre (limitado só pelos 300 mais recentes). Agora qualquer
    # incidente com mais de 72h é descartado automaticamente a cada
    # leitura, ou seja, a lista "reseta" sozinha a cada 72h sem precisar
    # de botão manual nem de job separado — e some das notificações no
    # mesmo prazo, já que elas usam essa mesma função como origem.
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=72)
    fresh = []
    for it in items:
        try:
            criado = datetime.datetime.fromisoformat(it.get("criado_em", ""))
        except Exception:
            fresh.append(it)  # sem data parseável — mantém, não some sem explicação
            continue
        if criado >= cutoff:
            fresh.append(it)

    if len(fresh) != len(items):
        try:
            _atomic_write_json(DIAG_INCIDENTS_F, fresh, indent=2)
        except Exception:
            pass

    return fresh

def _diag_save_incidents(items):
    # mantém só os 300 mais recentes pra não crescer pra sempre
    items = items[-300:]
    _atomic_write_json(DIAG_INCIDENTS_F, items, indent=2)

def _diag_register(incident):
    """Grava (ou ATUALIZA, se já existir um com o mesmo id — caso de uma
    aprovação manual de um incidente que já estava pendente) um incidente
    no histórico. Retorna o incidente já com id."""
    with DIAG_LOCK:
        items = _diag_load_incidents()
        incident.setdefault("id", uuidlib.uuid4().hex[:12])
        incident.setdefault("criado_em", datetime.datetime.now().isoformat())
        incident.setdefault("status", "sem_correcao_conhecida")
        incident.setdefault("auto_aplicada", False)
        incident.setdefault("notificado_whatsapp", False)
        idx = next((i for i, it in enumerate(items) if it.get("id") == incident["id"]), None)
        if idx is not None:
            items[idx] = incident
        else:
            items.append(incident)
        _diag_save_incidents(items)
    try:
        system_log_write(f"DIAG [{incident.get('causa_tipo')}] {incident.get('causa_detalhe')} -> {incident.get('status')}")
    except Exception:
        pass
    return incident

def _diag_load_settings():
    if not os.path.exists(DIAG_SETTINGS_F):
        return {"modo": "automatico"}
    try:
        with open(DIAG_SETTINGS_F) as f:
            data = json.load(f)
        if data.get("modo") not in DIAG_MODES:
            data["modo"] = "automatico"
        return data
    except Exception:
        return {"modo": "automatico"}

def _diag_save_settings(data):
    _atomic_write_json(DIAG_SETTINGS_F, data, indent=2)

def _diag_mode():
    return _diag_load_settings().get("modo", "automatico")

def _diag_pode_auto_aplicar(causa_tipo, modo):
    """Restaurar config corrompido é sempre permitido, em qualquer modo:
    é uma restauração pro último estado bom conhecido (baixíssimo risco),
    e o painel PRECISA de um config funcional pra sequer carregar a tela
    onde o admin aprovaria manualmente — não dá pra "pausar" esse caso.

    'ameaca_seguranca' também é sempre permitido, em qualquer modo, por
    pedido explícito do Simon após o incidente de cryptomining de
    setembro/2026: diferente de um arquivo faltando ou serviço caído
    (onde esperar aprovação é seguro), uma ameaça ativa consumindo CPU
    ou tentando se espalhar PIORA a cada minuto que passa esperando
    alguém abrir o painel. As assinaturas usadas aqui (processo
    disfarçado de thread de kernel, diretório oculto em /dev/shm) têm
    risco de falso positivo extremamente baixo -- software legítimo
    nunca se chama literalmente 'ksmd'/'kdevtmpfs' com argumentos de
    linha de comando, e não usa diretórios ocultos em /dev/shm."""
    if causa_tipo in ("config_corrompido", "ameaca_seguranca"):
        return True
    if modo == "automatico":
        return True
    if modo == "manual":
        return False
    if modo == "parcial":
        return causa_tipo == "servico_parado"
    return False

def _diag_describe_causa(tipo, alvo):
    if tipo == "ameaca_seguranca" and isinstance(alvo, dict):
        return f"Ameaça de segurança: processo \"{alvo.get('comm')}\" disfarçado (PID {alvo.get('pid')}, usuário {alvo.get('username')})"
    return {
        "arquivo_faltando": f"Arquivo de código ausente: {alvo}",
        "permissao_incorreta": f"Permissão incorreta em: {alvo}",
        "servico_parado": f"Serviço '{alvo}' fora do ar",
        "config_corrompido": "painel_config.json corrompido",
    }.get(tipo, tipo)

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — backup antes de qualquer correção (pra dar pra
#  reverter depois pela tela de Diagnóstico)
# ══════════════════════════════════════════════════════════════════
def _diag_backup_file(path):
    """Copia o arquivo pro diretório de backups do diagnóstico ANTES de
    qualquer correção automática mexer nele. Retorna o caminho do backup,
    ou None se o arquivo original nem existia (não há o que reverter
    nesse caso, já que "corrigir" aqui é justamente criá-lo)."""
    if not path or not os.path.exists(path):
        return None
    try:
        os.makedirs(DIAG_BACKUP_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = os.path.join(DIAG_BACKUP_DIR, f"{os.path.basename(path)}.{ts}.bak")
        shutil.copy2(path, dest)
        return dest
    except Exception as e:
        system_log_write(f"DIAG — falha ao fazer backup de {path}: {e}")
        return None

def _diag_snapshot_config_if_valid():
    """Chamado sempre que save_config() grava um painel_config.json que
    ACABOU de ser validado (é o próprio dict em memória, então por
    definição é válido) — mantém um histórico rotativo (10 versões) do
    último estado bom conhecido, pra poder restaurar se corromper depois."""
    try:
        if not os.path.exists(PAINEL_CFG):
            return
        os.makedirs(DIAG_CONFIG_HIST, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = os.path.join(DIAG_CONFIG_HIST, f"painel_config.{ts}.json")
        shutil.copy2(PAINEL_CFG, dest)
        snaps = sorted(os.listdir(DIAG_CONFIG_HIST))
        for old in snaps[:-10]:
            try:
                os.remove(os.path.join(DIAG_CONFIG_HIST, old))
            except Exception:
                pass
    except Exception as e:
        system_log_write(f"DIAG — falha ao criar snapshot de config: {e}")

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — correções catalogadas
# ══════════════════════════════════════════════════════════════════
def _diag_find_local_restore_source(filename):
    """Procura, só no que já existe NO PRÓPRIO SERVIDOR, a cópia mais
    recente de `filename` pra restaurar — nunca sai pra rede. Olha em
    dois lugares (nessa ordem de preferência):
      1) DIAG_BACKUP_DIR (/etc/painel/diag_backups) — backups feitos
         pelo próprio autodiagnóstico antes de mexer em algo.
      2) /etc/painel/backups/correcoes_*/ — backups das correções
         manuais (fixes) já aplicadas neste servidor, tanto em
         etc-painel/ quanto em var-www-html/.
    Retorna (caminho_encontrado, mtime) do mais recente, ou (None, None)
    se não achar nenhuma cópia local."""
    candidatos = []

    diag_pattern = os.path.join(DIAG_BACKUP_DIR, f"{filename}.*.bak")
    candidatos.extend(glob.glob(diag_pattern))

    fixes_glob = os.path.join(BASE, "backups", "correcoes_*", "*", filename)
    candidatos.extend(glob.glob(fixes_glob))

    candidatos = [c for c in candidatos if os.path.isfile(c) and os.path.getsize(c) > 0]
    if not candidatos:
        return None, None
    mais_recente = max(candidatos, key=os.path.getmtime)
    return mais_recente, os.path.getmtime(mais_recente)

def _diag_fix_missing_file(filename):
    """Restaura um arquivo de CÓDIGO conhecido (script ou página do
    painel) a partir de uma cópia LOCAL já existente no servidor (backup
    do próprio autodiagnóstico ou de correções manuais anteriores).
    Nunca usado pra arquivo de dado.

    FIX (parar de baixar da internet sozinho): antes, isso baixava o
    arquivo de novo direto do repositório oficial no GitHub via wget —
    then se o repositório estivesse fora do ar, sem internet, ou o
    arquivo tivesse sido renomeado/removido de lá (como aconteceu com
    "config.json.template", que nunca existiu no repo), a correção
    automática ficava tentando (e falhando) sozinha a cada 10 minutos,
    gerando incidente atrás de incidente. Agora o autodiagnóstico NUNCA
    acessa a internet pra isso: só repara se já existir uma cópia local
    (backup) desse arquivo neste servidor; senão, reporta como pendente
    sem tentar nada externo."""
    if filename in DIAG_FRONTEND_FILES:
        dest = os.path.join(DIAG_WEBROOT, filename)
    elif filename in DIAG_BACKEND_FILES:
        dest = os.path.join(BASE, filename)
    else:
        return {"ok": False, "arquivo_alvo": None,
                "motivo": f"'{filename}' não está no catálogo de arquivos gerenciados — "
                          f"não é seguro restaurar algo não catalogado de forma automática."}

    fonte, _ = _diag_find_local_restore_source(filename)
    if not fonte:
        return {"ok": False, "arquivo_alvo": dest, "backup_path": None,
                "motivo": f"sem cópia local de '{filename}' pra restaurar (nenhum backup encontrado "
                          f"em {DIAG_BACKUP_DIR} nem em {BASE}/backups/correcoes_*/) — "
                          f"download automático da internet está desativado, correção manual necessária"}

    backup_path = _diag_backup_file(dest)
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(fonte, dest)
        ok = os.path.exists(dest) and os.path.getsize(dest) > 0
    except Exception as e:
        ok = False
        system_log_write(f"DIAG — falha ao restaurar {filename} a partir de cópia local {fonte}: {e}")
    if ok and filename.endswith(".sh"):
        run_cmd(f'chmod +x "{dest}"')
    return {"ok": ok, "arquivo_alvo": dest, "backup_path": backup_path,
            "motivo": None if ok else f"falha ao copiar de {fonte}", "restaurado_de": fonte if ok else None}

def _diag_fix_permission(path):
    """Corrige permissão/dono de um arquivo gerenciado pro valor esperado,
    guardando o modo/dono anterior pra dar pra reverter depois."""
    try:
        st = os.stat(path)
        anterior = {"modo": oct(st.st_mode & 0o777), "uid": st.st_uid, "gid": st.st_gid}
    except Exception:
        return {"ok": False, "arquivo_alvo": path, "permissao_anterior": None,
                "aplicado": None, "motivo": "arquivo não encontrado pra corrigir permissão"}

    if path.endswith(".sh") or path.endswith(".py"):
        run_cmd(f'chmod +x "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "755 (executável), root:root"
    elif path in (USERDB, PAINEL_CFG, BLOCKED, DEVICE_DB) or path.endswith(".db"):
        run_cmd(f'chmod 600 "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "600, root:root"
    elif "/.ssh" in path:
        run_cmd(f'chmod 700 "{path}"')
        aplicado = "700"
    else:
        run_cmd(f'chmod 644 "{path}"'); run_cmd(f'chown root:root "{path}"')
        aplicado = "644, root:root"

    return {"ok": True, "arquivo_alvo": path, "permissao_anterior": anterior, "aplicado": aplicado, "motivo": None}

def _diag_restart_service(name):
    cmd = DIAG_SERVICE_RESTART_CMDS.get(name)
    if not cmd:
        return False
    _, rc = run_cmd(cmd)
    return rc == 0

# ── Autocorreção com causa real (item: watchdog "burro" virou esperto) ──
# Antes, tanto o watchdog automático quanto o botão "Tentar novamente"
# faziam UMA coisa só: rodar o comando de restart, esperar 3s, checar se
# subiu. Se a causa fosse qualquer coisa um pouco menos trivial — um
# processo órfão preso na porta, uma unit "masked", a unit do systemd
# nem existindo mais em disco — a tentativa falhava sempre, mesmo sendo
# uma causa 100% resolvível sem intervenção humana. Isso aqui adiciona
# heurísticas reais de causa comum, tentadas em sequência, ANTES de
# desistir e marcar como "falhou": só joga a bola pro admin depois de
# genuinamente ter tentado resolver sozinho.

# Porta(s) que cada serviço monitorado precisa conseguir ocupar pra
# subir. Usado tanto pra diagnóstico ("quem está segurando a porta?")
# quanto pra autocorreção (matar só processo órfão do PRÓPRIO painel
# que esteja preso nela).
SERVICE_PORTS = {
    "xray":      [443],
    "proxy":     [80],
    "wss":       [8443],
    "wsssec":    [8888],
    "checkuser": [5000],
    "badvpn":    [7300],
    "stunnel":   [2053],
}

# Unit(s) systemd de verdade por trás de cada serviço monitorado — na
# maioria é 1:1 com o nome. v41: wss-security@ (wss_security.py, sem
# TLS, porta 8888) entra como um 4º modo NOVO e independente, ao lado
# do wss@.service (wss.py, TLS real, porta 8443) que já existia — os
# dois convivem, nenhum substitui o outro.
# limiter/slowdns não têm unit própria (ainda rodam via screen/nohup) —
# a lista vazia faz a checagem de unit ser pulada de propósito pra
# esses dois.
SERVICE_UNITS = {
    "xray":      ["xray"],
    "proxy":     ["proxy@80"],
    "wss":       ["wss@8443"],
    "wsssec":    ["wss-security@8888"],
    "checkuser": ["checkuser"],
    "badvpn":    ["badvpn"],
    "limiter":   [],
    "slowdns":   [],
    "stunnel":   ["netsimon-stunnel"],
}

# Nomes de processo reconhecidos como "peça do próprio painel" — só
# processos que batem com um desses são candidatos a serem encerrados
# automaticamente por estarem presos numa porta. Isso é de propósito
# uma lista fechada: o autodiagnóstico NUNCA mata um processo que não
# reconheça (ex: Nginx, Apache, ou algo que o cliente subiu na mão),
# só limpa lixo órfão do próprio sistema — evitar "resolver" derrubando
# serviço de terceiro sem querer.
_DIAG_KNOWN_PROC_TOKENS = ("proxy.py", "wss.py", "wss_security.py", "checkuser.py", "badvpn-udpgw", "xray")

def _diag_who_holds_port(port):
    """Descobre PID + linha de comando de quem está de fato escutando
    numa porta TCP agora, via 'ss' (mais confiável que lsof numa VPS
    enxuta, onde lsof às vezes nem está instalado)."""
    out, _ = run_cmd(f"ss -ltnp 2>/dev/null | grep ':{port} '")
    m = re.search(r'pid=(\d+)', out)
    if not m:
        return None, None
    pid = m.group(1)
    cmd_out, _ = run_cmd(f"ps -p {pid} -o args= 2>/dev/null")
    return pid, cmd_out.strip()

def _diag_kill_stray_on_port(port):
    """Se a porta estiver presa por um processo ÓRFÃO reconhecido do
    próprio painel (ex: uma instância antiga do proxy.py que não morreu
    direito quando a unit systemd tentou subir uma nova), mata só esse
    processo específico e devolve o que foi feito — pra entrar no log
    do incidente. Nunca mexe em processo que não reconheça."""
    pid, cmd = _diag_who_holds_port(port)
    if not pid or not cmd:
        return None
    if any(tok in cmd for tok in _DIAG_KNOWN_PROC_TOKENS):
        run_cmd(f"kill -9 {pid} 2>/dev/null")
        return f"porta {port}: processo órfão (PID {pid}) encerrado — \"{cmd[:80]}\""
    return f"porta {port}: ocupada por processo não reconhecido (PID {pid}) — \"{cmd[:80]}\" (não mexido, pode ser de outro serviço)"

def _diag_ensure_unit_healthy(unit):
    """Corrige dois estados de unit systemd que travam qualquer restart
    até alguém mexer manualmente: 'masked' (alguém desabilitou de
    propósito ou uma reinstalação antiga deixou assim) e unit ausente
    do daemon em memória depois de o arquivo .service ter sido
    recriado por fora (precisa de daemon-reload pra ser enxergada)."""
    acoes = []
    estado, _ = run_cmd(f"systemctl is-enabled {unit} 2>&1")
    if "masked" in estado:
        run_cmd(f"systemctl unmask {unit} 2>/dev/null")
        acoes.append(f"unit '{unit}' estava mascarada — systemctl unmask aplicado")
    load_state, _ = run_cmd(f"systemctl show -p LoadState --value {unit} 2>/dev/null")
    if load_state.strip() == "not-found":
        run_cmd("systemctl daemon-reload")
        acoes.append(f"unit '{unit}' não estava carregada pelo systemd — daemon-reload aplicado")
    return acoes

def _diag_syntax_ok(name):
    """Pra serviços em Python do próprio painel (proxy, checkuser),
    checa se o script tem erro de sintaxe ANTES de insistir em
    reiniciar — evita ficar em loop de restart quando a causa real é
    um arquivo corrompido/editado errado, e já devolve isso como
    evidência clara em vez de só 'falhou'."""
    script_por_servico = {"proxy": f"{BASE}/proxy.py", "wss": f"{BASE}/wss.py", "wsssec": f"{BASE}/wss_security.py", "checkuser": f"{BASE}/checkuser.py"}
    script = script_por_servico.get(name)
    if not script or not os.path.exists(script):
        return True, None
    out, err, rc = run_cmd_full(f"python3 -c \"import ast; ast.parse(open('{script}').read())\"")
    if rc != 0:
        return False, f"Erro de sintaxe em {script}:\n{err or out}"
    return True, None

# ── Diagnóstico rico por serviço (item: autodiagnóstico mais claro) ─
# Antes, quando um restart automático falhava, o incidente só guardava
# a frase genérica "tentativa automática de reinício falhou" — nenhuma
# pista do PORQUÊ. Isso aqui coleta evidência real (status do systemd,
# fim do log próprio do serviço) no momento da falha, e guarda junto
# do incidente pra aparecer na tela sem o admin precisar entrar no
# servidor toda vez.
SERVICE_DIAG_INFO = {
    "xray": {
        "label": "Xray (VLESS/XHTTP, porta 443)", "unit": "xray", "log": "/var/log/xray/error.log",
        "dica": "Cause comum: erro de sintaxe no config.json do Xray, ou a porta 443 já está sendo usada por "
                "outro processo. Teste manualmente com: xray run -test -config /usr/local/etc/xray/config.json",
    },
    "proxy": {
        "label": "WS PROXY (porta 80, sem auth)", "unit": "proxy@80", "log": "/var/log/netsimon_proxy.log",
        "dica": "Cause comum: a porta 80 já está ocupada por outro processo (Nginx, Apache, outra instância "
                "travada). Verifique com: ss -tlnp | grep ':80 '",
    },
    "wss": {
        "label": "WSS TLS (porta 8443)", "unit": "wss@8443",
        "log": "/var/log/netsimon_wss.log",
        "dica": "Cause comum: a porta 8443 já está ocupada por outro processo, ou o certificado/chave em "
                "/etc/painel/wss/ está ausente/ilegível. Verifique com: ss -tlnp | grep ':8443 ' e "
                "ls -la /etc/painel/wss/",
    },
    "wsssec": {
        "label": "WSS SSH (porta 8888)", "unit": "wss-security@8888",
        "log": "/var/log/netsimon_wss_security.log",
        "dica": "Cause comum: a porta 8888 já está ocupada por outro processo. "
                "Verifique com: ss -tlnp | grep ':8888 '",
    },
    "limiter": {
        "label": "Limiter", "unit": "limiter", "log": "/var/log/netsimon_limit.log",
        "dica": "Cause comum: /etc/painel/usuarios.db ausente/vazio, ou a API do Xray (porta 2000) não está "
                "respondendo. Verifique com: xray api statsonline --server=127.0.0.1:2000",
    },
    "checkuser": {
        "label": "CheckUser API (porta 5000)", "unit": "checkuser", "log": "/var/log/checkuser.log",
        "dica": "Cause comum: porta 5000 já ocupada, dependência Flask ausente, ou o arquivo checkuser.py foi "
                "editado e ficou com erro de sintaxe. Teste manualmente com: python3 /etc/painel/checkuser.py",
    },
    "badvpn": {
        "label": "BadVPN UDPGW (porta 7300)", "unit": "badvpn", "log": None,
        "dica": "Cause comum: o binário /usr/local/bin/badvpn-udpgw sumiu ou ficou sem permissão de execução.",
    },
    "slowdns": {
        "label": "SlowDNS", "unit": "slowdns", "log": None,
        "dica": "Cause comum: processo dnstt-server ausente ou a porta UDP configurada está sendo usada por outro serviço.",
    },
    "stunnel": {
        "label": "STUNNEL SSL (porta 2053)", "unit": "netsimon-stunnel",
        "log": "/var/log/netsimon_stunnel.log",
        "dica": "Cause comum: a porta configurada já está ocupada por outro processo, ou o certificado em "
                "/etc/painel/stunnel/ está ausente/ilegível. Verifique com: ss -tlnp | grep ':2053 ' e "
                "ls -la /etc/painel/stunnel/",
    },
}

def run_cmd_full(cmd, timeout=15):
    """Como run_cmd(), mas devolve stdout E stderr separados — necessário
    pra diagnóstico de verdade, porque erro de processo (traceback do
    Python, 'command not found', etc.) quase sempre vai pro stderr, e o
    run_cmd() normal descarta essa informação."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def _diag_collect_service_evidence(name):
    """Roda no momento da falha (ou sob demanda pelo botão 'Diagnosticar'
    na tela) e devolve evidência legível: status real do systemd + fim
    do log próprio do serviço + uma dica objetiva do que costuma causar
    esse tipo de falha nesse serviço específico."""
    info = SERVICE_DIAG_INFO.get(name, {})
    unit = info.get("unit", name)
    evidencia = {"servico": name, "coletado_em": datetime.datetime.now().isoformat()}

    status_out, _, _ = run_cmd_full(f"systemctl status {unit} --no-pager -l 2>&1 | tail -n 15")
    evidencia["systemctl_status"] = status_out or "(sem saída — serviço pode não existir como unidade systemd)"

    log_path = info.get("log")
    if log_path and os.path.exists(log_path):
        log_out, _, _ = run_cmd_full(f"tail -n 20 {log_path} 2>&1")
        evidencia["log_tail"] = log_out
        evidencia["log_path"] = log_path
    else:
        evidencia["log_tail"] = None
        evidencia["log_path"] = log_path

    # Quem está de fato segurando cada porta que esse serviço precisa —
    # a causa mais comum de restart falhar (porta ocupada) agora aparece
    # explícita na evidência, em vez do admin ter que descobrir na mão.
    portas_info = []
    for port in SERVICE_PORTS.get(name, []):
        pid, cmd = _diag_who_holds_port(port)
        portas_info.append({
            "porta": port,
            "ocupada_por": cmd or None,
            "pid": pid or None,
        })
    if portas_info:
        evidencia["portas"] = portas_info

    evidencia["dica"] = info.get("dica", "Sem dica específica cadastrada para este serviço.")
    return evidencia

def _diag_restart_service_com_evidencia(name, max_tentativas=3):
    """Tenta religar o serviço com heurísticas de causa real, não só
    'roda o restart e reza'. Ordem de tentativa:
      1) checa sintaxe do script (serviços em Python do painel) — se
         estiver quebrado, nem tenta reiniciar, já volta a causa certa
      2) tenta o restart normal
      3) se continuar fora do ar: desmascara/recarrega a unit se for o
         caso, mata processo ÓRFÃO reconhecido preso na porta, e tenta
         de novo — até max_tentativas rodadas
    Usado tanto pelo watchdog automático quanto pelo botão manual de
    'Tentar novamente' na tela de incidentes. Só desiste (status
    'falhou') depois de ter tentado de verdade resolver sozinho — e
    quando desiste, a evidência já vem com o que foi tentado e por quê."""
    cmd = DIAG_SERVICE_RESTART_CMDS.get(name)
    if not cmd:
        return False, None, "Nenhum comando de reinício configurado para este serviço."

    ok_sintaxe, erro_sintaxe = _diag_syntax_ok(name)
    if not ok_sintaxe:
        evidencia = _diag_collect_service_evidence(name)
        evidencia["comando_tentado"] = None
        evidencia["saida_comando"] = None
        evidencia["erro_comando"] = erro_sintaxe
        evidencia["tentativas"] = [{"tentativa": 1, "resultado": "abortado — erro de sintaxe no script, restart não resolveria"}]
        return False, evidencia, None

    units = SERVICE_UNITS.get(name, [name])
    tentativas_log = []
    saida = erro = ""
    for tentativa in range(1, max_tentativas + 1):
        acoes_extra = []
        if tentativa > 1:
            # só entra em ação corretiva a partir da 2ª tentativa — a
            # 1ª é sempre o caminho feliz (restart simples), igual antes
            for unit in units:
                acoes_extra += _diag_ensure_unit_healthy(unit)
            for port in SERVICE_PORTS.get(name, []):
                resultado_porta = _diag_kill_stray_on_port(port)
                if resultado_porta:
                    acoes_extra.append(resultado_porta)
            if acoes_extra:
                time.sleep(1)

        saida, erro, rc = run_cmd_full(cmd)
        time.sleep(3 if tentativa == 1 else 4)
        up = service_status(name)
        tentativas_log.append({
            "tentativa": tentativa, "rc": rc, "up_depois": up,
            "acoes_corretivas": acoes_extra or None,
        })
        if up:
            return True, {"tentativas": tentativas_log} if tentativa > 1 else None, None

    evidencia = _diag_collect_service_evidence(name)
    evidencia["comando_tentado"] = cmd
    evidencia["saida_comando"] = saida or None
    evidencia["erro_comando"] = erro or None
    evidencia["tentativas"] = tentativas_log
    return False, evidencia, None

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — classificação por padrões (determinística, não é
#  IA generativa: compara o texto do erro com assinaturas conhecidas)
# ══════════════════════════════════════════════════════════════════
def _diag_classify_text(text):
    if not text:
        return None

    m = re.search(r"No such file or directory:?\s*'?\"?([^\s'\"]+)'?\"?", text)
    if m:
        base = os.path.basename(m.group(1))
        if base in DIAG_FRONTEND_FILES or base in DIAG_BACKEND_FILES:
            return ("arquivo_faltando", base)

    m = re.search(r"(?:bash|sh): ([^\s:]+): (?:command not found|No such file)", text)
    if m:
        base = os.path.basename(m.group(1))
        if base in DIAG_FRONTEND_FILES or base in DIAG_BACKEND_FILES:
            return ("arquivo_faltando", base)

    m = re.search(r"Permission denied:?\s*'?\"?([^\s'\"]+)'?\"?", text)
    if m:
        return ("permissao_incorreta", m.group(1))

    if ("JSONDecodeError" in text or "Expecting value" in text) and ("painel_config" in text or "PAINEL_CFG" in text):
        return ("config_corrompido", PAINEL_CFG)

    if re.search(r"Connection refused", text, re.I) and re.search(r"127\.0\.0\.1:2000|xray", text, re.I):
        return ("servico_parado", "xray")

    return None

def _diag_apply_fix(incident, tipo, alvo, rota=None, aprovado_manualmente=False):
    """Aplica DE FATO a correção catalogada pro (tipo, alvo) informado e
    grava o resultado no incidente. Usado tanto pelo caminho automático
    quanto pela aprovação manual de um incidente pendente — é o único
    lugar que efetivamente executa uma correção, então tanto faz por
    onde a chamada chegou até aqui."""
    incident["causa_tipo"] = tipo
    incident["alvo_bruto"] = alvo
    incident["causa_detalhe"] = _diag_describe_causa(tipo, alvo)
    incident["auto_aplicada"] = True
    if aprovado_manualmente:
        incident["aprovado_em"] = datetime.datetime.now().isoformat()

    if tipo == "arquivo_faltando":
        r = _diag_fix_missing_file(alvo)
        incident["status"] = "corrigido" if r["ok"] else "falhou"
        incident["correcao"] = f"Restaurado '{alvo}' a partir de cópia local (backup em {r.get('restaurado_de')})" if r["ok"] else r.get("motivo")
        incident["arquivo_alvo"] = r.get("arquivo_alvo")
        incident["backup_path"] = r.get("backup_path")

    elif tipo == "permissao_incorreta":
        r = _diag_fix_permission(alvo)
        incident["status"] = "corrigido" if r["ok"] else "falhou"
        incident["correcao"] = f"Ajustado para {r.get('aplicado')}" if r["ok"] else r.get("motivo")
        incident["arquivo_alvo"] = r.get("arquivo_alvo")
        incident["permissao_anterior"] = r.get("permissao_anterior")

    elif tipo == "servico_parado":
        ok, evidencia, _ = _diag_restart_service_com_evidencia(alvo)
        incident["status"] = "corrigido" if ok else "falhou"
        tentativas = (evidencia or {}).get("tentativas") if evidencia else None
        acoes = [a for t in (tentativas or []) for a in (t.get("acoes_corretivas") or [])]
        if ok and acoes:
            incident["correcao"] = "Religado após correção automática: " + "; ".join(acoes)
        elif ok:
            incident["correcao"] = f"systemctl restart {alvo}"
        else:
            incident["correcao"] = "Falha ao reiniciar o serviço mesmo após tentativas com correção automática de causas comuns"
        incident["servico_reiniciado"] = alvo if ok else None
        incident["diagnostico"] = evidencia if evidencia else incident.get("diagnostico")
        send_whatsapp_alert("admin", f"🛠️ Serviço *{alvo}* foi reiniciado {'automaticamente' if not aprovado_manualmente else 'após sua aprovação'} "
                                      f"após detectar falha{' em ' + rota if rota else ''}."
                                      if ok else
                                      f"🚨 Tentativa de reiniciar *{alvo}* {'automaticamente' if not aprovado_manualmente else 'após sua aprovação'} FALHOU. "
                                      f"Veja o diagnóstico detalhado em Diagnóstico > Incidentes técnicos.")
        incident["notificado_whatsapp"] = True

    elif tipo == "config_corrompido":
        # normalmente já é tratado dentro do próprio load_config() antes
        # de chegar aqui; isso é uma rede de segurança extra.
        incident["status"] = "sem_correcao_conhecida"
        incident["correcao"] = "Reinicie o painel ou acesse Diagnóstico > Incidentes para detalhes"

    elif tipo == "ameaca_seguranca":
        # 'alvo' aqui é o forensic dict coletado por _sec_coletar_forense()
        # (não um nome de arquivo/serviço como nos outros tipos) -- ver
        # _sec_neutralizar() logo abaixo pra entender cada ação tomada.
        forense = alvo
        resultado = _sec_neutralizar(forense)
        incident["status"] = "corrigido" if resultado["ok"] else "falhou"
        incident["diagnostico"] = {
            "processo": forense.get("comm"),
            "pid": forense.get("pid"),
            "caminho_executavel": forense.get("exe"),
            "sha256_binario": forense.get("sha256"),
            "usuario_dono": forense.get("username"),
            "linha_de_comando": forense.get("cmdline"),
            "motivo_deteccao": forense.get("motivo"),
            "acoes_tomadas": resultado.get("acoes"),
        }
        incident["correcao"] = "; ".join(resultado.get("acoes") or []) or resultado.get("motivo")
        emoji = "🛡️" if resultado["ok"] else "🚨"
        send_whatsapp_alert("admin", f"{emoji} Autodiagnóstico de segurança detectou e "
                                      f"{'neutralizou' if resultado['ok'] else 'tentou neutralizar (falhou)'} uma ameaça: "
                                      f"processo \"{forense.get('comm')}\" disfarçado, rodando de {forense.get('exe')} "
                                      f"como o usuário \"{forense.get('username')}\". Ações: {incident['correcao']}. "
                                      f"Veja detalhes em Diagnóstico > Incidentes técnicos.")
        incident["notificado_whatsapp"] = True

    return _diag_register(incident)

def _diag_maybe_fix(origem, tipo, alvo, rota=None, metodo=None, status_http=None, causa_detalhe_bruto=None):
    """Ponto único de decisão: conforme o MODO DE AUTOMAÇÃO configurado
    pelo admin (manual/parcial/automatico), aplica a correção agora ou
    registra como pendente de aprovação (e avisa por WhatsApp, já que
    "pendente" ainda pode ser algo urgente, como um serviço caído)."""
    incident = {
        "origem": origem, "rota": rota, "metodo": metodo, "status_http": status_http,
        "causa_detalhe_bruto": (causa_detalhe_bruto or "")[:2000],
    }
    modo = _diag_mode()
    if not _diag_pode_auto_aplicar(tipo, modo):
        incident["causa_tipo"] = tipo
        incident["alvo_bruto"] = alvo
        incident["causa_detalhe"] = _diag_describe_causa(tipo, alvo)
        incident["status"] = "pendente_aprovacao"
        incident["auto_aplicada"] = False
        incident["correcao"] = None
        if tipo == "servico_parado":
            send_whatsapp_alert("admin", f"🚨 Serviço *{alvo}* caiu e está aguardando sua aprovação pra "
                                          f"reiniciar (modo de automação: {modo}). Acesse Diagnóstico > Incidentes técnicos.")
            incident["notificado_whatsapp"] = True
        return _diag_register(incident)
    return _diag_apply_fix(incident, tipo, alvo, rota)

def _diag_handle_error(origem, rota, metodo, status_http, texto_erro):
    """Ponto de entrada reativo: recebe o texto de um erro (traceback ou
    mensagem), classifica a causa e decide (via _diag_maybe_fix) se
    corrige na hora ou deixa pendente de aprovação."""
    causa = _diag_classify_text(texto_erro)
    if not causa:
        incident = {
            "origem": origem, "rota": rota, "metodo": metodo, "status_http": status_http,
            "causa_detalhe_bruto": (texto_erro or "")[:2000],
            "causa_tipo": "desconhecido",
            "causa_detalhe": "Não bateu com nenhum padrão catalogado — precisa de revisão manual.",
            "status": "sem_correcao_conhecida",
        }
        return _diag_register(incident)

    tipo, alvo = causa
    return _diag_maybe_fix(origem, tipo, alvo, rota=rota, metodo=metodo, status_http=status_http, causa_detalhe_bruto=texto_erro)


# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — interceptação global: qualquer exceção não tratada
#  OU qualquer resposta 4xx/5xx retornada explicitamente por uma rota
#  passa por aqui antes de chegar no cliente.
# ══════════════════════════════════════════════════════════════════
@app.errorhandler(Exception)
def _diag_global_exception_handler(e):
    # HTTPException (404 de rota inexistente, abort(...) intencional etc.)
    # é comportamento NORMAL do Flask, não um bug — deixa seguir pro
    # tratamento padrão em vez de "diagnosticar" tráfego rotineiro.
    if isinstance(e, HTTPException):
        return e

    tb = traceback.format_exc()
    try:
        system_log_write(f"EXCEÇÃO NÃO TRATADA em {request.path}: {e}")
    except Exception:
        pass
    request._ns_diag_handled = True
    incident = _diag_handle_error(
        origem="exception",
        rota=request.path,
        metodo=request.method,
        status_http=500,
        texto_erro=f"{type(e).__name__}: {e}\n{tb}",
    )
    return jsonify({
        "error": "Ocorreu um erro interno. O autodiagnóstico já analisou o caso.",
        "diagnostico_incidente_id": incident.get("id"),
        "diagnostico_status": incident.get("status"),
    }), 500

@app.after_request
def _diag_after_request(response):
    try:
        already = getattr(request, "_ns_diag_handled", False)
        is_diag_route = request.path.startswith("/api/diagnostics")
        if response.status_code >= 400 and not already and not is_diag_route:
            texto = ""
            if response.is_json:
                body = response.get_json(silent=True) or {}
                texto = " ".join(str(v) for v in body.values() if v)
            causa = _diag_classify_text(texto)
            # 5xx sempre vale registrar (é sempre anormal). Já um 4xx
            # "comum" (login errado, campo inválido, sem permissão etc.)
            # só vira incidente se bater com um padrão técnico conhecido —
            # senão é só o dia a dia normal do painel, não um bug.
            if response.status_code >= 500 or causa is not None:
                _diag_handle_error(
                    origem="http_error",
                    rota=request.path,
                    metodo=request.method,
                    status_http=response.status_code,
                    texto_erro=texto,
                )
    except Exception as e:
        try:
            system_log_write(f"DIAG after_request erro: {e}")
        except Exception:
            pass
    return response



# ── Config do painel ──────────────────────────────────────────────
def _atomic_write(path, write_fn):
    """Escrita atômica genérica: escreve num arquivo temporário no mesmo
    diretório (garante que fica no mesmo filesystem, pra os.replace()
    poder ser atômico), força persistência em disco, e só então substitui
    o arquivo final. Usado por todo save_*()/​_save_*() do painel pra
    eliminar a classe de bug 'arquivo de config truncado/corrompido por
    causa de um restart no meio da escrita' (foi exatamente isso que
    fazia a chave de IA, entre outras configs, sumir esporadicamente)."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    # BUGFIX (item 6): o sufixo era só o PID. Depois de muitos restarts o
    # SO reaproveita números de PID baixos, então um arquivo .tmpNNNN
    # órfão de uma escrita antiga (processo derrubado no meio, antes do
    # os.replace) podia ficar no disco e colidir com um PID novo — o
    # incidente "Permissão incorreta em test_logins.json.tmpNNNN" (visto
    # no autodiagnóstico) era exatamente isso: o arquivo órfão tinha dono/
    # permissão de uma execução anterior. Acrescenta um token aleatório
    # pra cada tmp ser sempre único de verdade, e limpa órfão antigo do
    # MESMO path (não só o do PID atual) antes de escrever.
    tmp_path = f"{path}.tmp{os.getpid()}{secrets.token_hex(4)}"
    try:
        with open(tmp_path, "w") as f:
            write_fn(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        # Se algo falhou entre criar o tmp e o replace, não deixa lixo.
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

def _atomic_write_json(path, data, indent=None):
    _atomic_write(path, lambda f: json.dump(data, f, indent=indent))

def load_config():
    default = {
        "admin": {
            "username": "admin",
            "password": hashlib.sha256(b"netsimon").hexdigest()
        },
        "resellers": {},
        "public_domain": "",  # ex: "painel.netsimon.fun" — usado para gerar
                              # links clicáveis (WhatsApp não linkifica
                              # URLs com IP puro, só domínios)
        "device_block": {
            # Interruptor REAL do bloqueio por device_hash (_device_check_core).
            # Antes esse sistema não tinha nenhuma flag: rodava sempre,
            # incondicionalmente, e o botão "Ativar/Desativar Limiter" da
            # tela Dispositivos só controlava o limit.sh (outro sistema,
            # que limita conexões simultâneas por IP/SSH). Os dois eram
            # independentes no código mas apareciam como se fossem um só
            # na tela. Agora cada um tem seu próprio interruptor de verdade.
            "enabled": True
        }
    }
    if not os.path.exists(PAINEL_CFG):
        save_config(default)
        return default
    try:
        with open(PAINEL_CFG) as f:
            return json.load(f)
    except Exception as e:
        return _diag_recover_corrupt_config(e, default)

def _diag_recover_corrupt_config(exc, default):
    """painel_config.json corrompido: antes disso, um config quebrado
    fazia o painel voltar silenciosamente pro default vazio (sem
    revendedor nenhum!) sem avisar absolutamente ninguém. Agora: guarda
    o arquivo quebrado pra investigação, tenta restaurar o último
    snapshot válido salvo por save_config(), e sempre avisa o admin por
    WhatsApp sobre o que aconteceu (corrigido ou não)."""
    backup_path = _diag_backup_file(PAINEL_CFG)
    restored = None
    try:
        if os.path.isdir(DIAG_CONFIG_HIST):
            snaps = sorted(os.listdir(DIAG_CONFIG_HIST))
            if snaps:
                latest = os.path.join(DIAG_CONFIG_HIST, snaps[-1])
                with open(latest) as f:
                    candidate = json.load(f)  # valida que o snapshot também não está corrompido
                shutil.copy2(latest, PAINEL_CFG)
                restored = candidate
    except Exception as e2:
        system_log_write(f"DIAG — snapshot de config também inválido: {e2}")

    incident = {
        "origem": "config_corrompido", "causa_tipo": "config_corrompido",
        "causa_detalhe": f"painel_config.json inválido: {exc}",
        "arquivo_alvo": PAINEL_CFG, "backup_path": backup_path,
        "auto_aplicada": True,
    }

    if restored is not None:
        incident["status"] = "corrigido"
        incident["correcao"] = "Restaurado o último snapshot válido de painel_config.json"
        send_whatsapp_alert("admin", "🛠️ Autodiagnóstico: o config.json do painel estava corrompido e foi "
                                      "restaurado automaticamente a partir do último backup válido. "
                                      "Confira em Diagnóstico > Incidentes técnicos.")
        incident["notificado_whatsapp"] = True
        _diag_register(incident)
        return restored
    else:
        incident["status"] = "falhou"
        incident["correcao"] = None
        send_whatsapp_alert("admin", "🚨 URGENTE: o config.json do painel está corrompido e não havia "
                                      "nenhum backup válido pra restaurar automaticamente. O painel está "
                                      "rodando com configuração padrão agora (revendedores podem ter "
                                      "sumido da tela!). Acesse o servidor o quanto antes.")
        incident["notificado_whatsapp"] = True
        _diag_register(incident)
        return default

def save_config(cfg):
    """BUG RAIZ da chave de IA (e de revendedores/configs) sumindo de vez
    em quando: esta função gravava direto em cima do painel_config.json
    (open(..., "w") trunca o arquivo na hora, ANTES de escrever o
    conteúdo novo). O painel é reiniciado com frequência — updates,
    watchdog, autodiagnóstico, restart manual — e se um desses restarts
    (ou uma queda de energia/OOM) acontecesse no meio exato dessa escrita,
    o arquivo ficava truncado/corrompido. O painel então caía no
    recovery de config corrompido e restaurava o ÚLTIMO SNAPSHOT VÁLIDO
    — que podia ser de ANTES da chave de IA ter sido salva, fazendo ela
    "sumir" mesmo sem ninguém ter mexido nela.
    Fix: escrita atômica — grava num arquivo temporário no mesmo
    diretório, força o SO a persistir em disco (flush+fsync) e só então
    substitui o arquivo original com os.replace(), que no Linux é uma
    operação atômica (o arquivo final nunca fica "pela metade", em
    nenhum instante — mesmo que o processo morra no meio do caminho, o
    pior caso é o arquivo temporário ficar orfão, nunca o config real
    corrompido)."""
    _atomic_write_json(PAINEL_CFG, cfg, indent=2)
    # config recém-gravado passou pelo json.dump sem erro, então por
    # definição é válido — vira o próximo "último estado bom conhecido"
    # pra restaurar se ele corromper depois.
    _diag_snapshot_config_if_valid()

# ── Interruptor do bloqueio por dispositivo (device_hash) ──────────
# Sistema 100% separado do Limiter (limit.sh). Usa .get() com default
# True em vez de depender de migração do painel_config.json existente,
# então instalações antigas continuam bloqueando por device_hash igual
# sempre bloquearam (comportamento anterior, sem flag nenhuma) até o
# admin desativar explicitamente pela tela ou pelo menu SSH.
def device_block_enabled():
    cfg = load_config()
    return bool(cfg.get("device_block", {}).get("enabled", True))

def set_device_block_enabled(value):
    cfg = load_config()
    cfg["device_block"] = {"enabled": bool(value)}
    save_config(cfg)

# ── Hierarquia de revendedores (admin > revendedor nível 2 > revendedor
#    nível 3) ─────────────────────────────────────────────────────────
# Cada revendedor tem um campo "parent": o username de quem o criou.
# Se parent == admin username -> nível 2. Se parent é outro revendedor
# -> nível 3. Nível 3 nunca pode criar sub-revendedores (máx. 3 níveis).

def reseller_level(cfg, username):
    r = cfg.get("resellers", {}).get(username)
    if not r:
        return None
    parent = r.get("parent", cfg["admin"]["username"])
    if parent == cfg["admin"]["username"]:
        return 2
    return 3

def direct_children(cfg, username):
    """Revendedores cujo 'parent' é este username."""
    return [name for name, r in cfg.get("resellers", {}).items()
            if r.get("parent") == username]

def all_descendant_resellers(cfg, username):
    """Todos os revendedores abaixo (filhos + netos, recursivo)."""
    out = []
    for child in direct_children(cfg, username):
        out.append(child)
        out.extend(all_descendant_resellers(cfg, child))
    return out

def all_owned_logins(cfg, username):
    """Todos os logins de usuário criados por este revendedor E por
    todos os seus sub-revendedores (usado para escopo de listagem e
    para a apuração de cota)."""
    r = cfg.get("resellers", {}).get(username, {})
    logins = set(r.get("users", []))
    for child in all_descendant_resellers(cfg, username):
        logins |= set(cfg["resellers"].get(child, {}).get("users", []))
    return logins

# ── Fotos de usuário — portado do NetSimon 7.0 ────────────────────
def read_photos():
    photos = {}
    if os.path.exists(FOTOS_DB):
        with open(FOTOS_DB) as f:
            for line in f:
                parts = line.strip().split("|", 1)
                if len(parts) == 2 and parts[0]:
                    photos[parts[0]] = parts[1]
    return photos

def save_photos(photos):
    def _write(f):
        for login, fn in photos.items():
            f.write(f"{login}|{fn}\n")
    _atomic_write(FOTOS_DB, _write)

def detect_image_ext(data: bytes):
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None

def quota_usage(cfg, username):
    """(usados, cota) — usados soma o 'limite' (quantidade de acessos/
    dispositivos) de cada usuário próprio + de todos os sub-revendedores,
    e não a quantidade de usuários. Cada crédito de cota representa 1
    acesso, então um usuário criado com limite=5 consome 5 créditos, não
    1. Isso vale em cascata pra cota de nível 2 e nível 3."""
    r = cfg.get("resellers", {}).get(username, {})
    owned = all_owned_logins(cfg, username)
    if owned:
        limit_by_login = {}
        for u in read_users():
            try:
                limit_by_login[u["login"]] = max(1, int(u.get("limite", 1)))
            except (TypeError, ValueError):
                limit_by_login[u["login"]] = 1
        used = sum(limit_by_login.get(login, 1) for login in owned)
    else:
        used = 0
    quota = int(r.get("quota", 0))
    return used, quota

def reseller_and_ancestors(cfg, username):
    """[username, pai, avô, ...] até chegar no admin."""
    chain = []
    cur = username
    seen = set()
    while cur and cur in cfg.get("resellers", {}) and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = cfg["resellers"][cur].get("parent")
        if cur == cfg["admin"]["username"]:
            break
    return chain

def quota_available_for_new_user(cfg, username, limite=1):
    """Verifica se o próprio revendedor E toda a cadeia de pais acima
    dele ainda têm cota livre para acomodar um novo usuário com este
    `limite` de acessos (uma cota de nível 2 também limita o total dos
    seus filhos de nível 3)."""
    try:
        limite = max(1, int(limite))
    except (TypeError, ValueError):
        limite = 1
    for name in reseller_and_ancestors(cfg, username):
        used, quota = quota_usage(cfg, name)
        if quota > 0 and used + limite > quota:
            return False, name
    return True, None

def register_user_to_reseller(cfg, username, login):
    res = cfg["resellers"].setdefault(username, {})
    res.setdefault("users", []).append(login)
    _maybe_alert_quota(cfg, username)

def _maybe_alert_quota(cfg, username):
    """Item: avisa o revendedor por WhatsApp quando a cota bate 90% —
    só uma vez por "ciclo" (não repete até cair de novo abaixo de 90%
    e voltar a subir, controlado por 'quota_alert_sent')."""
    used, quota = quota_usage(cfg, username)
    if quota <= 0:
        return
    pct = used / quota
    res = cfg["resellers"].setdefault(username, {})
    if pct >= 0.9 and not res.get("quota_alert_sent"):
        res["quota_alert_sent"] = True
        send_whatsapp_alert(username, f"📦 Atenção: sua cota está quase no limite ({used}/{quota} usuários). Considere pedir um aumento.")
    elif pct < 0.9 and res.get("quota_alert_sent"):
        res["quota_alert_sent"] = False

def unregister_user_from_reseller(cfg, login):
    """Remove o login da lista de qualquer revendedor que o possua
    (libera a cota automaticamente)."""
    for r in cfg.get("resellers", {}).values():
        if login in r.get("users", []):
            r["users"].remove(login)

def find_owner_of_login(cfg, login):
    """Retorna o username do revendedor dono do login, ou None se foi
    criado diretamente pelo admin."""
    for name, r in cfg.get("resellers", {}).items():
        if login in r.get("users", []):
            return name
    return None

# ── Rastreamento de tempo de conexão contínua (item 13) ──────────────
ONLINE_SINCE_F = "/etc/painel/online_since.json"
_online_since_lock = threading.Lock()

def _load_online_since():
    if not os.path.exists(ONLINE_SINCE_F):
        return {}
    try:
        with open(ONLINE_SINCE_F) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_online_since(data):
    _atomic_write_json(ONLINE_SINCE_F, data)

def update_online_since(currently_online):
    """Chamado toda vez que a lista de online é calculada. Marca o
    horário em que cada usuário ficou online pela primeira vez desde a
    última desconexão, e zera (remove) quem caiu."""
    with _online_since_lock:
        data = _load_online_since()
        now = time.time()
        changed = False
        for login in currently_online:
            if login not in data:
                data[login] = now
                changed = True
        for login in list(data.keys()):
            if login not in currently_online:
                _record_completed_session(login, data[login], now, int(now - data[login]))
                del data[login]
                changed = True
        if changed:
            _save_online_since(data)
        return data

def _record_completed_session(login, since_ts, now_ts, duration_seconds):
    # Grava no netsimon_logs.db (mesmo banco do log_watcher.py) uma
    # sessao completa assim que o online_since detecta que o usuario
    # caiu. Fonte real de duracao -- o access.log do Xray nao tem
    # evento de desconexao, entao esse eh o unico jeito de medir tempo
    # de fato conectado sem mexer no app cliente.
    if duration_seconds < 20:
        return  # ignora flutuacoes curtas (queda de rede momentanea)
    try:
        conn = get_logs_db()
        conn.execute(
            """INSERT INTO connection_sessions
               (user_id, server, connect_at, disconnect_at, duration_seconds)
               VALUES (?,?,?,?,?)""",
            (
                login,
                "painel",
                datetime.datetime.utcfromtimestamp(since_ts).strftime("%Y-%m-%d %H:%M:%S"),
                datetime.datetime.utcfromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S"),
                duration_seconds,
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # banco de logs pode nao existir ainda -- nao quebra o online-tracking

def online_duration_seconds(login, data=None):
    data = data if data is not None else _load_online_since()
    since = data.get(login)
    if not since:
        return 0
    return int(time.time() - since)

# ── Auth helpers ──────────────────────────────────────────────────
def create_session(username, role):
    token = secrets.token_hex(32)
    _sessions[token] = {
        "user": username,
        "role": role,
        "expires": time.time() + 86400  # 24h
    }
    return token

def get_session(token):
    s = _sessions.get(token)
    if not s:
        return None
    if time.time() > s["expires"]:
        del _sessions[token]
        return None
    return s

def _load_sync_token():
    path = "/etc/painel/sync_token.txt"
    if os.path.exists(path):
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def _internal_request_ok():
    """Item de segurança: substitui a checagem antiga de
    request.remote_addr in ("127.0.0.1", ...) — que NUNCA bloqueava
    ninguém vindo de fora pelo domínio/IP público, porque o Nginx faz
    proxy_pass pra todo /api/ e a conexão com o Flask sempre parte do
    próprio localhost (então remote_addr é sempre 127.0.0.1, venha a
    requisição de onde vier). Sem isso, qualquer pessoa na internet podia
    forjar uma "mensagem recebida" do bot ou poluir a última interação
    usada pelas campanhas.
    Reaproveita o mesmo arquivo de segredo do X-Sync-Token (já existe,
    já tem permissão 600), mas com um header próprio e uma checagem
    isolada — só libera essas 2 rotas internas específicas, não dá acesso
    de admin à API inteira como o X-Sync-Token dá."""
    token = request.headers.get("X-Internal-Token", "")
    expected = _load_sync_token()
    if not expected or not token:
        return False
    return secrets.compare_digest(token, expected)

def auth_required(roles=None):
    """Decorator de autenticação. Aceita sessão normal (X-Token) OU o
    token de sincronização entre servidores (X-Sync-Token) — usado
    quando outro servidor Painel Netsimon replica uma ação de usuário aqui."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            sync_token_header = request.headers.get("X-Sync-Token")
            if sync_token_header:
                expected = _load_sync_token()
                if expected and sync_token_header == expected:
                    request.ns_session = {"user": "sync", "role": "admin", "via_sync": True}
                    return f(*args, **kwargs)
                return jsonify({"error": "sync token inválido"}), 401

            token = request.headers.get("X-Token") or request.cookies.get("ns_token")
            s = get_session(token) if token else None
            if not s:
                return jsonify({"error": "unauthorized"}), 401
            if roles and s["role"] not in roles:
                return jsonify({"error": "forbidden"}), 403
            s.setdefault("via_sync", False)
            request.ns_session = s
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route("/api/license/status", methods=["GET"])
@auth_required(roles=["admin"])
def api_license_status():
    return jsonify(license_status())

@app.route("/api/license/ativar", methods=["POST"])
@auth_required(roles=["admin"])
def api_license_ativar():
    data = request.get_json(force=True, silent=True) or {}
    key = (data.get("key") or "").strip()
    server_url = (data.get("server_url") or "").strip()
    if not key or not server_url:
        return jsonify({"ok": False, "erro": "key e server_url são obrigatórios"}), 400
    ok, resultado = license_ativar(key, server_url)
    if not ok:
        return jsonify({"ok": False, "erro": resultado}), 400
    return jsonify({"ok": True, "licenca": resultado})

# ── Helpers de dados ──────────────────────────────────────────────
def gen_random_login(existing_logins=None):
    """Gera um login aleatório de exatamente 4 caracteres, sempre
    começando com letra: ou 1 letra + 3 números, ou 4 letras."""
    existing_logins = existing_logins or set()
    for _ in range(50):
        first = random.choice(string.ascii_lowercase)
        if random.random() < 0.5:
            rest = ''.join(random.choices(string.digits, k=3))
        else:
            rest = ''.join(random.choices(string.ascii_lowercase, k=3))
        candidate = first + rest
        if candidate not in existing_logins:
            return candidate
    return first + rest  # fallback extremamente improvável de colidir

def read_users():
    users = []
    if not os.path.exists(USERDB):
        return users
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5:
                users.append({
                    "login":  parts[0],
                    "uuid":   parts[1],
                    "expira": parts[2],
                    "senha":  parts[3],
                    "limite": parts[4]
                })
    return users

def is_expired(expira_str):
    try:
        exp = datetime.datetime.strptime(expira_str, "%Y-%m-%d %H:%M:%S")
        return datetime.datetime.now() > exp
    except Exception:
        try:
            exp = datetime.datetime.strptime(expira_str, "%Y-%m-%d")
            return datetime.datetime.now().date() > exp.date()
        except Exception:
            return False

def run_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        return str(e), 1

def xray_kick_live(login):
    """BUGFIX CRÍTICO: em TODO lugar do painel que bloqueava/suspendia um
    usuário, a remoção do Xray usava só xray_remove_client_safe (edita o
    config.json em disco). Isso sozinho NÃO afeta o processo do Xray que
    já está rodando — o Xray só relê o config.json inteiro no start ou
    em "systemctl restart xray". Resultado prático: um usuário removido
    do arquivo continuava sendo aceito pelo Xray em memória — sessão já
    aberta seguia funcionando normalmente, e até conexão NOVA com o
    mesmo UUID conseguia entrar, porque o processo vivo nunca soube que
    o client tinha sido removido. Testado e confirmado: dava pra
    conectar (e duplicar acesso) via Xray mesmo com o usuário expirado
    ou bloqueado.

    A correção correta é chamar a Handler API do Xray (mesmo comando que
    o limit.sh já usa em kick_xray_block): "xray api rmu" remove o
    usuário do inbound em tempo real, na memória do processo, sem
    precisar reiniciar o Xray (e sem afetar nenhum outro usuário
    conectado). Deve ser chamado SEMPRE junto com xray_remove_client_safe
    — um cuida do "agora" (sessão ativa/conexão nova imediata), o outro
    garante que a remoção sobrevive a um restart/reload futuro."""
    run_cmd(f'xray api rmu --server={XRAY_API} -tag={XRAY_TAG} "{login}" 2>/dev/null')

def get_online_users():
    out, _ = run_cmd("who 2>/dev/null | awk '{print $1}' | sort -u")
    who_users = [u for u in out.splitlines() if u]
    # "who" só enxerga sessão com pty alocado (login interativo de verdade).
    # Conexão usada só como túnel (ssh -N, ou o modo "SSL" do painel, que é
    # só SSH encapsulado em TLS via stunnel — porta 8443 -> 127.0.0.1:22,
    # ver install.sh) nunca aloca pty, então nunca aparece no "who". Mas
    # sempre existe um processo sshd rodando com o dono = usuário do
    # sistema autenticado, então checar isso cobre SSH normal E SSL de
    # uma vez só (mesma técnica que o limit.sh já usa por usuário).
    #
    # BUGFIX (painel web mostrando "Online" após o usuário já ter caído,
    # enquanto o painel SSH/menu já mostrava offline corretamente): antes
    # aqui a gente contava um usuário como online só por EXISTIR um
    # processo "sshd" com aquele dono, sem checar se o socket TCP dele
    # ainda estava de pé. Como o sshd_config não tem ClientAliveInterval/
    # TCPKeepAlive, uma queda "suja" de rede (troca de torre 4G, app do
    # cliente morto sem enviar FIN/RST) deixa esse processo pendurado no
    # servidor por muito tempo sem o SO perceber — o `who` já limpa a
    # sessão (por isso o menu já mostrava offline), mas o processo sshd
    # órfão continuava de pé e era contado como "online" aqui. Agora só
    # conta o processo se ele tiver, agora, uma conexão TCP ESTABLISHED
    # de verdade (via `ss`); processo sshd sem socket ESTAB correspondente
    # é tratado como resquício e ignorado.
    estab_out, estab_rc = run_cmd(
        "ss -H -tnp state established 2>/dev/null | grep -oP 'pid=\\K[0-9]+' | sort -u"
    )
    estab_pids = set(estab_out.splitlines())

    ps_out, _ = run_cmd(
        "ps -eo user:32,pid,comm 2>/dev/null | awk '$3==\"sshd\"{print $1, $2}'"
    )
    sshd_users = []
    for line in ps_out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        user, pid = parts
        if pid in estab_pids:
            sshd_users.append(user)
    if estab_rc != 0 and not estab_pids:
        # Fail-safe: se o `ss` falhar/não existir no sistema, cai no
        # comportamento antigo (só existência do processo) em vez de
        # zerar todo mundo que só usa túnel sem pty.
        sshd_users = [l.split()[0] for l in ps_out.splitlines() if l.split()]

    ssh_users = list(set(who_users + sshd_users))
    # Xray online via API
    xray_out, _ = run_cmd(f"xray api statsgetallonlineusers --server={XRAY_API} 2>/dev/null")
    xray_users = re.findall(r'user>>>(.*?)>>>online', xray_out)
    all_online = list(set(ssh_users + xray_users))
    # filtra só quem está no banco
    db_logins = {u["login"] for u in read_users()}
    result = [u for u in all_online if u in db_logins]
    update_online_since(result)
    return result

def get_system_stats():
    cpu_out, _ = run_cmd("top -bn1 2>/dev/null | grep 'Cpu(s)' | awk '{print int($2+$4)}'")
    ram_out, _  = run_cmd("free 2>/dev/null | awk '/Mem:/ {printf \"%d\", $3/$2*100}'")
    disk_out, _ = run_cmd("df / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%'")
    uptime_out, _ = run_cmd("uptime -p 2>/dev/null | sed 's/up //'")
    ip_out, _   = run_cmd("wget -qO- --timeout=3 ipv4.icanhazip.com 2>/dev/null || echo offline")
    return {
        "cpu":    int(cpu_out) if cpu_out.isdigit() else 0,
        "ram":    int(ram_out) if ram_out.isdigit() else 0,
        "disk":   int(disk_out) if disk_out.isdigit() else 0,
        "uptime": uptime_out or "--",
        "ip":     ip_out or "offline"
    }

def _active_template_port(prefix):
    """Descobre a porta real de uma unit systemd 'template' (prefix@PORTA)
    que estiver ativa, em vez de assumir uma porta fixa cravada no código.
    Item: antes 'wss'/'wsssec' só eram considerados ativos se estivessem
    exatamente na porta padrão (8443/8888) -- se o admin subisse em outra
    porta pela tela, o painel continuava mostrando tudo como inativo/
    vermelho, mesmo com o processo rodando perfeitamente. Devolve o
    número da porta (int) da primeira instância ativa encontrada, ou
    None se nenhuma estiver ativa."""
    out, _ = run_cmd(
        f"systemctl list-units --type=service --state=active --no-legend '{prefix}@*.service' "
        f"2>/dev/null | awk '{{print $1}}'"
    )
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(rf"^{re.escape(prefix)}@(\d+)\.service$", line)
        if m:
            return int(m.group(1))
    return None


def _stop_other_template_instances(prefix, keep_port):
    """Antes de subir prefix@keep_port, derruba qualquer OUTRA instância
    ativa do mesmo template (prefix@outra_porta) -- evita ficar com duas
    portas do mesmo protocolo rodando ao mesmo tempo sem o admin saber,
    o que também bagunçaria a detecção de porta ativa."""
    out, _ = run_cmd(
        f"systemctl list-units --type=service --state=active --no-legend '{prefix}@*.service' "
        f"2>/dev/null | awk '{{print $1}}'"
    )
    for line in out.splitlines():
        line = line.strip()
        m = re.match(rf"^{re.escape(prefix)}@(\d+)\.service$", line)
        if m and int(m.group(1)) != keep_port:
            run_cmd(f"systemctl stop {line}")


def service_status(name):
    # Item: BUG CORRIGIDO — "pgrep -f X" rodado via subprocess(shell=True)
    # SEMPRE encontrava pelo menos 1 processo, mesmo com o serviço
    # parado: o processo intermediário "/bin/sh -c 'pgrep -f X'" tem a
    # string X na própria linha de comando, então o pgrep batia nele
    # mesmo (self-match). Resultado: o status sempre voltava "rodando",
    # e o botão liga/desliga do painel nunca ficava vermelho de verdade.
    # Fix: o truque clássico "[x]yz" — o padrão de busca vira uma regex
    # que não bate na própria string literal "[x]yz" da invocação, só
    # no processo real "xyz" que a gente quer encontrar.
    if name == "xray":
        _, rc = run_cmd("systemctl is-active xray")
        return rc == 0
    if name == "proxy":
        # Item: BUG CORRIGIDO (definitivo) — proxy.py agora roda como
        # serviço systemd de verdade (proxy@80.service, Restart=always),
        # exatamente igual ao xray — não é mais subprocesso em "screen"
        # derrubado junto com o netsimon-painel.service a cada
        # restart/atualização do painel. Status é checado via systemctl,
        # igual xray/badvpn/checkuser.
        _, rc = run_cmd("systemctl is-active --quiet proxy@80")
        return rc == 0
    if name == "wss":
        # Item: agora reconhece o WSS TLS ativo em QUALQUER porta
        # configurada, não só na porta padrão 8443 -- ver
        # _active_template_port() acima.
        return _active_template_port("wss") is not None
    if name == "wsssec":
        # Item: mesma generalização acima -- qualquer porta ativa conta.
        return _active_template_port("wss-security") is not None
    if name == "stunnel":
        # v41: Stunnel roda como netsimon-stunnel.service — checado
        # via systemctl, mesmo padrão do wss/wsssec.
        _, rc = run_cmd("systemctl is-active --quiet netsimon-stunnel")
        return rc == 0
    if name == "limiter":
        # Item: BUG CORRIGIDO — igual ao "proxy" acima, o status era
        # checado via "systemctl is-active limiter", mas o start/stop
        # real do limiter (botão do painel, service_action() abaixo)
        # sobe/derruba o processo via "screen -dmS limitador bash
        # /etc/painel/limit.sh", sem NUNCA tocar em systemd. A unit
        # systemd "limiter" nunca existe/nunca é iniciada por ninguém,
        # então "systemctl is-active" sempre voltava inativo — o botão
        # "Ativar Limiter" chegava a subir o processo de verdade, mas a
        # confirmação de status (linha ~2685) sempre via "não rodando" e
        # o painel desfazia a UI, mostrando "desativado" de novo mesmo
        # com o processo no ar. Fix: checar o processo real via pgrep,
        # do mesmo jeito que proxy/slowdns/wss já fazem.
        out, _ = run_cmd("pgrep -f '[l]imit\\.sh'")
        return bool(out)
    if name == "slowdns":
        out, _ = run_cmd("pgrep -f '[d]nstt-server'")
        return bool(out)
    if name == "checkuser":
        _, rc = run_cmd("systemctl is-active checkuser")
        return rc == 0
    if name == "badvpn":
        _, rc = run_cmd("systemctl is-active badvpn")
        return rc == 0
    return False

def get_active_ports():
    ports = []
    out, _ = run_cmd("ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | sed 's/.*://'")
    for p in out.splitlines():
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
    return sorted(set(ports))

# ══════════════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════

# Item de segurança: proteção simples contra força bruta no login. Sem
# isso, /api/auth/login aceitava tentativas ilimitadas — e como a API
# ficava exposta sem TLS/firewall (ver install.sh) e a senha do admin é
# só um SHA256 sem salt (comparação direta), um invasor conseguia testar
# milhares de senhas por segundo direto contra o painel.
_login_attempts = {}   # ip -> {"count": int, "first_ts": float, "locked_until": float}
_login_attempts_lock = threading.Lock()
LOGIN_MAX_ATTEMPTS   = 5
LOGIN_WINDOW_SECONDS = 600   # 10 minutos pra acumular tentativas
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutos bloqueado depois de estourar o limite

def _login_client_ip():
    # request.remote_addr já reflete o IP real do cliente agora (ver
    # ProxyFix acima) — antes disso, TODA requisição vinda pelo Nginx
    # aparecia como 127.0.0.1, o que teria travado o painel inteiro pra
    # todo mundo junto na primeira tentativa errada de qualquer um.
    return request.remote_addr or "unknown"

def _login_rate_limited(ip):
    with _login_attempts_lock:
        info = _login_attempts.get(ip)
        if not info:
            return False, 0
        now = time.time()
        if info["locked_until"] > now:
            return True, int(info["locked_until"] - now)
        if now - info["first_ts"] > LOGIN_WINDOW_SECONDS:
            del _login_attempts[ip]
            return False, 0
        return False, 0

def _register_login_failure(ip):
    with _login_attempts_lock:
        now = time.time()
        info = _login_attempts.get(ip)
        if not info or now - info["first_ts"] > LOGIN_WINDOW_SECONDS:
            info = {"count": 0, "first_ts": now, "locked_until": 0}
        info["count"] += 1
        if info["count"] >= LOGIN_MAX_ATTEMPTS:
            info["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
        _login_attempts[ip] = info
        # limpeza leve pra não crescer sem limite se alguém tentar rodar
        # por muitos IPs diferentes (bem improvável em VPS, mas de graça)
        if len(_login_attempts) > 5000:
            for k, v in list(_login_attempts.items()):
                if v["locked_until"] < now and now - v["first_ts"] > LOGIN_WINDOW_SECONDS:
                    del _login_attempts[k]

def _clear_login_failures(ip):
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = _login_client_ip()
    locked, retry_after = _login_rate_limited(ip)
    if locked:
        return jsonify({
            "error": f"Muitas tentativas de login. Tente novamente em {max(1, retry_after // 60)} minuto(s).",
            "retry_after": retry_after
        }), 429

    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    cfg = load_config()

    pw_hash = hashlib.sha256(password.encode()).hexdigest()

    # Admin
    if (username == cfg["admin"]["username"] and
            pw_hash == cfg["admin"]["password"]):
        _clear_login_failures(ip)
        token = create_session(username, "admin")
        resp = jsonify({"token": token, "role": "admin", "username": username})
        resp.set_cookie("ns_token", token, httponly=True, samesite="Lax", max_age=86400)
        return resp

    # Revendedor
    resellers = cfg.get("resellers", {})
    if username in resellers and pw_hash == resellers[username]["password"]:
        r = resellers[username]
        expired = bool(r.get("expires")) and is_expired(r["expires"])
        if r.get("suspended") or expired:
            _clear_login_failures(ip)  # credencial certa — não é tentativa de adivinhação
            return jsonify({
                "error": "Painel de revendedor suspenso ou vencido.",
                "suspended": True,
                "expires": r.get("expires", ""),
                "renew_url": "https://wa.me/5511997675068"
            }), 403
        _clear_login_failures(ip)
        token = create_session(username, "reseller")
        resp = jsonify({"token": token, "role": "reseller", "username": username})
        resp.set_cookie("ns_token", token, httponly=True, samesite="Lax", max_age=86400)
        return resp

    _register_login_failure(ip)
    return jsonify({"error": "Usuário ou senha inválidos"}), 401

@app.route("/api/auth/verify", methods=["GET"])
def auth_verify():
    """Usado internamente pelo Nginx (auth_request) para proteger o
    Terminal Web — só admin autenticado consegue passar."""
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    s = get_session(token) if token else None
    if not s or s.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True}), 200

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    if token and token in _sessions:
        del _sessions[token]
    resp = jsonify({"ok": True})
    resp.set_cookie("ns_token", "", expires=0)
    return resp

@app.route("/api/auth/me", methods=["GET"])
def me():
    token = request.headers.get("X-Token") or request.cookies.get("ns_token")
    s = get_session(token) if token else None
    if not s:
        return jsonify({"error": "unauthorized"}), 401
    resp = {"username": s["user"], "role": s["role"]}
    if s["role"] == "reseller":
        cfg = load_config()
        resp["level"] = reseller_level(cfg, s["user"]) or 2
        resp["can_manage_resellers"] = resp["level"] == 2
    return jsonify(resp)

# ══════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════

@app.route("/api/dashboard", methods=["GET"])
@auth_required()
def dashboard():
    users = read_users()
    online = get_online_users()
    expired = [u for u in users if is_expired(u["expira"])]

    # BUGFIX (2ª rodada): o card "Bloqueados" ainda não batia com a
    # realidade mesmo depois do fix de dono/revendedor abaixo — porque
    # blocked.db mistura bloqueio do Limiter com expirado (watchdog) e
    # suspensão manual/cascata de revendedor (ver comentário de
    # _is_limiter_block, mais abaixo no arquivo), e bloqueio por
    # dispositivo (device_hash) nem passa por blocked.db — fica só em
    # device_log (ver _device_check_core). Resultado: o número mostrado
    # não era "bloqueado pelo Limiter ou por Dispositivo" (o que o admin
    # espera ver aqui), e ainda duplicava com o card "Expirados" (cliente
    # vencido já aparece lá; não precisa contar de novo aqui). Agora:
    # Limiter = só linhas de blocked.db com motivo do limit.sh
    # (_is_limiter_block); Dispositivo = logins com bloqueio real recente
    # em device_log (_recent_device_blocked_logins) — nunca os apenas
    # REGISTRADOS. Expirado/suspensão manual/cascata ficam de fora daqui.
    limiter_blocked_logins = set()
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 3 and parts[0] and _is_limiter_block(parts[2]):
                    limiter_blocked_logins.add(parts[0])
    active_blocked_logins = limiter_blocked_logins | _recent_device_blocked_logins()

    # revendedor só vê seus usuários (e os dos sub-revendedores dele)
    s = request.ns_session
    quota_block = None
    reseller_expires = None
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]
        online = [u for u in online if u in owned]
        expired = [u for u in expired if u["login"] in owned]
        blocked_count = len(active_blocked_logins & owned)
        used, quota = quota_usage(cfg, s["user"])
        quota_block = {"used": used, "quota": quota, "unlimited": quota <= 0}
        # Item: validade do PAINEL do próprio revendedor (não confundir
        # com validade de cliente dele) — mesma data usada por
        # renovar_reseller()/reseller_expiry_scheduler_loop() pra
        # suspender o acesso dele automaticamente quando vence.
        reseller_expires = cfg.get("resellers", {}).get(s["user"], {}).get("expires")
    else:
        blocked_count = len(active_blocked_logins)

    resp = {
        "users":       len(users),
        "online":      len(online),
        "expired":     len(expired),
        "blocked":     blocked_count,
        "online_list": online[:20],
        "quota":       quota_block,
        "reseller_expires": reseller_expires,
    }

    # Bloco de recursos do servidor / serviços / portas — item 3:
    # visível apenas para o admin.
    if s["role"] == "admin":
        resp["stats"]    = get_system_stats()
        resp["services"] = {
            "xray":         service_status("xray"),
            "proxy":        service_status("proxy"),
            "limiter":      service_status("limiter"),
            "slowdns":      service_status("slowdns"),
            "checkuser":    service_status("checkuser"),
            "badvpn":       service_status("badvpn"),
            "wss":          service_status("wss"),
            "wsssec":       service_status("wsssec"),
            "stunnel":      service_status("stunnel"),
            # Não é um processo do SO como os demais — é um interruptor de
            # config (painel_config.json). Incluído aqui só pra visibilidade
            # rápida no dashboard; não entra nas notificações de "serviço
            # parado" porque estar desligado pode ser intencional.
            "device_block": device_block_enabled()
        }
        resp["ports"] = get_active_ports()

    return jsonify(resp)

# ══════════════════════════════════════════════════════════════════
#  USUÁRIOS
# ══════════════════════════════════════════════════════════════════

def _parse_dt(s):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
    return None

@app.route("/api/notifications", methods=["GET"])
@auth_required()
def notifications():
    """Central de avisos do painel. Fica de olho no que importa e avisa
    de forma simples e direta — sem enrolação, como uma IA deveria."""
    notifs = []
    now = datetime.datetime.now()
    s = request.ns_session

    users = read_users()
    if s["role"] == "reseller":
        cfg0 = load_config()
        owned = set(cfg0["resellers"].get(s["user"], {}).get("users", []))
        users = [u for u in users if u["login"] in owned]

    # 1) Clientes faltando 2 dias (ou menos) para vencer
    for u in users:
        dt = _parse_dt(u["expira"])
        if not dt:
            continue
        dias_restantes = (dt - now).total_seconds() / 86400
        if 0 <= dias_restantes <= 2:
            notifs.append({
                "id": f"user-exp-{u['login']}",
                "level": "warning",
                "icon": "⏳",
                "title": f"{u['login']} vence em breve",
                "message": f"Faltam menos de 2 dias para o acesso de \"{u['login']}\" vencer. Bom avisar o cliente ou renovar.",
                "ts": now.isoformat()
            })

    if s["role"] == "admin":
        # 2) Serviços parados
        svc_labels = {
            "xray": "Xray", "proxy": "WebSocket Proxy", "limiter": "Limiter",
            "slowdns": "SlowDNS", "checkuser": "CheckUser API"
        }
        for key, label in svc_labels.items():
            if not service_status(key):
                notifs.append({
                    "id": f"svc-down-{key}",
                    "level": "danger",
                    "icon": "🛑",
                    "title": f"{label} parado",
                    "message": f"O serviço {label} não está rodando agora. Vale checar o que aconteceu.",
                    "ts": now.isoformat()
                })

        # 3) Performance abaixo do normal (heurística por carga de CPU/RAM/disco)
        stats = get_system_stats()
        if stats["cpu"] >= 90:
            notifs.append({
                "id": "perf-cpu",
                "level": "warning",
                "icon": "🐢",
                "title": "Servidor com CPU no limite",
                "message": f"CPU em {stats['cpu']}% agora. O desempenho pode estar bem abaixo do normal para os clientes.",
                "ts": now.isoformat()
            })
        if stats["ram"] >= 90:
            notifs.append({
                "id": "perf-ram",
                "level": "warning",
                "icon": "🐢",
                "title": "Memória quase no limite",
                "message": f"RAM em {stats['ram']}% agora. Fique de olho, pode afetar a velocidade das conexões.",
                "ts": now.isoformat()
            })
        if stats["disk"] >= 90:
            notifs.append({
                "id": "perf-disk",
                "level": "warning",
                "icon": "💾",
                "title": "Disco quase cheio",
                "message": f"Disco em {stats['disk']}% de uso. Pode valer a pena limpar logs ou liberar espaço.",
                "ts": now.isoformat()
            })

        # 4) Painéis de revendedor faltando 1 dia para vencer
        cfg = load_config()
        for rname, r in cfg.get("resellers", {}).items():
            exp = r.get("expires", "")
            dt = _parse_dt(exp) if exp else None
            if dt:
                dias_restantes = (dt - now).total_seconds() / 86400
                if 0 <= dias_restantes <= 1:
                    notifs.append({
                        "id": f"reseller-exp-{rname}",
                        "level": "warning",
                        "icon": "🤝",
                        "title": f"Painel de {rname} vence amanhã",
                        "message": f"O acesso do revendedor \"{rname}\" vence em menos de 1 dia.",
                        "ts": now.isoformat()
                    })

        # 5) Servidores sincronizados que não estão respondendo
        for sid, srv in cfg.get("servers", {}).items():
            try:
                r = requests.get(f"http://{srv['host']}:{srv.get('port', 81)}/ping", timeout=3)
                ok = r.status_code == 200
            except Exception:
                ok = False
            if not ok:
                notifs.append({
                    "id": f"server-down-{sid}",
                    "level": "danger",
                    "icon": "🖧",
                    "title": f"Servidor \"{srv['name']}\" não responde",
                    "message": f"Não consegui falar com o servidor sincronizado \"{srv['name']}\" ({srv['host']}). Vale checar se ele está online.",
                    "ts": now.isoformat()
                })

        # 6) Autodiagnóstico técnico — incidentes recém-corrigidos (últimas
        #    3h), pendentes de aprovação (modo manual/parcial) e incidentes
        #    que precisam de atenção manual (sem correção conhecida ou
        #    correção que falhou), até serem resolvidos.
        for inc in _diag_load_incidents():
            try:
                inc_dt = datetime.datetime.fromisoformat(inc.get("criado_em", ""))
            except Exception:
                continue
            status = inc.get("status")
            if status == "corrigido" and (now - inc_dt).total_seconds() <= 3 * 3600:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "info",
                    "icon": "🛠️",
                    "title": "Autodiagnóstico corrigiu um problema sozinho",
                    "message": f"{inc.get('causa_detalhe', '')} — {inc.get('correcao', '')}",
                    "ts": inc_dt.isoformat()
                })
            elif status == "pendente_aprovacao" and (now - inc_dt).total_seconds() <= 72 * 3600:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "warning",
                    "icon": "⏳",
                    "title": "Correção aguardando sua aprovação",
                    "message": f"{inc.get('causa_detalhe', '')} — aprove ou rejeite em Diagnóstico > Incidentes técnicos.",
                    "ts": inc_dt.isoformat()
                })
            elif status in ("falhou", "sem_correcao_conhecida") and (now - inc_dt).total_seconds() <= 72 * 3600:
                notifs.append({
                    "id": f"diag-{inc['id']}",
                    "level": "danger",
                    "icon": "🚨",
                    "title": "Autodiagnóstico precisa da sua atenção",
                    "message": f"{inc.get('causa_detalhe', '')} — veja em Diagnóstico > Incidentes técnicos.",
                    "ts": inc_dt.isoformat()
                })

    return jsonify(notifs)

@app.route("/api/users", methods=["GET"])
@auth_required()
def list_users():
    users = read_users()
    online = set(get_online_users())
    online_since = _load_online_since()
    s = request.ns_session
    cfg = load_config()

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    result = []
    photos = read_photos()
    for u in users:
        owner = find_owner_of_login(cfg, u["login"])
        foto = photos.get(u["login"])
        result.append({
            "login":   u["login"],
            "uuid":    u["uuid"],
            "expira":  u["expira"],
            "limite":  u["limite"],
            "senha":   u["senha"],
            "expired": is_expired(u["expira"]),
            "online":  u["login"] in online,
            "online_seconds": online_duration_seconds(u["login"], online_since) if u["login"] in online else 0,
            "criado_por": owner if owner else cfg["admin"]["username"],
            "foto_url": f"/fotos/{foto}" if foto else None,
            "blocked": False  # expandido abaixo
        })

    # Marca bloqueados
    blocked_users = set()
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts:
                    blocked_users.add(parts[0])
    for u in result:
        u["blocked"] = u["login"] in blocked_users

    return jsonify(result)

@app.route("/api/users", methods=["POST"])
@auth_required()
def create_user():
    data = request.get_json() or {}
    login  = data.get("login", "").strip()
    senha  = data.get("senha", "1234").strip()
    dias   = int(data.get("dias", 30))
    limite = int(data.get("limite", 1))

    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
    elif not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return jsonify({"error": "Nome de usuário inválido"}), 400

    # FIX (trava de nome duplicado, case-insensitive): antes comparava
    # login com == (case-sensitive), então "yndaiara" e "Yndaiara" eram
    # tratados como usuários diferentes aqui, mas o Xray rejeita os dois
    # como o mesmo "email" internamente -- o segundo nunca era carregado
    # de fato no config.json, ficando "fantasma" (existe no usuarios.db,
    # mas sem funcionar). Agora a checagem é sempre case-insensitive,
    # igual o Xray já trata, e sempre bloqueia ANTES de criar qualquer
    # coisa no sistema (Linux, Xray, usuarios.db).
    users = read_users()
    if any(u["login"].lower() == login.lower() for u in users):
        return jsonify({"error": f'Usuário "{login}" já existe (nomes são tratados sem diferenciar maiúsculas/minúsculas)'}), 409

    # CRÍTICO (item 2): verifica a cota ANTES de criar qualquer coisa no
    # sistema — nunca depois. Isso vale para toda a cadeia de revendedores
    # (o revendedor e todo pai acima dele até o admin).
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, s["user"], limite)
        if not ok:
            return jsonify({
                "error": f"Cota insuficiente para criar este usuário com limite de {limite} acesso(s)" + (f" (limite de \"{blocked_at}\")" if blocked_at != s["user"] else ""),
            }), 403

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        exp=$(date -d "+{dias} days" +"%Y-%m-%d 23:59:59")
        exp_chage=$(date -d "+{dias} days +1 day" +"%Y-%m-%d")
        chage -E "$exp_chage" "{login}"
        uuid=$(cat /proc/sys/kernel/random/uuid)
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|{limite}" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "OK:$uuid:$exp"
        '
    """)

    if rc != 0 or "OK:" not in out:
        return jsonify({"error": "Falha ao criar usuário", "detail": out}), 500

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    # Revendedor — registra na config (a cota já foi validada acima)
    if s["role"] == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, s["user"], login)
        save_config(cfg)

    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", "/api/users", {"login": login, "senha": senha, "dias": dias, "limite": limite})

    return jsonify({"ok": True, "login": login, "uuid": uuid, "expira": exp, "senha": senha, "limite": limite}), 201

@app.route("/api/users/<username>", methods=["DELETE"])
@auth_required()
def delete_user(username):
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    out, rc = run_cmd(f"bash /etc/painel/deluser.sh {username} --auto")
    if rc != 0:
        return jsonify({"error": "Falha ao remover usuário"}), 500

    # Libera a cota (deluser.sh --auto já remove do painel_config.json,
    # isto aqui é só reforço síncrono para a sessão atual)
    cfg = load_config()
    unregister_user_from_reseller(cfg, username)
    save_config(cfg)

    if not s.get("via_sync"):
        propagate_to_servers("DELETE", f"/api/users/{username}")

    return jsonify({"ok": True})

@app.route("/api/users/<username>/photo", methods=["POST"])
@auth_required()
def upload_user_photo(username):
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        if username not in all_owned_logins(cfg, s["user"]):
            return jsonify({"error": "forbidden"}), 403

    if "foto" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    data = request.files["foto"].read()
    if not data:
        return jsonify({"error": "Arquivo vazio"}), 400
    if len(data) > MAX_PHOTO_SIZE:
        return jsonify({"error": "Imagem muito grande (máximo 2 MB)"}), 400

    ext = detect_image_ext(data)
    if not ext:
        return jsonify({"error": "Formato inválido. Use JPG, PNG ou WEBP"}), 400

    os.makedirs(FOTOS_DIR, exist_ok=True)
    safe_login = re.sub(r'[^a-zA-Z0-9_-]', '_', username).lower()

    for other_ext in ("jpg", "png", "webp"):
        if other_ext != ext:
            old_path = os.path.join(FOTOS_DIR, f"{safe_login}.{other_ext}")
            if os.path.exists(old_path):
                os.remove(old_path)

    filename = f"{safe_login}.{ext}"
    path = os.path.join(FOTOS_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o644)

    photos = read_photos()
    photos[username] = filename
    save_photos(photos)

    return jsonify({"ok": True, "foto_url": f"/fotos/{filename}"})

@app.route("/api/users/<username>/photo", methods=["DELETE"])
@auth_required()
def delete_user_photo(username):
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        if username not in all_owned_logins(cfg, s["user"]):
            return jsonify({"error": "forbidden"}), 403

    photos = read_photos()
    filename = photos.pop(username, None)
    if filename:
        path = os.path.join(FOTOS_DIR, filename)
        if os.path.exists(path):
            os.remove(path)
        save_photos(photos)
    return jsonify({"ok": True})

@app.route("/api/users/expired", methods=["DELETE"])
@auth_required(roles=["admin"])
def delete_expired():
    users = read_users()
    removed = []
    for u in users:
        if is_expired(u["expira"]):
            run_cmd(f"bash /etc/painel/deluser.sh {u['login']} --auto --no-restart")
            removed.append(u["login"])
            if not request.ns_session.get("via_sync"):
                propagate_to_servers("DELETE", f"/api/users/{u['login']}")
    if removed:
        run_cmd("systemctl restart xray")
    return jsonify({"ok": True, "removed": removed})

@app.route("/api/users/bulk-delete", methods=["POST"])
@auth_required()
def bulk_delete_users():
    """Item 7: seleciona vários usuários na lista e remove todos de uma vez."""
    data = request.get_json() or {}
    logins = data.get("logins", [])
    if not isinstance(logins, list) or not logins:
        return jsonify({"error": "Nenhum usuário informado"}), 400

    s = request.ns_session
    cfg = load_config()
    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        forbidden = [l for l in logins if l not in owned]
        if forbidden:
            return jsonify({"error": "forbidden", "logins": forbidden}), 403

    removed, failed = [], []
    for login in logins:
        out, rc = run_cmd(f"bash /etc/painel/deluser.sh {login} --auto --no-restart")
        if rc == 0:
            removed.append(login)
        else:
            failed.append(login)

    # Reinicia o Xray só UMA vez no final, não uma vez por usuário — antes
    # disso, apagar vários usuários de uma vez reiniciava o serviço N
    # vezes seguidas, o que era lento o bastante pra travar/estourar o
    # tempo da requisição antes de terminar (e nenhum usuário parecia ter
    # sido removido, mesmo alguns tendo sido no meio do caminho).
    if removed:
        run_cmd("systemctl restart xray")
        try:
            with open(LOG_LIMIT, "a") as f:
                f.write(f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} - ADMIN: exclusão em massa de {len(removed)} usuário(s) ({s['user']}): {', '.join(removed)}\n")
        except Exception:
            pass

    cfg = load_config()
    for login in removed:
        unregister_user_from_reseller(cfg, login)
    save_config(cfg)

    if not s.get("via_sync"):
        for login in removed:
            propagate_to_servers("DELETE", f"/api/users/{login}")

    return jsonify({"ok": True, "removed": removed, "failed": failed})

@app.route("/api/users/bulk-action", methods=["POST"])
@auth_required()
def bulk_action_users():
    """Item 2: menu "Opções" da seleção múltipla em Usuários — reúne as
    ações que antes só existiam uma-a-uma (renovar +1/+30 dias, suspender,
    desbloquear) pra aplicar de uma vez em todos os logins selecionados.
    Reaproveita exatamente as mesmas funções internas dos botões
    individuais (renew_access_internal/_suspend_login/_unblock_login) —
    não duplica a lógica de nenhuma delas."""
    data = request.get_json() or {}
    logins = data.get("logins", [])
    action = data.get("action", "")
    if not isinstance(logins, list) or not logins:
        return jsonify({"error": "Nenhum usuário informado"}), 400
    if action not in ("add_1_day", "add_30_days", "suspend", "unblock"):
        return jsonify({"error": "Ação inválida"}), 400

    s = request.ns_session
    cfg = load_config()
    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        forbidden = [l for l in logins if l not in owned]
        if forbidden:
            return jsonify({"error": "forbidden", "logins": forbidden}), 403

    users_by_login = {u["login"]: u for u in read_users()}
    aplicado, pulado, falhou = [], [], []

    for login in logins:
        u = users_by_login.get(login)
        if not u:
            falhou.append(login)
            continue
        try:
            if action == "add_1_day":
                ok, _ = renew_access_internal(login, dias=1)
                (aplicado if ok else falhou).append(login)

            elif action == "add_30_days":
                # Mesma regra do botão ♻️ individual: soma os dias e já
                # desbloqueia (se estava bloqueado), porque "renovei mas
                # continua bloqueado" não faz sentido pro cliente.
                ok, _ = renew_access_internal(login, dias=30)
                if ok:
                    _unblock_login(login)
                    aplicado.append(login)
                else:
                    falhou.append(login)

            elif action == "suspend":
                (aplicado if _suspend_login(login) else falhou).append(login)

            elif action == "unblock":
                # Regra explícita pedida: usuário EXPIRADO fica de fora
                # dessa ação em lote — ele não está bloqueado por Limiter
                # ou por Dispositivo, está bloqueado por ter vencido o
                # tempo contratado; desbloquear sem estender validade
                # daria acesso além do que foi pago. Só "Adicionar dias"
                # (que já libera junto) resolve o caso dele.
                if is_expired(u["expira"]):
                    pulado.append(login)
                else:
                    _unblock_login(login)
                    aplicado.append(login)
        except Exception:
            falhou.append(login)

    if aplicado:
        label = {"add_1_day": "+1 dia", "add_30_days": "+30 dias",
                  "suspend": "suspensão", "unblock": "desbloqueio"}[action]
        try:
            with open(LOG_LIMIT, "a") as f:
                f.write(f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} - "
                        f"AÇÃO EM LOTE ({label}) por {s['user']}: {', '.join(aplicado)}\n")
        except Exception:
            pass
        if not s.get("via_sync"):
            sync_path = {"add_1_day": "renovar", "add_30_days": "renovar",
                         "suspend": "suspend", "unblock": "unblock"}[action]
            sync_payload = {"dias": 1} if action == "add_1_day" else ({"dias": 30} if action == "add_30_days" else None)
            for login in aplicado:
                propagate_to_servers("POST", f"/api/users/{login}/{sync_path}", payload=sync_payload)

    return jsonify({"ok": True, "action": action, "aplicado": aplicado, "pulado": pulado, "falhou": falhou})

@app.route("/api/users/all", methods=["GET"])
@auth_required()
def list_all_users():
    """Item 4: bloco "todos os usuários". Admin vê todo mundo (com a
    coluna de quem criou); revendedor vê os dele + dos sub-revendedores
    (2º e 3º nível), também com a coluna de quem criou."""
    users = read_users()
    online = set(get_online_users())
    online_since = _load_online_since()
    s = request.ns_session
    cfg = load_config()

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    blocked_users = set()
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts:
                    blocked_users.add(parts[0])

    result = []
    for u in users:
        owner = find_owner_of_login(cfg, u["login"])
        result.append({
            "login":      u["login"],
            "expira":     u["expira"],
            "limite":     u["limite"],
            "expired":    is_expired(u["expira"]),
            "online":     u["login"] in online,
            "online_seconds": online_duration_seconds(u["login"], online_since) if u["login"] in online else 0,
            "blocked":    u["login"] in blocked_users,
            "criado_por": owner if owner else cfg["admin"]["username"],
            "criado_por_nivel": reseller_level(cfg, owner) if owner else "admin"
        })
    return jsonify(result)

def _unblock_login(login):
    """Remove um login do blocked.db e readiciona o client dele no Xray —
    é a ÚNICA definição dessa lógica (antes estava duplicada em 3 lugares
    ligeiramente diferentes, o que foi exatamente a causa de um bug: o
    "resetar dispositivos" e o "limpar bloqueios em massa" não faziam a
    parte do Xray, só a tela de Usuários fazia).

    BUGFIX: agora que bloquear (limit.sh/register_block, device_check
    expirado, e o novo botão de suspensão manual) trava a conta Linux
    com "passwd -l", desbloquear precisa necessariamente destravar com
    "passwd -u" — senão o usuário "desbloqueado"/"renovado" continuava
    sem conseguir logar via SSH mesmo com o painel mostrando tudo OK."""
    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
    run_cmd(f"passwd -u '{login}' 2>/dev/null")
    users = read_users()
    u = next((x for x in users if x["login"] == login), None)
    if u and u["uuid"]:
        run_cmd(f"""
            bash -c '
            source /etc/painel/xray_lib.sh
            xray_add_client_safe "{login}" "{u["uuid"]}" 443
            systemctl restart xray >/dev/null 2>&1
            '
        """)

@app.route("/api/users/<username>/renovar", methods=["POST"])
@auth_required()
def renovar_user(username):
    """Botão ♻️ da tela de Usuários/Todos os Usuários: soma +30 dias à
    validade do acesso (a partir de hoje ou do vencimento atual, o que
    for mais tarde — mesma regra do bot de renovação via WhatsApp) e,
    se o usuário estiver bloqueado por qualquer motivo, já libera na
    mesma ação, porque "renovei mas continua bloqueado" não faz
    sentido nenhum pro cliente."""
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = cfg["resellers"].get(s["user"], {}).get("users", [])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    dias = int((request.get_json(silent=True) or {}).get("dias", 30))
    ok, payload = renew_access_internal(username, dias=dias)
    if not ok:
        return jsonify(payload), 404

    _unblock_login(username)
    system_log_write(f"RENOVAÇÃO manual — {username} +{dias} dia(s), nova validade {payload.get('expira')}, desbloqueado se estava bloqueado")

    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", f"/api/users/{username}/renovar", payload={"dias": dias})

    return jsonify({"ok": True, **payload})

def _suspend_login(login, motivo="Suspensão manual pelo admin"):
    """Suspende IMEDIATAMENTE um usuário, independente de estar expirado
    ou não: derruba qualquer sessão SSH/Xray ativa agora, remove o
    client do Xray (impede reconexão pelo túnel) e trava a conta Linux
    com "passwd -l" (impede reconexão via SSH — mesma trava que
    register_block() do limit.sh já aplica nos outros tipos de
    bloqueio, ver comentário lá). Fica registrado em blocked.db até o
    admin desbloquear ou renovar (ambos já chamam _unblock_login, que
    destrava com "passwd -u")."""
    users = read_users()
    u = next((x for x in users if x["login"] == login), None)
    if not u:
        return False

    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
    with open(BLOCKED, "a") as f:
        f.write(f"{login}|{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}|{motivo}\n")

    xray_kick_live(login)
    run_cmd(f"""
        bash -c '
        pkill -KILL -u "{login}" 2>/dev/null
        source /etc/painel/xray_lib.sh
        xray_remove_client_safe "{login}"
        passwd -l "{login}" 2>/dev/null
        '
    """)
    device_log_write(f"SUSPENSO MANUALMENTE | user={login} | uuid={u['uuid']}")
    return True

@app.route("/api/users/<username>/suspend", methods=["POST"])
@auth_required()
def suspend_user(username):
    """Botão ⛔ da tela de Usuários: suspensão IMEDIATA, sem esperar o
    limiter (ciclo de até 8s) nem depender do usuário estar expirado —
    corta o acesso na hora (SSH + Xray) e mantém bloqueado até o admin
    desbloquear/renovar. Mesma regra de escopo do /unblock: revendedor
    só pode suspender usuário próprio ou de sub-revendedor."""
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    ok = _suspend_login(username)
    if not ok:
        return jsonify({"error": "Usuário não encontrado"}), 404

    system_log_write(f"SUSPENSÃO manual — {username} suspenso imediatamente por {s['user']}")

    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", f"/api/users/{username}/suspend")

    return jsonify({"ok": True, "login": username, "blocked": True})

@app.route("/api/users/<username>/unblock", methods=["POST"])
@auth_required()
def unblock_user(username):
    # Liberado pra revendedor (nível 2 e 3) desbloquear, mas só usuário
    # próprio ou de algum sub-revendedor dele — nunca de fora da sua
    # árvore. Antes essa rota era admin-only; o revendedor via o próprio
    # usuário bloqueado na tela "Usuários" mas não tinha como agir.
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = all_owned_logins(cfg, s["user"])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    _unblock_login(username)
    if not request.ns_session.get("via_sync"):
        propagate_to_servers("POST", f"/api/users/{username}/unblock")
    return jsonify({"ok": True})

@app.route("/api/users/<username>", methods=["PUT"])
@auth_required()
def update_user(username):
    """Edita um usuário existente: senha, validade, limite e/ou chave de
    acesso (UUID). Usado pelo popup unificado de Link/Editar (item 9)."""
    s = request.ns_session
    if s["role"] == "reseller":
        cfg = load_config()
        owned = cfg["resellers"].get(s["user"], {}).get("users", [])
        if username not in owned:
            return jsonify({"error": "forbidden"}), 403

    users = read_users()
    u = next((x for x in users if x["login"] == username), None)
    if not u:
        return jsonify({"error": "Usuário não encontrado"}), 404

    data = request.get_json() or {}
    nova_senha  = data.get("senha", "").strip()
    nova_exp    = data.get("expira", "").strip()
    novo_limite = data.get("limite", None)
    nova_uuid   = data.get("uuid", "").strip()

    senha  = nova_senha if nova_senha else u["senha"]
    exp    = nova_exp if nova_exp else u["expira"]
    limite = str(int(novo_limite)) if novo_limite not in (None, "") else u["limite"]
    uuid_  = nova_uuid if nova_uuid else u["uuid"]

    # Se o revendedor está AUMENTANDO o limite de acessos de um usuário já
    # existente, isso consome mais cota — sem checar aqui, dava pra burlar
    # a cota criando com limite=1 e depois editando pra um valor alto.
    if s["role"] == "reseller" and novo_limite not in (None, ""):
        try:
            delta = max(1, int(novo_limite)) - max(1, int(u.get("limite", 1)))
        except (TypeError, ValueError):
            delta = 0
        if delta > 0:
            for name in reseller_and_ancestors(cfg, s["user"]):
                used, quota = quota_usage(cfg, name)
                if quota > 0 and used + delta > quota:
                    return jsonify({"error": f"Cota insuficiente para aumentar o limite (faltam {delta} crédito(s) disponíveis)" + (f" (limite de \"{name}\")" if name != s["user"] else "")}), 403

    cmds = []
    if nova_senha:
        cmds.append(f'echo "{username}:{nova_senha}" | chpasswd 2>/dev/null')
    if nova_exp:
        exp_chage = (datetime.datetime.strptime(nova_exp.split(" ")[0], "%Y-%m-%d") + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        cmds.append(f'chage -E "{exp_chage}" "{username}" 2>/dev/null')
    if nova_uuid and nova_uuid != u["uuid"]:
        cmds.append(f'''source /etc/painel/xray_lib.sh
            xray_remove_client_safe "{username}"
            xray_add_client_safe "{username}" "{uuid_}" 443
            systemctl restart xray >/dev/null 2>&1''')

    if cmds:
        run_cmd("bash -c '" + "\n".join(cmds) + "'")

    # Reescreve a linha do usuário no usuarios.db preservando a ordem
    new_lines = []
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[0] == username:
                new_lines.append(f"{username}|{uuid_}|{exp}|{senha}|{limite}")
            elif line.strip():
                new_lines.append(line.strip())
    with open(USERDB, "w") as f:
        f.write("\n".join(new_lines) + "\n")

    if not s.get("via_sync"):
        propagate_to_servers("PUT", f"/api/users/{username}", {
            "senha": senha, "expira": exp, "limite": limite, "uuid": uuid_
        })

    return jsonify({"ok": True, "login": username, "uuid": uuid_, "expira": exp, "senha": senha, "limite": limite})

def _get_app_links_internal():
    """Núcleo da busca dos links do app — sem decorator de autenticação,
    pra poder ser chamado tanto pela rota HTTP (/api/app-links) quanto
    internamente pelo bot do WhatsApp (que roda dentro do próprio
    processo Flask, sem X-Token, então NUNCA deve chamar uma função
    decorada com @auth_required diretamente)."""
    cfg = load_config()
    links = cfg.get("app_links", {})
    defaults = {
        "apk_android": "", "apk_iphone": "", "npvtunnel_iphone": "",
        "tutorial_iphone": "", "tutorial_android": ""
    }
    defaults.update(links)
    if not defaults["apk_iphone"]:
        defaults["apk_iphone"] = "https://apps.apple.com/br/app/npv-tunnel/id1629465476"
    if not defaults["apk_android"]:
        try:
            app_info = app_latest_public().get_json()
            if app_info and app_info.get("available"):
                defaults["apk_android"] = app_info["url"]
        except Exception:
            pass
    return defaults

@app.route("/api/app-links", methods=["GET"])
@auth_required()
def get_app_links():
    """Links de download do app e tutoriais — agora GLOBAIS (movidos
    pro menu de Configurações), em vez de configuráveis por usuário."""
    return jsonify(_get_app_links_internal())

@app.route("/api/app-links", methods=["POST"])
@auth_required(roles=["admin"])
def save_app_links():
    data = request.get_json() or {}
    allowed = ["apk_android", "apk_iphone", "npvtunnel_iphone", "tutorial_iphone", "tutorial_android"]
    cfg = load_config()
    cfg.setdefault("app_links", {})
    for k in allowed:
        if k in data:
            cfg["app_links"][k] = data[k]
    save_config(cfg)
    return jsonify({"ok": True})

TEST_LOGINS_FILE = "/etc/painel/test_logins.json"

def _load_test_logins():
    """Conjunto de logins criados como TESTE (nascem com exclusão automática
    já agendada via `at`). Usado só pra saber, na hora do pagamento, que um
    login encontrado pelo telefone NÃO deve ser reaproveitado/renovado —
    porque ele vai ser apagado de qualquer forma pelo job de auto-exclusão
    do teste, mesmo que a gente tente estender a validade dele."""
    if not os.path.exists(TEST_LOGINS_FILE):
        return set()
    try:
        with open(TEST_LOGINS_FILE) as f:
            return set(json.load(f))
    except Exception:
        return set()

def _save_test_logins(logins):
    _atomic_write_json(TEST_LOGINS_FILE, sorted(logins))

def _mark_login_as_test(login):
    logins = _load_test_logins()
    logins.add(login)
    _save_test_logins(logins)

def create_test_internal(owner_role, owner_user, login="", senha="123", minutos=60, auto=False):
    """Núcleo da criação de teste, reutilizado pela rota HTTP normal e
    pelo bot de WhatsApp (item: auto-atendimento). Retorna
    (ok: bool, payload_ou_erro: dict)."""
    login = (login or "").strip()
    senha = (senha or "123").strip()

    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
        if auto:
            senha = login

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return False, {"error": "Nome de usuário inválido"}

    # FIX (trava de nome duplicado, case-insensitive): esta função interna
    # (usada pelo bot do WhatsApp em autoatendimento, tanto pra teste grátis
    # quanto pra acesso pago via comprovante PIX) comparava login com ==
    # (case-sensitive), diferente da rota /api/users (criação manual pelo
    # painel) que já foi corrigida antes. Resultado: o bot conseguia criar
    # um login "gabriel" mesmo já existindo um usuário "Gabriel" (criado
    # manualmente) -- useradd/xray_add_client_safe rodavam sem erro na hora,
    # mas o Xray trata o "email" do client no config.json sem diferenciar
    # maiúsculas/minúsculas -- então na próxima subida do serviço (restart,
    # reboot, outro fix) o Xray recusava o config inteiro com "User gabriel
    # already exists" (exit-code 23) e o serviço ficava fora do ar até
    # alguém editar o config.json na mão pra remover a duplicata. Agora
    # bloqueia a criação ANTES de tocar em useradd/Xray/usuarios.db, com a
    # mesma checagem case-insensitive e a mesma mensagem de erro clara que a
    # rota /api/users já usa.
    users = read_users()
    if any(u["login"].lower() == login.lower() for u in users):
        return False, {"error": f'Usuário "{login}" já existe (nomes são tratados sem diferenciar maiúsculas/minúsculas)'}

    if owner_role == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, owner_user)
        if not ok:
            return False, {"error": "Cota de usuários esgotada" + (f' (limite de "{blocked_at}")' if blocked_at != owner_user else "")}

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        uuid=$(cat /proc/sys/kernel/random/uuid)
        exp=$(date -d "now + {minutos} minutes" +"%Y-%m-%d %H:%M:%S")
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|1" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "bash /etc/painel/deluser.sh {login} --auto" | at "now + {minutos} minutes" 2>/dev/null
        echo "OK:$uuid:$exp"
        '
    """)

    if "OK:" not in out:
        return False, {"error": "Falha ao criar teste"}

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    if owner_role == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, owner_user, login)
        save_config(cfg)

    # BUGFIX (item 6): a partir daqui o teste JÁ FOI criado de verdade
    # (useradd, xray, linha em usuarios.db — tudo acima já rodou com
    # sucesso). _mark_login_as_test é só bookkeeping auxiliar (pra saber
    # depois, na hora do pagamento, que esse login não deve ser
    # reaproveitado). Se isso falhar (foi visto falhando por permissão
    # no arquivo temporário — ver _atomic_write), NÃO pode derrubar a
    # resposta com 500: o admin via o popup de erro mesmo com o teste
    # criado certinho, e nunca via a tela com uuid/senha/validade pra
    # copiar. Bookkeeping secundário nunca mascara um sucesso primário.
    try:
        _mark_login_as_test(login)
    except Exception as e:
        device_log_write(f"AVISO: falha ao marcar '{login}' como teste (não bloqueia a criação): {e}") if 'device_log_write' in globals() else None

    # BUGFIX v33: até aqui, "Criar Teste"/"Criar Teste Automático" (e o
    # teste dado pelo bot do WhatsApp, que também passa por aqui) nunca
    # replicava pros servidores sincronizados — só a criação de usuário
    # completo (/api/users) fazia isso. getattr(...) porque esta função
    # também é chamada de dentro do webhook do bot, onde request.ns_session
    # não existe (não é uma rota autenticada por sessão/token de sync).
    if not getattr(request, "ns_session", {}).get("via_sync", False):
        propagate_to_servers("POST", "/api/users/test", {"login": login, "senha": senha, "minutos": minutos, "auto": auto})

    return True, {"login": login, "uuid": uuid, "expira": exp, "minutos": minutos, "senha": senha, "limite": 1}

def create_paid_access_internal(owner_role, owner_user, dias=30, login="", senha=""):
    """Cria um acesso PAGO (não-teste) com validade de `dias` dias.
    Núcleo equivalente ao de /api/users (rota HTTP autenticada), mas
    chamável internamente sem sessão — usado pelo bot de autoatendimento
    quando o cliente novo manda o comprovante do PIX."""
    login = (login or "").strip()
    if not login:
        existing = {u["login"] for u in read_users()}
        login = gen_random_login(existing)
    if not senha:
        senha = login  # usuário e senha iguais: fácil do cliente digitar no app

    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$', login):
        return False, {"error": "Nome de usuário inválido"}

    # FIX (trava de nome duplicado, case-insensitive): mesma causa-raiz do
    # fix aplicado em create_test_internal -- esta função (usada pelo bot
    # quando o cliente novo manda o comprovante do PIX) comparava login com
    # == (case-sensitive), então "gabriel" passava mesmo já existindo
    # "Gabriel", e o Xray rejeitava o config na subida seguinte, derrubando
    # o serviço. Agora bloqueia sempre case-insensitive, ANTES de criar
    # qualquer coisa no sistema.
    users = read_users()
    if any(u["login"].lower() == login.lower() for u in users):
        return False, {"error": f'Usuário "{login}" já existe (nomes são tratados sem diferenciar maiúsculas/minúsculas)'}

    if owner_role == "reseller":
        cfg = load_config()
        ok, blocked_at = quota_available_for_new_user(cfg, owner_user)
        if not ok:
            return False, {"error": "Cota de usuários esgotada" + (f' (limite de "{blocked_at}")' if blocked_at != owner_user else "")}

    out, rc = run_cmd(f"""
        bash -c '
        source /etc/painel/xray_lib.sh
        useradd -m -s /bin/bash "{login}"
        echo "{login}:{senha}" | chpasswd
        mkdir -p /home/{login}/.ssh
        chmod 700 /home/{login}/.ssh
        chown -R {login}:{login} /home/{login}
        exp=$(date -d "+{dias} days" +"%Y-%m-%d 23:59:59")
        exp_chage=$(date -d "+{dias} days +1 day" +"%Y-%m-%d")
        chage -E "$exp_chage" "{login}"
        uuid=$(cat /proc/sys/kernel/random/uuid)
        xray_add_client_safe "{login}" "$uuid" 443
        echo "{login}|$uuid|$exp|{senha}|1" >> /etc/painel/usuarios.db
        systemctl restart xray >/dev/null 2>&1
        echo "OK:$uuid:$exp"
        '
    """)

    if rc != 0 or "OK:" not in out:
        return False, {"error": "Falha ao criar usuário", "detail": out}

    parts = out.strip().split("OK:")[-1].split(":")
    uuid = parts[0] if parts else ""
    exp  = ":".join(parts[1:]) if len(parts) > 1 else ""

    if owner_role == "reseller":
        cfg = load_config()
        register_user_to_reseller(cfg, owner_user, login)
        save_config(cfg)

    # BUGFIX v33: acesso pago criado pelo bot (comprovante PIX de cliente
    # novo) não replicava pros servidores sincronizados — mesma causa-raiz
    # do "Criar Teste". Reaproveita a rota /api/users normal no servidor
    # remoto, que já aceita exatamente esse formato de payload.
    if not getattr(request, "ns_session", {}).get("via_sync", False):
        propagate_to_servers("POST", "/api/users", {"login": login, "senha": senha, "dias": dias, "limite": 1})

    return True, {"login": login, "uuid": uuid, "expira": exp, "senha": senha, "limite": 1, "dias": dias}


def renew_access_internal(username, dias=30):
    """Estende a validade de um acesso já existente em `dias` dias, a
    partir de hoje ou do vencimento atual (o que for mais tarde) — usado
    pelo bot quando o comprovante é de um cliente que já tem login
    vinculado ao número (renovação, não conta nova)."""
    users = read_users()
    u = next((x for x in users if x["login"] == username), None)
    if not u:
        return False, {"error": "Usuário não encontrado"}

    atual = _parse_dt(u["expira"])
    base = atual if (atual and atual > datetime.datetime.now()) else datetime.datetime.now()
    nova_exp_dt = base + datetime.timedelta(days=dias)
    nova_exp = nova_exp_dt.strftime("%Y-%m-%d 23:59:59")
    exp_chage = (nova_exp_dt + datetime.timedelta(days=1)).strftime("%Y-%m-%d")

    run_cmd(f'chage -E "{exp_chage}" "{username}" 2>/dev/null')

    new_lines = []
    with open(USERDB) as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[0] == username:
                new_lines.append(f"{username}|{u['uuid']}|{nova_exp}|{u['senha']}|{u['limite']}")
            elif line.strip():
                new_lines.append(line.strip())
    _atomic_write(USERDB, lambda f: f.write("\n".join(new_lines) + "\n"))

    return True, {"login": username, "uuid": u["uuid"], "expira": nova_exp, "senha": u["senha"], "limite": u["limite"], "dias": dias}


@app.route("/api/users/test", methods=["POST"])
@auth_required()
def create_test():
    data = request.get_json() or {}
    s = request.ns_session
    ok, payload = create_test_internal(
        s["role"], s["user"],
        login=data.get("login", ""), senha=data.get("senha", "123"),
        minutos=int(data.get("minutos", 60)), auto=bool(data.get("auto"))
    )
    if not ok:
        return jsonify(payload), 409 if "já existe" in payload.get("error", "") else (403 if "Cota" in payload.get("error", "") else 500)
    return jsonify({"ok": True, **payload}), 201

# ══════════════════════════════════════════════════════════════════
#  SERVIDORES — gerenciamento multi-servidor em paralelo
#  O admin pode registrar outros servidores Painel Netsimon aqui. Toda
#  ação de usuário (criar/remover/testar/desbloquear) feita neste
#  painel é replicada automaticamente para todos os servidores
#  registrados, usando o token de sincronização de cada um (visível
#  na aba Servidores de cada instância, gerado na instalação).
# ══════════════════════════════════════════════════════════════════

def propagate_to_servers(method, path, payload=None):
    """
    Dispara (em background, best-effort) a mesma ação para todos os
    servidores registrados. Nunca bloqueia a resposta ao admin nem
    derruba a ação local se um servidor remoto estiver fora do ar.

    BUGFIX: antes, uma resposta HTTP de erro do servidor remoto (ex:
    401 por token de sincronização errado/desatualizado, 404 porque o
    login não existe lá, 500 por exceção no servidor remoto) passava
    OK — o requests.post()/delete() só levanta exceção em falha de
    REDE (timeout, conexão recusada), nunca por causa do status code
    da resposta. Resultado real: a renovação (ou qualquer outra ação)
    "sumia" no servidor remoto sem NENHUM log em lugar nenhum — nem
    aqui, nem no painel — parecia que tinha funcionado só porque o
    servidor local não travou. Agora todo status >= 400 é tratado como
    falha e logado com o motivo, servidor e ação, pra aparecer na tela
    de Logs do painel em vez de falhar em silêncio.
    """
    cfg = load_config()
    servers = cfg.get("servers", {})
    if not servers:
        return

    def _fire(server_name, base_url, token):
        try:
            headers = {"X-Sync-Token": token}
            url = f"{base_url}{path}"
            if method == "POST":
                resp = requests.post(url, json=payload, headers=headers, timeout=8)
            elif method == "DELETE":
                resp = requests.delete(url, headers=headers, timeout=8)
            else:
                return
            if resp.status_code >= 400:
                motivo = "token de sincronização inválido/desatualizado" if resp.status_code == 401 else f"HTTP {resp.status_code}"
                device_log_write(
                    f"SYNC FALHOU -> servidor '{server_name}' ({base_url}{path}): {motivo} — resposta: {resp.text[:200]}"
                )
        except Exception as e:
            device_log_write(f"SYNC FALHOU -> servidor '{server_name}' ({base_url}{path}): {e}")

    for _id, s in servers.items():
        base_url = f"http://{s['host']}:{s.get('port', 81)}"
        threading.Thread(target=_fire, args=(s.get("name", _id), base_url, s["token"]), daemon=True).start()

@app.route("/api/servers", methods=["GET"])
@auth_required(roles=["admin"])
def list_servers():
    cfg = load_config()
    result = []
    for sid, s in cfg.get("servers", {}).items():
        online = False
        try:
            r = requests.get(f"http://{s['host']}:{s.get('port', 81)}/ping", timeout=3)
            online = r.status_code == 200
        except Exception:
            online = False
        result.append({"id": sid, "name": s["name"], "host": s["host"],
                        "port": s.get("port", 81), "online": online})
    return jsonify(result)

@app.route("/api/servers", methods=["POST"])
@auth_required(roles=["admin"])
def add_server():
    data = request.get_json() or {}
    name  = data.get("name", "").strip()
    host  = data.get("host", "").strip()
    port  = int(data.get("port", 81))
    token = data.get("token", "").strip()

    if not name or not host or not token:
        return jsonify({"error": "name, host e token são obrigatórios"}), 400

    cfg = load_config()
    sid = secrets.token_hex(6)
    cfg.setdefault("servers", {})[sid] = {"name": name, "host": host, "port": port, "token": token}
    save_config(cfg)
    return jsonify({"ok": True, "id": sid}), 201

@app.route("/api/servers/<sid>", methods=["DELETE"])
@auth_required(roles=["admin"])
def remove_server(sid):
    cfg = load_config()
    if sid not in cfg.get("servers", {}):
        return jsonify({"error": "não encontrado"}), 404
    del cfg["servers"][sid]
    save_config(cfg)
    return jsonify({"ok": True})

@app.route("/api/servers/self-token", methods=["GET"])
@auth_required(roles=["admin"])
def self_sync_token():
    """Token deste servidor, para ser colado no painel de OUTRO servidor
    que queira registrar este aqui e gerenciar os dois em paralelo."""
    return jsonify({"token": _load_sync_token()})

# ══════════════════════════════════════════════════════════════════
#  SLOWDNS — instalação/gerenciamento via popup do painel
# ══════════════════════════════════════════════════════════════════

SLOWDNS_DIR = "/etc/slowdns"
# Binário do dnstt-server já compilado e versionado junto com o resto do
# painel (linux/amd64, compilado a partir do fonte oficial do autor,
# www.bamsoftware.com/git/dnstt.git) -- ver README-dnstt.txt na raiz do
# projeto pra reproduzir o build caso precise atualizar essa cópia um dia.
SLOWDNS_EMBEDDED_BIN = "/etc/painel/dnstt-server"


def _slowdns_ensure_binary():
    """v42 — CONSERTO do popup de erro ao instalar o SlowDNS pelo painel
    web: antes (e ainda na v41), o botão só funcionava se o admin já
    tivesse compilado o dnstt-server manualmente e colocado em
    /root/dnstt-server, OU dependia de baixar/compilar na hora via
    'go install' — que nem funcionava de verdade, porque o dnstt não é
    publicado como módulo versionado no proxy do Go (proxy.golang.org
    devolve 404 pra ele). v42 tira essa dependência de rede por completo:
    o binário já vem PRONTO junto com o projeto, em
    /etc/painel/dnstt-server -- essa função só garante que ele foi
    copiado pra /etc/slowdns/dnstt-server, o lugar onde o serviço
    systemd espera encontrá-lo. Devolve (bin_path, erro) -- erro é None
    quando deu certo."""
    bin_path = f"{SLOWDNS_DIR}/dnstt-server"
    if os.path.exists(bin_path):
        return bin_path, None

    os.makedirs(SLOWDNS_DIR, exist_ok=True)

    if os.path.exists(SLOWDNS_EMBEDDED_BIN):
        run_cmd(f"cp '{SLOWDNS_EMBEDDED_BIN}' {bin_path} && chmod +x {bin_path}")
        return bin_path, None

    # Compatibilidade com quem já tinha o hábito antigo de compilar na
    # mão e deixar em /root.
    found, _ = run_cmd("find /root -maxdepth 2 -name 'dnstt-server' -type f 2>/dev/null | head -n1")
    found = found.strip()
    if found:
        run_cmd(f"cp '{found}' {bin_path} && chmod +x {bin_path}")
        return bin_path, None

    return None, (f"Binário do dnstt-server não encontrado em {SLOWDNS_EMBEDDED_BIN}. "
                   "Reinstale/atualize o painel -- esse arquivo deve vir junto com o projeto.")


@app.route("/api/slowdns/status", methods=["GET"])
@auth_required(roles=["admin"])
def slowdns_status():
    out, _ = run_cmd("pgrep -f dnstt-server")
    running = bool(out)
    configured = os.path.exists(f"{SLOWDNS_DIR}/domain")
    ns = ""
    pubkey = ""
    if configured:
        ns_out, _ = run_cmd(f"cat {SLOWDNS_DIR}/domain 2>/dev/null")
        ns = ns_out.strip()
        pub_out, _ = run_cmd(f"cat {SLOWDNS_DIR}/pub.key 2>/dev/null")
        pubkey = pub_out.strip()
    return jsonify({"running": running, "configured": configured, "ns": ns, "pubkey": pubkey})

@app.route("/api/slowdns/setup", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_setup():
    data = request.get_json() or {}
    ns = data.get("ns", "").strip()
    if not ns:
        return jsonify({"error": "Informe o NS (nameserver)"}), 400

    bin_path, bin_err = _slowdns_ensure_binary()
    if bin_err:
        return jsonify({"error": bin_err}), 400

    out, rc = run_cmd(f"""
        bash -c '
        cd {SLOWDNS_DIR}
        rm -f priv.key pub.key
        ./dnstt-server -gen-key -privkey-file priv.key -pubkey-file pub.key > /dev/null 2>&1
        cat pub.key
        '
    """)
    pubkey = out.strip()
    if not pubkey:
        return jsonify({"error": "Falha ao gerar chaves do SlowDNS"}), 500

    with open(f"{SLOWDNS_DIR}/domain", "w") as f:
        f.write(ns + "\n")

    run_cmd(f"""
        bash -c '
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
        iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353
        iptables -I INPUT -p udp --dport 53 -j ACCEPT
        iptables -I INPUT -p udp --dport 5353 -j ACCEPT
        '
    """)

    with open("/etc/systemd/system/slowdns.service", "w") as f:
        f.write(f"""[Unit]
Description=SlowDNS Painel Netsimon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={SLOWDNS_DIR}
ExecStart={bin_path} -udp :5353 -privkey-file {SLOWDNS_DIR}/priv.key {ns} 127.0.0.1:22
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""")
    run_cmd("systemctl daemon-reload && systemctl enable slowdns >/dev/null 2>&1 && systemctl restart slowdns")

    return jsonify({"ok": True, "ns": ns, "pubkey": pubkey})

@app.route("/api/slowdns/restart", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_restart():
    run_cmd("systemctl restart slowdns")
    return jsonify({"ok": True})

@app.route("/api/slowdns/uninstall", methods=["POST"])
@auth_required(roles=["admin"])
def slowdns_uninstall():
    run_cmd(f"""
        bash -c '
        systemctl stop slowdns 2>/dev/null
        systemctl disable slowdns 2>/dev/null
        rm -f /etc/systemd/system/slowdns.service
        systemctl daemon-reload
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null
        rm -rf {SLOWDNS_DIR}
        '
    """)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  WEBSOCKET SECURITY / WSS — TLS real (wss.py), handshake RFC6455
#  correto (Sec-WebSocket-Accept calculado, não fixo/"foo"). Sem
#  dependência de binário/script de terceiro — roda com o mesmo
#  interpretador Python do painel, a partir de /etc/painel/wss.py.
#  v40: substitui de vez o antigo security.py (TLS incompleto, nunca
#  abria socket SSL de fato — só o nome "Security" enganava; token
#  também saiu, o TLS já autentica o canal). Mesmo padrão de template
#  systemd multi-porta do proxy@.service (wss@<porta>.service).
# ══════════════════════════════════════════════════════════════════

WSS_PY   = "/etc/painel/wss.py"
WSS_DIR  = "/etc/painel/wss"
WSS_CONF = f"{WSS_DIR}/wss.conf"
WSS_CERT = f"{WSS_DIR}/cert.pem"
WSS_KEY  = f"{WSS_DIR}/key.pem"
WSS_DEFAULT_PORT = 8443


def _wss_port_valid(port):
    return isinstance(port, int) and 1 <= port <= 65535


def _wss_listen_valid(listen):
    # host:porta simples — evita injeção via campo "destino" livre
    return bool(re.fullmatch(r"[A-Za-z0-9_.\-]+:[0-9]{1,5}", listen or ""))


@app.route("/api/wss/status", methods=["GET"])
@auth_required(roles=["admin"])
def wss_status():
    installed = os.path.exists(WSS_PY) and os.path.exists(WSS_CERT) and os.path.exists(WSS_KEY)
    _, rc = run_cmd(f"systemctl is-active --quiet wss@{WSS_DEFAULT_PORT}")
    dest_out, _ = run_cmd(f"grep -oP 'WSS_DEST=\\K.*' {WSS_CONF} 2>/dev/null")
    return jsonify({
        "installed": installed,
        "running":   rc == 0,
        "port":      WSS_DEFAULT_PORT,
        "dest":      dest_out.strip() or "127.0.0.1:22",
    })

@app.route("/api/wss/configure", methods=["POST"])
@auth_required(roles=["admin"])
def wss_configure():
    data = request.get_json() or {}
    dest = (data.get("dest") or "127.0.0.1:22").strip()
    if not _wss_listen_valid(dest):
        return jsonify({"error": "Destino inválido — use o formato host:porta"}), 400
    os.makedirs(WSS_DIR, exist_ok=True)
    with open(WSS_CONF, "w") as f:
        f.write(f"WSS_DEST={dest}\n")
    # Instâncias wss@<porta> já ativas só leem o EnvironmentFile no
    # start — reinicia as que estiverem no ar pra aplicar o destino novo.
    units_out, _ = run_cmd("systemctl list-units --type=service --all --no-legend 'wss@*' | awk '{print $1}'")
    for unit in [u for u in units_out.splitlines() if u.strip()]:
        run_cmd(f"systemctl is-active --quiet {unit} && systemctl restart {unit}")
    return jsonify({"ok": True})

@app.route("/api/wss/start", methods=["POST"])
@auth_required(roles=["admin"])
def wss_start():
    data = request.get_json() or {}
    port = int(data.get("port", WSS_DEFAULT_PORT))
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    if not os.path.exists(WSS_PY):
        return jsonify({"error": "wss.py não encontrado — reinstale o painel"}), 400
    if not (os.path.exists(WSS_CERT) and os.path.exists(WSS_KEY)):
        return jsonify({"error": "Certificado/chave ausentes em /etc/painel/wss/ — reinstale o painel"}), 400
    # Mesma trava do proxy@<porta>: libera a porta parando quem estiver
    # nela do lado do WebSocket Proxy simples ou do WSS Security sem
    # TLS, via systemctl (nunca kill cru — o Restart=always religaria
    # em segundos brigando pela porta).
    run_cmd(f"systemctl stop proxy@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss-security@{port} 2>/dev/null")
    _stop_other_template_instances("wss", port)
    run_cmd("sleep 1")
    _, rc = run_cmd(f"systemctl enable --now wss@{port}")
    return jsonify({"ok": rc == 0})

@app.route("/api/wss/stop", methods=["POST"])
@auth_required(roles=["admin"])
def wss_stop():
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    port = int(port) if port else (_active_template_port("wss") or WSS_DEFAULT_PORT)
    # v45: desabilita também, senão volta sozinho no próximo boot.
    run_cmd(f"systemctl disable wss@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss@{port}")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  WEBSOCKET SECURITY (SEM TLS) — wss_security.py, desenvolvido e
#  testado separadamente pelo Simon. Roda EXATAMENTE como enviado —
#  nenhuma linha do script foi alterada, e não é a mesma coisa que o
#  wss.py acima (TLS real): esse aqui é só a camuflagem HTTP/1.1 101,
#  sem criptografia por cima. Serviço de sistema próprio
#  (wss-security@<porta>.service), independente do proxy.py e do
#  wss.py — os três convivem lado a lado, cada um na sua porta. Padrão
#  automático na instalação: porta 8888.
# ══════════════════════════════════════════════════════════════════

WSSSEC_PY           = "/etc/painel/wss_security.py"
WSSSEC_DIR          = "/etc/painel/wss-security"
WSSSEC_CONF         = f"{WSSSEC_DIR}/wss-security.conf"
WSSSEC_DEFAULT_PORT = 8888


@app.route("/api/wsssec/status", methods=["GET"])
@auth_required(roles=["admin"])
def wsssec_status():
    installed = os.path.exists(WSSSEC_PY)
    active_port = _active_template_port("wss-security")
    dest_out, _ = run_cmd(f"grep -oP 'WSSSEC_DEST=\\K.*' {WSSSEC_CONF} 2>/dev/null")
    return jsonify({
        "installed": installed,
        "running":   active_port is not None,
        "port":      active_port or WSSSEC_DEFAULT_PORT,
        "dest":      dest_out.strip() or "127.0.0.1:22",
    })

@app.route("/api/wsssec/configure", methods=["POST"])
@auth_required(roles=["admin"])
def wsssec_configure():
    data = request.get_json() or {}
    dest = (data.get("dest") or "127.0.0.1:22").strip()
    if not _wss_listen_valid(dest):
        return jsonify({"error": "Destino inválido — use o formato host:porta"}), 400
    os.makedirs(WSSSEC_DIR, exist_ok=True)
    with open(WSSSEC_CONF, "w") as f:
        f.write(f"WSSSEC_DEST={dest}\n")
    units_out, _ = run_cmd("systemctl list-units --type=service --all --no-legend 'wss-security@*' | awk '{print $1}'")
    for unit in [u for u in units_out.splitlines() if u.strip()]:
        run_cmd(f"systemctl is-active --quiet {unit} && systemctl restart {unit}")
    return jsonify({"ok": True})

@app.route("/api/wsssec/start", methods=["POST"])
@auth_required(roles=["admin"])
def wsssec_start():
    data = request.get_json() or {}
    port = int(data.get("port", WSSSEC_DEFAULT_PORT))
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    if not os.path.exists(WSSSEC_PY):
        return jsonify({"error": "wss_security.py não encontrado — reinstale o painel"}), 400
    run_cmd(f"systemctl stop proxy@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss@{port} 2>/dev/null")
    _stop_other_template_instances("wss-security", port)
    run_cmd("sleep 1")
    _, rc = run_cmd(f"systemctl enable --now wss-security@{port}")
    return jsonify({"ok": rc == 0})

@app.route("/api/wsssec/stop", methods=["POST"])
@auth_required(roles=["admin"])
def wsssec_stop():
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    port = int(port) if port else (_active_template_port("wss-security") or WSSSEC_DEFAULT_PORT)
    # v45: desabilita também, senão volta sozinho no próximo boot.
    run_cmd(f"systemctl disable wss-security@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss-security@{port}")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  STUNNEL (SSL) — SSH sobre TLS "cru" (netsimon-stunnel.service).
#  Serviço de sistema dedicado, diretório e config próprios em
#  /etc/painel/stunnel, porta de entrada e destino configuráveis pelo
#  painel (web e SSH). Independente dos outros 3 modos — não usa
#  wss.py nem wss_security.py, é o Stunnel de fato.
# ══════════════════════════════════════════════════════════════════

STUNNEL_DIR          = "/etc/painel/stunnel"
STUNNEL_SETTINGS     = f"{STUNNEL_DIR}/stunnel_settings.conf"
STUNNEL_CONF         = f"{STUNNEL_DIR}/stunnel.conf"
STUNNEL_CERT         = f"{STUNNEL_DIR}/stunnel.pem"
STUNNEL_UNIT         = "netsimon-stunnel"
STUNNEL_DEFAULT_PORT = 2053
STUNNEL_DEFAULT_DEST = "127.0.0.1:22"


def _stunnel_bin():
    """Localiza o binário do stunnel instalado (nome do executável varia
    por distro/pacote: stunnel4 no Debian/Ubuntu, stunnel em outros)."""
    for name in ("stunnel4", "stunnel"):
        out, rc = run_cmd(f"command -v {name}")
        if rc == 0 and out.strip():
            return out.strip()
    return None


def _stunnel_ensure_bin():
    """Robustez: se o stunnel não estiver instalado (VPS provisionada
    fora do install.sh, ou pacote removido depois), instala na hora em
    vez de só devolver erro — mesmo princípio do fix do SlowDNS."""
    bin_path = _stunnel_bin()
    if bin_path:
        return bin_path
    run_cmd("apt-get update -y && apt-get install -y stunnel4")
    return _stunnel_bin()


def _stunnel_settings():
    port, dest = STUNNEL_DEFAULT_PORT, STUNNEL_DEFAULT_DEST
    if os.path.exists(STUNNEL_SETTINGS):
        port_out, _ = run_cmd(f"grep -oP 'STUNNEL_PORT=\\K.*' {STUNNEL_SETTINGS} 2>/dev/null")
        dest_out, _ = run_cmd(f"grep -oP 'STUNNEL_DEST=\\K.*' {STUNNEL_SETTINGS} 2>/dev/null")
        if port_out.strip().isdigit():
            port = int(port_out.strip())
        if dest_out.strip():
            dest = dest_out.strip()
    return port, dest


def _stunnel_ensure_cert():
    if os.path.exists(STUNNEL_CERT):
        return
    os.makedirs(STUNNEL_DIR, exist_ok=True)
    run_cmd(
        f"openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -sha256 "
        f"-subj '/CN=Painel Netsimon' -keyout {STUNNEL_CERT} -out {STUNNEL_CERT}"
    )
    run_cmd(f"chmod 600 {STUNNEL_CERT}")


def _stunnel_write_conf(port, dest):
    os.makedirs(STUNNEL_DIR, exist_ok=True)
    with open(STUNNEL_SETTINGS, "w") as f:
        f.write(f"STUNNEL_PORT={port}\nSTUNNEL_DEST={dest}\n")
    with open(STUNNEL_CONF, "w") as f:
        f.write(f"""pid = /var/run/{STUNNEL_UNIT}.pid
cert = {STUNNEL_CERT}
client = no
foreground = yes
output = /var/log/netsimon_stunnel.log
socket = a:SO_REUSEADDR=1

[{STUNNEL_UNIT}]
accept = {port}
connect = {dest}
""")


def _stunnel_write_unit(bin_path):
    unit_path = f"/etc/systemd/system/{STUNNEL_UNIT}.service"
    if os.path.exists(unit_path):
        return
    with open(unit_path, "w") as f:
        f.write(f"""[Unit]
Description=Painel Netsimon - Stunnel (SSH sobre TLS "cru")
After=network.target

[Service]
Type=simple
ExecStart={bin_path} {STUNNEL_CONF}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""")
    run_cmd("systemctl daemon-reload")


@app.route("/api/stunnel/status", methods=["GET"])
@auth_required(roles=["admin"])
def stunnel_status():
    port, dest = _stunnel_settings()
    _, rc = run_cmd(f"systemctl is-active --quiet {STUNNEL_UNIT}")
    return jsonify({
        "installed": _stunnel_bin() is not None,
        "running":   rc == 0,
        "port":      port,
        "dest":      dest,
    })


@app.route("/api/stunnel/configure", methods=["POST"])
@auth_required(roles=["admin"])
def stunnel_configure():
    data = request.get_json() or {}
    port = data.get("port", STUNNEL_DEFAULT_PORT)
    dest = (data.get("dest") or STUNNEL_DEFAULT_DEST).strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return jsonify({"error": "Porta inválida"}), 400
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    if not _wss_listen_valid(dest):
        return jsonify({"error": "Destino inválido — use o formato host:porta"}), 400

    bin_path = _stunnel_ensure_bin()
    if not bin_path:
        return jsonify({"error": "Falha ao instalar o stunnel — verifique a conexão do servidor com a internet"}), 500

    _stunnel_ensure_cert()
    _stunnel_write_conf(port, dest)
    _stunnel_write_unit(bin_path)

    # Se já estiver ativo, reinicia agora pra aplicar porta/destino novos.
    _, rc = run_cmd(f"systemctl is-active --quiet {STUNNEL_UNIT}")
    if rc == 0:
        run_cmd(f"systemctl restart {STUNNEL_UNIT}")
    return jsonify({"ok": True})


@app.route("/api/stunnel/start", methods=["POST"])
@auth_required(roles=["admin"])
def stunnel_start():
    data = request.get_json(silent=True) or {}
    saved_port, saved_dest = _stunnel_settings()
    port = data.get("port", saved_port)
    dest = (data.get("dest") or saved_dest).strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return jsonify({"error": "Porta inválida"}), 400
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    if not _wss_listen_valid(dest):
        return jsonify({"error": "Destino inválido — use o formato host:porta"}), 400

    bin_path = _stunnel_ensure_bin()
    if not bin_path:
        return jsonify({"error": "Falha ao instalar o stunnel — verifique a conexão do servidor com a internet"}), 500

    _stunnel_ensure_cert()
    _stunnel_write_conf(port, dest)
    _stunnel_write_unit(bin_path)

    # Mesma trava dos outros 3 modos: libera a porta escolhida se algum
    # deles estiver ocupando ela, antes de subir o stunnel.
    run_cmd(f"systemctl stop proxy@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss-security@{port} 2>/dev/null")
    run_cmd("sleep 1")
    _, rc = run_cmd(f"systemctl enable --now {STUNNEL_UNIT}")
    return jsonify({"ok": rc == 0})


@app.route("/api/stunnel/stop", methods=["POST"])
@auth_required(roles=["admin"])
def stunnel_stop():
    # v45: desabilita também, senão volta sozinho no próximo boot.
    run_cmd(f"systemctl disable {STUNNEL_UNIT} 2>/dev/null")
    run_cmd(f"systemctl stop {STUNNEL_UNIT}")
    return jsonify({"ok": True})


@app.route("/api/stunnel/restart", methods=["POST"])
@auth_required(roles=["admin"])
def stunnel_restart():
    port, dest = _stunnel_settings()
    _stunnel_write_conf(port, dest)
    _, rc = run_cmd(f"systemctl restart {STUNNEL_UNIT}")
    return jsonify({"ok": rc == 0})

# ══════════════════════════════════════════════════════════════════
#  XRAY
# ══════════════════════════════════════════════════════════════════

def _websocket_port_service(port):
    """Descobre não só se a porta está em LISTEN, mas QUEM está nela:
    Proxy simples (proxy@<porta>), WSS TLS real (wss@<porta>), Websocket
    Security sem TLS (wss-security@<porta>) ou o Stunnel (netsimon-stunnel,
    instância única — checa se a porta configurada nele bate com a
    pedida). Todos são templates systemd (ou serviço único no caso do
    Stunnel), então a fonte de verdade é sempre 'systemctl is-active',
    nunca pgrep cru (evita falso positivo com processo órfão que não
    morreu direito). Usado pra mostrar no WebSocket Manager qual
    serviço está de fato ativo em cada porta, em vez de só
    'Ativa/Inativa' sem contexto nenhum."""
    _, rc = run_cmd(f"systemctl is-active --quiet proxy@{port}")
    if rc == 0:
        return True, "proxy"
    _, rc = run_cmd(f"systemctl is-active --quiet wss@{port}")
    if rc == 0:
        return True, "wss"
    _, rc = run_cmd(f"systemctl is-active --quiet wss-security@{port}")
    if rc == 0:
        return True, "wsssec"
    stunnel_port, _ = _stunnel_settings()
    if stunnel_port == port:
        _, rc = run_cmd(f"systemctl is-active --quiet {STUNNEL_UNIT}")
        if rc == 0:
            return True, "stunnel"
    out_listen, _ = run_cmd(f"ss -tln 2>/dev/null | grep -q ':{port} ' && echo on || echo off")
    listening = out_listen.strip() == "on"
    return listening, ("other" if listening else None)

@app.route("/api/websocket/status", methods=["GET"])
@auth_required(roles=["admin"])
def websocket_status():
    listen80, service80 = _websocket_port_service(80)
    # Item: usa a porta REAL em uso (qualquer uma), caindo pro padrão só
    # quando não há nenhuma instância ativa -- assim o badge não fica
    # preso a 8443/8888 quando o admin trocou a porta pela tela.
    wss_port = _active_template_port("wss") or WSS_DEFAULT_PORT
    wsssec_port = _active_template_port("wss-security") or WSSSEC_DEFAULT_PORT
    listen_wss, service_wss = _websocket_port_service(wss_port)
    listen_sec, service_sec = _websocket_port_service(wsssec_port)
    stunnel_port, _ = _stunnel_settings()
    listen_stunnel, service_stunnel = _websocket_port_service(stunnel_port)
    return jsonify({
        "port80":   listen80,
        "port8443": listen_wss,
        "port_wss": wss_port,
        "port8888": listen_sec,
        "port_wsssec": wsssec_port,
        "port_stunnel": stunnel_port,
        "listen_stunnel": listen_stunnel,
        # Item: qual serviço está de fato ocupando cada porta (proxy /
        # wss / wsssec / stunnel / other), pra exibir no bloco superior
        # do WebSocket Manager junto do badge Ativa/Inativa.
        "service80":   service80,
        "service8443": service_wss,
        "service8888": service_sec,
        "service_stunnel": service_stunnel,
    })

@app.route("/api/websocket/start", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_start():
    data = request.get_json() or {}
    port = int(data.get("port", 80))
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    # Item: liberdade de porta pro WebSocket Proxy simples -- o template
    # systemd "proxy@.service" aceita qualquer instância (proxy@80,
    # proxy@8888, proxy@<qualquer porta>). Libera a porta dos outros 3
    # modos primeiro (mesma trava, na direção contrária dos outros _start).
    run_cmd(f"systemctl stop wss@{port} 2>/dev/null")
    run_cmd(f"systemctl stop wss-security@{port} 2>/dev/null")
    run_cmd("sleep 1")
    # v45: "enable --now" — ativação manual pelo admin fica persistida
    # (religa sozinho depois de reboot); antes do v45 o proxy@80 já
    # vinha ligado direto do install.sh, agora é só instalado.
    _, rc = run_cmd(f"systemctl enable --now proxy@{port}")
    return jsonify({"ok": rc == 0})

@app.route("/api/websocket/stop", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_stop():
    data = request.get_json() or {}
    port = int(data.get("port", 80))
    if not _wss_port_valid(port):
        return jsonify({"error": "Porta inválida"}), 400
    # v45: desabilita também, senão volta sozinho no próximo boot.
    run_cmd(f"systemctl disable proxy@{port} 2>/dev/null")
    _, rc = run_cmd(f"systemctl stop proxy@{port}")
    return jsonify({"ok": rc == 0})

@app.route("/api/websocket/restart-all", methods=["POST"])
@auth_required(roles=["admin"])
def websocket_restart_all():
    _, rc = run_cmd(
        f"systemctl restart proxy@80 "
        f"wss@{WSS_DEFAULT_PORT} "
        f"wss-security@{WSSSEC_DEFAULT_PORT} "
        f"{STUNNEL_UNIT}"
    )
    return jsonify({"ok": rc == 0})

@app.route("/api/bhttp/status", methods=["GET"])
@auth_required(roles=["admin"])
def bhttp_status():
    installed = os.path.exists("/usr/local/bin/netsimon-bhttp") and \
        os.path.exists("/etc/systemd/system/netsimon-bhttp.service")
    _, rc = run_cmd("systemctl is-active --quiet netsimon-bhttp")
    http_port, https_port = 80, 443
    cfg_path = "/etc/netsimon-bhttp/config.json"
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
            for listen in cfg.get("proxy", {}).get("listen", []):
                if listen.get("ssl"):
                    https_port = listen.get("port", https_port)
                else:
                    http_port = listen.get("port", http_port)
        except Exception:
            pass
    return jsonify({
        "installed": installed,
        "running": rc == 0,
        "http_port": http_port,
        "https_port": https_port,
    })

@app.route("/api/bhttp/install", methods=["POST"])
@auth_required(roles=["admin"])
def bhttp_install_route():
    # v45: instala o Netsimon-BHTTP a partir do binário JÁ EMBUTIDO no
    # projeto (bhttp.sh copia /etc/painel/netsimon-bhttp) — nada é
    # baixado da internet aqui. Só instala; não ativa.
    out, rc = run_cmd("bash /etc/painel/bhttp.sh install")
    if rc != 0:
        return jsonify({"error": out or "Falha ao instalar o BHTTP"}), 500
    return jsonify({"ok": True})

@app.route("/api/bhttp/start", methods=["POST"])
@auth_required(roles=["admin"])
def bhttp_start_route():
    data = request.get_json(silent=True) or {}
    http_port = int(data.get("http_port", 80))
    https_port = int(data.get("https_port", 443))
    if not _wss_port_valid(http_port) or not _wss_port_valid(https_port):
        return jsonify({"error": "Porta inválida"}), 400
    run_cmd(f"bash /etc/painel/bhttp.sh set-ports {http_port} {https_port}")
    out, rc = run_cmd("bash /etc/painel/bhttp.sh start")
    if rc != 0:
        return jsonify({"error": out or "Falha ao ativar o BHTTP"}), 500
    return jsonify({"ok": True})

@app.route("/api/bhttp/stop", methods=["POST"])
@auth_required(roles=["admin"])
def bhttp_stop_route():
    run_cmd("bash /etc/painel/bhttp.sh stop")
    return jsonify({"ok": True})

@app.route("/api/xray/status", methods=["GET"])
@auth_required(roles=["admin"])
def xray_status():
    active, _ = run_cmd("systemctl is-active xray")
    online_raw, _ = run_cmd(f"xray api statsgetallonlineusers --server={XRAY_API} 2>/dev/null")
    online_count = len(re.findall(r'user>>>.*?>>>online', online_raw))
    host = ""
    port = 443
    if os.path.exists(XRAY_CONF):
        try:
            with open(XRAY_CONF) as f:
                cfg = json.load(f)
            for ib in cfg.get("inbounds", []):
                if ib.get("protocol") != "dokodemo-door":
                    port = ib.get("port", 443)
                    host = (ib.get("streamSettings", {})
                              .get("xhttpSettings", {})
                              .get("host", ""))
        except Exception:
            pass
    return jsonify({
        "status":  active,
        "online":  online_count,
        "port":    port,
        "host":    host
    })

@app.route("/api/xray/start", methods=["POST"])
@auth_required(roles=["admin"])
def xray_start_route():
    # v45: ativação manual pelo admin — instalado no install.sh mas
    # nunca habilitado/iniciado automaticamente. Esse endpoint é quem
    # liga de fato (enable --now), persistindo mesmo após reboot.
    _, rc = run_cmd("systemctl enable --now xray")
    return jsonify({"ok": rc == 0})

@app.route("/api/xray/restart", methods=["POST"])
@auth_required(roles=["admin"])
def xray_restart():
    _, rc = run_cmd("systemctl restart xray")
    return jsonify({"ok": rc == 0})

@app.route("/api/xray/stop", methods=["POST"])
@auth_required(roles=["admin"])
def xray_stop():
    # v45: "stop" pelo painel também desabilita (systemctl disable),
    # senão o xray voltaria sozinho no próximo boot mesmo desligado
    # manualmente aqui.
    run_cmd("systemctl disable xray")
    _, rc = run_cmd("systemctl stop xray")
    return jsonify({"ok": rc == 0})

@app.route("/api/xray/config", methods=["GET"])
@auth_required(roles=["admin"])
def xray_get_config():
    if not os.path.exists(XRAY_CONF):
        return jsonify({"error": "config não encontrado"}), 404
    with open(XRAY_CONF) as f:
        return jsonify(json.load(f))

@app.route("/api/xray/config", methods=["POST"])
@auth_required(roles=["admin"])
def xray_save_config():
    """v41: config.json deixou de ser somente leitura no menu do Xray.
    Antes de sobrescrever o arquivo real, valida em duas camadas —
    JSON sintaticamente válido E aceito pelo próprio binário do Xray
    ('xray run -test') — e guarda uma cópia do config anterior, pra
    nunca deixar o Xray em pé quebrado por causa de uma edição errada."""
    data = request.get_json(silent=True)
    raw = request.data.decode("utf-8", errors="replace") if data is None else None

    if data is None:
        # Aceita tanto {"config": {...}} quanto o JSON cru do config no body.
        try:
            parsed = json.loads(raw)
        except Exception as e:
            return jsonify({"error": f"JSON inválido: {e}"}), 400
    else:
        parsed = data.get("config", data)

    if not isinstance(parsed, dict) or "inbounds" not in parsed:
        return jsonify({"error": "Config inválida — precisa ser um objeto JSON com a chave \"inbounds\""}), 400

    os.makedirs(os.path.dirname(XRAY_CONF), exist_ok=True)
    tmp_path = f"{XRAY_CONF}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(parsed, f, indent=2, ensure_ascii=False)

    # Cautela em produção: testa a config nova ANTES de substituir a que
    # está valendo — 'xray run -test' recusa o processo se o JSON tiver
    # erro que o parser padrão não pega (campo desconhecido, tipo errado
    # de inbound/outbound, TLS mal configurado etc).
    out, err, rc = run_cmd_full(f"xray run -test -config {tmp_path}", timeout=20)
    if rc != 0:
        run_cmd(f"rm -f {tmp_path}")
        return jsonify({"error": f"O Xray rejeitou essa configuração — nada foi salvo. Detalhe: {(err or out)[:500]}"}), 400

    backup_path = f"{XRAY_CONF}.bak-{int(time.time())}"
    if os.path.exists(XRAY_CONF):
        shutil.copy2(XRAY_CONF, backup_path)
    os.replace(tmp_path, XRAY_CONF)

    _, restart_rc = run_cmd("systemctl restart xray")
    return jsonify({"ok": True, "restarted": restart_rc == 0, "backup": backup_path})

@app.route("/api/xray/host", methods=["POST"])
@auth_required(roles=["admin"])
def xray_set_host():
    data = request.get_json() or {}
    host = data.get("host", "")
    run_cmd(f"""jq --arg h "{host}" '(.inbounds[] | select(.port==443)).streamSettings.xhttpSettings.host = $h' {XRAY_CONF} > /tmp/xc.tmp && mv /tmp/xc.tmp {XRAY_CONF}""")
    run_cmd("systemctl restart xray")
    return jsonify({"ok": True})

@app.route("/api/xray/port", methods=["POST"])
@auth_required(roles=["admin"])
def xray_set_port():
    data = request.get_json() or {}
    port = int(data.get("port", 443))
    run_cmd(f"""jq --argjson p {port} '(.inbounds[] | select(.port==443)).port = $p' {XRAY_CONF} > /tmp/xc.tmp && mv /tmp/xc.tmp {XRAY_CONF}""")
    run_cmd("systemctl restart xray")
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  SERVIÇOS
# ══════════════════════════════════════════════════════════════════

@app.route("/api/services/<name>/status", methods=["GET"])
@auth_required(roles=["admin"])
def service_status_route(name):
    return jsonify({"running": service_status(name)})

@app.route("/api/services/<name>/<action>", methods=["POST"])
@auth_required(roles=["admin"])
def service_action(name, action):
    cmds = {
        # v45: "start" agora usa "enable --now" e "stop" usa "disable" +
        # "stop" — o admin ativa/desativa pelo painel e isso já fica
        # persistido pro systemd religar sozinho (ou não) depois de um
        # reboot, sem depender do boot_check.sh pra isso.
        ("xray",    "restart"): "systemctl restart xray",
        ("xray",    "stop"):    "systemctl disable xray; systemctl stop xray",
        ("xray",    "start"):   "systemctl enable --now xray",
        # Item: BUG CORRIGIDO — start/restart aqui viravam UMA linha de
        # comando só ("pkill ...; screen -S ... quit; sleep; screen -dmS
        # ... limit.sh"). Como a MESMA linha de comando termina com
        # "bash /etc/painel/limit.sh" (texto puro, sem o truque [l]),
        # o "pkill -f '[l]imit.sh'" do INÍCIO da linha acabava batendo
        # nessa mesma linha (por causa do "limit.sh" que aparece mais
        # adiante nela) e matava o próprio shell no meio — antes dele
        # chegar no "screen -dmS" final. Resultado: o limiter nunca
        # subia pelo painel, só na mão (comando avulso, sem esse
        # conflito). Fix: virou uma LISTA — cada comando roda como uma
        # invocação de shell separada, então o comando de limpeza nunca
        # "enxerga" o comando de start na mesma linha.
        # Item: BUG CORRIGIDO (definitivo) — proxy.py virou serviço systemd
        # independente (proxy@80, Restart=always), igual ao xray.
        # Antes subia via "screen -dmS" como subprocesso do próprio
        # painel_api.py, então ficava dentro da MESMA cgroup do
        # netsimon-painel.service — todo "systemctl restart netsimon-painel"
        # (ex: durante uma atualização) matava o WebSocket junto, mesmo a
        # screen estando "destacada" (destacar não tira da cgroup). Agora o
        # painel só liga/desliga a unit — o protocolo em si roda por conta
        # própria, sobrevive a restart/atualização/crash do painel.
        ("proxy",   "restart"): "systemctl restart proxy@80",
        ("proxy",   "stop"):    "systemctl disable proxy@80; systemctl stop proxy@80",
        ("proxy",   "start"):   "systemctl enable --now proxy@80",
        # v40: wss@<porta> (TLS real) — netsimon-security antigo saiu.
        # Item: usa a porta REAL ativa (qualquer uma), não mais fixa em
        # 8443/8888 -- por isso essas 6 entradas viraram função (chamada
        # na hora do clique, não em tempo de import).
        ("wss", "restart"): lambda: f"systemctl restart wss@{_active_template_port('wss') or WSS_DEFAULT_PORT}",
        ("wss", "stop"):    lambda: f"systemctl disable wss@{_active_template_port('wss') or WSS_DEFAULT_PORT}; systemctl stop wss@{_active_template_port('wss') or WSS_DEFAULT_PORT}",
        ("wss", "start"):   lambda: f"systemctl enable --now wss@{_active_template_port('wss') or WSS_DEFAULT_PORT}",
        # v41: wss-security@<porta> — Websocket Security SEM TLS,
        # protocolo novo e independente do wss@ acima (wss_security.py,
        # desenvolvido separadamente). Porta padrão 8888.
        ("wsssec", "restart"): lambda: f"systemctl restart wss-security@{_active_template_port('wss-security') or WSSSEC_DEFAULT_PORT}",
        ("wsssec", "stop"):    lambda: f"systemctl disable wss-security@{_active_template_port('wss-security') or WSSSEC_DEFAULT_PORT}; systemctl stop wss-security@{_active_template_port('wss-security') or WSSSEC_DEFAULT_PORT}",
        ("wsssec", "start"):   lambda: f"systemctl enable --now wss-security@{_active_template_port('wss-security') or WSSSEC_DEFAULT_PORT}",
        # v41: Stunnel (netsimon-stunnel.service) — mesma inclusão dos
        # dois acima, pra manter esse endpoint genérico completo. A
        # porta real usada é a que estiver salva em
        # /etc/painel/stunnel/stunnel_settings.conf (a unit já lê o
        # /etc/painel/stunnel/stunnel.conf sozinha; não depende de argumento).
        ("stunnel", "restart"): "systemctl restart netsimon-stunnel",
        ("stunnel", "stop"):    "systemctl disable netsimon-stunnel; systemctl stop netsimon-stunnel",
        ("stunnel", "start"):   "systemctl enable --now netsimon-stunnel",
        # "stop" do limiter precisa ser mais agressivo que um pkill simples:
        # o processo roda dentro de uma sessão "screen" (limitador), e só
        # matar o processo interno às vezes deixava a sessão viva/zumbi,
        # que o "pgrep -f limit.sh" do status ainda enxergava como "rodando"
        # — por isso o ícone nunca ficava vermelho depois de parar.
        # Item: BUG CORRIGIDO — "pkill -f limit.sh" dentro de um comando
        # composto ("A; B; C") batia na própria linha de comando do shell
        # que executa a sequência inteira (ela contém a string "limit.sh"
        # várias vezes), matando o shell no meio e abortando os passos
        # seguintes (o screen quit/restart às vezes nem rodava). Por isso
        # o "[l]imit.sh" também aqui, não só no status.
        # FIX (reativação sozinha do Limiter): o install.sh cria uma unit
        # systemd "limiter" com Restart=always (pra outro fim), mas o
        # limiter de verdade é gerenciado via screen/pgrep, nunca via
        # systemd. Resultado: ao clicar "Desativar", o painel matava só o
        # processo, e o systemd — com Restart=always — subia outro em
        # ~3s por conta própria, sem passar por aqui e sem gerar log
        # nenhum. Agora start/stop/restart também param e desabilitam
        # essa unit systemd, garantindo que só existe UM dono real do
        # processo (o próprio painel, via screen).
        ("limiter", "start"):   ["systemctl stop limiter 2>/dev/null; systemctl disable limiter 2>/dev/null; pkill -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3", "screen -dmS limitador bash /etc/painel/limit.sh"],
        ("limiter", "stop"):    "systemctl stop limiter 2>/dev/null; systemctl disable limiter 2>/dev/null; pkill -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3; pkill -9 -f '[l]imit.sh' 2>/dev/null",
        ("limiter", "restart"): ["systemctl stop limiter 2>/dev/null; systemctl disable limiter 2>/dev/null; pkill -9 -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null; sleep 0.3", "screen -dmS limitador bash /etc/painel/limit.sh"],
        ("badvpn",  "restart"): "systemctl restart badvpn",
        ("badvpn",  "stop"):    "systemctl stop badvpn",
        ("badvpn",  "start"):   "systemctl start badvpn",
    }
    cmd = cmds.get((name, action))
    if not cmd:
        return jsonify({"error": "ação inválida"}), 400
    # cmd pode ser: uma string (1 invocação), uma lista (várias
    # invocações separadas, sem risco de uma pisar na outra — ver
    # comentário acima sobre o self-match do pkill), ou uma função sem
    # argumentos (pra descobrir a porta ativa na hora do clique, não
    # em tempo de import -- ver wss/wsssec acima).
    if callable(cmd):
        cmd = cmd()
    for c in (cmd if isinstance(cmd, list) else [cmd]):
        _, rc = run_cmd(c)

    # Confere o resultado de VERDADE antes de responder, em vez de assumir
    # que o comando funcionou depois de uma única espera fixa — um serviço
    # rodando dentro de "screen" (limiter/proxy) pode levar um instante a
    # mais pra realmente cair, e uma checagem única e rápida demais fazia
    # o painel responder "running" desatualizado: o botão/bolinha ficavam
    # sem nenhuma confirmação visual de que o clique fez efeito. Agora
    # insiste por até ~2.5s, reforçando o kill se for esperado "parado" e
    # ainda estiver detectando o processo — só devolve quando o estado
    # bate com o esperado ou o tempo de tentativas acaba (nesse caso,
    # devolve o estado real mesmo assim, nunca um valor otimista chutado).
    expect_running = action in ("start", "restart")
    running = service_status(name)
    tries = 0
    while running != expect_running and tries < 5:
        time.sleep(0.5)
        if not expect_running and name in ("limiter", "proxy"):
            # reforça o encerramento pra sessões "screen" que demoram a cair
            kill_cmd = {
                "limiter": "systemctl stop limiter 2>/dev/null; pkill -9 -f '[l]imit.sh' 2>/dev/null; screen -S limitador -X quit 2>/dev/null",
                "proxy":   "pkill -9 -f '[p]roxy.py' 2>/dev/null",
            }[name]
            run_cmd(kill_cmd)
        running = service_status(name)
        tries += 1

    s = request.ns_session
    try:
        with open(LOG_LIMIT, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')} - ADMIN ({s['user']}): serviço \"{name}\" -> {action} "
                     f"[{'rodando' if running else 'parado'}]"
                     f"{' (nao confirmou o estado esperado apos varias tentativas)' if running != expect_running else ''}\n")
    except Exception:
        pass

    return jsonify({"ok": True, "running": running})


# ══════════════════════════════════════════════════════════════════
#  LOGS
# ══════════════════════════════════════════════════════════════════

@app.route("/api/logs/<name>", methods=["GET"])
@auth_required(roles=["admin"])
def get_logs(name):
    lines = int(request.args.get("lines", 50))
    files = {
        "xray":      XRAY_LOG,
        "limit":     LOG_LIMIT,
        "device":    DEVICE_LOG,
        "system":    SYSTEM_LOG,
        "checkuser": "/var/log/checkuser.log",
        "proxy":     "/var/log/netsimon_proxy.log",
        "panel":     "/var/log/netsimon_painel_api.log",
    }
    path = files.get(name)
    if not path or not os.path.exists(path):
        return jsonify({"lines": []})
    out, _ = run_cmd(f"tail -n {lines} {path}")
    return jsonify({"lines": out.splitlines()})

# ══════════════════════════════════════════════════════════════════
#  REVENDEDORES
# ══════════════════════════════════════════════════════════════════

def bump_api_keys_version(cfg):
    """Incrementa o contador usado pelo app cliente para saber quando
    precisa buscar as chaves de revendedor atualizadas (ver device_check)."""
    cfg["api_keys_version"] = int(cfg.get("api_keys_version", 0)) + 1

@app.route("/api/resellers", methods=["GET"])
@auth_required(roles=["admin", "reseller"])
def list_resellers():
    cfg = load_config()
    s = request.ns_session

    if s["role"] == "admin":
        names = list(cfg.get("resellers", {}).keys())
    else:
        # Revendedor só vê seus filhos diretos (o revendedor nível 2 vê
        # seus sub-revendedores nível 3; nível 3 não vê nenhum, pois não
        # pode criar mais sub-revendedores).
        names = direct_children(cfg, s["user"])

    result = []
    for name in names:
        data = cfg["resellers"][name]
        used, quota = quota_usage(cfg, name)
        result.append({
            "username":  name,
            "quota":     quota,
            "quota_used": used,
            "users":     len(data.get("users", [])),
            "level":     reseller_level(cfg, name),
            "parent":    data.get("parent", cfg["admin"]["username"]),
            "sub_resellers": len(direct_children(cfg, name)),
            "created":   data.get("created", ""),
            "api_key":   data.get("api_key", ""),
            "expires":   data.get("expires", ""),
            "suspended": data.get("suspended", False),
            "expired":   is_expired(data.get("expires", "")) if data.get("expires") else False
        })
    return jsonify(result)

@app.route("/api/resellers", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def create_reseller():
    """Item 5/6: admin cria revendedores nível 2 livremente. Um
    revendedor nível 2 pode criar sub-revendedores nível 3 (dentro da
    própria cota). Nível 3 nunca pode criar mais revendedores."""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    quota    = int(data.get("quota", 10))
    expires  = data.get("expires", "").strip()

    if not username or not password:
        return jsonify({"error": "username e password obrigatórios"}), 400

    cfg = load_config()
    s = request.ns_session

    if s["role"] == "reseller":
        my_level = reseller_level(cfg, s["user"])
        if my_level != 2:
            return jsonify({"error": "Revendedores de nível 3 não podem criar sub-revendedores"}), 403
        used, my_quota = quota_usage(cfg, s["user"])
        if my_quota > 0 and used + quota > my_quota:
            return jsonify({"error": "A cota do sub-revendedor não pode ultrapassar sua cota disponível"}), 403
        parent = s["user"]
    else:
        parent = cfg["admin"]["username"]

    if not expires:
        expires = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d 23:59:59")
    elif len(expires) == 10:  # só a data (YYYY-MM-DD) veio do <input type=date>
        expires = f"{expires} 23:59:59"

    if username in cfg.get("resellers", {}):
        return jsonify({"error": "Revendedor já existe"}), 409

    cfg.setdefault("resellers", {})[username] = {
        "password":  hashlib.sha256(password.encode()).hexdigest(),
        "quota":     quota,
        "users":     [],
        "parent":    parent,
        "created":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "expires":   expires,
        "suspended": False,
        "api_key":   secrets.token_hex(16)
    }
    bump_api_keys_version(cfg)
    save_config(cfg)
    return jsonify({"ok": True, "username": username, "quota": quota, "expires": expires}), 201

def _reseller_edit_allowed(cfg, s, username):
    if s["role"] == "admin":
        return username in cfg.get("resellers", {})
    return username in direct_children(cfg, s["user"])

@app.route("/api/resellers/<username>", methods=["DELETE"])
@auth_required(roles=["admin", "reseller"])
def delete_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404

    # Exclusão em cascata: remove sub-revendedores e todos os usuários
    # (deles e do próprio) do sistema, para não deixar órfãos.
    to_delete = [username] + all_descendant_resellers(cfg, username)
    for name in to_delete:
        for login in cfg["resellers"].get(name, {}).get("users", []):
            run_cmd(f"bash /etc/painel/deluser.sh {login} --auto")
        cfg["resellers"].pop(name, None)

    bump_api_keys_version(cfg)
    save_config(cfg)
    return jsonify({"ok": True, "removed_resellers": to_delete})

def block_reseller_client(login):
    """Bloqueia um usuário (mesma trilha do limiter) e remove do Xray."""
    users = read_users()
    u = next((x for x in users if x["login"] == login), None)
    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
    with open(BLOCKED, "a") as f:
        f.write(f"{login}|{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}|Revendedor suspenso\n")
    if u and u["uuid"]:
        run_cmd(f"""
            bash -c '
            source /etc/painel/xray_lib.sh
            xray_remove_client_safe "{login}"
            systemctl restart xray >/dev/null 2>&1
            '
        """)

def unblock_reseller_client(login):
    """Libera um usuário bloqueado por suspensão do revendedor."""
    _unblock_login(login)

@app.route("/api/resellers/<username>", methods=["PUT"])
@auth_required(roles=["admin", "reseller"])
def update_reseller(username):
    """Edição completa do revendedor: nome de exibição, senha, cota e validade."""
    data = request.get_json() or {}
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404

    r = cfg["resellers"][username]
    if "quota" in data:
        new_quota = int(data["quota"])
        if s["role"] == "reseller":
            used_parent, my_quota = quota_usage(cfg, s["user"])
            # cota do filho não pode extrapolar a cota disponível do pai
            other_children_used = used_parent - quota_usage(cfg, username)[0]
            if my_quota > 0 and other_children_used + new_quota > my_quota:
                return jsonify({"error": "Cota excede o limite disponível do seu painel"}), 403
        r["quota"] = new_quota
    if "expires" in data and data["expires"]:
        expires = data["expires"].strip()
        if len(expires) == 10:
            expires = f"{expires} 23:59:59"
        r["expires"] = expires
    if data.get("password"):
        r["password"] = hashlib.sha256(data["password"].encode()).hexdigest()

    save_config(cfg)
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/renovar", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def renovar_reseller(username):
    """Botão ♻️ da tela de Revendedores: soma +30 dias à validade do
    painel do revendedor (a partir de hoje ou do vencimento atual, o que
    for mais tarde) e, se ele estiver suspenso, já reativa em cascata
    (ele e todos os usuários/sub-revendedores dele) na mesma ação —
    mesma lógica do botão "Reativar", só que já embutindo a renovação."""
    data = request.get_json(silent=True) or {}
    dias = int(data.get("dias", 30))
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404

    r = cfg["resellers"][username]
    atual = _parse_dt(r.get("expires", ""))
    base = atual if (atual and atual > datetime.datetime.now()) else datetime.datetime.now()
    nova_exp = (base + datetime.timedelta(days=dias)).strftime("%Y-%m-%d 23:59:59")
    r["expires"] = nova_exp

    estava_suspenso = bool(r.get("suspended"))
    if estava_suspenso:
        _cascade_suspend(cfg, username, False)

    save_config(cfg)
    system_log_write(f"RENOVAÇÃO manual — revendedor {username} +{dias} dia(s), nova validade {nova_exp}"
                      + (" | reativado (estava suspenso)" if estava_suspenso else ""))
    send_whatsapp_alert(username, f"✅ Seu painel ({username}) foi renovado até {nova_exp[:10]}!")
    return jsonify({"ok": True, "expires": nova_exp, "reativado": estava_suspenso})

@app.route("/api/resellers/<username>/quota", methods=["PUT"])
@auth_required(roles=["admin", "reseller"])
def update_quota(username):
    """Mantido por compatibilidade — usar PUT /api/resellers/<username> no lugar."""
    return update_reseller(username)

def _cascade_suspend(cfg, username, suspend):
    """Item 6: suspender/reativar um revendedor propaga em cascata para
    todos os sub-revendedores e usuários abaixo dele na árvore."""
    r = cfg["resellers"][username]
    r["suspended"] = suspend
    if not suspend and r.get("expires") and is_expired(r["expires"]):
        r["expires"] = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y-%m-%d 23:59:59")
    for login in r.get("users", []):
        (block_reseller_client if suspend else unblock_reseller_client)(login)
    for child in direct_children(cfg, username):
        _cascade_suspend(cfg, child, suspend)

@app.route("/api/resellers/<username>/suspend", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def suspend_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    _cascade_suspend(cfg, username, True)
    save_config(cfg)
    send_whatsapp_alert(username, f"⚠️ Seu painel ({username}) foi suspenso. Fale com quem te vendeu o acesso para reativar.")
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/activate", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def activate_reseller(username):
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    _cascade_suspend(cfg, username, False)
    save_config(cfg)
    send_whatsapp_alert(username, f"✅ Seu painel ({username}) foi reativado!")
    return jsonify({"ok": True})

@app.route("/api/resellers/<username>/impersonate", methods=["POST"])
@auth_required(roles=["admin", "reseller"])
def impersonate_reseller(username):
    """Item 14: entra no painel de um revendedor já autenticado. O admin
    pode entrar em qualquer revendedor; um revendedor nível 2 pode
    entrar apenas nos seus sub-revendedores (nível 3) diretos."""
    cfg = load_config()
    s = request.ns_session
    if not _reseller_edit_allowed(cfg, s, username):
        return jsonify({"error": "não encontrado"}), 404
    r = cfg["resellers"][username]
    if r.get("suspended"):
        return jsonify({"error": "Este painel está suspenso"}), 403
    token = create_session(username, "reseller")
    return jsonify({"token": token, "role": "reseller", "username": username})

def reseller_expiry_scheduler_loop():
    """Roda em background — suspende automaticamente revendedores vencidos
    (e todos os clientes deles) assim que a validade expira."""
    while True:
        try:
            cfg = load_config()
            changed = False
            for name, r in cfg.get("resellers", {}).items():
                if r.get("suspended"):
                    continue
                expires = r.get("expires", "")
                if expires and is_expired(expires):
                    _cascade_suspend(cfg, name, True)
                    changed = True
                    device_log_write(f"REVENDEDOR SUSPENSO (validade vencida, cascata): {name}")
                    send_whatsapp_alert(name, f"⚠️ Seu painel ({name}) venceu e foi suspenso automaticamente. Renove para reativar.")
            if changed:
                save_config(cfg)
        except Exception as e:
            device_log_write(f"RESELLER SCHEDULER erro: {e}")
        time.sleep(300)

def expired_user_kick_scheduler_loop():
    """Roda em background SEMPRE, independente do Limiter estar ligado ou
    desligado — é o sistema PRIMORDIAL de bloqueio por expiração, não
    depende de nenhum toggle do painel nem do limit.sh.

    Cobre dois casos:
    (1) usuário vence e JÁ ESTAVA com sessão SSH/Xray aberta -> derruba
        a sessão agora;
    (2) usuário vence (esteja conectado ou não) e ainda não está
        registrado em blocked.db -> bloqueia e TRAVA a conta Linux
        preventivamente, pra nenhuma conexão nova (SSH ou Xray, de
        nenhum dispositivo) conseguir entrar depois.

    BUGFIX CRÍTICO (2ª rodada): esse loop já existia e já rodava sempre,
    mas tinha os mesmos dois furos do antigo Bloco 4 do limit.sh:
      a) só agia sobre quem estava "online" no instante do ciclo — um
         usuário vencido que nunca tinha se conectado, ou que reconectava
         logo depois de ser derrubado, passava batido até o próximo
         ciclo de 20s, repetidamente, de quantos dispositivos quisesse;
      b) derrubava a sessão e tirava do Xray, mas NUNCA travava a conta
         Linux (passwd -l) — então SSH continuava aceitando login normal
         pra qualquer usuário vencido, bastando reconectar.
    Agora todo usuário vencido é bloqueado (blocked.db) E travado
    (passwd -l) assim que detectado, esteja com sessão aberta ou não —
    e só volta a aceitar login quando o admin desbloquear/renovar
    (que já fazem "passwd -u" em _unblock_login)."""
    while True:
        try:
            users = read_users()
            expired = {u["login"]: u for u in users if is_expired(u["expira"])}
            if expired:
                already_blocked = set()
                if os.path.exists(BLOCKED):
                    with open(BLOCKED) as f:
                        for line in f:
                            parts = line.strip().split("|")
                            if parts and parts[0]:
                                already_blocked.add(parts[0])

                online = set(get_online_users())

                for login, user in expired.items():
                    is_online = login in online
                    is_new_block = login not in already_blocked

                    # Nada a fazer: já está bloqueado E não está online
                    # (não precisa reprocessar a cada 20s à toa).
                    if not is_online and not is_new_block:
                        continue

                    if is_online:
                        device_log_write(
                            f"EXPIRE WATCHDOG KICK | user={login}({user['uuid']}) | exp={user['expira']} "
                            f"| sessão aberta derrubada agora"
                        )
                    else:
                        device_log_write(
                            f"EXPIRE WATCHDOG BLOQUEIO PREVENTIVO | user={login}({user['uuid']}) | exp={user['expira']} "
                            f"| sem sessão ativa agora, travando pra impedir reconexão"
                        )

                    run_cmd(f"sed -i '/^{login}|/d' {BLOCKED}")
                    with open(BLOCKED, "a") as f:
                        f.write(
                            f"{login}|{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}|"
                            f"Usuário expirado ({user['expira']}) — bloqueado pelo watchdog\n"
                        )
                    xray_kick_live(login)
                    run_cmd(f"""
                        bash -c '
                        pkill -KILL -u "{login}" 2>/dev/null
                        source /etc/painel/xray_lib.sh
                        xray_remove_client_safe "{login}"
                        passwd -l "{login}" 2>/dev/null
                        '
                    """)
        except Exception as e:
            device_log_write(f"EXPIRE WATCHDOG erro: {e}")
        # 20s: rápido o bastante pra não deixar a sessão pendurada por
        # muito tempo (ou a conta destravada) nem por muito tempo entre
        # o vencimento e o bloqueio preventivo, mas leve o bastante pra
        # não pesar no servidor.
        time.sleep(20)

# ══════════════════════════════════════════════════════════════════
#  BOT TELEGRAM
# ══════════════════════════════════════════════════════════════════

BOT_CFG = "/etc/painel/bot_config.json"

def load_bot_config():
    if not os.path.exists(BOT_CFG):
        return {
            "enabled": False,
            "token": "",
            "admin_chat_id": "",
            "mp_token": "",
            "planos": [
                {"dias": 30,  "limite": 1, "preco": 15.00, "nome": "Mensal 1 Acesso"},
                {"dias": 30,  "limite": 2, "preco": 25.00, "nome": "Mensal 2 Acessos"},
                {"dias": 7,   "limite": 1, "preco": 5.00,  "nome": "Semanal"},
            ]
        }
    with open(BOT_CFG) as f:
        return json.load(f)

def save_bot_config(cfg):
    _atomic_write_json(BOT_CFG, cfg, indent=2)

@app.route("/api/bot/config", methods=["GET"])
@auth_required(roles=["admin"])
def bot_get_config():
    return jsonify(load_bot_config())

@app.route("/api/bot/config", methods=["POST"])
@auth_required(roles=["admin"])
def bot_save_config():
    data = request.get_json() or {}
    cfg = load_bot_config()
    cfg.update(data)
    save_bot_config(cfg)
    # Reinicia o bot se estiver rodando
    run_cmd("pkill -f bot_telegram.py; sleep 1")
    if cfg.get("enabled") and cfg.get("token"):
        run_cmd("nohup python3 /etc/painel/bot_telegram.py > /var/log/netsimon_bot.log 2>&1 &")
    return jsonify({"ok": True})

@app.route("/api/bot/status", methods=["GET"])
@auth_required(roles=["admin"])
def bot_status():
    out, _ = run_cmd("pgrep -f bot_telegram.py")
    return jsonify({"running": bool(out)})

@app.route("/api/bot/toggle", methods=["POST"])
@auth_required(roles=["admin"])
def bot_toggle():
    out, _ = run_cmd("pgrep -f bot_telegram.py")
    if out:
        run_cmd("pkill -f bot_telegram.py")
        return jsonify({"running": False})
    else:
        cfg = load_bot_config()
        if not cfg.get("token"):
            return jsonify({"error": "Token não configurado"}), 400
        run_cmd("nohup python3 /etc/painel/bot_telegram.py > /var/log/netsimon_bot.log 2>&1 &")
        return jsonify({"running": True})

# ══════════════════════════════════════════════════════════════════
#  WHATSAPP — notificações de vencimento por painel (item 16b)
#  Cada painel (admin ou revendedor) tem sua própria sessão do
#  WhatsApp, pareada por QR Code (multi-dispositivo), sua própria
#  mensagem editável e sua chave PIX. O pareamento e envio de fato
#  são feitos pelo microserviço Node.js "whatsapp_bot.js" (Baileys),
#  que este backend só chama por HTTP local.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_CFG   = "/etc/painel/whatsapp_config.json"
WHATSAPP_SENT  = "/etc/painel/whatsapp_sent.json"   # dedupe de envios/dia
WHATSAPP_NODE  = "http://127.0.0.1:5055"            # microserviço Baileys local

DEFAULT_WA_TEMPLATE = (
    "Olá {nome}! 👋\n\n"
    "Seu acesso *{login}* vence em {dias_txt}.\n"
    "📅 Vencimento: {vencimento}\n\n"
    "Para renovar, é só fazer o PIX para a chave abaixo e me enviar o comprovante:\n"
    "🔑 Chave PIX: {pix}\n\n"
    "Qualquer dúvida, estou por aqui!"
)

# Item: bot de autoatendimento (WhatsApp responde sozinho a comandos simples)
DEFAULT_BOT_MENU = (
    "Olá! 👋 Eu sou o assistente automático.\n\n"
    "Digite uma das opções abaixo:\n"
    "🆓 *teste* — gerar um acesso de teste grátis\n"
    "📅 *vencimento* — consultar quando seu acesso vence\n"
    "💳 *renovar* — ver a chave PIX para renovação"
)
DEFAULT_BOT_TEST_MSG = (
    "✅ Aqui está seu acesso de teste!\n\n"
    "👤 Usuário: {login}\n"
    "🔒 Senha: {senha}\n"
    "⏱️ Válido por: {minutos} minutos\n"
    "🔑 Chave: {uuid}\n\n"
    "Aproveite! Se quiser continuar depois do teste, digite *renovar*."
)
DEFAULT_BOT_STATUS_FOUND = (
    "📅 Seu acesso *{login}* vence em {dias_txt} ({vencimento})."
)
DEFAULT_BOT_STATUS_NOTFOUND = (
    "Não encontrei nenhum acesso vinculado a este número. Digite *teste* pra gerar um acesso grátis."
)
DEFAULT_BOT_RENEW_MSG = (
    "💳 Para renovar, faça o PIX pra chave abaixo e me envie o comprovante:\n"
    "🔑 Chave PIX: {pix}\n\n"
    "Qualquer dúvida, é só chamar!"
)
DEFAULT_BOT_QUOTA_FULL = (
    "No momento não consigo gerar novos testes automáticos — fala com o suporte que já te ajudamos por aqui. 🙏"
)
DEFAULT_BOT_COOLDOWN_MSG = (
    "Você já pegou um teste recentemente. Tenta de novo mais tarde, ou digite *renovar* pra virar cliente. 😉"
)

# Item: ampliação do bot — envio de APK/link, venda de plano mensal com
# confirmação automática por comprovante (imagem), pedido de print da
# tela inicial e encaminhamento pra atendimento humano.
DEFAULT_BOT_APK_MSG = (
    "📲 Aqui estão os links para baixar o aplicativo:\n\n"
    "🤖 Android: {apk_android}\n"
    "🍏 iPhone: {apk_iphone}\n\n"
    "Qualquer dúvida na instalação, é só chamar!"
)
DEFAULT_BOT_PLAN_MSG = (
    "📦 Nosso plano:\n"
    "⏱️ {dias} dias de acesso\n"
    "💰 R$ {preco}\n\n"
    "💳 Faça o PIX pra chave abaixo e me envie o *comprovante* (foto/print do pagamento) "
    "que eu libero seu acesso automaticamente:\n"
    "🔑 Chave PIX: {pix}"
)
DEFAULT_BOT_PLAN_WAITING_MSG = (
    "Ainda estou aguardando o *comprovante* do PIX (a foto/print do pagamento). "
    "Assim que enviar, libero seu acesso automaticamente. 📸"
)
DEFAULT_BOT_PAYMENT_RECEIVED_MSG = (
    "✅ Pagamento confirmado! Seu acesso está liberado:\n\n"
    "👤 Usuário: {login}\n"
    "🔒 Senha: {senha}\n"
    "🔑 UUID: {uuid}\n"
    "📅 Válido por {dias} dias (vence em {vencimento})\n\n"
    "Qualquer dúvida, estou por aqui. Obrigado pela confiança! 🙏"
)
DEFAULT_BOT_PRINT_REQUEST_MSG = (
    "Pra eu te ajudar melhor, me manda um *print da tela inicial do aplicativo*, por favor. 📱📸"
)
DEFAULT_BOT_PRINT_WAITING_MSG = (
    "Só preciso do *print* (a imagem) da tela inicial do app pra seguir com o atendimento. 📸"
)
DEFAULT_BOT_PRINT_RECEIVED_MSG = (
    "Recebi seu print, obrigado! Já vou encaminhar pra um atendente te ajudar. 🙋"
)
DEFAULT_BOT_HANDOFF_MSG = (
    "Não consegui entender automaticamente. 🙋 Já estou chamando um atendente humano pra te ajudar, só um instante!"
)
DEFAULT_BOT_SUPPORT_HANDOFF_MSG = (
    "Entendi! 🙋 Já vou chamar um atendente humano pra te ajudar, só um instante. Se puder, me manda "
    "também um *print da tela inicial do aplicativo* enquanto isso — não é obrigatório, mas ajuda a "
    "agilizar bastante o atendimento. 📱📸"
)
DEFAULT_BOT_PRINT_MAX_ATTEMPTS_MSG = (
    "Sem problemas! Já vou chamar um atendente humano pra te ajudar por aqui mesmo, sem precisar do print. 🙋"
)
DEFAULT_BOT_RESET_MSG = "Atendimento reiniciado! 🔄"

DEFAULT_BOT_ADMIN_NOTIFY_PAYMENT = (
    "💰 Novo pagamento confirmado automaticamente pelo bot!\n"
    "📱 Cliente: {phone}\n"
    "👤 Login: {login}\n"
    "📅 {dias} dias"
)
DEFAULT_BOT_ADMIN_NOTIFY_HANDOFF = (
    "🙋 Atendimento humano solicitado!\n"
    "📱 Cliente: {phone}\n"
    "💬 Última mensagem: \"{text}\"\n\n"
    "Acesse o WhatsApp e responda diretamente. O bot fica em silêncio com esse número até você "
    "reativar em WhatsApp › Atendimentos aguardando atendente."
)
DEFAULT_BOT_REENGAGE_MSG = (
    "Oi! 👋 Faz {dias} dias que a gente não se fala por aqui.\n\n"
    "Ainda usa internet? Se quiser voltar, digite *teste* pra pegar um acesso grátis, ou *mensal* pra já contratar. 😉"
)
DEFAULT_BOT_ASK_USERNAME_MSG = (
    "Pra eu consultar certinho, me informa o nome EXATO do usuário que você recebeu ao contratar "
    "(sem espaços, é só uma palavra). 🔎"
)
DEFAULT_BOT_ASK_NAME_FOR_ACCESS_MSG = (
    "Recebi seu comprovante! ✅ Só preciso que me informe um nome (ou apelido, sem espaços) "
    "pra eu já criar o seu acesso com ele. 😉"
)
DEFAULT_BOT_INVALID_PROOF_MSG = (
    "Não consegui confirmar esse comprovante automaticamente. 🧐 Manda uma foto NÍTIDA e completa do "
    "comprovante do PIX (com o valor e a palavra \"comprovante\" ou \"PIX\" visíveis), por favor."
)

def _owner_key(s):
    """Identificador do painel dono da sessão do WhatsApp: 'admin' ou o
    username do revendedor."""
    return "admin" if s["role"] == "admin" else s["user"]

def load_whatsapp_config():
    if not os.path.exists(WHATSAPP_CFG):
        return {}
    try:
        with open(WHATSAPP_CFG) as f:
            return json.load(f)
    except Exception:
        return {}

def save_whatsapp_config(cfg):
    _atomic_write_json(WHATSAPP_CFG, cfg, indent=2)

def get_owner_wa_config(owner):
    all_cfg = load_whatsapp_config()
    default = {
        "enabled": False,
        "message_template": DEFAULT_WA_TEMPLATE,
        "pix_key": "",
        "days_before": 1,
        # Item: bot de autoatendimento via WhatsApp
        "bot_enabled": False,
        "bot_test_minutes": 60,
        "bot_cooldown_hours": 24,
        "bot_menu_message": DEFAULT_BOT_MENU,
        "bot_test_message": DEFAULT_BOT_TEST_MSG,
        "bot_status_found": DEFAULT_BOT_STATUS_FOUND,
        "bot_status_not_found": DEFAULT_BOT_STATUS_NOTFOUND,
        "bot_renew_message": DEFAULT_BOT_RENEW_MSG,
        "bot_quota_full_message": DEFAULT_BOT_QUOTA_FULL,
        "bot_cooldown_message": DEFAULT_BOT_COOLDOWN_MSG,
        # Item: ampliação do bot — apk/link, plano mensal + comprovante,
        # print da tela inicial, encaminhamento pra humano
        "bot_apk_message": DEFAULT_BOT_APK_MSG,
        "bot_plan_days": 30,
        "bot_plan_price": "",
        "bot_plan_message": DEFAULT_BOT_PLAN_MSG,
        "bot_plan_waiting_message": DEFAULT_BOT_PLAN_WAITING_MSG,
        "bot_payment_received_message": DEFAULT_BOT_PAYMENT_RECEIVED_MSG,
        "bot_print_request_message": DEFAULT_BOT_PRINT_REQUEST_MSG,
        "bot_print_waiting_message": DEFAULT_BOT_PRINT_WAITING_MSG,
        "bot_print_received_message": DEFAULT_BOT_PRINT_RECEIVED_MSG,
        "bot_print_max_attempts_message": DEFAULT_BOT_PRINT_MAX_ATTEMPTS_MSG,
        "bot_handoff_message": DEFAULT_BOT_HANDOFF_MSG,
        "bot_support_handoff_message": DEFAULT_BOT_SUPPORT_HANDOFF_MSG,
        "bot_reset_message": DEFAULT_BOT_RESET_MSG,
        "bot_admin_notify_payment": DEFAULT_BOT_ADMIN_NOTIFY_PAYMENT,
        "bot_admin_notify_handoff": DEFAULT_BOT_ADMIN_NOTIFY_HANDOFF,
        # Item: reengajamento de contatos inativos (rastreia quem não fala
        # com o bot há muito tempo e manda uma msg pré-definida, com
        # intervalo de reenvio e pausa entre os envios do lote)
        "bot_reengage_enabled": False,
        "bot_reengage_inactive_days": 60,
        "bot_reengage_resend_interval_days": 30,
        "bot_reengage_max_attempts": 3,
        "bot_reengage_send_delay_seconds": 30,
        "bot_reengage_message": DEFAULT_BOT_REENGAGE_MSG,
        # Item: consulta de vencimento por nome exato + criação de acesso
        # já com o nome do contato (ou perguntando, se não der pra deduzir)
        "bot_ask_username_message": DEFAULT_BOT_ASK_USERNAME_MSG,
        "bot_ask_name_for_access_message": DEFAULT_BOT_ASK_NAME_FOR_ACCESS_MSG,
        "bot_invalid_proof_message": DEFAULT_BOT_INVALID_PROOF_MSG,
        # Item: avisos de eventos do painel/servidor (pro próprio dono do painel)
        "alerts_enabled": False,
        "alert_phone": "",
    }
    default.update(all_cfg.get(owner, {}))
    return default

def send_whatsapp_alert(owner, message):
    """Manda um aviso de evento (painel suspenso, servidor com problema,
    cota no limite, etc.) pro número de alerta cadastrado pelo DONO
    daquele painel — não confundir com a mensagem enviada ao cliente."""
    try:
        wa = get_owner_wa_config(owner)
        if wa.get("alerts_enabled") and wa.get("alert_phone"):
            _wa_send(owner, wa["alert_phone"], message)
    except Exception as e:
        device_log_write(f"Falha ao enviar alerta WhatsApp pra {owner}: {e}")

@app.route("/api/whatsapp/config", methods=["GET"])
@auth_required()
def whatsapp_get_config():
    owner = _owner_key(request.ns_session)
    return jsonify(get_owner_wa_config(owner))

@app.route("/api/whatsapp/config", methods=["POST"])
@auth_required()
def whatsapp_save_config():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    all_cfg = load_whatsapp_config()
    entry = all_cfg.setdefault(owner, {})
    campos_permitidos = (
        "enabled", "message_template", "pix_key", "days_before",
        "bot_enabled", "bot_test_minutes", "bot_cooldown_hours",
        "bot_menu_message", "bot_test_message",
        "bot_status_found", "bot_status_not_found",
        "bot_renew_message", "bot_quota_full_message", "bot_cooldown_message",
        "bot_apk_message", "bot_plan_days", "bot_plan_price",
        "bot_plan_message", "bot_plan_waiting_message", "bot_payment_received_message",
        "bot_print_request_message", "bot_print_waiting_message", "bot_print_received_message",
        "bot_print_max_attempts_message", "bot_reset_message",
        "bot_handoff_message", "bot_support_handoff_message", "bot_admin_notify_payment", "bot_admin_notify_handoff",
        "bot_reengage_enabled", "bot_reengage_inactive_days", "bot_reengage_resend_interval_days",
        "bot_reengage_max_attempts", "bot_reengage_send_delay_seconds", "bot_reengage_message",
        "bot_ask_username_message", "bot_ask_name_for_access_message", "bot_invalid_proof_message",
        "alerts_enabled", "alert_phone",
    )
    for k in campos_permitidos:
        if k in data:
            entry[k] = data[k]
    save_whatsapp_config(all_cfg)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/qr", methods=["GET"])
@auth_required()
def whatsapp_get_qr():
    """Proxy para o microserviço Node — devolve o QR atual (base64) para
    parear este painel a um número de WhatsApp via multi-dispositivo."""
    owner = _owner_key(request.ns_session)
    try:
        r = requests.get(f"{WHATSAPP_NODE}/qr/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp (whatsapp_bot.js) não está rodando"}), 503

@app.route("/api/whatsapp/status", methods=["GET"])
@auth_required()
def whatsapp_get_status():
    owner = _owner_key(request.ns_session)
    try:
        r = requests.get(f"{WHATSAPP_NODE}/status/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"connected": False, "error": "Serviço do WhatsApp offline"}), 200

@app.route("/api/whatsapp/logout", methods=["POST"])
@auth_required()
def whatsapp_logout():
    owner = _owner_key(request.ns_session)
    try:
        r = requests.post(f"{WHATSAPP_NODE}/logout/{owner}", timeout=5)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/whatsapp/pair", methods=["POST"])
@auth_required()
def whatsapp_pair():
    """Força um novo ciclo de pareamento (usado pelo botão 'Parear /
    Gerar novo QR Code' quando a tentativa automática expirou)."""
    # Gate de licença: automação de WhatsApp é recurso do plano Pro
    # pra cima — ver PLANO_RECURSOS. Só barra aqui, no "ligar" — quem
    # já tinha pareado antes e a licença caducou continua conseguindo
    # ver o histórico, só não consegue iniciar um pareamento novo.
    if not license_allows("bot"):
        return jsonify({"error": "Automação de WhatsApp não incluída no seu plano de licença."}), 402
    owner = _owner_key(request.ns_session)
    try:
        r = requests.post(f"{WHATSAPP_NODE}/pair/{owner}", timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/whatsapp/test", methods=["POST"])
@auth_required()
def whatsapp_send_test():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not phone:
        return jsonify({"error": "Telefone inválido"}), 400
    cfg = get_owner_wa_config(owner)
    msg = cfg["message_template"].format(
        nome=data.get("nome", "Cliente"), login=data.get("login", "teste"),
        dias_txt="2 dias", vencimento="--/--/----", pix=cfg.get("pix_key", "")
    )
    try:
        r = requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": msg}, timeout=10)
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error": "Serviço do WhatsApp offline"}), 503

@app.route("/api/users/<username>/whatsapp", methods=["GET"])
@auth_required()
def get_user_whatsapp(username):
    cfg = load_config()
    return jsonify({"phone": cfg.get("user_phones", {}).get(username, "")})

@app.route("/api/users/<username>/whatsapp", methods=["PUT"])
@auth_required()
def save_user_whatsapp(username):
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    cfg = load_config()
    cfg.setdefault("user_phones", {})[username] = phone
    save_config(cfg)
    if phone:
        # Item: inicia a contagem de inatividade (reengajamento) a partir
        # do momento em que o telefone foi vinculado manualmente.
        _touch_wa_contact(_owner_key(request.ns_session), phone)
    return jsonify({"ok": True, "phone": phone})

# ══════════════════════════════════════════════════════════════════
#  BOT DE AUTOATENDIMENTO — recebe mensagens do microserviço Node
#  (whatsapp_bot.js) e decide a resposta automática. Só aceita
#  chamadas locais (o Node roda no mesmo servidor, nunca é exposto).
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  ASSISTENTE DE IA (Gemini) — fallback inteligente pro bot de
#  WhatsApp quando nenhum comando por palavra-chave é reconhecido.
#  Configuração GLOBAL (um único painel — o admin — controla e paga
#  pela chave de API; vale pro atendimento de todos os revendedores).
#  As etapas críticas (pagamento, criação/renovação de acesso) NUNCA
#  passam pela IA — continuam 100% controladas por código, sempre.
# ══════════════════════════════════════════════════════════════════

AI_TRANSCRIPT_LOG = "/etc/painel/ai_conversations.jsonl"
AI_TRANSCRIPT_MAX_BYTES = 20 * 1024 * 1024  # 20MB — rotaciona pra não crescer pra sempre

# Item 3: config de IA deixou de ser global (só o admin configurava e
# pagava, valendo pra todos) — agora cada painel (admin OU revendedor,
# qualquer nível) tem sua própria config isolada: própria chave de API,
# próprio modelo, próprio prompt. Mesmo padrão de arquivo já usado pelo
# WhatsApp (ver WHATSAPP_CFG/get_owner_wa_config) — um único JSON,
# indexado por owner ("admin" ou o username do revendedor).
AI_ASSISTANT_CFG = "/etc/painel/ai_assistant_config.json"

def load_ai_assistant_all():
    if not os.path.exists(AI_ASSISTANT_CFG):
        # Migração: antes a config vivia em painel_config.json (global,
        # um valor só). Se existir algo lá e o arquivo novo ainda não
        # existe, herda pro admin — evita que quem já tinha IA
        # configurada precise recadastrar a chave depois do upgrade.
        cfg = load_config()
        legado = cfg.get("ai_assistant")
        return {"admin": legado} if legado else {}
    try:
        with open(AI_ASSISTANT_CFG) as f:
            return json.load(f)
    except Exception:
        return {}

def save_ai_assistant_all(all_cfg):
    _atomic_write_json(AI_ASSISTANT_CFG, all_cfg, indent=2)

def save_ai_assistant_config(owner, ai_cfg):
    all_cfg = load_ai_assistant_all()
    all_cfg[owner] = ai_cfg
    save_ai_assistant_all(all_cfg)

DEFAULT_AI_SYSTEM_PROMPT = (
    "Você é o atendimento humano e empático de um serviço de VPN/acesso à internet pelo WhatsApp. "
    "Seu papel é acolher, entender o que o cliente precisa e conversar com naturalidade — não é o seu "
    "trabalho executar ações do sistema (isso é feito por um mecanismo automático separado, ver regras "
    "abaixo). Responda curto, direto e cordial, como um atendente de verdade escreveria no WhatsApp. "
    "Não se apresente como robô ou IA a menos que perguntem diretamente. Não use emojis em excesso."
)

def get_ai_assistant_config(owner="admin"):
    all_cfg = load_ai_assistant_all()
    default = {
        "enabled": False,
        "provider": "gemini",
        "model": "gemini-3-flash-preview",
        "api_key": "",
        "system_prompt": DEFAULT_AI_SYSTEM_PROMPT,
        "log_conversations": True,
        "max_history_turns": 8,
    }
    default.update(all_cfg.get(owner, {}))
    return default

# ── "Treinar a IA" — conhecimento/instruções extras ensinadas pelo
# admin, que passam a valer pra TODAS as frentes de IA do painel (bot
# do WhatsApp, diagnóstico técnico, relatório de situação e monitor em
# tempo real) — não é um chat solto, é conhecimento persistente que se
# soma ao prompt de cada uma dessas frentes.
#
# Fica salvo em /etc/painel/ai_training.json — um arquivo solto DENTRO
# de /etc/painel, então já entra automaticamente no backup completo
# existente (build_full_backup_path() empacota todo item de /etc/painel
# sem precisar de lista extra) e volta sozinho num restore/reinstalação,
# sem precisar re-treinar a IA do zero.
AI_TRAINING_F = os.path.join(BASE, "ai_training.json")

def _ai_load_training():
    if not os.path.exists(AI_TRAINING_F):
        return []
    try:
        with open(AI_TRAINING_F) as f:
            return json.load(f)
    except Exception:
        return []

def _ai_save_training(items):
    _atomic_write_json(AI_TRAINING_F, items, indent=2)

def _ai_training_as_prompt_block():
    """Monta o bloco de texto a ser anexado no FIM de qualquer prompt de
    sistema de IA do painel. Fica de propósito depois das regras fixas
    de segurança/roteamento — o comentário na função que monta cada
    prompt já deixa claro que o treinamento nunca pode contradizer
    essas regras."""
    itens = [it.get("texto", "").strip() for it in _ai_load_training() if (it.get("texto") or "").strip()]
    if not itens:
        return ""
    linhas = "\n".join(f"- {t}" for t in itens)
    return (
        "\n\nCONHECIMENTO E INSTRUÇÕES ADICIONAIS ensinadas pelo administrador do painel "
        "(aplicam-se a você sempre, mas NUNCA podem contradizer as regras fixas de segurança "
        "e roteamento definidas acima — se houver conflito, as regras fixas vencem):\n" + linhas
    )

def _ai_mask_key(key):
    key = key or ""
    if len(key) <= 6:
        return "•" * len(key)
    return "•" * (len(key) - 4) + key[-4:]

def _ai_system_prompt(ai_cfg, wa):
    """Monta o prompt final: a personalidade configurável pelo admin +
    as regras fixas de segurança e roteamento (preço/PIX reais, e o
    mapa exato de palavras-chave que o mecanismo automático reconhece —
    isso é o que faz o reconhecimento de intenção INDIRETA funcionar de
    verdade: a IA entende o que o cliente quer e orienta a mandar
    exatamente a palavra certa, em vez de tentar resolver ela mesma)."""
    base = (ai_cfg.get("system_prompt") or "").strip() or DEFAULT_AI_SYSTEM_PROMPT
    preco = wa.get("bot_plan_price") or "não informado — oriente o cliente a falar com um atendente pra saber o valor"
    pix = wa.get("pix_key") or "não configurada"
    regras = (
        f"\n\nInformações reais do negócio (nunca invente valores diferentes destes): "
        f"preço do plano mensal = {preco}; chave PIX para pagamento = {pix}."
        "\n\nCOMO FUNCIONA A DIVISÃO DE TRABALHO: existe um mecanismo automático (não é você) que "
        "reconhece palavras-chave exatas e executa a ação de verdade (cria teste, gera cobrança, renova "
        "acesso, etc.) — ele só é acionado quando o cliente manda a palavra-chave certa como próxima "
        "mensagem, sozinha ou no meio de uma frase. Você NUNCA executa essas ações, mesmo que o cliente "
        "insista, mande um comprovante de pagamento ou peça diretamente — você só reconhece a intenção "
        "(mesmo quando ela vem de forma indireta/nas entrelinhas) e ORIENTA o cliente a mandar a palavra "
        "certa. Sempre que perceber uma dessas intenções, oriente-o a mandar exatamente uma destas "
        "palavras (pode ser dentro de uma frase natural, não precisa ser só a palavra sozinha):"
        "\n- Quer experimentar/conhecer o serviço antes de decidir → oriente a mandar \"teste\""
        "\n- Quer saber até quando o acesso dele vale / se está perto de vencer → oriente a mandar \"vencimento\""
        "\n- Quer o link/instalador do aplicativo (Android/iPhone) → oriente a mandar \"apk\" ou \"aplicativo\""
        "\n- Quer assinar/contratar um plano novo (cliente ainda não é assinante) → oriente a mandar \"mensal\""
        "\n- Já é cliente e quer renovar/pagar de novo (evitar expirar) → oriente a mandar \"renovar\""
        "\nExemplos de como reconhecer a intenção mesmo quando o cliente não usa a palavra exata: "
        "\"posso ver se funciona antes de pagar?\" = quer teste. \"até quando ainda tenho acesso?\" = "
        "quer saber vencimento. \"como faço pra usar no meu celular?\" = quer o apk. \"quero começar a "
        "usar\"/\"como assino?\" = quer contratar (mensal). \"já sou cliente, preciso pagar de novo\" = "
        "quer renovar."
        "\nApós orientar o cliente a mandar a palavra-chave, você pode continuar sendo acolhedor na "
        "mesma mensagem — não precisa ser seco, só não invente que já resolveu algo que não resolveu. "
        "Nunca invente prazos, políticas ou descontos que não foram informados aqui."
        "\n\nSUPORTE TÉCNICO — aqui você TEM espaço pra desenvolver a conversa de verdade antes de "
        "encaminhar pra um humano; não corte pra \"suporte\" na primeira reclamação. Quando o cliente disser "
        "que algo não funciona, não conecta ou deu erro, siga esta sequência, uma pergunta de cada vez "
        "(sem despejar tudo de uma vez):"
        "\n1. Pergunte especificamente o que está acontecendo (não conecta? conecta e cai? está lento? "
        "app não abre? mensagem de erro específica?) antes de sugerir qualquer coisa."
        "\n2. Peça um print da tela inicial do aplicativo, mostrando o status da conexão."
        "\n3. Peça pra ele testar conectar com o wifi desligado, usando só dados móveis (e vice-versa, se "
        "já usava dados móveis, pedir pra testar no wifi) — e contar o que aconteceu em cada teste. Isso "
        "ajuda a identificar se o problema é do app, da rede local ou do dispositivo."
        "\n4. Só depois de tentar entender o problema com essas perguntas (não precisa esgotar todas se o "
        "cliente já der uma resposta clara e completa), se ainda não resolver, pergunte diretamente se ele "
        "quer que você chame um atendente humano pra continuar o suporte. Não force nem repita a pergunta "
        "várias vezes — pergunte uma vez, com naturalidade."
        "\n5. Só quando o cliente confirmar que quer falar com um atendente (ou pedir isso diretamente, a "
        "qualquer momento da conversa, mesmo sem você ter perguntado) → oriente-o a mandar \"suporte\" pra "
        "acionar o encaminhamento automático."
        "\nEssa mesma lógica vale pra qualquer assunto que a conversa não esteja evoluindo bem: você pode, "
        "a qualquer momento, oferecer transferir pra um atendente humano se perceber que o cliente está "
        "frustrado, confuso, ou repetindo a mesma dúvida sem sair do lugar — sempre perguntando antes, "
        "nunca transferindo sem avisar."
    )
    return base + regras

def _call_gemini(ai_cfg, system_prompt, history, user_text, max_tokens=400, thinking_budget=None):
    """Chama a API da Gemini. Retorna (ok: bool, texto_ou_erro: str).

    max_tokens / thinking_budget: parâmetros opcionais só pra quem
    precisa de respostas mais longas que o padrão do bot do WhatsApp
    (ver diag_ask_ai). Sem eles, o comportamento de todo mundo que já
    chamava essa função continua idêntico.

    Item: "treinar a IA" — o conhecimento/instruções extras cadastrados
    pelo admin (ver _ai_training_as_prompt_block) são anexados aqui,
    num lugar SÓ, ao final de QUALQUER prompt de sistema que passe por
    essa função — assim toda frente de IA do painel (WhatsApp, diagnóstico,
    relatório de situação) aprende o mesmo treinamento automaticamente,
    sem precisar lembrar de colar isso em cada lugar que monta um prompt."""
    api_key = (ai_cfg.get("api_key") or "").strip()
    if not api_key:
        return False, "Chave de API da Gemini não configurada"
    model = (ai_cfg.get("model") or "gemini-3-flash-preview").strip()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    system_prompt = (system_prompt or "") + _ai_training_as_prompt_block()

    contents = []
    for turn in history or []:
        role = "model" if turn.get("role") == "model" else "user"
        txt = (turn.get("text") or "").strip()
        if txt:
            contents.append({"role": role, "parts": [{"text": txt}]})
    contents.append({"role": "user", "parts": [{"text": user_text}]})

    generation_config = {"temperature": 0.6, "maxOutputTokens": max_tokens}
    if thinking_budget is not None:
        # Item: BUG CORRIGIDO — modelos "gemini-3-flash-preview" (e os
        # 2.5 antes dele) têm "thinking" ligado por padrão, e o Google
        # conta os tokens do raciocínio interno DENTRO do mesmo
        # maxOutputTokens da resposta visível. Sem limitar isso, o
        # modelo podia gastar o orçamento inteiro só "pensando" e
        # devolver o texto cortado no meio (foi exatamente o que
        # aconteceu no diagnóstico da IA: a resposta parava no meio de
        # uma palavra, tipo "...o que está aconte", porque o raciocínio
        # consumiu os 400 tokens antes de terminar de escrever). Fix:
        # limitar o orçamento de "pensamento" e, junto com o
        # max_tokens maior passado por quem precisa (diag_ask_ai),
        # garantir que sempre sobre espaço de verdade pra resposta.
        generation_config["thinkingConfig"] = {"thinkingBudget": thinking_budget}

    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": generation_config,
    }
    try:
        r = requests.post(url, json=payload, timeout=40)
    except requests.exceptions.RequestException as e:
        return False, f"Falha de conexão com a Gemini: {e}"

    if r.status_code == 429:
        return False, "Cota gratuita da Gemini esgotada no momento (erro 429)"
    if r.status_code != 200:
        detail = r.text[:200] if r.text else ""
        return False, f"Erro Gemini (HTTP {r.status_code}): {detail}"

    try:
        data = r.json()
        candidates = data.get("candidates", [])
        if not candidates:
            block_reason = data.get("promptFeedback", {}).get("blockReason")
            return False, f"Gemini não retornou resposta{f' (bloqueio: {block_reason})' if block_reason else ''}"
        cand0 = candidates[0]
        parts = cand0.get("content", {}).get("parts", [])
        reply = "".join(p.get("text", "") for p in parts).strip()
        finish_reason = cand0.get("finishReason")
        if not reply:
            if finish_reason == "MAX_TOKENS":
                return False, ("A Gemini gastou todo o limite de tokens só pensando e não sobrou espaço "
                               "pra escrever a resposta. Tente de novo — se persistir, aumente o limite "
                               "de tokens da IA nas configurações.")
            return False, "Resposta vazia da Gemini"
        if finish_reason == "MAX_TOKENS":
            # Ainda veio algum texto, mas foi cortado no meio — melhor avisar
            # com clareza do que entregar uma resposta pela metade sem dizer nada.
            reply += "\n\n⚠️ (resposta cortada por limite de tokens — peça pra IA continuar, ou tente novamente)"
        return True, reply
    except Exception as e:
        return False, f"Resposta inesperada da Gemini: {e}"

def _log_ai_transcript(owner, phone, role, text):
    """Registra cada mensagem (cliente e bot) em JSONL — item pedido
    explicitamente: dar visibilidade total da conversa, servindo tanto
    pra auditoria quanto como dataset pra revisar/ajustar os prompts no
    futuro. Roda independente da IA estar respondendo ou não (também
    loga as respostas da máquina de estados por palavra-chave), desde
    que 'log_conversations' esteja ligado."""
    try:
        if os.path.getsize(AI_TRANSCRIPT_LOG) > AI_TRANSCRIPT_MAX_BYTES:
            os.replace(AI_TRANSCRIPT_LOG, AI_TRANSCRIPT_LOG + ".1")
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(AI_TRANSCRIPT_LOG), exist_ok=True)
        with open(AI_TRANSCRIPT_LOG, "a") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "owner": owner, "phone": phone, "role": role, "text": text[:2000],
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass

WHATSAPP_BOT_STATE = "/etc/painel/whatsapp_bot_state.json"

def _load_bot_state():
    """Estado por contato (chave 'owner|phone'). Cada entrada é um dict:
    {"last_test": <timestamp>, "step": "aguardando_comprovante"|"aguardando_print"|None,
     "human": bool, "human_since": <timestamp>}.
    Item: migra automaticamente o formato antigo (só guardava o timestamp
    do último teste, como número solto) pro formato novo em dict."""
    if not os.path.exists(WHATSAPP_BOT_STATE):
        return {}
    try:
        with open(WHATSAPP_BOT_STATE) as f:
            raw = json.load(f)
    except Exception:
        return {}
    migrated = {}
    for k, v in raw.items():
        migrated[k] = v if isinstance(v, dict) else {"last_test": v}
    return migrated

def _save_bot_state(data):
    _atomic_write_json(WHATSAPP_BOT_STATE, data)

WHATSAPP_MEDIA_LOG = "/etc/painel/whatsapp_media_log.json"

def _log_bot_media(owner, phone, kind, image_path, note=""):
    """Guarda um registro (comprovante/print recebido) pro admin poder
    conferir depois — não bloqueia o fluxo do bot se falhar."""
    try:
        log = []
        if os.path.exists(WHATSAPP_MEDIA_LOG):
            with open(WHATSAPP_MEDIA_LOG) as f:
                log = json.load(f)
        log.append({
            "owner": owner, "phone": phone, "kind": kind,
            "image_path": image_path, "note": note, "ts": time.time()
        })
        log = log[-500:]  # mantém só os últimos 500 registros
        with open(WHATSAPP_MEDIA_LOG, "w") as f:
            json.dump(log, f)
    except Exception as e:
        device_log_write(f"Falha ao registrar mídia do bot WhatsApp: {e}")

# Item: reengajamento de contatos inativos — guarda, por contato
# ("owner|phone"), quando ele foi visto pela última vez interagindo com
# o bot, e o histórico de mensagens de reengajamento já enviadas.
WHATSAPP_CONTACTS = "/etc/painel/whatsapp_contacts.json"

def _load_wa_contacts():
    if not os.path.exists(WHATSAPP_CONTACTS):
        return {}
    try:
        with open(WHATSAPP_CONTACTS) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_wa_contacts(data):
    _atomic_write_json(WHATSAPP_CONTACTS, data)

def _normalize_br_phone(raw):
    """Normaliza um telefone pro mesmo formato usado nas chaves de
    _load_wa_contacts (55 + DDD + número, só dígitos — igual ao JID do
    WhatsApp sem o "@s.whatsapp.net"). Contatos exportados do celular
    costumam vir sem o "+55" (ex: "(21) 96433-7899" ou "21964337899"),
    então completa o código do país quando reconhece um número BR sem
    ele (10 ou 11 dígitos = DDD + telefone fixo/celular).

    Item: BUG CORRIGIDO — alguns exports de agenda (ou reimportações em
    cima de um contato que já tinha o "55" salvo) duplicavam o código
    do país, virando algo como "555579981260383" (55 + 55 + DDD + 9
    dígitos = 15 dígitos) em vez do "5579981260383" certo (13 dígitos).
    Sem essa checagem, esse número quebrado passava direto — nunca
    batia com o número real do WhatsApp, então o contato nunca recebia
    campanha nem contava como confirmado, e cada reimportação criava
    esse "fantasma" de novo. Agora detecta o "55" duplicado (15 ou 14
    dígitos, esse último pro caso de telefone fixo de 8 dígitos) e
    remove o par extra antes de seguir a validação normal."""
    digits = re.sub(r"\D", "", raw or "")
    if not digits:
        return ""
    if digits.startswith("5555") and len(digits) in (14, 15):
        digits = "55" + digits[4:]
    if digits.startswith("55") and len(digits) in (12, 13):
        return digits
    if len(digits) in (10, 11):
        return "55" + digits
    return digits  # não reconhecido — devolve como veio (dígitos só)

def _normalize_name_for_match(name):
    """Normaliza um nome pra casar 'Alexander Revendedor' com
    'alexander revendedor' vindo de fontes diferentes (agenda exportada
    vs. captura de tela) — minúsculas, sem acento, espaços colapsados."""
    if not name:
        return ""
    n = unicodedata.normalize("NFKD", name)
    n = "".join(c for c in n if not unicodedata.combining(c))
    n = re.sub(r"\s+", " ", n).strip().lower()
    return n

def _parse_vcard(text):
    """Parser mínimo de vCard (2.1/3.0/4.0) — extrai nome (FN, ou N como
    fallback) e todos os TEL de cada contato. Não depende de biblioteca
    externa (vobject/vcard não estão nas dependências do projeto)."""
    contacts = []
    cur_name = None
    cur_phones = []

    def flush():
        if cur_name and cur_phones:
            for tel in cur_phones:
                contacts.append((cur_name, tel))

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        upper = line.upper()
        if upper.startswith("BEGIN:VCARD"):
            cur_name, cur_phones = None, []
            continue
        if upper.startswith("END:VCARD"):
            flush()
            cur_name, cur_phones = None, []
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field_upper = field.upper()
        if field_upper.startswith("FN"):
            cur_name = value.strip()
        elif field_upper.startswith("N") and not cur_name:
            # N;;;: Sobrenome;Nome;;; — monta um nome legível se FN não veio
            parts = [p for p in value.split(";") if p.strip()]
            if parts:
                cur_name = " ".join(reversed(parts)).strip()
        elif field_upper.startswith("TEL"):
            tel = _normalize_br_phone(value)
            if tel:
                cur_phones.append(tel)
    return contacts  # lista de (nome, telefone)

def _parse_contacts_csv(text):
    """Parser de CSV/TSV de contatos exportados — detecta a coluna de
    nome e de telefone por cabeçalho comum (name/nome/telefone/phone/
    numero/celular), com fallback pras duas primeiras colunas se não
    reconhecer os cabeçalhos."""
    contacts = []
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except Exception:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    rows = list(reader)
    if not rows:
        return contacts

    header = [h.strip().lower() for h in rows[0]]
    name_keys = {"name", "nome", "fullname", "nome completo", "contato"}
    phone_keys = {"phone", "telefone", "numero", "número", "celular", "tel", "whatsapp", "phone number"}
    name_idx = next((i for i, h in enumerate(header) if h in name_keys), None)
    phone_idx = next((i for i, h in enumerate(header) if h in phone_keys), None)

    data_rows = rows[1:] if (name_idx is not None or phone_idx is not None) else rows
    if name_idx is None:
        name_idx = 0
    if phone_idx is None:
        phone_idx = 1 if len(header) > 1 else 0

    for row in data_rows:
        if len(row) <= max(name_idx, phone_idx):
            continue
        name = (row[name_idx] or "").strip()
        phone = _normalize_br_phone(row[phone_idx])
        if name and phone:
            contacts.append((name, phone))
    return contacts

# ══════════════════════════════════════════════════════════════════
#  CONTATOS IGNORADOS PELA AUTOMAÇÃO — bloqueio determinístico, por
#  código, de números específicos (por painel/owner). Existe porque o
#  recurso "Treinar a IA" (ver _ai_training_as_prompt_block) NUNCA
#  serviu pra isso: é só texto livre anexado ao prompt da Gemini, e
#  nem _ai_system_prompt() nem _call_gemini() recebem o telefone/nome
#  do contato — a IA não tem como saber quem está falando com ela pra
#  obedecer uma instrução do tipo "ignore o contato X". Além disso, as
#  respostas por PALAVRA-CHAVE (teste, mensal, renovar, vencimento,
#  apk, suporte) rodam em código, antes de a IA ser sequer chamada —
#  um "ensinamento" nunca alcançaria esse caminho de qualquer forma.
#  Por isso o bloqueio de contato precisa ser código determinístico,
#  igual às outras etapas críticas do bot (ver comentário no topo da
#  seção do Assistente de IA), e é checado ANTES de qualquer lógica de
#  bot/IA em /api/whatsapp/inbound — o número ignorado não recebe
#  resposta nenhuma (nem automática, nem da IA), como se o bot nem
#  existisse pra ele.
# ══════════════════════════════════════════════════════════════════
WA_IGNORED_CONTACTS_F = os.path.join(BASE, "wa_ignored_contacts.json")

def _wa_load_ignored():
    if not os.path.exists(WA_IGNORED_CONTACTS_F):
        return {}
    try:
        with open(WA_IGNORED_CONTACTS_F) as f:
            return json.load(f)
    except Exception:
        return {}

def _wa_save_ignored(data):
    _atomic_write_json(WA_IGNORED_CONTACTS_F, data, indent=2)

def _wa_is_ignored(owner, phone):
    itens = _wa_load_ignored().get(owner, [])
    return any(it.get("phone") == phone for it in itens)

def _touch_wa_contact(owner, phone, name=""):
    """Marca 'visto agora' pra esse contato. Chamado sempre que o
    cliente manda mensagem pro bot, e também quando um telefone é
    vinculado manualmente a um login pelo painel (pra já começar a
    contar o prazo de inatividade a partir do cadastro). Quando o
    WhatsApp informa o nome do contato (pushName), guarda também —
    usado pelo filtro de campanhas (ex: contatos com "rev" no nome)."""
    try:
        contacts = _load_wa_contacts()
        key = f"{owner}|{phone}"
        entry = contacts.setdefault(key, {})
        entry["last_seen"] = time.time()
        if name:
            entry["name"] = name
        _save_wa_contacts(contacts)
    except Exception as e:
        device_log_write(f"Falha ao registrar contato WhatsApp ({owner}/{phone}): {e}")

def _sync_wa_contacts_history(owner, contacts_list):
    """Item: sincronização do histórico REAL de conversas do WhatsApp.
    Diferente do _touch_wa_contact (que só marca 'agora', quando o bot
    literalmente vê uma mensagem chegando ao vivo), isso aqui recebe do
    whatsapp_bot.js o histórico verdadeiro entregue pelo próprio WhatsApp
    na conexão (evento messaging-history.set do Baileys) — com a data/
    hora REAL da última mensagem de cada chat, mesmo de antes do bot
    existir. Usa o maior valor entre o que já tinha e o que veio agora,
    pra nunca "regredir" um contato que já teve uma interação ao vivo
    mais recente que a sincronizada."""
    try:
        contacts = _load_wa_contacts()
        updated = 0
        for item in contacts_list:
            phone = re.sub(r"\D", "", str(item.get("phone", "")))
            last_seen = item.get("last_seen")
            if not phone or not last_seen:
                continue
            try:
                last_seen = float(last_seen)
            except (TypeError, ValueError):
                continue
            key = f"{owner}|{phone}"
            entry = contacts.setdefault(key, {})
            entry["last_seen"] = max(entry.get("last_seen", 0) or 0, last_seen)
            name = (item.get("name") or "").strip()
            if name and not entry.get("name"):
                entry["name"] = name
            updated += 1
        _save_wa_contacts(contacts)
        return updated
    except Exception as e:
        device_log_write(f"Falha ao sincronizar histórico WhatsApp ({owner}): {e}")
        return 0

def _find_login_by_phone(cfg, phone, owner):
    phones = cfg.get("user_phones", {})
    scope = all_owned_logins(cfg, owner) if owner != "admin" else None
    for login, p in phones.items():
        if p == phone:
            if scope is None or login in scope:
                return login
    return None

def _wa_send(owner, phone, text):
    try:
        requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": text}, timeout=10)
    except Exception:
        pass

def _wa_send_media(owner, phone, text, media=None):
    """Envia uma mensagem (com ou sem anexo) e devolve o ID atribuído
    pelo WhatsApp — usado pelas campanhas pra depois casar os eventos
    de entrega/leitura (messages.update, reportado pelo Node) com o
    contato certo. Retorna (ok, msg_id_ou_erro)."""
    payload = {"owner": owner, "phone": phone, "message": text}
    if media and media.get("path"):
        payload["mediaType"] = media.get("type")
        payload["mediaPath"] = media.get("path")
        payload["mediaFilename"] = media.get("filename", "")
    try:
        r = requests.post(f"{WHATSAPP_NODE}/send", json=payload, timeout=30)
        body = r.json()
        if r.status_code == 200 and body.get("ok"):
            return True, body.get("id")
        return False, body.get("error", "falha desconhecida")
    except Exception as e:
        return False, str(e)

def _normalize_login_from_name(name):
    """Deriva um possível LOGIN a partir do nome salvo do contato no
    WhatsApp: usa só o primeiro "nome" (primeira palavra), remove
    acentos/caracteres especiais e deixa em minúsculas.
    Ex: "João Tim" -> "joao" | "joao1 tim" -> "joao1" | "Maria" -> "maria"."""
    if not name:
        return ""
    first = name.strip().split()[0] if name.strip() else ""
    first = unicodedata.normalize("NFKD", first).encode("ascii", "ignore").decode("ascii")
    first = re.sub(r"[^a-zA-Z0-9]", "", first).lower()
    return first

def _parse_contact_name(name):
    """Interpreta o nome salvo do contato pra descobrir se é um cliente
    VPN (sem data no nome — ex: "joao tim", "joao vivo") ou um cliente
    NETFLIX (tem uma data DD/MM depois do nome — ex: "joao 15/08" — o
    painel não gerencia esses, só reconhece pra não confundir na hora
    de sugerir um login). Devolve o login sugerido, o tipo, e (se for
    Netflix) a próxima ocorrência dessa data como vencimento."""
    login = _normalize_login_from_name(name)
    m = re.search(r"(\d{1,2})[/\-.](\d{1,2})(?:[/\-.](\d{2,4}))?", name or "")
    if not m:
        return {"login": login, "tipo": "vpn", "vencimento": None}

    try:
        dia, mes = int(m.group(1)), int(m.group(2))
        ano_str = m.group(3)
        hoje = datetime.datetime.now()
        if ano_str:
            ano = int(ano_str)
            if ano < 100:
                ano += 2000
        else:
            ano = hoje.year
            if datetime.datetime(ano, mes, dia).date() < hoje.date():
                ano += 1
        vencimento = datetime.datetime(ano, mes, dia).strftime("%Y-%m-%d")
        return {"login": login, "tipo": "netflix", "vencimento": vencimento}
    except (ValueError, TypeError):
        return {"login": login, "tipo": "vpn", "vencimento": None}

def _get_contact_name(owner, phone):
    return _load_wa_contacts().get(f"{owner}|{phone}", {}).get("name", "")

# ══════════════════════════════════════════════════════════════════
#  VALIDAÇÃO DE COMPROVANTE POR OCR (Tesseract, local e gratuito) ────
#  Sem isso, o bot liberava o acesso pago pra QUALQUER imagem recebida
#  no fluxo de comprovante (uma selfie, um print de qualquer coisa).
#  Não impede fraude sofisticada (print editado), mas bloqueia o abuso
#  mais óbvio sem depender de nenhuma API paga de terceiros.
# ══════════════════════════════════════════════════════════════════

PROOF_KEYWORDS = [
    "pix", "comprovante", "transferencia", "transferido", "pagamento",
    "recibo", "valor", "transacao", "efetuada", "recebedor", "pagador",
    "banco", "nubank", "itau", "bradesco", "caixa economica", "santander",
    "banco inter", "picpay", "mercado pago", "sicoob", "sicredi", "c6 bank",
    "comprovante de pagamento", "comprovante de transferencia",
]

def _ocr_extract_text(image_path):
    """Roda OCR local (Tesseract — grátis, open-source, sem API externa)
    na imagem e devolve o texto reconhecido em minúsculas e sem acento.
    Levanta exceção se o Tesseract não estiver instalado no servidor —
    quem chama decide o que fazer nesse caso (ver _looks_like_payment_proof)."""
    import pytesseract
    from PIL import Image
    img = Image.open(image_path)
    texto = pytesseract.image_to_string(img, lang="por+eng")
    return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii").lower()

def _text_looks_like_own_bot_message(texto, wa):
    """Item: SEGURANÇA — detecta se o texto do OCR é, na real, um PRINT
    DA PRÓPRIA CONVERSA com o bot (o cliente manda um print da tela do
    WhatsApp em vez do comprovante bancário de verdade). Esse era o caso
    mais comum de falso-positivo: a mensagem que o bot manda pedindo o
    PIX já contém "pix", "comprovante" e "valor" — as mesmas palavras
    que a checagem de comprovante procura — então um simples print da
    conversa batia com a checagem antiga (que bastava 1 palavra) e
    liberava acesso de graça.
    Compara por sequência de 5 palavras seguidas contra as mensagens que
    o próprio bot manda sobre pagamento/PIX — usa a config REAL do
    painel (não só o texto padrão), pra funcionar mesmo se o admin tiver
    personalizado essas mensagens."""
    candidatos = [
        wa.get("bot_plan_message", "") or "",
        wa.get("bot_plan_waiting_message", "") or "",
        wa.get("bot_renew_message", "") or "",
        wa.get("bot_invalid_proof_message", "") or "",
    ]
    texto_liso = " ".join(texto.split())
    for msg in candidatos:
        msg_norm = unicodedata.normalize("NFKD", msg).encode("ascii", "ignore").decode("ascii").lower()
        msg_norm = re.sub(r"\{[^}]*\}", " ", msg_norm)  # remove placeholders tipo {pix}
        palavras = [w for w in re.sub(r"[^a-z0-9\s]", " ", msg_norm).split() if len(w) > 2]
        for i in range(len(palavras) - 4):
            trecho = " ".join(palavras[i:i + 5])
            if trecho and trecho in texto_liso:
                return True
    return False

def _looks_like_payment_proof(image_path, wa):
    """Confirmação automática, mas com checagens antes de liberar o
    acesso:
      1) Descarta de cara se o texto parecer print da PRÓPRIA conversa
         com o bot (ver _text_looks_like_own_bot_message) — era o abuso
         mais comum e passava despercebido pela checagem antiga.
      2) Só considera válido com pelo menos 2 sinais de comprovante
         real: duas palavras típicas de comprovante bancário/PIX (ou o
         valor configurado em bot_plan_price aparecendo no texto), OU
         uma palavra-chave + um valor monetário reconhecido (ex:
         "R$ 20,00"). Um único acerto solto (ex: só a palavra "pix")
         não basta mais — é fácil demais de aparecer numa imagem
         qualquer sem ser de fato um comprovante.
    NÃO é infalível — ainda dá pra falsificar um print — mas barra os
    casos mais comuns de abuso (foto qualquer, ou print da própria
    conversa com o bot)."""
    texto = _ocr_extract_text(image_path)  # pode levantar exceção — ver chamador
    if not texto.strip():
        return False
    if _text_looks_like_own_bot_message(texto, wa):
        return False
    acertos = sum(1 for kw in PROOF_KEYWORDS if kw in texto)
    preco_digits = re.sub(r"[^\d]", "", str(wa.get("bot_plan_price", "") or ""))
    tem_valor_monetario = bool(re.search(r"r\$\s*\d|\b\d{1,3}[.,]\d{2}\b", texto))
    if preco_digits and preco_digits in re.sub(r"[^\d]", "", texto):
        acertos += 1
    pontos = acertos + (1 if tem_valor_monetario else 0)
    return pontos >= 2

@app.route("/api/whatsapp/contacts/sync-history", methods=["POST"])
def whatsapp_contacts_sync_history():
    """Endpoint interno — o whatsapp_bot.js chama isso logo que a sessão
    conecta, com o histórico real de chats que o próprio WhatsApp entrega
    (não é algo que o admin aciona pelo painel)."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner = (data.get("owner") or "").strip()
    contacts_list = data.get("contacts") or []
    if not owner or not isinstance(contacts_list, list):
        return jsonify({"ok": True, "updated": 0})
    updated = _sync_wa_contacts_history(owner, contacts_list)
    device_log_write(f"WhatsApp ({owner}): sincronizado histórico real de {updated} chat(s)")
    return jsonify({"ok": True, "updated": updated})

@app.route("/api/whatsapp/inbound", methods=["POST"])
def whatsapp_inbound():
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json() or {}
    owner = data.get("owner", "").strip()
    phone = re.sub(r"\D", "", data.get("phone", ""))
    text  = (data.get("text") or "").strip().lower()
    # Item: whatsapp_bot.js agora também encaminha imagens (comprovante
    # de PIX, print da tela inicial) — hasImage=True e imagePath aponta
    # pro arquivo salvo em disco pelo microserviço Node.
    has_image  = bool(data.get("hasImage"))
    image_path = (data.get("imagePath") or "").strip()
    # Item: comprovante em PDF — bastante comum quando o cliente exporta
    # o recibo direto do app do banco. Aceito como anexo válido de
    # comprovante SEM rodar OCR (não é necessário ler o conteúdo do PDF
    # pra confiar nele — é só outro formato de "anexo de comprovante",
    # ver _looks_like_payment_proof mais abaixo). has_media junta os
    # dois tipos de anexo pra qualquer checagem genérica de "o cliente
    # mandou algum arquivo, seja lá qual for".
    has_pdf   = bool(data.get("hasPdf"))
    pdf_path  = (data.get("pdfPath") or "").strip()
    has_media  = has_image or has_pdf
    media_path = image_path or pdf_path
    if not owner or not phone or (not text and not has_media):
        return jsonify({"ok": True})  # nada a fazer

    cfg = load_config()
    if owner != "admin" and owner not in cfg.get("resellers", {}):
        return jsonify({"ok": True})

    # ── Contato ignorado pela automação — checagem determinística, ANTES
    # de qualquer lógica de bot/IA (ver comentário em _wa_is_ignored).
    # Pra esse número, o bot se comporta como se nem existisse: não marca
    # "visto agora", não loga transcript, não responde por palavra-chave
    # nem por IA.
    if _wa_is_ignored(owner, phone):
        return jsonify({"ok": True})

    wa = get_owner_wa_config(owner)
    if not wa.get("bot_enabled"):
        return jsonify({"ok": True})  # bot desligado pra este painel

    owner_role = "admin" if owner == "admin" else "reseller"
    owner_user = cfg["admin"]["username"] if owner == "admin" else owner

    _touch_wa_contact(owner, phone, name=(data.get("name") or "").strip())

    ai_cfg = get_ai_assistant_config(owner)
    if ai_cfg.get("log_conversations") and (text or has_media):
        _log_ai_transcript(owner, phone, "user", data.get("text") or ("[pdf]" if has_pdf else ("[imagem]" if has_image else "")))

    state = _load_bot_state()
    key = f"{owner}|{phone}"
    contact = state.get(key, {})

    # ── comando de RESET — reinicia o atendimento do zero pra esse
    # contato. Funciona em QUALQUER estado (mesmo já transferido pra
    # humano ou preso numa etapa como "aguardando_print"), por isso é
    # checado antes de qualquer outra lógica. Não precisa de intenção
    # de IA nem de etapa aberta — é um escape manual explícito.
    if not has_media and text.strip().strip("#") in ("reset", "reiniciar", "reiniciar atendimento"):
        state[key] = {}
        _save_bot_state(state)
        device_log_write(f"BOT WHATSAPP: atendimento reiniciado (reset manual) — {phone} (painel {owner})")
        reset_msg = wa["bot_reset_message"] + "\n\n" + wa["bot_menu_message"]
        _wa_send(owner, phone, reset_msg)
        if ai_cfg.get("log_conversations"):
            _log_ai_transcript(owner, phone, "bot", reset_msg)
        return jsonify({"ok": True, "reply": reset_msg})

    # ── contato em atendimento humano: as AÇÕES automáticas do bot (menu,
    # comandos, criação de acesso etc.) ficam desligadas até um atendente
    # reassumir manualmente (WhatsApp › Atendimentos aguardando atendente),
    # mas a IA (se ligada) continua batendo papo pra não deixar o cliente
    # no vácuo enquanto espera. Ela é instruída a só fazer companhia, sem
    # tentar resolver o problema de novo nem repetir pedidos já feitos.
    if contact.get("human"):
        # Item: mesmo já em atendimento humano, se o cliente mandar o
        # print da tela inicial (que agora é OPCIONAL — o encaminhamento
        # já aconteceu sem exigir ele, ver comando de suporte mais
        # abaixo), o print ainda é registrado no histórico de mídia pro
        # atendente conferir. Não manda nenhuma resposta automática
        # aqui: quem está atendendo já é humano, o bot só guarda o
        # anexo silenciosamente.
        if has_image and contact.get("step") == "aguardando_print":
            _log_bot_media(
                owner, phone, "print_tela_inicial", image_path,
                "recebido durante atendimento humano — encaminhamento já tinha sido feito sem exigir o print"
            )
            contact["step"] = None
            state[key] = contact
            _save_bot_state(state)
            return jsonify({"ok": True, "reply": None, "human": True})

        if ai_cfg.get("enabled") and not contact.get("human_replied_manually") and not has_media and text:
            history = contact.get("ai_history", [])
            waiting_prompt = (
                _ai_system_prompt(ai_cfg, wa)
                + "\n\nAVISO IMPORTANTE: este cliente JÁ FOI encaminhado pra atendimento humano e está "
                "aguardando um atendente assumir a conversa manualmente pelo WhatsApp — isso já aconteceu, "
                "não oriente ele a mandar \"suporte\" de novo. Seu papel agora é só fazer companhia: seja "
                "breve, acolhedor, e reforce que o atendente já foi avisado e vai responder assim que "
                "possível. NÃO tente diagnosticar ou resolver o problema técnico de novo, NÃO peça print de "
                "novo (o atendimento já foi acionado — o print é só opcional, pra agilizar, e não é mais "
                "obrigatório), e não repita informações que já foram passadas nesta conversa."
            )
            ok, ai_reply = _call_gemini(ai_cfg, waiting_prompt, history, data.get("text") or "")
            if ok:
                # BUG CORRIGIDO: a chamada à IA (Gemini) é lenta, e nesse
                # meio-tempo o atendente pode ter respondido manualmente
                # pelo WhatsApp (o que grava human_replied_manually via
                # /api/whatsapp/human-activity). Salvar aqui usando o
                # `contact`/`state` carregados ANTES da chamada sobrescrevia
                # esse flag gravado nesse intervalo, fazendo a IA continuar
                # respondendo mesmo depois do humano já ter assumido. Agora
                # relê o estado do disco antes de decidir.
                fresh_state = _load_bot_state()
                fresh_contact = fresh_state.get(key, {})
                if fresh_contact.get("human_replied_manually"):
                    device_log_write(f"BOT WHATSAPP (IA): resposta descartada — atendente já respondeu manualmente durante o processamento ({phone}, painel {owner})")
                    return jsonify({"ok": True, "reply": None, "human": True})
                max_turns = int(ai_cfg.get("max_history_turns", 8) or 8)
                new_history = (history + [
                    {"role": "user", "text": (data.get("text") or "")[:1000]},
                    {"role": "model", "text": ai_reply[:1000]},
                ])[-max_turns * 2:]
                fresh_contact["ai_history"] = new_history
                fresh_state[key] = fresh_contact
                _save_bot_state(fresh_state)
                _wa_send(owner, phone, ai_reply)
                if ai_cfg.get("log_conversations"):
                    _log_ai_transcript(owner, phone, "bot", ai_reply)
                return jsonify({"ok": True, "reply": ai_reply, "human": True})
        return jsonify({"ok": True, "reply": None, "human": True})

    def _reply(msg, **state_updates):
        contact.update(state_updates)
        state[key] = contact
        _save_bot_state(state)
        _wa_send(owner, phone, msg)
        if ai_cfg.get("log_conversations"):
            _log_ai_transcript(owner, phone, "bot", msg)
        return jsonify({"ok": True, "reply": msg})

    BOT_REPEAT_MSG_COOLDOWN_HOURS = 12  # Item: anti-repetição — mesmo aviso de "espera" não se repete pro mesmo contato dentro desse intervalo

    def _reply_throttled(msg_key, msg, **state_updates):
        """Como _reply(), mas evita mandar a MESMA mensagem de espera/
        lembrete (ex: "ainda aguardando o comprovante", "ainda aguardando
        o print") pro mesmo contato mais de uma vez a cada
        BOT_REPEAT_MSG_COOLDOWN_HOURS horas. Antes, um cliente que mandava
        várias mensagens seguidas sem resolver a pendência recebia o
        mesmo aviso repetido a cada mensagem — bem irritante. O estado
        (step, contadores de tentativa etc.) sempre é atualizado
        normalmente; só o ENVIO da mensagem em si fica em silêncio quando
        é uma repetição recente dentro da janela."""
        agora = time.time()
        historico = contact.get("last_msg_sent", {})
        ultimo_envio = historico.get(msg_key, 0)
        deve_enviar = (agora - ultimo_envio) >= BOT_REPEAT_MSG_COOLDOWN_HOURS * 3600
        contact.update(state_updates)
        if deve_enviar:
            historico[msg_key] = agora
            contact["last_msg_sent"] = historico
        state[key] = contact
        _save_bot_state(state)
        if not deve_enviar:
            return jsonify({"ok": True, "reply": None})
        _wa_send(owner, phone, msg)
        if ai_cfg.get("log_conversations"):
            _log_ai_transcript(owner, phone, "bot", msg)
        return jsonify({"ok": True, "reply": msg})

    def _handoff(motivo="", msg=None, **extra_state):
        _log_bot_media(owner, phone, "handoff", media_path, motivo)
        send_whatsapp_alert(owner, wa["bot_admin_notify_handoff"].format(phone=phone, text=(data.get("text") or "")[:200]))
        device_log_write(f"BOT WHATSAPP: atendimento encaminhado pra humano — {phone} (painel {owner}) motivo: {motivo}")
        # Item: por padrão zera a etapa (step=None) e marca human=True —
        # que já suspende TODO atendimento automático (bot/IA) pra esse
        # contato por pelo menos 12h (ver BOT_HANDOFF_AUTO_RESUME_HOURS /
        # bot_handoff_auto_resume_loop mais abaixo), reativando antes
        # disso só se um atendente reassumir manualmente pelo painel.
        # Quem chama pode sobrescrever campos (ex: manter
        # step="aguardando_print" pra o bot ainda reconhecer o print se
        # ele chegar depois, mesmo já em atendimento humano).
        state_updates = {"step": None, "human": True, "human_since": time.time()}
        state_updates.update(extra_state)
        return _reply(msg or wa["bot_handoff_message"], **state_updates)

    step = contact.get("step")

    # ── ETAPA: aguardando comprovante do PIX (plano mensal ou renovação) ──
    if step == "aguardando_comprovante":
        if has_image or has_pdf:
            # Item: SEGURANÇA — antes de liberar qualquer coisa, confere
            # se o anexo realmente parece um comprovante bancário/PIX:
            #   • PDF: aceito direto, SEM OCR — não é necessário ler o
            #     conteúdo (é o formato que os apps de banco já exportam
            #     o comprovante de verdade; ler o texto do PDF exigiria
            #     outra biblioteca e não é o que foi pedido).
            #   • Imagem: roda OCR local (Tesseract, grátis) e exige
            #     indícios reais de comprovante. BUG corrigido: antes
            #     bastava achar UMA palavra solta tipo "pix" no texto —
            #     mas a própria mensagem que o bot manda pedindo o PIX já
            #     contém "pix", "comprovante" e "valor", então um simples
            #     PRINT DA CONVERSA com o bot (em vez do comprovante
            #     bancário de verdade) batia com a checagem antiga e
            #     liberava acesso de graça. Agora exige pelo menos 2
            #     sinais reais E descarta de cara se o texto bater com a
            #     própria conversa do bot (ver _looks_like_payment_proof).
            if has_pdf:
                comprovante_valido = True
            else:
                try:
                    comprovante_valido = _looks_like_payment_proof(image_path, wa)
                except Exception as e:
                    # Tesseract não instalado/configurado no servidor — por
                    # segurança, NÃO libera automaticamente: encaminha pra
                    # conferência humana e avisa o admin no log pra corrigir.
                    device_log_write(
                        f"BOT WHATSAPP: OCR indisponível ({e}) — comprovante de {phone} (painel {owner}) "
                        f"foi para conferência humana por segurança. Instale o Tesseract OCR no servidor "
                        f"(apt install tesseract-ocr tesseract-ocr-por) pra habilitar a confirmação automática."
                    )
                    return _handoff("OCR indisponível no servidor — comprovante encaminhado pra conferência manual")

            if not comprovante_valido:
                tentativas = contact.get("comprovante_tentativas", 0) + 1
                _log_bot_media(owner, phone, "comprovante_suspeito", image_path, f"tentativa {tentativas} — não parece comprovante real (ou parece print da própria conversa)")
                if tentativas >= 3:
                    return _handoff("comprovante não confirmado automaticamente após 3 tentativas")
                return _reply(wa["bot_invalid_proof_message"], comprovante_tentativas=tentativas)

            media_path_comprovante = pdf_path if has_pdf else image_path
            dias = int(wa.get("bot_plan_days", 30))
            existing_login = _find_login_by_phone(cfg, phone, owner)
            test_logins = _load_test_logins()
            if existing_login and existing_login in test_logins:
                # Item: BUG corrigido — um acesso de TESTE já nasce com uma
                # auto-exclusão agendada no sistema (comando `at`), que roda
                # de qualquer forma no horário original mesmo que a gente
                # "renove" a validade dele no banco. Resultado real que
                # aconteceu: o teste virava (no papel) um acesso mensal, mas
                # era apagado sozinho horas depois pela exclusão automática
                # que ninguém cancelou. Por isso, NUNCA renova um login
                # marcado como teste — trata como cliente novo e cria um
                # acesso mensal à parte (perguntando o nome se precisar).
                device_log_write(
                    f"BOT WHATSAPP: pagamento de {phone} (painel {owner}) achou o login de TESTE "
                    f"'{existing_login}' vinculado ao telefone — ignorado de propósito (não reaproveita "
                    f"teste pra virar mensal), vai criar um acesso novo em vez de renovar esse."
                )
                existing_login = None
            if existing_login:
                ok, payload = renew_access_internal(existing_login, dias=dias)
                if ok:
                    # Item: BUG CORRIGIDO — o bot somava os dias certinho, mas
                    # nunca desbloqueava quem já estava bloqueado (por vencido,
                    # dispositivo, limite de conexões etc.). Resultado: o
                    # cliente pagava, o painel mostrava validade renovada, e
                    # mesmo assim continuava sem conseguir conectar — só
                    # voltava a funcionar se um atendente humano clicasse
                    # "renovar" manualmente (que já faz esse desbloqueio, ver
                    # renovar_user()). Agora o bot faz a mesma coisa.
                    _unblock_login(existing_login)
                    # BUGFIX v33: renovação via bot (comprovante PIX de
                    # cliente já existente) não replicava pros servidores
                    # sincronizados — era o único fluxo de renovação que
                    # ainda faltava (botão ♻️ individual e ação em lote já
                    # propagavam). Fica aqui no ponto de chamada, e não
                    # dentro de renew_access_internal(), porque essa função é
                    # reaproveitada por renovar_user()/bulk_action_users(),
                    # que JÁ propagam sozinhas — propagar dentro da função
                    # faria os dias serem somados em dobro no servidor remoto
                    # para esses dois casos.
                    if not getattr(request, "ns_session", {}).get("via_sync", False):
                        propagate_to_servers("POST", f"/api/users/{existing_login}/renovar", payload={"dias": dias})
            else:
                # Item: cliente novo — tenta criar já com o nome salvo no
                # contato do WhatsApp (só pra clientes VPN, sem data no
                # nome; contatos com data são clientes Netflix, de outro
                # serviço, e não usam o nome pra isso). Se não der pra
                # deduzir um nome válido e livre, pede pro cliente informar.
                desired_login = None
                contact_name = _get_contact_name(owner, phone)
                if contact_name:
                    parsed = _parse_contact_name(contact_name)
                    if parsed["tipo"] == "vpn" and parsed["login"] and not any(u["login"] == parsed["login"] for u in read_users()):
                        desired_login = parsed["login"]

                if not desired_login:
                    return _reply(wa["bot_ask_name_for_access_message"], step="aguardando_nome_acesso", comprovante_tentativas=0)

                ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=desired_login)
                if ok:
                    cfg = load_config()
                    # limpa qualquer login de TESTE antigo que ainda estivesse
                    # apontando pra esse mesmo telefone, pra não confundir a
                    # próxima consulta/pagamento (o de teste já era, mesmo
                    # que ainda não tenha sido fisicamente excluído)
                    phones_map = cfg.setdefault("user_phones", {})
                    for l in [l for l, p in phones_map.items() if p == phone and l in test_logins]:
                        del phones_map[l]
                    phones_map[payload["login"]] = phone
                    save_config(cfg)

            if not ok:
                _log_bot_media(owner, phone, "comprovante_falha", media_path_comprovante, str(payload.get("error", "")))
                return _handoff(f"falha ao liberar acesso automático: {payload.get('error', '')}")

            _log_bot_media(owner, phone, "comprovante", media_path_comprovante)
            send_whatsapp_alert(owner, wa["bot_admin_notify_payment"].format(phone=phone, login=payload["login"], dias=dias))
            device_log_write(f"BOT WHATSAPP: acesso {'renovado' if existing_login else 'criado'} via comprovante automático — {phone} ({payload['login']}) painel {owner}")
            reply = wa["bot_payment_received_message"].format(
                login=payload["login"], senha=payload["senha"], dias=dias, vencimento=payload["expira"], uuid=payload.get("uuid", "")
            )
            return _reply(reply, step=None, comprovante_tentativas=0)
        else:
            # Item: anti-repetição — não fica mandando "ainda aguardando o
            # comprovante" de novo pro mesmo contato a cada mensagem;
            # espera pelo menos 12h desde o último aviso desse tipo.
            return _reply_throttled("plan_waiting", wa["bot_plan_waiting_message"])

    # ── ETAPA: aguardando o cliente informar um nome pra criar o acesso
    # (comprovante já confirmado — só faltou um nome utilizável) ──────
    if step == "aguardando_nome_acesso":
        if has_media:
            return _reply(wa["bot_ask_name_for_access_message"])

        nome_informado = (data.get("text") or "").strip()
        base_login = _normalize_login_from_name(nome_informado) or _normalize_login_from_name(phone)
        dias = int(wa.get("bot_plan_days", 30))

        ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=base_login)
        if not ok:
            # nome já em uso — tenta variações numéricas automaticamente
            # antes de desistir, pra não travar o atendimento por causa disso
            for n in range(1, 6):
                ok, payload = create_paid_access_internal(owner_role, owner_user, dias=dias, login=f"{base_login}{n}")
                if ok:
                    break
        if not ok:
            return _handoff(f"não consegui criar login a partir do nome '{nome_informado}': {payload.get('error', '')}")

        cfg = load_config()
        test_logins = _load_test_logins()
        phones_map = cfg.setdefault("user_phones", {})
        for l in [l for l, p in phones_map.items() if p == phone and l in test_logins]:
            del phones_map[l]
        phones_map[payload["login"]] = phone
        save_config(cfg)

        _log_bot_media(owner, phone, "comprovante", media_path)
        send_whatsapp_alert(owner, wa["bot_admin_notify_payment"].format(phone=phone, login=payload["login"], dias=dias))
        device_log_write(f"BOT WHATSAPP: acesso criado com nome informado pelo cliente — {phone} ({payload['login']}) painel {owner}")
        reply = wa["bot_payment_received_message"].format(
            login=payload["login"], senha=payload["senha"], dias=dias, vencimento=payload["expira"], uuid=payload.get("uuid", "")
        )
        return _reply(reply, step=None, comprovante_tentativas=0)

    # ── ETAPA: aguardando print da tela inicial (suporte) ─────────────
    # Item: regra alterada — o pedido de suporte (mais abaixo) já
    # encaminha pra atendimento humano NA HORA, sem exigir o print
    # primeiro (o print virou opcional, só pra agilizar). Isso faz esse
    # bloco só ser alcançado em casos residuais (ex: step ficou
    # "aguardando_print" sem human=True por algum motivo externo) — na
    # prática o print, quando chega, é tratado no bloco "contato em
    # atendimento humano" lá no topo da função.
    if step == "aguardando_print":
        if has_image:
            _log_bot_media(owner, phone, "print_tela_inicial", image_path)
            confirm_msg = wa["bot_print_received_message"] + "\n\n" + wa["bot_handoff_message"]
            return _handoff("cliente enviou o print solicitado — segue pra conferência humana", msg=confirm_msg)
        # Saída de emergência: se o cliente mandar um comando claro (ex:
        # "vencimento", "teste", "menu") em vez do print, não fica preso
        # repetindo o pedido pra sempre — libera a etapa e deixa o fluxo
        # normal de comandos (mais abaixo) tratar a mensagem dele.
        elif not any(p in text for p in ("teste", "vencimento", "apk", "aplicativo", "mensal", "renov", "pix", "menu", "suporte")):
            # Item: limite de repetição — o bot já pediu o print 1x ao
            # entrar nessa etapa (bot_print_request_message). Se o
            # cliente não manda a imagem, o bot insiste MAIS UMA vez
            # (contada aqui). Na 3ª mensagem sem print, em vez de
            # repetir a mesma pergunta pra sempre, encaminha pra um
            # atendente humano — mas continua respondendo o cliente
            # normalmente (a IA, se ligada, assume a companhia — ver o
            # bloco "contato em atendimento humano" no topo da função).
            tentativas = contact.get("print_tentativas", 1)
            if tentativas >= 2:
                return _handoff(
                    "cliente não enviou o print após 2 solicitações — encaminhado automaticamente",
                    msg=wa["bot_print_max_attempts_message"],
                )
            # Item: anti-repetição — mesmo aviso de "só falta o print" não
            # se repete pro mesmo contato dentro de 12h.
            return _reply_throttled("print_waiting", wa["bot_print_waiting_message"], print_tentativas=tentativas + 1)
        else:
            contact["step"] = None
            step = None

    # ── ETAPA: aguardando o cliente informar o nome exato do usuário
    # (consulta de vencimento) — pedir explicitamente em vez de adivinhar
    # pelo telefone deixa a consulta muito mais acertiva, já que um
    # mesmo número pode ter mais de um acesso ao longo do tempo ───────
    if step == "aguardando_login_vencimento":
        if has_media:
            return _reply(wa["bot_ask_username_message"])

        login_informado = re.sub(r"\s+", "", (data.get("text") or "").strip())
        users = {u["login"]: u for u in read_users()}
        u = users.get(login_informado)
        if not u:
            # tenta uma versão normalizada (sem acento/maiúsculas) do que
            # o cliente digitou, caso ele tenha escrito com variação
            norm = _normalize_login_from_name(login_informado)
            u = users.get(norm)
            if u:
                login_informado = norm
        if not u:
            return _reply(wa["bot_status_not_found"], step=None)

        dt = _parse_dt(u["expira"])
        dias = (dt - datetime.datetime.now()).total_seconds() / 86400 if dt else 0
        dias_txt = "menos de 1 dia" if dias < 1 else f"{int(dias)} dia(s)"
        reply = wa["bot_status_found"].format(login=login_informado, dias_txt=dias_txt, vencimento=u["expira"])
        return _reply(reply, step=None)

    # ── sem etapa em aberto: interpreta comandos por palavra-chave ────

    # comando: TESTE
    if not has_media and "teste" in text:
        cooldown_h = wa.get("bot_cooldown_hours", 24)
        last = contact.get("last_test")
        if last:
            elapsed_h = (time.time() - last) / 3600
            if elapsed_h < cooldown_h:
                return _reply(wa["bot_cooldown_message"])

        minutos = int(wa.get("bot_test_minutes", 60))
        ok, payload = create_test_internal(owner_role, owner_user, minutos=minutos, auto=True)
        if not ok:
            return _reply(wa["bot_quota_full_message"])

        cfg = load_config()
        cfg.setdefault("user_phones", {})[payload["login"]] = phone
        save_config(cfg)

        device_log_write(f"BOT WHATSAPP: teste automático criado via WhatsApp para {phone} ({payload['login']}) — painel {owner}")
        reply = wa["bot_test_message"].format(
            login=payload["login"], senha=payload["senha"],
            minutos=payload["minutos"], uuid=payload["uuid"]
        )
        return _reply(reply, last_test=time.time())

    # comando: VENCIMENTO / STATUS — pede o nome EXATO do usuário em vez
    # de adivinhar pelo telefone, pra consulta ser sempre acertiva
    if not has_media and ("vencim" in text or "vence" in text or "status" in text):
        return _reply(wa["bot_ask_username_message"], step="aguardando_login_vencimento")

    # comando: APK / LINK DO APLICATIVO
    # BUGFIX: o menu mostra o comando como "apk", mas o cliente comumente
    # digita "app" (inclusive foi o termo usado ao tentar treinar isso na
    # IA) — e "app" não é substring de nenhuma das palavras antigas
    # ("aplicativo" não contém "app", tem só um "p"). Sem bater aqui, a
    # mensagem caía no fallback de IA, que só tem o TEXTO treinado como
    # dica e não o link de verdade (isso só esse trecho busca, via
    # _get_app_links_internal()) — por isso "treinar a IA" pra isso
    # nunca ia devolver o link real.
    if not has_media and ("apk" in text or "app" in text or "aplicativo" in text or "baixar" in text or "download" in text or "link" in text):
        links = _get_app_links_internal()
        reply = wa["bot_apk_message"].format(
            apk_android=links.get("apk_android") or "indisponível no momento",
            apk_iphone=links.get("apk_iphone") or "indisponível no momento",
        )
        return _reply(reply)

    # comando: PLANO MENSAL / CONTRATAR (cliente novo)
    if not has_media and any(p in text for p in ("mensal", "assinar", "contratar", "plano", "comprar")):
        dias = int(wa.get("bot_plan_days", 30))
        reply = wa["bot_plan_message"].format(
            dias=dias, preco=wa.get("bot_plan_price", "") or "consulte o valor com o suporte",
            pix=wa.get("pix_key", "não configurada")
        )
        return _reply(reply, step="aguardando_comprovante")

    # comando: RENOVAR / PIX (cliente já ativo)
    if not has_media and ("renov" in text or "pix" in text):
        reply = wa["bot_renew_message"].format(pix=wa.get("pix_key", "não configurada"))
        return _reply(reply, step="aguardando_comprovante")

    # comando: PERSONALIZADO — cadastrado pelo admin em WhatsApp -> "🔧
    # Comandos Personalizados", sem precisar mexer em código. Roda
    # DEPOIS dos comandos fixos oficiais acima (teste/vencimento/apk/
    # mensal/renovar), pra um cadastro novo nunca conseguir sobrescrever
    # esses por acidente, e ANTES do suporte/IA abaixo, pra ser sempre
    # determinístico — a mesma pergunta sempre volta a mesma resposta,
    # não depende da IA estar ligada nem de interpretação (diferente de
    # "Treinar a IA", que é só sugestão de contexto pra IA usar).
    if not has_media:
        custom_reply = _match_custom_command(owner, text)
        if custom_reply:
            return _reply(custom_reply)

    # comando: SUPORTE / AJUDA / PROBLEMA
    # Se a IA estiver ligada, deixa ela conversar e tentar diagnosticar
    # primeiro (perguntar o que houve, pedir print, sugerir testar com
    # wifi desligado/dados móveis) em vez de já cortar pro fluxo rígido.
    # Só a palavra explícita "suporte" — que é a que a própria IA orienta
    # o cliente a mandar quando já tentou ajudar e não resolveu — segue
    # direto pro encaminhamento humano. Com a IA desligada, mantém o
    # comportamento antigo (qualquer sinal de problema já encaminha).
    is_support_intent = not has_media and any(
        p in text for p in ("suporte", "ajuda", "não funciona", "nao funciona", "erro", "problema", "não conect", "nao conect")
    )
    if is_support_intent and (not ai_cfg.get("enabled") or "suporte" in text):
        # Item: regra alterada — o encaminhamento pra atendimento humano
        # NÃO depende mais do cliente mandar o print da tela inicial
        # primeiro (antes o bot ficava pedindo/repetindo até 2x antes de
        # encaminhar). Agora já chama o atendente NA HORA, e só pede o
        # print como algo OPCIONAL que ajuda a agilizar — se o cliente
        # mandar depois, ainda é registrado no histórico de mídia (ver
        # bloco "contato em atendimento humano" no topo da função).
        return _handoff(
            "pedido de suporte — atendente chamado direto, print pedido só como algo opcional pra agilizar",
            msg=wa["bot_support_handoff_message"],
            step="aguardando_print",
        )

    # ── mensagem não reconhecida (ou imagem fora de qualquer fluxo) ───
    # Item: anti-loop — antes de chamar um atendente, garante que o
    # contato já viu o menu de opções recentemente. A msg inicial com o
    # menu só é reenviada no MÁXIMO 1x a cada 12h; se mesmo depois dela
    # o cliente mandar outra coisa não reconhecida dentro dessa janela,
    # aí sim encaminha pra atendimento humano (e fica em silêncio até o
    # atendente reassumir manualmente — bem mais que as 12h mínimas).
    # ── mensagem não reconhecida: tenta o assistente de IA (se ligado
    # nas Configurações) antes de cair no menu/atendimento humano ─────
    if ai_cfg.get("enabled") and not has_media and text:
        history = contact.get("ai_history", [])
        ok, ai_reply = _call_gemini(ai_cfg, _ai_system_prompt(ai_cfg, wa), history, data.get("text") or "")
        if ok:
            # BUG CORRIGIDO: mesma corrida do bloco de "companhia" pós-
            # handoff — a chamada à IA é lenta e um atendente pode ter
            # assumido a conversa manualmente enquanto ela ainda estava
            # respondendo. _reply() salvaria por cima usando o `contact`
            # antigo, apagando o "human"/"human_replied_manually" gravado
            # nesse meio-tempo e mandando a resposta da IA depois do
            # humano já ter atendido. Agora relê o estado do disco antes
            # de mandar/salvar.
            fresh_state = _load_bot_state()
            fresh_contact = fresh_state.get(key, {})
            if fresh_contact.get("human") or fresh_contact.get("human_replied_manually"):
                device_log_write(f"BOT WHATSAPP (IA): resposta descartada — contato já foi assumido por humano durante o processamento ({phone}, painel {owner})")
                return jsonify({"ok": True, "reply": None})
            max_turns = int(ai_cfg.get("max_history_turns", 8) or 8)
            new_history = (history + [
                {"role": "user", "text": (data.get("text") or "")[:1000]},
                {"role": "model", "text": ai_reply[:1000]},
            ])[-max_turns * 2:]
            fresh_contact["ai_history"] = new_history
            fresh_state[key] = fresh_contact
            _save_bot_state(fresh_state)
            _wa_send(owner, phone, ai_reply)
            if ai_cfg.get("log_conversations"):
                _log_ai_transcript(owner, phone, "bot", ai_reply)
            device_log_write(f"BOT WHATSAPP (IA): Gemini respondeu {phone} (painel {owner})")
            return jsonify({"ok": True, "reply": ai_reply})
        else:
            device_log_write(f"BOT WHATSAPP (IA): Gemini falhou pra {phone} (painel {owner}) — {ai_reply}")
            # cai pro fluxo padrão (menu/handoff) abaixo — nunca deixa o
            # cliente sem resposta só porque a IA falhou/está sem cota.

    last_menu = contact.get("last_menu_sent", 0)
    if time.time() - last_menu > 12 * 3600:
        return _reply(wa["bot_menu_message"], last_menu_sent=time.time())

    # Mensagem genérica sem nenhuma intenção clara (tipo "oi", "calma",
    # "ok") NÃO deve forçar o pedido de print — isso é reservado só pra
    # quando há intenção real de suporte (já tratado mais acima) ou
    # quando o cliente manda uma imagem "do nada" (sinal forte de que é
    # o print, mesmo sem ter sido pedido).
    if has_media:
        kind = "print_tela_inicial" if has_image else "documento_pdf_fora_de_fluxo"
        _log_bot_media(owner, phone, kind, media_path)
        confirm_msg = wa["bot_print_received_message"] + "\n\n" + wa["bot_handoff_message"]
        return _handoff("anexo recebido fora de um fluxo esperado (tratado como print/comprovante de suporte), mesmo após o menu", msg=confirm_msg)
    # BUG CORRIGIDO: aqui embaixo o código reenviava o bot_menu_message
    # incondicionalmente, mesmo dentro das 12h — anulando o throttle
    # acima e o próprio comentário original que dizia "encaminha pra
    # atendimento humano" nesse caso. Era a causa do menu sendo mandado
    # várias vezes na mesma conversa. Agora, se o menu já foi mostrado
    # há menos de 12h e o cliente continua sem mandar um comando
    # reconhecido, encaminha pra atendimento humano de verdade.
    return _handoff("cliente já viu o menu recentemente e continua sem enviar um comando reconhecido")

@app.route("/api/whatsapp/human-activity", methods=["POST"])
def whatsapp_human_activity():
    """Chamado pelo whatsapp_bot.js quando detecta uma mensagem enviada
    do próprio WhatsApp (fromMe) que NÃO veio do bot (ou seja, o admin/
    atendente digitou e mandou manualmente pelo celular/WhatsApp Web).
    Isso marca o contato como assumido por humano — o bot (inclusive a
    IA, mesmo na fase de 'fazer companhia' pós-transferência) para de
    responder automaticamente esse número até ele ser reativado no
    painel (WhatsApp › Atendimentos aguardando atendente)."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner = data.get("owner", "").strip()
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not owner or not phone:
        return jsonify({"error": "owner e phone são obrigatórios"}), 400
    state = _load_bot_state()
    key = f"{owner}|{phone}"
    contact = state.get(key, {})
    contact["human"] = True
    contact["human_replied_manually"] = True
    contact.setdefault("human_since", time.time())
    # Item BUG CORRIGIDO (IA/bot voltando a responder com humano na
    # conversa): "human_since" só é gravado UMA VEZ (setdefault, acima) —
    # marca quando a conversa foi transferida pra humano pela PRIMEIRA vez,
    # e é isso que bot_handoff_auto_resume_loop usava pra decidir quando
    # reativar o bot sozinho (12h depois). Só que numa conversa em
    # atendimento humano ATIVO por mais de 12h (fila grande, caso mais
    # demorado, fim de semana), o atendente pode responder várias vezes
    # manualmente sem isso nunca "renovar" esse relógio — daí, 12h após a
    # transferência ORIGINAL, o loop reativava o bot/IA sozinho NO MEIO da
    # conversa, mesmo com o atendente ainda respondendo normalmente. Agora
    # grava também a data da ÚLTIMA atividade humana, atualizada A CADA
    # resposta manual — o auto-resume (ver bot_handoff_auto_resume_loop)
    # passa a contar a partir dela, não da primeira transferência.
    contact["human_last_activity"] = time.time()
    contact["step"] = None
    state[key] = contact
    _save_bot_state(state)
    device_log_write(f"BOT WHATSAPP: resposta manual detectada — {phone} (painel {owner}), bot silenciado")
    return jsonify({"ok": True})

@app.route("/api/whatsapp/bot/pending", methods=["GET"])
@auth_required()
def whatsapp_bot_pending():
    """Lista os contatos que o bot encaminhou pra atendimento humano e
    ainda estão aguardando um atendente reassumir a conversa."""
    owner = _owner_key(request.ns_session)
    state = _load_bot_state()
    prefix = f"{owner}|"
    pending = [
        {"phone": k.split("|", 1)[1], "since": v.get("human_since", 0)}
        for k, v in state.items()
        if k.startswith(prefix) and v.get("human")
    ]
    pending.sort(key=lambda x: x["since"], reverse=True)
    return jsonify(pending)

@app.route("/api/whatsapp/bot/resume", methods=["POST"])
@auth_required()
def whatsapp_bot_resume():
    """Devolve um contato específico pro bot voltar a responder
    automaticamente (usado depois que o atendente já respondeu manualmente)."""
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    if not phone:
        return jsonify({"error": "Telefone inválido"}), 400
    state = _load_bot_state()
    key = f"{owner}|{phone}"
    if key in state:
        state[key]["human"] = False
        state[key]["step"] = None
        state[key]["human_replied_manually"] = False
        _save_bot_state(state)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/bot/resume-all", methods=["POST"])
@auth_required()
def whatsapp_bot_resume_all():
    """Reativa de uma vez TODOS os contatos aguardando atendente do
    painel logado — pro admin não precisar clicar um por um quando já
    resolveu tudo manualmente pelo WhatsApp."""
    owner = _owner_key(request.ns_session)
    state = _load_bot_state()
    prefix = f"{owner}|"
    reativados = 0
    for key, contact in state.items():
        if key.startswith(prefix) and contact.get("human"):
            contact["human"] = False
            contact["step"] = None
            contact["human_replied_manually"] = False
            reativados += 1
    if reativados:
        _save_bot_state(state)
    device_log_write(f"BOT WHATSAPP ({owner}): reativação em massa — {reativados} contato(s) devolvido(s) ao bot")
    return jsonify({"ok": True, "reativados": reativados})

BOT_HANDOFF_AUTO_RESUME_HOURS = 12  # tempo que o bot fica "adormecido" num contato após transferir pra atendimento humano

def bot_handoff_auto_resume_loop():
    """Roda em background: depois de BOT_HANDOFF_AUTO_RESUME_HOURS horas
    SEM NENHUMA atividade humana nova nesse contato, o bot volta a
    responder sozinho automaticamente — mesmo que ninguém clique em
    'Reativar bot' no painel. Evita contato "esquecido" preso em silêncio
    pra sempre caso o atendente não reative manualmente.
    Item BUG CORRIGIDO: antes contava a partir de "human_since" (a
    PRIMEIRA transferência pra humano, gravada uma única vez), então uma
    conversa em atendimento humano ATIVO por mais de 12h (fila grande,
    caso mais demorado, fim de semana) tinha o bot/IA reativado sozinho NO
    MEIO da conversa, mesmo com o atendente respondendo normalmente o
    tempo todo — a causa real por trás de "a IA volta a responder o
    cliente mesmo com o humano na conversa". Agora conta a partir de
    "human_last_activity", atualizado a cada resposta manual (ver
    whatsapp_human_activity) — só reativa sozinho depois de 12h de
    SILÊNCIO humano de verdade."""
    while True:
        try:
            state = _load_bot_state()
            limite = time.time() - (BOT_HANDOFF_AUTO_RESUME_HOURS * 3600)
            changed = False
            for key, contact in state.items():
                if not contact.get("human"):
                    continue
                # Contatos antigos (gravados antes dessa correção) ainda não
                # têm "human_last_activity" — cai no fallback pra
                # "human_since" (comportamento antigo, só pra esses casos
                # legados; some sozinho assim que esse contato receber
                # qualquer atividade humana nova).
                since = contact.get("human_last_activity") or contact.get("human_since", 0) or 0
                if since and since <= limite:
                    contact["human"] = False
                    contact["step"] = None
                    contact["human_replied_manually"] = False
                    changed = True
                    owner, phone = (key.split("|", 1) + [""])[:2]
                    device_log_write(
                        f"BOT WHATSAPP ({owner}): {phone} reativado automaticamente após "
                        f"{BOT_HANDOFF_AUTO_RESUME_HOURS}h em atendimento humano sem reativação manual"
                    )
            if changed:
                _save_bot_state(state)
        except Exception as e:
            device_log_write(f"BOT WHATSAPP: erro no loop de auto-reativação — {e}")
        time.sleep(600)  # checa a cada 10 min — sobra de precisão suficiente pra uma janela de 12h

def _load_wa_sent_log():
    if not os.path.exists(WHATSAPP_SENT):
        return {}
    try:
        with open(WHATSAPP_SENT) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_wa_sent_log(data):
    _atomic_write_json(WHATSAPP_SENT, data)

SERVER_HEALTH_STATE = "/etc/painel/server_health_state.json"
# FIX: "limiter" saiu daqui de propósito — é o único serviço
# monitorado cujo estado "parado" pode ser 100% intencional (o
# admin desligando pela tela Dispositivos), então o watchdog não
# tem como saber se é queda de verdade ou desligamento manual, e
# reativava o limiter sozinho ~10min depois de qualquer "Desativar".
MONITORED_SERVICES = ["xray", "proxy", "wss", "wsssec", "slowdns", "checkuser", "badvpn", "stunnel"]

def _diag_proactive_file_scan():
    """Varredura leve (só checa existência, sem custo real) rodada junto
    com o monitor de saúde a cada 10 min — cobre o caso de um arquivo de
    código sumir sem que ninguém tenha clicado em nada que dependesse
    dele (ex: algo externo apagou o arquivo, disco corrompeu, etc).
    Respeita o modo de automação: só rebaixa sozinho se o modo permitir
    pra essa categoria (arquivo_faltando só é autônomo no modo "automático")."""
    faltando = []
    for f in DIAG_BACKEND_FILES:
        if not os.path.exists(os.path.join(BASE, f)):
            faltando.append(f)
    for f in DIAG_FRONTEND_FILES:
        if not os.path.exists(os.path.join(DIAG_WEBROOT, f)):
            faltando.append(f)

    aplicados, pendentes = [], []
    for f in faltando:
        inc = _diag_maybe_fix("proactive_scan", "arquivo_faltando", f)
        (aplicados if inc.get("status") == "corrigido" else pendentes).append(f)

    if aplicados:
        send_whatsapp_alert("admin", f"🛠️ Autodiagnóstico detectou e restaurou {len(aplicados)} arquivo(s) "
                                      f"de código ausente(s) no servidor: {', '.join(aplicados[:10])}")
    if pendentes:
        send_whatsapp_alert("admin", f"⚠️ Autodiagnóstico detectou {len(pendentes)} arquivo(s) de código "
                                      f"ausente(s) aguardando sua aprovação (modo não-automático): {', '.join(pendentes[:10])}")

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO — DETECÇÃO E NEUTRALIZAÇÃO AUTÔNOMA DE AMEAÇAS
# ══════════════════════════════════════════════════════════════════
# Item novo (setembro/2026), motivado por um incidente real: um
# minerador de criptomoeda entrou via força bruta de SSH numa conta
# Linux de teste com senha previsível, se instalou disfarçado num
# processo chamado "ksmd" (nome de uma thread real do kernel Linux,
# escolhido de propósito pra passar despercebido num "ps aux" rápido)
# rodando de dentro de um diretório oculto em /dev/shm, e consumiu ~92%
# de CPU do servidor -- foi isso que causou o "atraso/engasgo" do
# painel que o Simon percebeu primeiro pela lentidão da tela inicial.
#
# O que esta seção ensina o painel a fazer sozinho, sem esperar alguém
# notar a lentidão e investigar manualmente feito daquela vez:
#
#   1) reconhecer o MESMO PADRÃO (e variações dele) que causou aquele
#      incidente -- processo com nome de thread de kernel real mas que
#      na prática não é uma thread de kernel de verdade;
#   2) reconhecer diretórios ocultos em /dev/shm ou /tmp, o esconderijo
#      clássico desse tipo de ameaça (área em memória, some sozinha
#      num reboot, difícil de notar num "ls" comum por causa do ponto
#      no início do nome);
#   3) agir IMEDIATAMENTE, sem esperar aprovação do admin (ver
#      _diag_pode_auto_aplicar acima) -- matar o processo, travar a
#      conta Linux que o executava, apagar o diretório do payload, e
#      registrar tudo como um incidente técnico igual aos outros
#      (aparece em Diagnóstico > Incidentes técnicos, pode ser
#      perguntado à IA do painel pra mais contexto, e o admin é avisado
#      por WhatsApp na hora).
#
# O que ISSO NÃO FAZ (por decisão explícita do Simon): não mexe em como
# senhas de usuário são geradas/exigidas -- essa é uma frente separada,
# tratada à parte.

# Nomes de threads reais do kernel Linux que esse incidente (e ataques
# parecidos) costumam imitar. Uma thread de kernel de verdade SEMPRE
# roda como root, SEMPRE tem cmdline vazio (sem nenhum argumento -- o
# "ps aux" mostra ela entre colchetes, tipo "[ksmd]"), e o
# /proc/<pid>/exe dela nunca aponta pra um arquivo real (não existe
# link, porque não tem executável em disco -- vive só dentro do
# kernel). Se um processo usa um desses nomes MAS tem argumentos de
# linha de comando reais (como o "-c 3000 -t 5 -shuffle" do incidente)
# ou um /proc/<pid>/exe que aponta pra um arquivo de verdade, é
# impostor com certeza -- não existe cenário legítimo pra isso.
_SEC_KERNEL_THREAD_NAMES = frozenset({
    "ksmd", "kswapd0", "kswapd1", "kdevtmpfs", "kthreadd", "kauditd",
    "khungtaskd", "oom_reaper", "writeback", "kcompactd0", "kblockd",
    "rcu_gp", "rcu_par_gp", "rcu_sched", "migration", "watchdogd",
    "netns", "cpuhp", "idle_inject", "jbd2", "xfsaild", "scsi_eh",
    "kintegrityd", "kdmflush", "kswiotlb", "ksoftirqd",
})

# Estado de threats já tratadas nesta execução do painel, pra não
# registrar o mesmo incidente de novo a cada ciclo de varredura caso
# algo dê errado ao neutralizar (evita spam de WhatsApp/incidentes
# repetidos pro mesmíssimo processo/binário).
_SEC_HANDLED_STATE_F = "/etc/painel/security_handled.json"

def _sec_load_handled():
    try:
        with open(_SEC_HANDLED_STATE_F) as f:
            data = json.load(f)
        # só guarda os últimos 7 dias pra não crescer pra sempre
        cutoff = time.time() - 7 * 86400
        return {k: v for k, v in data.items() if v >= cutoff}
    except Exception:
        return {}

def _sec_mark_handled(sha256_ou_chave):
    data = _sec_load_handled()
    data[sha256_ou_chave] = time.time()
    try:
        _atomic_write_json(_SEC_HANDLED_STATE_F, data, indent=2)
    except Exception:
        pass

def _sec_processo_e_thread_kernel_falsa(pid):
    """Devolve um dict com a evidência se o PID for um processo se
    passando por thread de kernel, ou None se for legítimo (thread real
    OU um processo qualquer sem esse nome, que não nos interessa aqui)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            status_txt = f.read()
        comm = next((l.split(":", 1)[1].strip() for l in status_txt.splitlines() if l.startswith("Name:")), "")
    except Exception:
        return None

    if comm not in _SEC_KERNEL_THREAD_NAMES:
        return None

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline_raw = f.read()
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        cmdline = ""

    exe_path = None
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        exe_path = None

    # Thread de kernel de verdade: cmdline vazio E sem /proc/pid/exe.
    # Se qualquer um dos dois existir, é impostor.
    if not cmdline and not exe_path:
        return None

    motivo = (f"Processo chamado \"{comm}\" (nome reservado a uma thread real do kernel Linux) "
              f"mas rodando com {'linha de comando: ' + cmdline if cmdline else 'executável real em disco'}"
              f"{' (' + exe_path + ')' if exe_path else ''} -- threads de kernel de verdade nunca têm isso.")
    return {"pid": pid, "comm": comm, "cmdline": cmdline, "exe": exe_path, "motivo": motivo}

def _sec_scan_dirs_ocultos_shm_tmp():
    """Varre /dev/shm e /tmp por diretórios ESCONDIDOS (nome começando
    com ponto) de propriedade de um usuário comum (não root, não
    contas de serviço do sistema) -- o esconderijo clássico desse tipo
    de ameaça. Devolve lista de caminhos suspeitos encontrados."""
    achados = []
    for base in ("/dev/shm", "/tmp"):
        try:
            for nome in os.listdir(base):
                if not nome.startswith("."):
                    continue
                caminho = os.path.join(base, nome)
                if not os.path.isdir(caminho):
                    continue
                try:
                    st = os.stat(caminho)
                    dono = pwd.getpwuid(st.st_uid).pw_name
                except Exception:
                    dono = str(st.st_uid) if 'st' in dir() else "?"
                # Contas de serviço do sistema (uid baixo) que legitimamente
                # usam diretórios ocultos em /tmp não entram aqui -- só
                # usuários "normais" (uid >= 1000, o mesmo corte que o
                # Linux usa pra contas humanas) ou root com nome de dono
                # não reconhecido.
                try:
                    uid = pwd.getpwnam(dono).pw_uid
                except Exception:
                    uid = 0
                if uid >= 1000:
                    achados.append({"caminho": caminho, "dono": dono, "uid": uid})
        except Exception:
            continue
    return achados

def _sec_coletar_forense(pid_info, dir_oculto=None):
    """Enriquece a detecção com o que dá pra saber sobre o processo:
    dono (usuário Linux), hash do binário (pra registro/comparação
    futura, já que o conteúdo em si é apagado na neutralização) e o
    diretório oculto associado, se algum já foi localizado."""
    pid = pid_info["pid"]
    username = "desconhecido"
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    username = pwd.getpwuid(uid).pw_name
                    pid_info["uid"] = uid
                    break
    except Exception:
        pass
    pid_info["username"] = username

    sha256 = None
    exe = pid_info.get("exe")
    if exe and os.path.isfile(exe):
        try:
            h = hashlib.sha256()
            with open(exe, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except Exception:
            sha256 = None
    pid_info["sha256"] = sha256

    # Se o executável mora dentro de um diretório oculto conhecido,
    # associa pra apagar o diretório inteiro na neutralização (não só
    # o binário -- o kit costuma vir com vários arquivos de apoio).
    if not dir_oculto and exe:
        for base in ("/dev/shm", "/tmp"):
            if exe.startswith(base + "/."):
                partes = exe[len(base) + 1:].split("/")
                if partes:
                    dir_oculto = os.path.join(base, partes[0])
                break
    pid_info["dir_oculto"] = dir_oculto
    return pid_info

# Contas de sistema que NUNCA devem ser travadas automaticamente, não
# importa o que estejam rodando -- travar uma dessas derrubaria o
# próprio painel/servidor, o que seria pior que a ameaça em si.
_SEC_CONTAS_PROTEGIDAS = frozenset({
    "root", "www-data", "nobody", "daemon", "syslog", "messagebus",
    "systemd-timesync", "systemd-network", "systemd-resolve", "sshd",
})

def _sec_neutralizar(forense):
    """Executa de fato a neutralização: mata o processo, apaga o
    diretório do payload (se identificado) e trava a conta Linux que
    executava a ameaça (exceto contas protegidas do próprio sistema).
    Cada ação é registrada (sucesso ou falha) pra transparência total
    no incidente -- o admin (e a IA, se ele perguntar) veem exatamente
    o que foi feito, nunca uma "caixa preta"."""
    acoes = []
    ok_geral = True

    pid = forense.get("pid")
    if pid:
        _, rc = run_cmd(f"kill -9 {pid}")
        acoes.append(f"Processo PID {pid} ({forense.get('comm')}) encerrado" if rc == 0
                     else f"Falha ao encerrar PID {pid} (pode já ter terminado sozinho)")

    dir_oculto = forense.get("dir_oculto")
    if dir_oculto and dir_oculto.startswith(("/dev/shm/.", "/tmp/.")) and len(dir_oculto) > len("/dev/shm/."):
        # Trava extra de segurança: nunca apaga se o caminho resolvido
        # não for claramente um subdiretório oculto de /dev/shm ou
        # /tmp -- previne qualquer acidente de apagar algo importante
        # mesmo que a lógica acima tenha um bug.
        _, rc = run_cmd(f"rm -rf -- '{dir_oculto}'")
        acoes.append(f"Diretório do payload removido: {dir_oculto}" if rc == 0
                     else f"Falha ao remover diretório: {dir_oculto}")

    username = forense.get("username")
    uid = forense.get("uid", 0)
    if username and username not in _SEC_CONTAS_PROTEGIDAS and uid >= 1000:
        run_cmd(f"pkill -9 -u {username}")
        _, rc1 = run_cmd(f"usermod -L {username}")
        _, rc2 = run_cmd(f"usermod -s /usr/sbin/nologin {username}")
        acoes.append(f"Conta \"{username}\" travada (login por senha desabilitado, shell trocado pra nologin) "
                      f"-- reative manualmente em Usuários se confirmar que não foi ela a origem do problema"
                      if (rc1 == 0 or rc2 == 0) else f"Falha ao travar a conta \"{username}\"")
    elif username in _SEC_CONTAS_PROTEGIDAS:
        acoes.append(f"Conta \"{username}\" é uma conta de sistema protegida -- NÃO travada automaticamente, revise manualmente")

    if not acoes:
        ok_geral = False
        acoes.append("Nenhuma ação pôde ser determinada com segurança -- revise manualmente")

    return {"ok": ok_geral, "acoes": acoes}

def _diag_security_scan():
    """Ponto de entrada da varredura de segurança -- chamado
    periodicamente pelo server_health_scheduler_loop (a cada 2 minutos,
    bem mais frequente que os outros checks de 10 min, porque uma
    ameaça ativa piora rápido). Passos: 1) procura processo disfarçado
    de thread de kernel entre TODOS os processos rodando; 2) procura
    diretório oculto em /dev/shm ou /tmp; 3) cruza os dois quando dá; 4)
    neutraliza e registra incidente pra cada ameaça nova encontrada."""
    handled = _sec_load_handled()
    dirs_ocultos = _sec_scan_dirs_ocultos_shm_tmp()

    achou_algo = False
    try:
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except Exception:
        pids = []

    for pid in pids:
        pid_info = _sec_processo_e_thread_kernel_falsa(pid)
        if not pid_info:
            continue
        # Chave de dedupe: hash do binário se der pra calcular, senão
        # comm+exe (ainda assim evita repetir se o processo não sumiu
        # entre um ciclo e outro por algum motivo).
        forense = _sec_coletar_forense(pid_info, dir_oculto=(dirs_ocultos[0]["caminho"] if dirs_ocultos else None))
        chave = forense.get("sha256") or f"{forense.get('comm')}:{forense.get('exe')}"
        if chave in handled:
            continue

        achou_algo = True
        _diag_maybe_fix("security_scan", "ameaca_seguranca", forense)
        _sec_mark_handled(chave)

    # Diretório oculto encontrado mas SEM processo rodando associado
    # (ex: o payload já terminou sozinho, ou ainda não foi executado) --
    # ainda vale registrar e limpar, só não tem processo pra matar.
    for d in dirs_ocultos:
        chave = f"dir:{d['caminho']}"
        if chave in handled:
            continue
        achou_algo = True
        forense = {"comm": "(diretório oculto sem processo ativo)", "pid": None, "exe": None,
                   "cmdline": "", "username": d["dono"], "uid": d["uid"], "sha256": None,
                   "dir_oculto": d["caminho"],
                   "motivo": f"Diretório oculto em local de memória compartilhada, pertencente ao usuário \"{d['dono']}\": {d['caminho']}"}
        _diag_maybe_fix("security_scan", "ameaca_seguranca", forense)
        _sec_mark_handled(chave)

    return achou_algo

def security_watchdog_loop():
    """Roda em paralelo ao resto do painel desde a inicialização,
    verificando o servidor a cada 2 minutos -- bem mais frequente que
    o server_health_scheduler_loop (10 min) porque, como vimos no
    incidente real, uma ameaça de CPU/mineração some sozinha entre
    rajadas e pode passar despercebida num intervalo maior."""
    while True:
        try:
            _diag_security_scan()
        except Exception as e:
            try:
                system_log_write(f"security_watchdog_loop: erro inesperado na varredura -- {e}")
            except Exception:
                pass
        time.sleep(120)

def server_health_scheduler_loop():
    """Item: avisos de eventos do servidor — checa serviços caídos e
    disco cheio a cada 10 minutos. Desde a integração com o autodiagnóstico,
    quando um serviço monitorado cai, o painel TENTA reiniciá-lo sozinho
    conforme o modo de automação (nunca é um reboot de servidor, é só o
    processo/serviço específico — isso nunca derruba conexões de quem já
    está online em outros serviços) e sempre avisa o admin por WhatsApp
    sobre o que fez (ou o que está esperando aprovação)."""
    while True:
        try:
            state = {}
            if os.path.exists(SERVER_HEALTH_STATE):
                try:
                    with open(SERVER_HEALTH_STATE) as f:
                        state = json.load(f)
                except Exception:
                    state = {}

            stats = get_system_stats()
            changed = False

            disk = stats.get("disk", 0)
            was_full = state.get("disk_full", False)
            if disk >= 90 and not was_full:
                send_whatsapp_alert("admin", f"🚨 Disco do servidor em {disk}% de uso! Libere espaço antes que afete o serviço.")
                state["disk_full"] = True; changed = True
            elif disk < 85 and was_full:
                send_whatsapp_alert("admin", f"✅ Disco do servidor normalizado ({disk}% de uso).")
                state["disk_full"] = False; changed = True

            svc_state = state.setdefault("services", {})
            for svc in MONITORED_SERVICES:
                # FIX: slowdns e opcional -- so existe processo rodando se
                # o admin configurou (gerou dominio/chaves). Sem isso, "parado"
                # e o estado normal/esperado, nao queda -- nunca gerar incidente.
                if svc == "slowdns" and not os.path.exists(f"{SLOWDNS_DIR}/domain"):
                    continue
                # FIX: mesmo raciocínio do slowdns acima — em servidores
                # atualizados de uma versão anterior à v41 (repair.sh/
                # boot_check.sh ainda não recriaram o serviço), o SSL pode
                # simplesmente não ter sido configurado ainda. "Parado"
                # nesse caso é o estado normal, não uma queda.
                if svc == "stunnel" and not os.path.exists(STUNNEL_SETTINGS):
                    continue
                up = service_status(svc)
                was_up = svc_state.get(svc, True)
                if not up and was_up:
                    modo = _diag_mode()
                    if _diag_pode_auto_aplicar("servico_parado", modo):
                        up_depois, evidencia, _ = _diag_restart_service_com_evidencia(svc)
                        if up_depois:
                            tentativas = (evidencia or {}).get("tentativas") if evidencia else None
                            acoes = [a for t in (tentativas or []) for a in (t.get("acoes_corretivas") or [])]
                            if acoes:
                                detalhe_msg = " (precisou de correção extra: " + "; ".join(acoes) + ")"
                                correcao_txt = "Religado após correção automática: " + "; ".join(acoes)
                            else:
                                detalhe_msg = ""
                                correcao_txt = f"Reiniciado automaticamente ({svc})"
                            send_whatsapp_alert("admin", f"🛠️ Serviço *{svc}* caiu e foi reiniciado automaticamente pelo autodiagnóstico. Já está normal de novo.{detalhe_msg}")
                            _diag_register({
                                "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                                "causa_detalhe": f"Serviço '{svc}' estava fora do ar (checagem periódica)",
                                "correcao": correcao_txt, "status": "corrigido",
                                "auto_aplicada": True, "servico_reiniciado": svc, "notificado_whatsapp": True,
                                "diagnostico": evidencia,
                            })
                            svc_state[svc] = True
                        else:
                            label = SERVICE_DIAG_INFO.get(svc, {}).get("label", svc)
                            dica = (evidencia or {}).get("dica", "")
                            send_whatsapp_alert("admin", f"🚨 Serviço *{svc}* ({label}) caiu e a tentativa automática de "
                                                          f"reinício FALHOU. {dica}\nAbra Diagnóstico > Incidentes técnicos "
                                                          f"no painel pra ver o detalhe completo e tentar de novo com um clique.")
                            _diag_register({
                                "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                                "causa_detalhe": f"Serviço '{svc}' fora do ar — tentativa automática de reinício falhou",
                                "correcao": None, "status": "falhou",
                                "auto_aplicada": True, "notificado_whatsapp": True,
                                "diagnostico": evidencia,
                            })
                            svc_state[svc] = False
                    else:
                        evidencia = _diag_collect_service_evidence(svc)
                        send_whatsapp_alert("admin", f"🚨 Serviço *{svc}* caiu e está aguardando sua aprovação pra "
                                                      f"reiniciar (modo de automação: {modo}). Acesse Diagnóstico > Incidentes técnicos.")
                        _diag_register({
                            "origem": "service_watchdog", "causa_tipo": "servico_parado", "alvo_bruto": svc,
                            "causa_detalhe": f"Serviço '{svc}' fora do ar — aguardando aprovação (modo {modo})",
                            "correcao": None, "status": "pendente_aprovacao",
                            "auto_aplicada": False, "notificado_whatsapp": True,
                            "diagnostico": evidencia,
                        })
                        svc_state[svc] = False
                    changed = True
                elif up and not was_up:
                    send_whatsapp_alert("admin", f"✅ Serviço *{svc}* voltou ao normal.")
                    svc_state[svc] = True; changed = True

            if changed:
                with open(SERVER_HEALTH_STATE, "w") as f:
                    json.dump(state, f)

            _diag_proactive_file_scan()
        except Exception as e:
            system_log_write(f"SERVER HEALTH SCHEDULER erro: {e}")
        time.sleep(600)  # a cada 10 minutos


def whatsapp_notify_scheduler_loop():
    """Roda em background: para cada painel (admin/revendedores) com o
    WhatsApp habilitado, verifica quem vence dentro do prazo configurado
    e dispara a mensagem — no máximo uma vez por dia por usuário."""
    while True:
        try:
            painel_cfg = load_config()
            users = read_users()
            phones = painel_cfg.get("user_phones", {})
            sent_log = _load_wa_sent_log()
            today = datetime.date.today().isoformat()

            owners = ["admin"] + list(painel_cfg.get("resellers", {}).keys())
            for owner in owners:
                wa = get_owner_wa_config(owner)
                if not wa.get("enabled"):
                    continue
                if owner == "admin":
                    scope_logins = {u["login"] for u in users} - all_owned_logins_all(painel_cfg)
                else:
                    scope_logins = all_owned_logins(painel_cfg, owner) if owner in painel_cfg.get("resellers", {}) else set()

                for u in users:
                    if u["login"] not in scope_logins:
                        continue
                    phone = phones.get(u["login"])
                    if not phone:
                        continue
                    dt = _parse_dt(u["expira"])
                    if not dt:
                        continue
                    dias = (dt - datetime.datetime.now()).total_seconds() / 86400
                    if not (0 <= dias <= wa.get("days_before", 1)):
                        continue
                    log_key = f"{u['login']}|{today}"
                    if sent_log.get(log_key):
                        continue
                    dias_txt = "menos de 1 dia" if dias < 1 else f"{int(dias)} dia(s)"
                    msg = wa["message_template"].format(
                        nome=u["login"], login=u["login"], dias_txt=dias_txt,
                        vencimento=u["expira"], pix=wa.get("pix_key", "")
                    )
                    try:
                        requests.post(f"{WHATSAPP_NODE}/send", json={"owner": owner, "phone": phone, "message": msg}, timeout=10)
                        sent_log[log_key] = True
                    except Exception:
                        pass
            _save_wa_sent_log(sent_log)
        except Exception as e:
            device_log_write(f"WHATSAPP SCHEDULER erro: {e}")
        time.sleep(3600)  # checa a cada hora

def whatsapp_reengage_scheduler_loop():
    """Roda em background: pra cada painel (admin/revendedores) com o
    reengajamento habilitado, procura contatos que não interagem com o
    bot há X dias e manda a mensagem pré-definida — respeitando um
    intervalo mínimo de reenvio por contato, um limite de tentativas, e
    uma PAUSA entre cada envio do lote (pra não levar o número a ser
    marcado como spam pelo WhatsApp). Não incomoda contatos que estão
    em atendimento humano no momento."""
    while True:
        try:
            painel_cfg = load_config()
            owners = ["admin"] + list(painel_cfg.get("resellers", {}).keys())
            contacts = _load_wa_contacts()
            bot_state = _load_bot_state()
            changed = False

            for owner in owners:
                wa = get_owner_wa_config(owner)
                if not wa.get("bot_reengage_enabled"):
                    continue

                inactive_days = float(wa.get("bot_reengage_inactive_days", 60) or 60)
                resend_days   = float(wa.get("bot_reengage_resend_interval_days", 30) or 30)
                max_attempts  = int(wa.get("bot_reengage_max_attempts", 3) or 0)
                delay_s       = max(5, int(wa.get("bot_reengage_send_delay_seconds", 30) or 30))
                prefix = f"{owner}|"

                for key, info in list(contacts.items()):
                    if not key.startswith(prefix):
                        continue
                    phone = key.split("|", 1)[1]

                    # não incomoda quem está em atendimento humano agora
                    if bot_state.get(key, {}).get("human"):
                        continue

                    last_seen = info.get("last_seen", 0)
                    if not last_seen:
                        continue
                    idle_days = (time.time() - last_seen) / 86400
                    if idle_days < inactive_days:
                        continue

                    last_sent = info.get("last_reengage_sent", 0)
                    since_sent_days = (time.time() - last_sent) / 86400 if last_sent else 999999
                    if since_sent_days < resend_days:
                        continue

                    attempts = info.get("reengage_count", 0)
                    if max_attempts and attempts >= max_attempts:
                        continue

                    login = _find_login_by_phone(painel_cfg, phone, owner)
                    try:
                        msg = wa["bot_reengage_message"].format(login=login or "", dias=int(idle_days))
                    except Exception:
                        msg = wa["bot_reengage_message"]  # template sem os placeholders — envia como está

                    _wa_send(owner, phone, msg)
                    info["last_reengage_sent"] = time.time()
                    info["reengage_count"] = attempts + 1
                    changed = True
                    device_log_write(f"BOT WHATSAPP: reengajamento enviado pra {phone} (painel {owner}, tentativa {attempts + 1}, {int(idle_days)}d inativo)")

                    # Item: pausa entre CADA envio do lote (mesmo pra
                    # contatos diferentes) — protege o número de ser
                    # sinalizado como spam por disparo em massa.
                    time.sleep(delay_s)

            if changed:
                _save_wa_contacts(contacts)
        except Exception as e:
            device_log_write(f"WHATSAPP REENGAGE SCHEDULER erro: {e}")
        time.sleep(6 * 3600)  # verifica novos contatos inativos a cada 6 horas

def all_owned_logins_all(cfg):
    """Todos os logins pertencentes a QUALQUER revendedor (usado para
    achar, por exclusão, quem foi criado diretamente pelo admin)."""
    logins = set()
    for name in cfg.get("resellers", {}):
        logins |= set(cfg["resellers"][name].get("users", []))
    return logins

# ══════════════════════════════════════════════════════════════════
#  CAMPANHAS DE REENGAJAMENTO MANUAIS — controle total do admin sobre
#  quem recebe, quando, com que mídia, no ritmo que quiser, com
#  relatório de entrega/leitura e histórico reaproveitável.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_CAMPAIGNS   = "/etc/painel/whatsapp_campaigns.json"
CAMPAIGN_MEDIA_DIR   = "/etc/painel/wa_campaign_media"
ALLOWED_CAMPAIGN_EXT = {
    "image":    {"jpg", "jpeg", "png", "webp"},
    "video":    {"mp4", "3gp", "mov"},
    "document": {"apk", "pdf", "zip", "doc", "docx", "xls", "xlsx", "txt"},
}

_campaign_lock    = threading.Lock()   # protege leitura/escrita concorrente do JSON
_campaign_threads = {}                 # campaign_id -> Thread em execução

# ── Lista mestre de "sucessos" ──────────────────────────────────────
# Item pedido: uma lista SEPARADA e CUMULATIVA (nunca é resetada por
# campanha) de contatos que já receberam mensagem com confirmação real
# do WhatsApp em pelo menos uma campanha — ou seja, contatos que a
# gente SABE que têm WhatsApp ativo. A cada campanha nova, os contatos
# que derem certo se somam aos que já estavam, nunca substituem. Serve
# pra, com o tempo, você identificar quem da sua base ainda tem
# WhatsApp de verdade e limpar o resto.
WHATSAPP_SUCCESS_CONTACTS = "/etc/painel/whatsapp_success_contacts.json"
_success_lock = threading.Lock()

def _load_success_contacts():
    if not os.path.exists(WHATSAPP_SUCCESS_CONTACTS):
        return {}
    try:
        with open(WHATSAPP_SUCCESS_CONTACTS) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_success_contacts(data):
    tmp = WHATSAPP_SUCCESS_CONTACTS + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, WHATSAPP_SUCCESS_CONTACTS)

_STATUS_ORDER = {"enviado": 1, "entregue": 2, "visualizado": 3}

def _record_campaign_success(owner, phone, name, campaign_id, campaign_name, status):
    """Chamado toda vez que uma mensagem de campanha é aceita pelo
    WhatsApp (status 'enviado' ou melhor) — soma esse contato na lista
    mestre, cumulativa entre campanhas. Nunca remove ninguém e nunca
    regride o 'melhor status' já alcançado."""
    with _success_lock:
        data = _load_success_contacts()
        key = f"{owner}|{phone}"
        entry = data.setdefault(key, {
            "phone": phone,
            "name": name,
            "first_success_at": time.time(),
            "last_success_at": time.time(),
            "best_status": status,
            "campaigns": [],
        })
        entry["last_success_at"] = time.time()
        if name and (not entry.get("name")):
            entry["name"] = name
        if _STATUS_ORDER.get(status, 0) > _STATUS_ORDER.get(entry.get("best_status"), 0):
            entry["best_status"] = status

        campanhas_registradas = entry.setdefault("campaigns", [])
        existente = next((c for c in campanhas_registradas if c.get("campaign_id") == campaign_id), None)
        if existente:
            if _STATUS_ORDER.get(status, 0) > _STATUS_ORDER.get(existente.get("status"), 0):
                existente["status"] = status
                existente["at"] = time.time()
        else:
            campanhas_registradas.append({
                "campaign_id": campaign_id, "campaign_name": campaign_name,
                "status": status, "at": time.time(),
            })
        _save_success_contacts(data)

def _load_campaigns():
    if not os.path.exists(WHATSAPP_CAMPAIGNS):
        return []
    try:
        with open(WHATSAPP_CAMPAIGNS) as f:
            return json.load(f)
    except Exception:
        return []

def _save_campaigns(data):
    _atomic_write_json(WHATSAPP_CAMPAIGNS, data, indent=2)

def _get_campaign(campaigns, campaign_id, owner):
    return next((c for c in campaigns if c["id"] == campaign_id and c["owner"] == owner), None)

def _campaign_match_contacts(owner, filters):
    """Aplica os filtros da campanha sobre os contatos conhecidos do
    bot: mês/ano EXATO da última interação (não "há X dias" — o admin
    escolhe precisamente o período, ex: 05/2022), opcionalmente um
    trecho do nome do contato (nome que o WhatsApp entrega — nem
    sempre é o nome que você salvou na sua agenda, ver tag abaixo), e/
    ou uma TAG atribuída manualmente/por importação (ex: "revendedor")
    — essa sim é 100% controlada por você, não depende do que o
    WhatsApp compartilha.

    Item: filtros de EXCLUSÃO — além dos filtros de inclusão acima,
    dá pra excluir do público final por período/nome/tag (ex: "todos
    os contatos, menos quem falou com a gente em 2023" = nenhum filtro
    de inclusão + exclude_year=2023) e/ou excluir/incluir números
    específicos na mão (excluded_phones / included_phones — decisão
    manual sobre AQUELE contato, sempre por cima de qualquer filtro:
    inclusão manual vence exclusão por filtro, e vice-versa em relação
    ao filtro de inclusão — é a vontade explícita do admin sobre um
    contato específico).

    Item: exclude_months aceita uma LISTA de meses (não só um) — ex:
    "excluir março E junho de 2021" = exclude_year=2021 +
    exclude_months=[3, 6]. Mantém compatibilidade com campanhas salvas
    antes dessa mudança, que guardavam só um mês em "exclude_month".

    Item: BUG CORRIGIDO — antes, um contato SEM nenhum "last_seen"
    registrado (ex: importado manualmente, nunca trocou mensagem)
    era excluído de QUALQUER campanha, mesmo com "qualquer mês/
    qualquer ano" selecionado — ou seja, "sem filtro" não trazia
    literalmente todos os contatos que o painel conhecia. Agora só
    exige last_seen quando month/year de fato filtram por período;
    sem esse filtro, o contato entra normalmente (mostra "—" na coluna
    de última interação)."""
    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    month = filters.get("month")   # 1-12 ou None/"" (qualquer mês)
    year  = filters.get("year")    # ex: 2022, ou None/"" (qualquer ano)
    name_contains = (filters.get("name_contains") or "").strip().lower()
    tag_filter = (filters.get("tag") or "").strip().lower()

    exclude_months_raw = filters.get("exclude_months")
    if exclude_months_raw is None:
        # compat com campanhas/chamadas antigas — só 1 mês em exclude_month
        legacy = filters.get("exclude_month")
        exclude_months_raw = [legacy] if legacy not in (None, "", 0, "0") else []
    exclude_months = {int(m) for m in exclude_months_raw if str(m).strip() not in ("", "0")}
    exclude_year  = filters.get("exclude_year")
    exclude_name_contains = (filters.get("exclude_name_contains") or "").strip().lower()
    exclude_tag = (filters.get("exclude_tag") or "").strip().lower()
    excluded_phones = set(filters.get("excluded_phones") or [])
    included_phones = list(dict.fromkeys(filters.get("included_phones") or []))

    month = int(month) if month not in (None, "", 0, "0") else None
    year  = int(year) if year not in (None, "", 0, "0") else None
    exclude_year  = int(exclude_year) if exclude_year not in (None, "", 0, "0") else None

    matched = []
    seen_phones = set()
    for key, info in contacts.items():
        if not key.startswith(prefix):
            continue
        phone = key.split("|", 1)[1]
        last_seen = info.get("last_seen")
        dt = datetime.datetime.fromtimestamp(last_seen) if last_seen else None

        if (year is not None or month is not None):
            if not dt:
                continue
            if year is not None and dt.year != year:
                continue
            if month is not None and dt.month != month:
                continue
        name = info.get("name", "")
        if name_contains and name_contains not in name.lower():
            continue
        tags = info.get("tags") or []
        if tag_filter and tag_filter not in [t.lower() for t in tags]:
            continue

        # exclusões — número específico marcado na mão sempre exclui
        if phone in excluded_phones:
            continue
        if dt and exclude_year is not None and dt.year == exclude_year and (not exclude_months or dt.month in exclude_months):
            continue
        if dt and exclude_months and exclude_year is None and dt.month in exclude_months:
            continue
        if exclude_name_contains and exclude_name_contains in name.lower():
            continue
        if exclude_tag and exclude_tag in [t.lower() for t in tags]:
            continue

        matched.append({
            "phone": phone,
            "name": name,
            "tags": tags,
            "last_seen": last_seen,
            "last_seen_txt": dt.strftime("%d/%m/%Y") if dt else "—",
        })
        seen_phones.add(phone)

    # Inclusões manuais — o admin escolheu esse contato especificamente
    # (na busca da tela de campanha), então ele entra mesmo que não bata
    # com nenhum filtro de inclusão e mesmo que bata com uma exclusão.
    for phone in included_phones:
        if phone in seen_phones:
            continue
        info = contacts.get(f"{prefix}{phone}")
        if not info:
            continue
        last_seen = info.get("last_seen")
        dt = datetime.datetime.fromtimestamp(last_seen) if last_seen else None
        matched.append({
            "phone": phone,
            "name": info.get("name", ""),
            "tags": info.get("tags") or [],
            "last_seen": last_seen,
            "last_seen_txt": dt.strftime("%d/%m/%Y") if dt else "—",
        })
        seen_phones.add(phone)

    # Item: ordem de envio pra reengajamento de verdade — quem tem a
    # interação mais ANTIGA recebe primeiro (ordem crescente de data),
    # dentro do grupo filtrado (mês específico ou "todos os clientes").
    # Contato sem last_seen (None -> 0) entra como "mais antigo" de
    # todos, o que faz sentido: nunca recebeu nada da gente ainda.
    matched.sort(key=lambda c: c["last_seen"] or 0)
    return matched

def _campaign_summary(campaign):
    results = campaign.get("results", {})
    total = len(campaign.get("targets", []))
    enviado     = sum(1 for r in results.values() if r["status"] in ("enviado", "entregue", "visualizado"))
    entregue    = sum(1 for r in results.values() if r["status"] in ("entregue", "visualizado"))
    visualizado = sum(1 for r in results.values() if r["status"] == "visualizado")
    falhou      = sum(1 for r in results.values() if r["status"] == "falhou")
    pendente    = total - len(results)
    return {
        "total": total, "pendente": pendente, "enviado": enviado,
        "entregue": entregue, "visualizado": visualizado, "falhou": falhou,
    }

def _next_business_window(dt):
    """Item: filtro de 'dias úteis + horário comercial' das campanhas.
    Dado um datetime, devolve ele mesmo se já estiver dentro da janela
    (seg–sex, 08:00–22:00), ou o próximo horário válido (podendo pular
    fim de semana) caso contrário."""
    while True:
        if dt.weekday() >= 5:  # 5=sábado, 6=domingo
            dt = (dt + datetime.timedelta(days=1)).replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        if dt.hour < 8:
            dt = dt.replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        if dt.hour >= 22:
            dt = (dt + datetime.timedelta(days=1)).replace(hour=8, minute=0, second=0, microsecond=0)
            continue
        return dt

def _sleep_checking_pause(campaign_id, seconds):
    """Dorme em pedaços de até 30 min, checando a cada retomada se a
    campanha foi pausada/removida nesse meio tempo — usado nas esperas
    longas (limite diário, agendamento) pra reagir rápido a um clique em
    "Pausar" mesmo no meio de uma espera de várias horas."""
    remaining = seconds
    while remaining > 0:
        time.sleep(min(remaining, 1800))
        remaining -= 1800
        campaigns = _load_campaigns()
        c = next((x for x in campaigns if x["id"] == campaign_id), None)
        if not c or c.get("paused") or c["status"] != "enviando":
            return False
    return True

def run_campaign_worker(campaign_id):
    """Roda em background e vai mandando a mensagem pra cada contato do
    lote, um de cada vez, respeitando a pausa entre envios e o limite
    diário configurados. Verifica o campo 'paused' a cada iteração — se
    o admin pausar pelo painel, o worker para exatamente onde está
    (guarda o "cursor") e um clique em "Retomar" continua dali, sem
    repetir quem já recebeu."""
    try:
        while True:
            with _campaign_lock:
                campaigns = _load_campaigns()
                campaign = next((c for c in campaigns if c["id"] == campaign_id), None)
                if not campaign or campaign.get("paused") or campaign["status"] != "enviando":
                    return  # foi pausada, apagada, ou terminou por outro caminho

                cursor = campaign.get("cursor", 0)
                targets = campaign.get("targets", [])
                if cursor >= len(targets):
                    campaign["status"] = "concluida"
                    campaign["finished_at"] = time.time()
                    _save_campaigns(campaigns)
                    owner = campaign["owner"]
                    s = _campaign_summary(campaign)
                    send_whatsapp_alert(
                        owner,
                        f"📣 Campanha \"{campaign['name']}\" concluída!\n"
                        f"👥 Total: {s['total']} | ✅ Enviados: {s['enviado']} | "
                        f"📩 Entregues: {s['entregue']} | 👁️ Visualizados: {s['visualizado']} | ⚠️ Falhas: {s['falhou']}"
                    )
                    device_log_write(f"CAMPANHA '{campaign['name']}' ({owner}) concluída: {s}")
                    return

                # Item: limite de envios por dia — se já bateu o teto de
                # hoje, espera até a madrugada seguinte antes de continuar
                # (sem contar como pausada; a barra de status mostra
                # "enviando" normalmente, só está represada até amanhã).
                max_per_day = int(campaign.get("max_per_day", 0) or 0)
                today_str = datetime.date.today().isoformat()
                if campaign.get("sent_today_date") != today_str:
                    campaign["sent_today_date"] = today_str
                    campaign["sent_today_count"] = 0
                    _save_campaigns(campaigns)
                if max_per_day and campaign.get("sent_today_count", 0) >= max_per_day:
                    amanha = (datetime.datetime.now() + datetime.timedelta(days=1)).replace(hour=0, minute=5, second=0, microsecond=0)
                    wait_s = (amanha - datetime.datetime.now()).total_seconds()
                    device_log_write(f"CAMPANHA '{campaign['name']}' ({campaign['owner']}): limite diário de {max_per_day} envios atingido — retomando amanhã")
                    should_continue = _sleep_checking_pause(campaign_id, wait_s)
                    if not should_continue:
                        return
                    continue  # reavalia tudo do zero (dia já virou, contador zera acima)

                target = targets[cursor]
                phone = target["phone"]
                owner = campaign["owner"]
                media = campaign.get("media")

                # Item: "enviar só em dias úteis/horário comercial" — se
                # agora está fora da janela, espera (sem perder o lugar
                # na fila nem contar como pausada) até o próximo horário
                # válido antes de mandar essa mensagem.
                if campaign.get("business_window"):
                    now = datetime.datetime.now()
                    proximo = _next_business_window(now)
                    if proximo > now:
                        wait_s = (proximo - now).total_seconds()
                        device_log_write(
                            f"CAMPANHA '{campaign['name']}' ({owner}): fora do horário comercial, "
                            f"retomando em {proximo.strftime('%d/%m %H:%M')}"
                        )
                        should_continue = _sleep_checking_pause(campaign_id, wait_s)
                        if not should_continue:
                            return
                        continue  # reavalia tudo do zero (limite diário etc. também podem ter mudado)

            ok, result = _wa_send_media(owner, phone, campaign["message"], media=media if media and media.get("path") else None)

            # Item CRÍTICO: log de auditoria por CONTATO, individual — sem
            # isso não tinha como provar se o worker realmente tentou
            # mandar pra um número específico ou se ele nunca chegou nem a
            # tentar (ex: thread travada em outra espera, exceção
            # engolida antes de chegar aqui). Agora toda tentativa —
            # sucesso ou falha — fica registrada no log de dispositivos
            # (mesmo arquivo que a tela "Logs" do painel já lê), com o
            # motivo exato quando falha (ex: "número não registrado no
            # WhatsApp").
            device_log_write(
                f"CAMPANHA '{campaign['name']}' ({owner}): tentativa de envio pro contato {phone} "
                f"[{cursor + 1}/{len(targets)}] -> {'OK (msg_id=' + str(result) + ')' if ok else 'FALHOU (' + str(result) + ')'}"
            )

            with _campaign_lock:
                campaigns = _load_campaigns()
                campaign = next((c for c in campaigns if c["id"] == campaign_id), None)
                if not campaign:
                    return
                campaign.setdefault("results", {})
                if ok:
                    campaign["results"][phone] = {
                        "status": "enviado", "msg_id": result,
                        "sent_at": time.time(), "delivered_at": None, "read_at": None,
                    }
                    _record_campaign_success(
                        owner, phone, _get_contact_name(owner, phone),
                        campaign_id, campaign.get("name", ""), "enviado",
                    )
                else:
                    campaign["results"][phone] = {
                        "status": "falhou", "msg_id": None, "error": str(result),
                        "sent_at": time.time(), "delivered_at": None, "read_at": None,
                    }
                campaign["cursor"] = cursor + 1
                campaign["sent_today_count"] = campaign.get("sent_today_count", 0) + 1
                _save_campaigns(campaigns)

            delay_s = max(5, int(campaign.get("delay_seconds", 30)))
            if campaign.get("hourly_interval"):
                delay_s = max(delay_s, 3600)  # item: intervalo mínimo de 1h entre cada envio
            should_continue = _sleep_checking_pause(campaign_id, delay_s)
            if not should_continue:
                return
    except Exception as e:
        device_log_write(f"CAMPANHA {campaign_id} worker erro: {e}")

def _start_campaign_thread(campaign_id):
    existing = _campaign_threads.get(campaign_id)
    if existing and existing.is_alive():
        return  # já rodando, não duplica
    t = threading.Thread(target=run_campaign_worker, args=(campaign_id,), daemon=True)
    _campaign_threads[campaign_id] = t
    t.start()

def whatsapp_campaign_scheduler_loop():
    """Roda em background verificando campanhas agendadas — assim que o
    horário escolhido chega, inicia o envio sozinho, sem precisar que o
    admin esteja com o painel aberto na hora."""
    while True:
        try:
            with _campaign_lock:
                campaigns = _load_campaigns()
                changed = False
                for c in campaigns:
                    if c["status"] == "agendada" and c.get("scheduled_at") and time.time() >= c["scheduled_at"]:
                        c["status"] = "enviando"
                        changed = True
                        device_log_write(f"CAMPANHA '{c['name']}' ({c['owner']}): horário agendado chegou, iniciando envio")
                if changed:
                    _save_campaigns(campaigns)
            for c in _load_campaigns():
                if c["status"] == "enviando" and not c.get("paused"):
                    _start_campaign_thread(c["id"])
        except Exception as e:
            device_log_write(f"CAMPANHA scheduler erro: {e}")
        time.sleep(60)

# ══════════════════════════════════════════════════════════════════
#  MODELOS DE MENSAGENS — mensagens salvas (texto + mídia opcional)
#  reaproveitáveis em qualquer tela de envio (Nova Campanha Manual,
#  Mensagem Aleatória Programável, e futuras telas de envio) via botão
#  "➕ Adicionar modelo", sem precisar redigitar/reanexar tudo de novo
#  a cada campanha/mensagem.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_MSG_TEMPLATES = "/etc/painel/whatsapp_message_templates.json"
TEMPLATE_MEDIA_DIR     = "/etc/painel/wa_template_media"
_template_lock = threading.Lock()

def _load_templates():
    if not os.path.exists(WHATSAPP_MSG_TEMPLATES):
        return []
    try:
        with open(WHATSAPP_MSG_TEMPLATES) as f:
            return json.load(f)
    except Exception:
        return []

def _save_templates(data):
    _atomic_write_json(WHATSAPP_MSG_TEMPLATES, data, indent=2)

def _get_template(templates, template_id, owner):
    return next((t for t in templates if t["id"] == template_id and t["owner"] == owner), None)

def _copy_template_media(template, dest_dir):
    """Copia o arquivo de mídia de um modelo pra dest_dir — usado quando
    uma campanha/mensagem avulsa é criada 'a partir de um modelo', pra não
    depender do navegador conseguir reanexar um arquivo que já está salvo
    só no servidor (o input file não aceita valor setado por script)."""
    media = template.get("media")
    if not media or not media.get("path") or not os.path.exists(media["path"]):
        return None
    os.makedirs(dest_dir, exist_ok=True)
    filename = media.get("filename") or os.path.basename(media["path"])
    dest_path = os.path.join(dest_dir, filename)
    shutil.copyfile(media["path"], dest_path)
    return {"type": media["type"], "path": dest_path, "filename": filename}

@app.route("/api/whatsapp/message-templates", methods=["GET"])
@auth_required()
def template_list():
    owner = _owner_key(request.ns_session)
    templates = [t for t in _load_templates() if t["owner"] == owner]
    templates.sort(key=lambda t: t["created_at"], reverse=True)
    return jsonify(templates)

@app.route("/api/whatsapp/message-templates", methods=["POST"])
@auth_required()
def template_create():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    message = (data.get("message") or "").strip()
    if not name:
        return jsonify({"error": "Dê um nome pro modelo"}), 400
    if not message and not data.get("has_media"):
        return jsonify({"error": "Escreva uma mensagem ou anexe uma mídia pro modelo"}), 400
    template = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "name": name,
        "message": message,
        "media": None,
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
    }
    with _template_lock:
        templates = _load_templates()
        templates.append(template)
        _save_templates(templates)
    return jsonify(template), 201

@app.route("/api/whatsapp/message-templates/<template_id>/media", methods=["POST"])
@auth_required()
def template_upload_media(template_id):
    owner = _owner_key(request.ns_session)
    with _template_lock:
        templates = _load_templates()
        template = _get_template(templates, template_id, owner)
        if not template:
            return jsonify({"error": "Modelo não encontrado"}), 404
        if "file" not in request.files:
            return jsonify({"error": "Nenhum arquivo enviado"}), 400
        file = request.files["file"]
        media_type = request.form.get("mediaType", "").strip()
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
            return jsonify({"error": f"Extensão .{ext} não permitida para {media_type or 'esse tipo'}"}), 400
        tmpl_dir = os.path.join(TEMPLATE_MEDIA_DIR, template_id)
        os.makedirs(tmpl_dir, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(tmpl_dir, filename)
        file.save(filepath)
        template["media"] = {"type": media_type, "path": filepath, "filename": filename}
        _save_templates(templates)
        return jsonify({"ok": True, "media": template["media"]})

@app.route("/api/whatsapp/message-templates/<template_id>", methods=["DELETE"])
@auth_required()
def template_delete(template_id):
    owner = _owner_key(request.ns_session)
    with _template_lock:
        templates = _load_templates()
        template = _get_template(templates, template_id, owner)
        if not template:
            return jsonify({"error": "Modelo não encontrado"}), 404
        media = template.get("media")
        if media and media.get("path") and os.path.exists(media["path"]):
            try:
                shutil.rmtree(os.path.dirname(media["path"]), ignore_errors=True)
            except Exception:
                pass
        templates = [t for t in templates if t["id"] != template_id]
        _save_templates(templates)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  MENSAGEM ALEATÓRIA PROGRAMÁVEL — envio avulso (fora do fluxo de
#  campanha em lote): número digitado na mão, mensagem digitada na mão
#  (ou vinda de um modelo salvo), mídia opcional, com botão de
#  agendamento pra escolher exatamente a data/hora do disparo.
# ══════════════════════════════════════════════════════════════════

WHATSAPP_RANDOM_MSGS = "/etc/painel/whatsapp_random_messages.json"
RANDOM_MSG_MEDIA_DIR = "/etc/painel/wa_random_msg_media"
_random_msg_lock = threading.Lock()

def _load_random_messages():
    if not os.path.exists(WHATSAPP_RANDOM_MSGS):
        return []
    try:
        with open(WHATSAPP_RANDOM_MSGS) as f:
            return json.load(f)
    except Exception:
        return []

def _save_random_messages(data):
    _atomic_write_json(WHATSAPP_RANDOM_MSGS, data, indent=2)

def _get_random_message(items, msg_id, owner):
    return next((m for m in items if m["id"] == msg_id and m["owner"] == owner), None)

def run_random_message_worker(msg_id):
    """Roda em thread separada e manda UMA mensagem avulsa assim que o
    horário agendado chega (chamado pelo scheduler abaixo)."""
    result = None
    ok = False
    try:
        with _random_msg_lock:
            items = _load_random_messages()
            msg = next((m for m in items if m["id"] == msg_id), None)
            if not msg or msg["status"] != "pendente":
                return
        ok, result = _wa_send_media(
            msg["owner"], msg["phone"], msg["message"],
            media=msg["media"] if msg.get("media") and msg["media"].get("path") else None,
        )
        with _random_msg_lock:
            items = _load_random_messages()
            msg = next((m for m in items if m["id"] == msg_id), None)
            if not msg:
                return
            if ok:
                msg["status"] = "enviada"
                msg["msg_id"] = result
                msg["sent_at"] = time.time()
                _record_campaign_success(
                    msg["owner"], msg["phone"], _get_contact_name(msg["owner"], msg["phone"]),
                    f"avulsa_{msg_id}", "Mensagem Aleatória Programável", "enviado",
                )
            else:
                msg["status"] = "falhou"
                msg["error"] = str(result)
                msg["sent_at"] = time.time()
            owner_log = msg["owner"]
            phone_log = msg["phone"]
            _save_random_messages(items)
        device_log_write(
            f"MSG ALEATORIA PROGRAMAVEL ({owner_log}): envio pro contato {phone_log} -> "
            f"{'OK (msg_id=' + str(result) + ')' if ok else 'FALHOU (' + str(result) + ')'}"
        )
    except Exception as e:
        device_log_write(f"MSG ALEATORIA PROGRAMAVEL {msg_id} worker erro: {e}")

def whatsapp_random_message_scheduler_loop():
    """Roda em background verificando mensagens avulsas agendadas — assim
    que o horário escolhido chega, dispara sozinho, sem precisar que o
    admin esteja com o painel aberto na hora."""
    while True:
        try:
            due = []
            with _random_msg_lock:
                items = _load_random_messages()
                for m in items:
                    if m["status"] == "pendente" and time.time() >= m.get("scheduled_at", 0):
                        due.append(m["id"])
            for msg_id in due:
                threading.Thread(target=run_random_message_worker, args=(msg_id,), daemon=True).start()
        except Exception as e:
            device_log_write(f"MSG ALEATORIA PROGRAMAVEL scheduler erro: {e}")
        time.sleep(30)

@app.route("/api/whatsapp/random-messages", methods=["GET"])
@auth_required()
def random_message_list():
    owner = _owner_key(request.ns_session)
    items = [m for m in _load_random_messages() if m["owner"] == owner]
    items.sort(key=lambda m: m["created_at"], reverse=True)
    return jsonify(items)

@app.route("/api/whatsapp/random-messages", methods=["POST"])
@auth_required()
def random_message_create():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone") or "")
    message = (data.get("message") or "").strip()
    if not phone:
        return jsonify({"error": "Informe o número do contato"}), 400
    if not message and not data.get("has_media"):
        return jsonify({"error": "Escreva a mensagem ou anexe uma mídia"}), 400

    raw_schedule = (data.get("scheduled_at") or "").strip()
    scheduled_at = time.time()
    if raw_schedule:
        try:
            dt = datetime.datetime.fromisoformat(raw_schedule)
            scheduled_at = dt.timestamp()
        except ValueError:
            return jsonify({"error": "Data/hora de agendamento inválida"}), 400

    msg = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "phone": phone,
        "message": message,
        "media": None,
        "status": "pendente",
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
        "scheduled_at": scheduled_at,
        "sent_at": None,
        "msg_id": None,
        "error": None,
    }

    # Item: "Adicionar modelo" — se a mensagem foi montada a partir de um
    # modelo salvo que tem mídia, copia o arquivo do modelo direto no
    # servidor (sem precisar reanexar pelo navegador).
    template_id = (data.get("template_id") or "").strip()
    if template_id:
        with _template_lock:
            template = _get_template(_load_templates(), template_id, owner)
        if template:
            copied = _copy_template_media(template, os.path.join(RANDOM_MSG_MEDIA_DIR, msg["id"]))
            if copied:
                msg["media"] = copied

    with _random_msg_lock:
        items = _load_random_messages()
        items.append(msg)
        _save_random_messages(items)
    return jsonify(msg), 201

@app.route("/api/whatsapp/random-messages/<msg_id>/media", methods=["POST"])
@auth_required()
def random_message_upload_media(msg_id):
    owner = _owner_key(request.ns_session)
    with _random_msg_lock:
        items = _load_random_messages()
        msg = _get_random_message(items, msg_id, owner)
        if not msg:
            return jsonify({"error": "Mensagem não encontrada"}), 404
        if msg["status"] != "pendente":
            return jsonify({"error": "Essa mensagem já foi processada"}), 400
        if "file" not in request.files:
            return jsonify({"error": "Nenhum arquivo enviado"}), 400
        file = request.files["file"]
        media_type = request.form.get("mediaType", "").strip()
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
            return jsonify({"error": f"Extensão .{ext} não permitida para {media_type or 'esse tipo'}"}), 400
        msg_dir = os.path.join(RANDOM_MSG_MEDIA_DIR, msg_id)
        os.makedirs(msg_dir, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(msg_dir, filename)
        file.save(filepath)
        msg["media"] = {"type": media_type, "path": filepath, "filename": filename}
        _save_random_messages(items)
        return jsonify({"ok": True, "media": msg["media"]})

@app.route("/api/whatsapp/random-messages/<msg_id>", methods=["DELETE"])
@auth_required()
def random_message_delete(msg_id):
    """Cancela/apaga uma mensagem avulsa — só permitido enquanto estiver
    'pendente' (ainda não disparada)."""
    owner = _owner_key(request.ns_session)
    with _random_msg_lock:
        items = _load_random_messages()
        msg = _get_random_message(items, msg_id, owner)
        if not msg:
            return jsonify({"error": "Mensagem não encontrada"}), 404
        if msg["status"] != "pendente":
            return jsonify({"error": "Só dá pra cancelar mensagens ainda pendentes"}), 400
        media = msg.get("media")
        if media and media.get("path"):
            try:
                shutil.rmtree(os.path.dirname(media["path"]), ignore_errors=True)
            except Exception:
                pass
        items = [m for m in items if m["id"] != msg_id]
        _save_random_messages(items)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  GESTÃO DE CONTATOS E TAGS — o nome que o WhatsApp compartilha via
#  API é só o que a própria pessoa definiu pra ela mesma (não o nome
#  que você salvou na sua agenda — o WhatsApp não expõe isso pra
#  dispositivos vinculados/bots, por privacidade). Essa seção dá um
#  jeito de trazer SEU próprio rótulo (ex: "revendedor") de volta pro
#  painel: manualmente (uma tag por vez) ou em lote, importando um
#  CSV/vCard exportado do celular.
# ══════════════════════════════════════════════════════════════════

@app.route("/api/whatsapp/contacts", methods=["GET"])
@auth_required()
def wa_contacts_list():
    """Lista os contatos conhecidos desse painel (owner), com busca
    opcional por telefone/nome/tag — usado pela tela de gestão de tags
    e pela pré-visualização geral de contatos."""
    owner = _owner_key(request.ns_session)
    q = (request.args.get("q") or "").strip().lower()
    try:
        limit = max(1, min(2000, int(request.args.get("limit", 300))))
    except (TypeError, ValueError):
        limit = 300

    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    out = []
    for key, info in contacts.items():
        if not key.startswith(prefix):
            continue
        phone = key.split("|", 1)[1]
        name = info.get("name", "")
        tags = info.get("tags") or []
        if q and q not in phone and q not in name.lower() and not any(q in t.lower() for t in tags):
            continue
        last_seen = info.get("last_seen")
        out.append({
            "phone": phone,
            "name": name,
            "tags": tags,
            "last_seen": last_seen,
            "last_seen_txt": datetime.datetime.fromtimestamp(last_seen).strftime("%d/%m/%Y") if last_seen else "",
        })
    out.sort(key=lambda c: c.get("last_seen") or 0, reverse=True)
    return jsonify({"total": len(out), "contatos": out[:limit]})

@app.route("/api/whatsapp/contacts/clear", methods=["POST"])
@auth_required(roles=["admin"])
def wa_contacts_clear():
    """Apaga TODO o histórico de contatos conhecidos do bot (nome, tags,
    última interação) desse painel — usado quando esse histórico
    acumulou entradas quebradas/duplicadas (ex: números com o "55" do
    país duplicado, ver _normalize_br_phone) e o admin quer recomeçar
    do zero com uma agenda já corrigida, sem o painel insistir em
    manter os contatos velhos quebrados misturados com os novos.
    Não apaga usuários/servidores — só a memória de contatos do bot;
    ela volta a se preencher sozinha conforme as pessoas mandam
    mensagem, ou via nova importação de CSV/vCard."""
    owner = _owner_key(request.ns_session)
    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    antes = sum(1 for k in contacts if k.startswith(prefix))
    contacts = {k: v for k, v in contacts.items() if not k.startswith(prefix)}
    _save_wa_contacts(contacts)
    system_log_write(f"{request.ns_session['user']} limpou o histórico de contatos do WhatsApp ({antes} removido(s))")
    return jsonify({"ok": True, "removidos": antes})

@app.route("/api/whatsapp/contacts/<phone>/tags", methods=["POST"])
@auth_required()
def wa_contact_set_tags(phone):
    """Define as tags de UM contato (substitui a lista inteira — o
    front manda a lista completa já editada). Cria o contato na base
    se ele ainda não existir (ex: admin quer marcar um número que
    ainda não interagiu com o bot)."""
    owner = _owner_key(request.ns_session)
    phone = re.sub(r"\D", "", phone)
    if not phone:
        return jsonify({"error": "Telefone inválido"}), 400
    data = request.get_json() or {}
    tags = data.get("tags")
    if not isinstance(tags, list):
        return jsonify({"error": "Envie 'tags' como lista"}), 400
    tags = sorted({t.strip() for t in tags if isinstance(t, str) and t.strip()})

    contacts = _load_wa_contacts()
    key = f"{owner}|{phone}"
    entry = contacts.setdefault(key, {})
    entry["tags"] = tags
    _save_wa_contacts(contacts)
    return jsonify({"ok": True, "phone": phone, "tags": tags})

@app.route("/api/whatsapp/contacts/import", methods=["POST"])
@auth_required()
def wa_contacts_import():
    """Importa contatos de um arquivo CSV ou vCard (.vcf) exportado do
    celular — pra trazer de volta o nome que VOCÊ salvou na sua agenda
    (que o WhatsApp não compartilha via API) e, opcionalmente, aplicar
    tags automaticamente por regra de nome (ex: nome contém "rev" →
    tag "revendedor").

    Campos do form (multipart):
      file         — o .csv ou .vcf exportado do celular
      update_names — "1" pra atualizar o nome salvo no painel com o
                     nome importado (default: sim)
      tag_rules    — uma regra por linha, formato "trecho=tag", ex:
                     "rev=revendedor\ncliente vip=vip"
                     (contatos cujo nome importado contém o trecho,
                     case-insensitive, recebem essa tag — cumulativo
                     com tags já existentes, não substitui)

    Só marca/atualiza contatos que JÁ existem na base desse owner
    (ou seja, que o WhatsApp já sincronizou em algum momento) — importar
    um número que nunca teve chat/histórico não cria contato novo aqui,
    porque não haveria como saber a última interação dele."""
    owner = _owner_key(request.ns_session)

    if "file" not in request.files:
        return jsonify({"error": "Envie um arquivo (.csv ou .vcf)"}), 400
    file = request.files["file"]
    filename = (file.filename or "").lower()
    try:
        raw_text = file.read().decode("utf-8-sig", errors="ignore")
    except Exception as e:
        return jsonify({"error": f"Não consegui ler o arquivo: {e}"}), 400

    if filename.endswith(".vcf") or "begin:vcard" in raw_text.lower()[:200]:
        parsed = _parse_vcard(raw_text)
    elif filename.endswith(".csv") or filename.endswith(".tsv") or filename.endswith(".txt"):
        parsed = _parse_contacts_csv(raw_text)
    else:
        # tenta adivinhar pelo conteúdo se a extensão não ajudou
        parsed = _parse_vcard(raw_text) if "begin:vcard" in raw_text.lower() else _parse_contacts_csv(raw_text)

    if not parsed:
        return jsonify({"error": "Não consegui reconhecer nenhum contato válido (nome + telefone) nesse arquivo"}), 400

    update_names = request.form.get("update_names", "1") not in ("0", "false", "False", "")
    tag_rules_raw = request.form.get("tag_rules", "")
    tag_rules = []
    for line in tag_rules_raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        substr, _, tag = line.partition("=")
        substr, tag = substr.strip().lower(), tag.strip()
        if substr and tag:
            tag_rules.append((substr, tag))

    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    matched_existing = 0
    names_updated = 0
    tags_applied = 0
    unmatched = 0  # telefones do arquivo que não existem na base desse owner

    for name, phone in parsed:
        key = prefix + phone
        if key not in contacts:
            unmatched += 1
            continue
        matched_existing += 1
        entry = contacts[key]

        if update_names and name:
            entry["name"] = name
            names_updated += 1

        if tag_rules:
            name_lower = name.lower()
            existing_tags = set(entry.get("tags") or [])
            before = len(existing_tags)
            for substr, tag in tag_rules:
                if substr in name_lower:
                    existing_tags.add(tag)
            if len(existing_tags) > before:
                tags_applied += 1
            entry["tags"] = sorted(existing_tags)

    _save_wa_contacts(contacts)
    device_log_write(
        f"WhatsApp ({owner}): importação de contatos — {matched_existing} casado(s) na base, "
        f"{names_updated} nome(s) atualizado(s), {tags_applied} contato(s) com tag aplicada, "
        f"{unmatched} do arquivo sem histórico no painel (ignorado)"
    )
    return jsonify({
        "ok": True,
        "arquivo_lidos": len(parsed),
        "casados_na_base": matched_existing,
        "nomes_atualizados": names_updated,
        "tags_aplicadas": tags_applied,
        "sem_historico_no_painel": unmatched,
    })

@app.route("/api/whatsapp/contacts/import-history-by-name", methods=["POST"])
@auth_required()
def wa_contacts_import_history_by_name():
    """Importação alternativa pra contatos cujo telefone o WhatsApp nunca
    revelou (chat endereçado por LID sem mapeamento resolvido — ver
    _sync_wa_contacts_history) e por isso NUNCA chegaram a existir na
    base de contatos do painel (nem o import comum em wa_contacts_import
    alcança esses, porque ele só atualiza quem já existe).

    Recebe DOIS arquivos:
      contacts_file — o mesmo .vcf/.csv da agenda do celular (dá o par
                       NOME + TELEFONE de cada contato salvo)
      history_file  — um .json no formato
                       [{"name": "...", "last_seen": <epoch>}, ...]
                       gerado por captura externa da lista de conversas
                       (nome + data da última mensagem, lidos da tela do
                       WhatsApp — ver script capturar_historico_whatsapp.py)

    Casa os dois pelo NOME (normalizado — sem acento/maiúsculas) e, com
    o telefone vindo do arquivo de agenda, CRIA o contato na base do
    painel (diferente do import comum, que só atualiza quem já existe)
    ou atualiza o last_seen se o novo for mais recente que o que já
    tinha. Tags automáticas por regra de nome também são aplicadas,
    igual ao import comum."""
    owner = _owner_key(request.ns_session)

    if "contacts_file" not in request.files:
        return jsonify({"error": "Envie o arquivo da agenda (.vcf ou .csv) em 'contacts_file'"}), 400
    if "history_file" not in request.files:
        return jsonify({"error": "Envie o arquivo de histórico (.json) em 'history_file'"}), 400

    contacts_file = request.files["contacts_file"]
    history_file = request.files["history_file"]

    try:
        contacts_raw = contacts_file.read().decode("utf-8-sig", errors="ignore")
    except Exception as e:
        return jsonify({"error": f"Não consegui ler o arquivo da agenda: {e}"}), 400
    try:
        history_raw = history_file.read().decode("utf-8-sig", errors="ignore")
    except Exception as e:
        return jsonify({"error": f"Não consegui ler o arquivo de histórico: {e}"}), 400

    contacts_filename = (contacts_file.filename or "").lower()
    if contacts_filename.endswith(".vcf") or "begin:vcard" in contacts_raw.lower()[:200]:
        agenda = _parse_vcard(contacts_raw)
    else:
        agenda = _parse_contacts_csv(contacts_raw)
    if not agenda:
        return jsonify({"error": "Não consegui reconhecer nenhum contato válido (nome + telefone) no arquivo da agenda"}), 400

    try:
        history = json.loads(history_raw)
        if not isinstance(history, list):
            raise ValueError("esperado uma lista")
    except Exception as e:
        return jsonify({"error": f"Arquivo de histórico não é um JSON válido no formato esperado: {e}"}), 400

    # nome normalizado -> telefone (da agenda; em caso de nomes duplicados,
    # fica o último — é um cenário raro e o usuário pode corrigir depois
    # manualmente na tela "Gerenciar contatos e tags")
    phone_by_name = {}
    for name, phone in agenda:
        norm = _normalize_name_for_match(name)
        if norm:
            phone_by_name[norm] = phone

    update_names = request.form.get("update_names", "1") not in ("0", "false", "False", "")
    tag_rules_raw = request.form.get("tag_rules", "")
    tag_rules = []
    for line in tag_rules_raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        substr, _, tag = line.partition("=")
        substr, tag = substr.strip().lower(), tag.strip()
        if substr and tag:
            tag_rules.append((substr, tag))

    contacts = _load_wa_contacts()
    prefix = f"{owner}|"
    created = 0
    updated = 0
    tags_applied = 0
    sem_telefone_na_agenda = 0
    sem_data_valida = 0

    for item in history:
        if not isinstance(item, dict):
            continue
        name = (item.get("name") or "").strip()
        last_seen = item.get("last_seen")
        if not name or last_seen in (None, ""):
            sem_data_valida += 1
            continue
        try:
            last_seen = float(last_seen)
        except (TypeError, ValueError):
            sem_data_valida += 1
            continue

        norm = _normalize_name_for_match(name)
        phone = phone_by_name.get(norm)
        if not phone:
            sem_telefone_na_agenda += 1
            continue

        key = prefix + phone
        is_new = key not in contacts
        entry = contacts.setdefault(key, {})
        prev_last_seen = entry.get("last_seen", 0) or 0
        entry["last_seen"] = max(prev_last_seen, last_seen)

        if update_names and (is_new or not entry.get("name")):
            entry["name"] = name

        if tag_rules:
            name_lower = name.lower()
            existing_tags = set(entry.get("tags") or [])
            before = len(existing_tags)
            for substr, tag in tag_rules:
                if substr in name_lower:
                    existing_tags.add(tag)
            if len(existing_tags) > before:
                tags_applied += 1
            entry["tags"] = sorted(existing_tags)

        if is_new:
            created += 1
        elif entry["last_seen"] != prev_last_seen:
            updated += 1

    _save_wa_contacts(contacts)
    device_log_write(
        f"WhatsApp ({owner}): importação de histórico por nome (captura de tela) — "
        f"{created} contato(s) novo(s) criado(s), {updated} atualizado(s), "
        f"{tags_applied} com tag aplicada, {sem_telefone_na_agenda} sem telefone correspondente "
        f"na agenda, {sem_data_valida} sem data válida no arquivo de histórico"
    )
    return jsonify({
        "ok": True,
        "historico_lido": len(history),
        "contatos_criados": created,
        "contatos_atualizados": updated,
        "tags_aplicadas": tags_applied,
        "sem_telefone_na_agenda": sem_telefone_na_agenda,
        "sem_data_valida": sem_data_valida,
    })

@app.route("/api/whatsapp/campaigns/preview", methods=["POST"])
@auth_required()
def campaign_preview():
    """Pré-visualização ao vivo: mostra quantos e quais contatos batem
    com o filtro ANTES de criar a campanha, pro admin ajustar mês/ano/
    nome com precisão."""
    owner = _owner_key(request.ns_session)
    filters = request.get_json() or {}
    matched = _campaign_match_contacts(owner, filters)
    return jsonify({"total": len(matched), "contatos": matched[:200]})

@app.route("/api/whatsapp/campaigns", methods=["GET"])
@auth_required()
def campaign_list():
    owner = _owner_key(request.ns_session)
    campaigns = [c for c in _load_campaigns() if c["owner"] == owner]
    campaigns.sort(key=lambda c: c["created_at"], reverse=True)
    out = []
    for c in campaigns:
        item = dict(c)
        item["summary"] = _campaign_summary(c)
        item.pop("results", None)  # lista não precisa da tabela inteira
        out.append(item)
    return jsonify(out)

@app.route("/api/whatsapp/campaigns/<campaign_id>", methods=["GET"])
@auth_required()
def campaign_detail(campaign_id):
    owner = _owner_key(request.ns_session)
    campaign = _get_campaign(_load_campaigns(), campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    out = dict(campaign)
    out["summary"] = _campaign_summary(campaign)
    return jsonify(out)

@app.route("/api/whatsapp/campaigns", methods=["POST"])
@auth_required()
def campaign_create():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    message = (data.get("message") or "").strip()
    if not name:
        return jsonify({"error": "Dê um nome pra campanha"}), 400
    # Item: mensagem deixou de ser obrigatória — dá pra criar uma
    # campanha só com anexo (ex: um banner/imagem, sem nenhum texto).
    # has_media vem do front-end avisando que um arquivo será enviado
    # logo em seguida (upload é uma chamada separada, ver /media abaixo).
    if not message and not data.get("has_media"):
        return jsonify({"error": "Escreva uma mensagem ou anexe uma mídia (ex: um banner)"}), 400

    filters = {
        "month": data.get("month") or None,
        "year": data.get("year") or None,
        "name_contains": (data.get("name_contains") or "").strip(),
        # Item: filtros de exclusão + inclusão/exclusão manual de
        # contatos específicos — ver _campaign_match_contacts.
        # exclude_months aceita vários meses (ex: [3, 6] pra excluir
        # março E junho do "Ano a excluir").
        "exclude_months": [int(m) for m in (data.get("exclude_months") or []) if str(m).strip() not in ("", "0")],
        "exclude_year": data.get("exclude_year") or None,
        "exclude_name_contains": (data.get("exclude_name_contains") or "").strip(),
        "excluded_phones": list(data.get("excluded_phones") or []),
        "included_phones": list(data.get("included_phones") or []),
    }
    matched = _campaign_match_contacts(owner, filters)
    if not matched:
        return jsonify({"error": "Nenhum contato encontrado com esse filtro"}), 400

    # Item: agendamento — se vier um horário futuro, a campanha nasce
    # como "agendada" e o scheduler a inicia sozinho na hora certa.
    scheduled_at = None
    status = "rascunho"
    raw_schedule = (data.get("scheduled_at") or "").strip()
    if raw_schedule:
        try:
            dt = datetime.datetime.fromisoformat(raw_schedule)
            if dt > datetime.datetime.now():
                scheduled_at = dt.timestamp()
                status = "agendada"
        except ValueError:
            pass  # horário inválido — ignora e mantém como rascunho

    campaign = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "name": name,
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
        "status": status,
        "paused": False,
        "cursor": 0,
        "filters": filters,
        "message": message,
        "media": None,
        "delay_seconds": max(5, int(data.get("delay_seconds", 30))),
        "max_per_day": max(0, int(data.get("max_per_day", 0) or 0)),
        "hourly_interval": bool(data.get("hourly_interval")),
        "business_window": bool(data.get("business_window")),
        "sent_today_date": None,
        "sent_today_count": 0,
        "scheduled_at": scheduled_at,
        "targets": matched,
        "results": {},
    }

    # Item: "Adicionar modelo" — se a campanha foi montada a partir de um
    # modelo salvo que tem mídia, copia o arquivo do modelo direto no
    # servidor (sem precisar reanexar pelo navegador a cada campanha).
    template_id = (data.get("template_id") or "").strip()
    if template_id:
        with _template_lock:
            template = _get_template(_load_templates(), template_id, owner)
        if template:
            copied = _copy_template_media(template, os.path.join(CAMPAIGN_MEDIA_DIR, campaign["id"]))
            if copied:
                campaign["media"] = copied

    campaigns = _load_campaigns()
    campaigns.append(campaign)
    _save_campaigns(campaigns)
    return jsonify(campaign), 201

@app.route("/api/whatsapp/campaigns/<campaign_id>/media", methods=["POST"])
@auth_required()
def campaign_upload_media(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    # Item: liberado também pra campanha 'enviando'/'agendada' — o botão
    # de editar campanha em andamento permite trocar o anexo sem
    # precisar pausar; só 'concluida' continua bloqueada (não faz
    # sentido anexar mídia a algo que já terminou de ser disparado).
    if campaign["status"] == "concluida":
        return jsonify({"error": "Campanha já concluída não pode mais ser editada"}), 400

    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    media_type = request.form.get("mediaType", "").strip()  # image | video | document
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""

    if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
        return jsonify({"error": f"Extensão .{ext} não permitida para {media_type or 'esse tipo'}"}), 400

    campaign_dir = os.path.join(CAMPAIGN_MEDIA_DIR, campaign_id)
    os.makedirs(campaign_dir, exist_ok=True)
    filename = secure_filename(file.filename)
    filepath = os.path.join(campaign_dir, filename)
    file.save(filepath)

    campaign["media"] = {"type": media_type, "path": filepath, "filename": filename}
    _save_campaigns(campaigns)
    return jsonify({"ok": True, "media": campaign["media"]})

@app.route("/api/whatsapp/campaigns/<campaign_id>/media", methods=["DELETE"])
@auth_required()
def campaign_remove_media(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    campaign["media"] = None
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>", methods=["PATCH"])
@auth_required()
def campaign_edit(campaign_id):
    """Edita uma campanha já criada — inclusive uma que está 'enviando'
    (em andamento), sem precisar pausar/recriar. Só mexe nos campos
    "seguros" (nome, mensagem, ritmo de envio); NUNCA mexe em
    'targets'/'cursor'/'filters', porque isso corromperia a posição de
    quem já recebeu x quem ainda falta receber na fila. O worker
    (run_campaign_worker) relê a campanha do disco a cada mensagem
    enviada, então uma edição feita aqui já vale a partir do PRÓXIMO
    envio da fila, sem precisar reiniciar a campanha nem o processo."""
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    with _campaign_lock:
        campaigns = _load_campaigns()
        campaign = _get_campaign(campaigns, campaign_id, owner)
        if not campaign:
            return jsonify({"error": "Campanha não encontrada"}), 404
        if campaign["status"] == "concluida":
            return jsonify({"error": "Campanha já concluída não pode mais ser editada"}), 400

        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                return jsonify({"error": "Dê um nome pra campanha"}), 400
            campaign["name"] = name
        if "message" in data:
            message = (data.get("message") or "").strip()
            has_media = bool(campaign.get("media") and campaign["media"].get("path"))
            if not message and not has_media:
                return jsonify({"error": "Escreva uma mensagem ou anexe uma mídia (ex: um banner)"}), 400
            campaign["message"] = message
        if "delay_seconds" in data:
            campaign["delay_seconds"] = max(5, int(data.get("delay_seconds") or 30))
        if "max_per_day" in data:
            campaign["max_per_day"] = max(0, int(data.get("max_per_day") or 0))
        if "hourly_interval" in data:
            campaign["hourly_interval"] = bool(data.get("hourly_interval"))
        if "business_window" in data:
            campaign["business_window"] = bool(data.get("business_window"))

        _save_campaigns(campaigns)
        device_log_write(f"CAMPANHA '{campaign['name']}' ({owner}) editada (status={campaign['status']})")
        out = dict(campaign)
        out["summary"] = _campaign_summary(campaign)
        return jsonify(out)

@app.route("/api/whatsapp/campaigns/<campaign_id>/start", methods=["POST"])
@auth_required()
def campaign_start(campaign_id):
    """Inicia (ou retoma, se estava pausada) o envio do lote a partir
    de onde parou."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "concluida":
        return jsonify({"error": "Campanha já concluída — use 'Reativar' pra criar uma nova com o mesmo filtro"}), 400

    wa = get_owner_wa_config(owner)
    if not wa.get("bot_enabled"):
        # não é bloqueante pro envio (o WhatsApp pode estar conectado
        # mesmo com o bot de respostas desligado), só um aviso
        pass

    campaign["status"] = "enviando"
    campaign["paused"] = False
    _save_campaigns(campaigns)
    _start_campaign_thread(campaign_id)
    device_log_write(f"CAMPANHA '{campaign['name']}' ({owner}) iniciada/retomada a partir do contato {campaign.get('cursor', 0)}")
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/pause", methods=["POST"])
@auth_required()
def campaign_pause(campaign_id):
    """Pausa uma campanha em envio. Se a campanha ainda estiver só
    'agendada' (não começou), isso funciona como CANCELAR o agendamento
    — ela volta a ser um rascunho editável."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "agendada":
        campaign["status"] = "rascunho"
        campaign["scheduled_at"] = None
    else:
        campaign["paused"] = True
        campaign["status"] = "pausada"
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/duplicate", methods=["POST"])
@auth_required()
def campaign_duplicate(campaign_id):
    """'Reativar no futuro': cria uma campanha NOVA com o mesmo nome/
    filtro/mensagem/mídia de uma campanha já concluída (ou de qualquer
    outra), recalculando os contatos-alvo na hora — assim, se o mesmo
    filtro de mês/ano trouxer gente nova (ex: alguém que voltou a falar
    justamente naquele período), ela também entra."""
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    original = _get_campaign(campaigns, campaign_id, owner)
    if not original:
        return jsonify({"error": "Campanha não encontrada"}), 404

    matched = _campaign_match_contacts(owner, original["filters"])
    if not matched:
        return jsonify({"error": "Nenhum contato encontrado com o filtro dessa campanha hoje"}), 400

    new_campaign = {
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "name": f"{original['name']} (cópia)",
        "created_at": time.time(),
        "created_by": request.ns_session["user"],
        "status": "rascunho",
        "paused": False,
        "cursor": 0,
        "filters": original["filters"],
        "message": original["message"],
        "media": original.get("media"),
        "delay_seconds": original.get("delay_seconds", 30),
        "targets": matched,
        "results": {},
    }
    campaigns.append(new_campaign)
    _save_campaigns(campaigns)
    return jsonify(new_campaign), 201

@app.route("/api/whatsapp/campaigns/<campaign_id>", methods=["DELETE"])
@auth_required()
def campaign_delete(campaign_id):
    owner = _owner_key(request.ns_session)
    campaigns = _load_campaigns()
    campaign = _get_campaign(campaigns, campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404
    if campaign["status"] == "enviando":
        return jsonify({"error": "Pause a campanha antes de excluir"}), 400
    campaigns = [c for c in campaigns if c["id"] != campaign_id]
    _save_campaigns(campaigns)
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/test-send", methods=["POST"])
@auth_required()
def campaign_test_send():
    """Manda a mensagem (com o anexo, se houver) só pra UM número — pra
    o admin conferir como fica antes de disparar pro lote inteiro. Não
    cria nem altera nenhuma campanha salva."""
    owner = _owner_key(request.ns_session)
    phone = re.sub(r"\D", "", request.form.get("phone", ""))
    message = request.form.get("message", "").strip()
    media_type = request.form.get("mediaType", "").strip()

    if not phone:
        return jsonify({"error": "Informe um telefone válido pro teste"}), 400
    if not message and not media_type:
        return jsonify({"error": "Escreva a mensagem (ou anexe uma mídia) antes de testar"}), 400

    media = None
    if media_type and "file" in request.files:
        file = request.files["file"]
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if media_type not in ALLOWED_CAMPAIGN_EXT or ext not in ALLOWED_CAMPAIGN_EXT[media_type]:
            return jsonify({"error": f"Extensão .{ext} não permitida para {media_type}"}), 400
        tmp_dir = os.path.join(CAMPAIGN_MEDIA_DIR, "_teste", owner)
        os.makedirs(tmp_dir, exist_ok=True)
        filename = secure_filename(file.filename)
        filepath = os.path.join(tmp_dir, filename)
        file.save(filepath)
        media = {"type": media_type, "path": filepath, "filename": filename}

    ok, result = _wa_send_media(owner, phone, message, media=media)
    if not ok:
        return jsonify({"error": f"Falha ao enviar: {result}"}), 500
    return jsonify({"ok": True})

@app.route("/api/whatsapp/campaigns/<campaign_id>/export", methods=["GET"])
@auth_required()
def campaign_export_csv(campaign_id):
    """Exporta o relatório da campanha (telefone, nome, status de envio/
    entrega/leitura e horários) em CSV, pronto pra abrir no Excel."""
    owner = _owner_key(request.ns_session)
    campaign = _get_campaign(_load_campaigns(), campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["telefone", "nome", "status", "entregue", "visualizado", "enviado_em", "entregue_em", "visualizado_em", "erro"])
    for t in campaign.get("targets", []):
        r = campaign.get("results", {}).get(t["phone"], {})
        status = r.get("status", "pendente")
        writer.writerow([
            t["phone"], t.get("name", ""), status,
            "sim" if status in ("entregue", "visualizado") else "não",
            "sim" if status == "visualizado" else "não",
            datetime.datetime.fromtimestamp(r["sent_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("sent_at") else "",
            datetime.datetime.fromtimestamp(r["delivered_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("delivered_at") else "",
            datetime.datetime.fromtimestamp(r["read_at"]).strftime("%Y-%m-%d %H:%M:%S") if r.get("read_at") else "",
            r.get("error", ""),
        ])

    mem = io.BytesIO(buf.getvalue().encode("utf-8-sig"))  # BOM pro Excel abrir acentos certinho
    mem.seek(0)
    filename = secure_filename(f"campanha_{campaign['name']}.csv") or f"campanha_{campaign_id}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)

@app.route("/api/whatsapp/contacts/success-list", methods=["GET"])
@auth_required()
def wa_success_list():
    """Lista mestre e cumulativa de contatos que já confirmaram ter
    WhatsApp ativo (mensagem de campanha aceita/entregue/visualizada)
    em QUALQUER campanha já rodada — nunca é resetada, só cresce.
    Serve pra identificar, com o tempo, quem da sua base ainda tem
    WhatsApp de verdade."""
    owner = _owner_key(request.ns_session)
    prefix = f"{owner}|"
    data = _load_success_contacts()
    q = (request.args.get("q") or "").strip().lower()
    items = []
    for key, entry in data.items():
        if not key.startswith(prefix):
            continue
        if q and q not in (entry.get("name") or "").lower() and q not in (entry.get("phone") or ""):
            continue
        items.append(entry)
    items.sort(key=lambda e: e.get("last_success_at", 0), reverse=True)
    return jsonify({"total": len(items), "items": items})

@app.route("/api/whatsapp/contacts/success-list/export", methods=["GET"])
@auth_required()
def wa_success_list_export():
    """Exporta a lista mestre de sucessos em CSV — pra você comparar
    com a sua agenda inteira e identificar quem NÃO está nessa lista
    (ou seja, quem nunca confirmou ter WhatsApp em nenhuma campanha)."""
    owner = _owner_key(request.ns_session)
    prefix = f"{owner}|"
    data = _load_success_contacts()

    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["telefone", "nome", "melhor_status", "primeira_confirmacao", "ultima_confirmacao", "qtd_campanhas", "campanhas"])
    for key, entry in data.items():
        if not key.startswith(prefix):
            continue
        campanhas_nomes = "; ".join(c.get("campaign_name") or c.get("campaign_id", "") for c in entry.get("campaigns", []))
        writer.writerow([
            entry.get("phone", ""), entry.get("name", ""), entry.get("best_status", ""),
            datetime.datetime.fromtimestamp(entry["first_success_at"]).strftime("%Y-%m-%d %H:%M:%S") if entry.get("first_success_at") else "",
            datetime.datetime.fromtimestamp(entry["last_success_at"]).strftime("%Y-%m-%d %H:%M:%S") if entry.get("last_success_at") else "",
            len(entry.get("campaigns", [])),
            campanhas_nomes,
        ])

    mem = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="contatos_confirmados_whatsapp.csv")

CAMPAIGN_AI_SYSTEM_PROMPT = (
    "Você é um especialista em campanhas de reengajamento via WhatsApp, ajudando o administrador de um "
    "painel (Painel Netsimon) a entender os RESULTADOS de uma campanha que ele disparou. O administrador não é "
    "programador — explique em português claro, sem jargão técnico desnecessário. Você vai receber um "
    "resumo numérico da campanha (quantos enviados, entregues, visualizados, falharam) e, quando houver "
    "falhas, uma amostra dos erros reais retornados pelo WhatsApp para contatos específicos. "
    "Estruture a resposta em até três partes curtas: "
    "(1) leitura geral do resultado (a campanha foi bem-sucedida? a taxa de falha é normal ou alta?); "
    "(2) se houver falhas, agrupe por causa provável e explique cada uma em linguagem simples — por "
    "exemplo: número não tem WhatsApp / número inválido ou mal formatado / número bloqueou o remetente / "
    "sessão do WhatsApp do painel caiu / limite de envio da conta atingido / erro de mídia (arquivo grande "
    "ou formato não suportado) / timeout de rede — e não invente uma causa que os dados não sustentam, "
    "diga que não dá pra ter certeza quando for o caso; "
    "(3) 1-3 dicas objetivas e acionáveis pra melhorar a próxima campanha (ex: aumentar o intervalo entre "
    "envios, revisar a lista de contatos antes de mandar, checar a conexão do WhatsApp, etc.), só sugerindo "
    "o que realmente fizer sentido dado o que foi observado — não empurre dicas genéricas sem relação com "
    "os dados. Se foi perguntado sobre UM contato específico, responda focado nele, sem precisar repetir a "
    "leitura geral da campanha inteira."
)

def _campaign_failure_breakdown(campaign, max_samples=15):
    """Agrupa as falhas por texto de erro (normalizado) e monta uma
    amostra representativa pra mandar pra IA sem estourar o limite de
    tokens em campanhas com milhares de contatos."""
    results = campaign.get("results", {})
    targets_by_phone = {t["phone"]: t.get("name", "") for t in campaign.get("targets", [])}
    grupos = {}
    for phone, r in results.items():
        if r.get("status") != "falhou":
            continue
        erro = (r.get("error") or "erro desconhecido").strip()
        grupos.setdefault(erro, []).append(phone)

    linhas = []
    for erro, phones in sorted(grupos.items(), key=lambda kv: -len(kv[1])):
        exemplos = ", ".join(f"{p} ({targets_by_phone.get(p, 'sem nome')})" for p in phones[:5])
        linhas.append(f"- \"{erro}\" — {len(phones)} contato(s). Exemplos: {exemplos}")
        if len(linhas) >= max_samples:
            linhas.append(f"(... e outros tipos de erro agrupados, {len(grupos) - max_samples} a mais)")
            break
    return "\n".join(linhas) if linhas else "(nenhuma falha registrada)"

@app.route("/api/whatsapp/campaigns/<campaign_id>/perguntar-ia", methods=["POST"])
@auth_required()
def campaign_ask_ai(campaign_id):
    """A mesma IA já configurada no painel (Configurações > Assistente
    de IA) passa a também explicar os RESULTADOS de campanhas — por que
    algo falhou, se a taxa de falha é normal, e dar dicas objetivas.
    Aceita opcionalmente um "phone" no corpo pra focar a pergunta num
    contato específico (ex: "por que não conseguiu enviar pro cliente
    X")."""
    if not license_allows("ia"):
        return jsonify({"error": "Assistente de IA não incluído no seu plano de licença."}), 402
    owner = _owner_key(request.ns_session)
    campaign = _get_campaign(_load_campaigns(), campaign_id, owner)
    if not campaign:
        return jsonify({"error": "Campanha não encontrada"}), 404

    cfg = load_config()
    ai = get_ai_assistant_config(owner)
    if not ai.get("api_key"):
        return jsonify({"error": "Configure uma chave de IA em Configurações > Assistente de IA antes de usar isso."}), 400

    data = request.get_json(silent=True) or {}
    phone_foco = re.sub(r"\D", "", data.get("phone") or "")
    pergunta_extra = (data.get("pergunta") or "").strip()

    s = _campaign_summary(campaign)
    resumo = (
        f"Campanha: \"{campaign.get('name')}\"\n"
        f"Status atual: {campaign.get('status')}\n"
        f"Total de contatos no alvo: {s['total']} | Pendentes: {s['pendente']} | "
        f"Enviados: {s['enviado']} | Entregues: {s['entregue']} | "
        f"Visualizados: {s['visualizado']} | Falhas: {s['falhou']}"
    )

    if phone_foco:
        r = campaign.get("results", {}).get(phone_foco)
        nome = _get_contact_name(owner, phone_foco) or next(
            (t.get("name", "") for t in campaign.get("targets", []) if t["phone"] == phone_foco), ""
        )
        if not r:
            contexto = f"{resumo}\n\nO contato {phone_foco} ({nome}) ainda está pendente — a campanha ainda não chegou nele."
        else:
            contexto = (
                f"{resumo}\n\nPergunta focada no contato {phone_foco} ({nome}):\n"
                f"Status: {r.get('status')}\n"
                f"Erro retornado (se houver): {r.get('error') or '(nenhum)'}\n"
                f"Enviado em: {datetime.datetime.fromtimestamp(r['sent_at']).strftime('%d/%m/%Y %H:%M') if r.get('sent_at') else '(não enviado ainda)'}"
            )
        pergunta = pergunta_extra or f"Por que não conseguiu (ou conseguiu) enviar a mensagem pra esse cliente especificamente?"
    else:
        contexto = f"{resumo}\n\nDetalhamento das falhas, agrupadas por causa:\n{_campaign_failure_breakdown(campaign)}"
        pergunta = pergunta_extra or "Analise esse resultado de campanha e me dê o diagnóstico."

    ok, resposta = _call_gemini(ai, CAMPAIGN_AI_SYSTEM_PROMPT, [], f"{contexto}\n\n{pergunta}")
    if not ok:
        return jsonify({"error": resposta}), 400

    campanhas = _load_campaigns()
    c2 = next((c for c in campanhas if c["id"] == campaign_id), None)
    if c2:
        c2.setdefault("ia_respostas", []).append({
            "em": datetime.datetime.now().isoformat(),
            "phone_foco": phone_foco or None,
            "pergunta": pergunta,
            "resposta": resposta,
        })
        _save_campaigns(campanhas)

    return jsonify({"ok": True, "resposta": resposta})

@app.route("/api/whatsapp/status-update", methods=["POST"])
def whatsapp_status_update():
    """Endpoint interno (só localhost) — o microserviço Node chama isso
    sempre que uma mensagem enviada muda de status (entregue/
    visualizado/falhou), pra gente atualizar o relatório da campanha."""
    if not _internal_request_ok():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json() or {}
    owner  = (data.get("owner") or "").strip()
    phone  = re.sub(r"\D", "", data.get("phone", ""))
    msg_id = data.get("msgId")
    status = data.get("status")
    if not owner or not phone or not msg_id or status not in ("enviado", "entregue", "visualizado", "falhou"):
        return jsonify({"ok": True})

    with _campaign_lock:
        campaigns = _load_campaigns()
        changed = False
        for c in campaigns:
            if c["owner"] != owner:
                continue
            r = c.get("results", {}).get(phone)
            if not r or r.get("msg_id") != msg_id:
                continue

            # Item BUG CORRIGIDO: o Baileys pode reportar status=0 (ERROR)
            # alguns instantes DEPOIS do /send já ter respondido ok:true —
            # acontece quando o número não existe/não tem mais WhatsApp,
            # a sessão cai no meio do envio, etc. Antes esse evento nem
            # chegava aqui (era descartado no whatsapp_bot.js), então o
            # relatório da campanha ficava preso em "enviado" pra sempre
            # mesmo a mensagem nunca tendo chegado de verdade (o falso
            # positivo reportado pelo usuário com o contato z3879). Agora
            # o Node manda "falhou" nesse caso, e aqui a gente rebaixa —
            # mas só se ainda estava em "enviado": nunca sobrescreve um
            # "entregue"/"visualizado" que já tenha sido confirmado antes
            # (não faria sentido, e evita race condition bobo).
            if status == "falhou":
                if r.get("status") == "enviado":
                    r["status"] = "falhou"
                    r["error"] = "WhatsApp rejeitou a mensagem após o envio (Baileys reportou status ERROR)"
                    changed = True
                continue

            # só evolui o status pra frente (não "desvisualiza")
            ordem = {"enviado": 1, "entregue": 2, "visualizado": 3}
            if ordem.get(status, 0) > ordem.get(r.get("status"), 0):
                r["status"] = status
                if status == "entregue":
                    r["delivered_at"] = time.time()
                elif status == "visualizado":
                    r["read_at"] = time.time()
                changed = True
                if status in ("entregue", "visualizado"):
                    _record_campaign_success(
                        owner, phone, _get_contact_name(owner, phone),
                        c.get("id"), c.get("name", ""), status,
                    )
        if changed:
            _save_campaigns(campaigns)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  DIAGNÓSTICO (item 16a) — análise do painel em linguagem simples
# ══════════════════════════════════════════════════════════════════

@app.route("/api/diagnostics", methods=["GET"])
@auth_required()
def diagnostics():
    """Não é um modelo de IA externo — é uma análise por regras, feita
    em cima dos dados reais do painel (vencimentos, tempo online,
    bloqueios), apresentada em linguagem simples com sugestões de ação.
    Disponível para admin e para revendedores (item 16), cada um vendo
    apenas o que está dentro do seu escopo."""
    s = request.ns_session
    cfg = load_config()
    users = read_users()
    online_since = _load_online_since()
    online = set(get_online_users())

    if s["role"] == "reseller":
        owned = all_owned_logins(cfg, s["user"])
        users = [u for u in users if u["login"] in owned]

    now = datetime.datetime.now()
    insights = []
    suggestions = []

    # Vencendo em breve
    venc = []
    for u in users:
        dt = _parse_dt(u["expira"])
        if dt:
            dias = (dt - now).total_seconds() / 86400
            if 0 <= dias <= 3:
                venc.append((u["login"], dias))
    venc.sort(key=lambda x: x[1])
    if venc:
        nomes = ", ".join(f"{n} ({d:.1f}d)" for n, d in venc[:8])
        insights.append({"tipo": "vencimento", "texto": f"{len(venc)} usuário(s) vencendo nos próximos 3 dias: {nomes}."})
        suggestions.append({"texto": f"Avisar ou renovar automaticamente os {len(venc)} usuário(s) prestes a vencer.", "acao": "notificar_vencendo", "auto_ok": True})

    # Tempo de conexão contínua — maior e menor
    durations = [(u["login"], online_duration_seconds(u["login"], online_since)) for u in users if u["login"] in online]
    if durations:
        durations.sort(key=lambda x: x[1], reverse=True)
        top = durations[0]
        insights.append({"tipo": "conexao_longa", "texto": f"\"{top[0]}\" está conectado sem interrupção há {top[1]//3600}h{(top[1]%3600)//60}min — a conexão mais longa agora."})
        if len(durations) > 1:
            bot = durations[-1]
            insights.append({"tipo": "conexao_curta", "texto": f"\"{bot[0]}\" é quem ficou conectado por menos tempo entre os online agora ({bot[1]//60} min)."})

    # Bloqueados
    blocked_logins = []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if parts and parts[0] in {u["login"] for u in users}:
                    blocked_logins.append(parts[0])
    if blocked_logins:
        insights.append({"tipo": "bloqueados", "texto": f"{len(blocked_logins)} usuário(s) bloqueado(s) no momento: {', '.join(blocked_logins[:8])}."})
        suggestions.append({"texto": "Revisar os usuários bloqueados — pode ser limite de dispositivo excedido ou suspensão manual.", "acao": "revisar_bloqueados", "auto_ok": False})

    # Cota (revendedor)
    if s["role"] == "reseller":
        used, quota = quota_usage(cfg, s["user"])
        if quota > 0 and used >= quota * 0.9:
            insights.append({"tipo": "cota", "texto": f"Sua cota está quase no limite: {used}/{quota} usuários."})
            suggestions.append({"texto": "Pedir ao admin um aumento de cota antes que fique impossível criar novos clientes.", "acao": "pedir_cota", "auto_ok": False})

    if not insights:
        insights.append({"tipo": "ok", "texto": "Nenhum ponto de atenção agora — tudo dentro do esperado."})

    return jsonify({"gerado_em": now.isoformat(), "insights": insights, "sugestoes": suggestions})

# ══════════════════════════════════════════════════════════════════
#  AUTODIAGNÓSTICO TÉCNICO — incidentes (erros interceptados, causa
#  detectada e correção aplicada) — só admin, é operação de servidor.
# ══════════════════════════════════════════════════════════════════
@app.route("/api/diagnostics/incidents", methods=["GET"])
@auth_required(roles=["admin"])
def diag_list_incidents():
    items = list(reversed(_diag_load_incidents()))[:150]
    return jsonify({"incidentes": items})

@app.route("/api/diagnostics/incidents/summary", methods=["GET"])
@auth_required(roles=["admin"])
def diag_incidents_summary():
    """Usado pela central de avisos (sininho) em toda página pra saber
    se tem algo do autodiagnóstico que merece a atenção do admin."""
    items = _diag_load_incidents()
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)

    def _dt(i):
        try:
            return datetime.datetime.fromisoformat(i.get("criado_em", ""))
        except Exception:
            return datetime.datetime.min

    recentes = [i for i in items if _dt(i) >= cutoff]
    corrigidos_24h = [i for i in recentes if i.get("status") == "corrigido"]
    pendentes = [i for i in items if i.get("status") in ("sem_correcao_conhecida", "falhou")]
    return jsonify({
        "ultimas_24h": len(recentes),
        "corrigidos_24h": len(corrigidos_24h),
        "pendentes_atencao": len(pendentes),
        "ultimo": items[-1] if items else None,
    })

@app.route("/api/diagnostics/incidents/<incident_id>/revert", methods=["POST"])
@auth_required(roles=["admin"])
def diag_revert_incident(incident_id):
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") == "revertido":
        return jsonify({"error": "Este incidente já foi revertido"}), 400
    if not inc.get("auto_aplicada"):
        return jsonify({"error": "Este incidente não teve nenhuma correção automática aplicada — nada para reverter"}), 400

    alvo = inc.get("arquivo_alvo")
    backup_path = inc.get("backup_path")
    perm_anterior = inc.get("permissao_anterior")
    mensagem = None

    if backup_path and alvo and os.path.exists(backup_path):
        shutil.copy2(backup_path, alvo)
        if alvo.endswith(".sh"):
            run_cmd(f'chmod +x "{alvo}"')
        mensagem = f"Arquivo '{alvo}' restaurado para o estado anterior à correção."
    elif perm_anterior and alvo and os.path.exists(alvo):
        try:
            modo = perm_anterior.get("modo")
            if modo:
                os.chmod(alvo, int(modo, 8))
            uid, gid = perm_anterior.get("uid"), perm_anterior.get("gid")
            if uid is not None and gid is not None:
                os.chown(alvo, uid, gid)
            mensagem = f"Permissões de '{alvo}' restauradas para o estado anterior."
        except Exception as e:
            return jsonify({"error": f"Falha ao reverter permissão: {e}"}), 500
    else:
        return jsonify({"error": "Não há backup/estado anterior registrado para reverter este incidente "
                                  "(ex: reinício de serviço não tem 'estado anterior' pra restaurar)"}), 400

    inc["status"] = "revertido"
    inc["revertido_em"] = datetime.datetime.now().isoformat()
    _diag_save_incidents(items)
    system_log_write(f"DIAG — incidente {incident_id} revertido pelo admin: {mensagem}")
    return jsonify({"ok": True, "mensagem": mensagem})

@app.route("/api/diagnostics/incidents/<incident_id>/aprovar", methods=["POST"])
@auth_required(roles=["admin"])
def diag_approve_incident(incident_id):
    """Aplica a correção de um incidente que ficou pendente de aprovação
    (modo manual/parcial). Reaproveita o mesmo _diag_apply_fix usado no
    caminho automático — é a mesma correção, só que autorizada na hora
    em vez de na hora do erro."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") != "pendente_aprovacao":
        return jsonify({"error": "Este incidente não está aguardando aprovação"}), 400

    tipo = inc.get("causa_tipo")
    alvo = inc.get("alvo_bruto")
    if not tipo or alvo is None:
        return jsonify({"error": "Incidente sem dados suficientes pra aplicar a correção"}), 400

    resultado = _diag_apply_fix(inc, tipo, alvo, inc.get("rota"), aprovado_manualmente=True)
    system_log_write(f"DIAG — incidente {incident_id} aprovado manualmente pelo admin -> {resultado.get('status')}")
    return jsonify({"ok": True, "incidente": resultado})

@app.route("/api/diagnostics/incidents/<incident_id>/rejeitar", methods=["POST"])
@auth_required(roles=["admin"])
def diag_reject_incident(incident_id):
    """Descarta um incidente pendente de aprovação sem aplicar nada —
    útil quando o admin já resolveu manualmente por fora, ou decide que
    não quer aquela correção específica."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") != "pendente_aprovacao":
        return jsonify({"error": "Este incidente não está aguardando aprovação"}), 400
    inc["status"] = "rejeitado"
    inc["rejeitado_em"] = datetime.datetime.now().isoformat()
    _diag_save_incidents(items)
    return jsonify({"ok": True})

@app.route("/api/diagnostics/incidents/<incident_id>/retry", methods=["POST"])
@auth_required(roles=["admin"])
def diag_retry_incident(incident_id):
    """Botão 'Tentar novamente' da tela de incidentes — reaproveita
    exatamente o mesmo caminho de correção que o autodiagnóstico usaria
    sozinho, mas disparado na hora pelo admin. Funciona pra incidentes
    que falharam ou que estão pendentes de aprovação."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    if inc.get("status") not in ("falhou", "pendente_aprovacao"):
        return jsonify({"error": "Este incidente não está em um estado que permita tentar de novo"}), 400

    tipo = inc.get("causa_tipo")
    alvo = inc.get("alvo_bruto")
    if not tipo or alvo is None:
        return jsonify({"error": "Incidente sem dados suficientes pra tentar a correção"}), 400

    resultado = _diag_apply_fix(inc, tipo, alvo, inc.get("rota"), aprovado_manualmente=True)
    system_log_write(f"DIAG — incidente {incident_id} — nova tentativa manual pelo admin -> {resultado.get('status')}")
    return jsonify({"ok": True, "incidente": resultado})

@app.route("/api/diagnostics/incidents/<incident_id>/diagnosticar", methods=["POST"])
@auth_required(roles=["admin"])
def diag_run_diagnosis(incident_id):
    """Botão 'Diagnosticar' — só COLETA evidência atualizada (status do
    systemd + fim do log do serviço), sem tentar reiniciar nada. Útil
    pra ver o estado agora sem mexer em nada, ou depois de já ter
    resolvido manualmente por fora."""
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404
    svc = inc.get("alvo_bruto")
    if not svc or inc.get("causa_tipo") != "servico_parado":
        return jsonify({"error": "Diagnóstico detalhado disponível apenas para incidentes de serviço parado"}), 400

    inc["diagnostico"] = _diag_collect_service_evidence(svc)
    _diag_save_incidents(items)
    return jsonify({"ok": True, "incidente": inc})

DIAG_AI_SYSTEM_PROMPT = (
    "Você é um engenheiro de suporte técnico ajudando o administrador de um painel de VPN (Painel Netsimon) a "
    "entender e resolver um problema real no servidor Linux dele. O administrador NÃO é programador — "
    "explique em português claro, sem jargão desnecessário, e quando indicar um comando pra rodar, dê o "
    "comando pronto para copiar e colar (um de cada vez, nunca vários comandos complexos amarrados). "
    "Estruture a resposta em três partes curtas: (1) o que provavelmente causou isso, (2) por que a correção "
    "automática do painel pode não ter resolvido sozinha, (3) o que fazer agora, passo a passo. Seja honesto "
    "quando não tiver certeza absoluta da causa — diga que é a hipótese mais provável dado o que foi coletado. "
    "Se o incidente for do tipo 'ameaça de segurança' (processo disfarçado de thread de kernel, diretório "
    "oculto em /dev/shm ou /tmp): o painel já neutralizou sozinho (matou o processo, apagou o payload, travou "
    "a conta Linux envolvida) antes mesmo de você ser chamado — não sugira rodar o malware, analisá-lo, nem "
    "reabrir a conta travada sem investigação. Foque em: se a evidência sugere como o invasor entrou "
    "(força bruta de SSH, senha fraca, etc.), se há sinal de que a conta travada era legítima e vale reabrir "
    "com senha nova, e o que o administrador deveria checar/monitorar nos próximos dias."
)

@app.route("/api/diagnostics/incidents/<incident_id>/perguntar-ia", methods=["POST"])
@auth_required(roles=["admin"])
def diag_ask_ai(incident_id):
    """Item: a IA já configurada no painel (mesma usada no atendimento do
    WhatsApp) passa a também ajudar a diagnosticar problemas TÉCNICOS do
    próprio painel — manda pra ela a causa detectada + a evidência real
    coletada do servidor (status do serviço, fim do log) e pede uma
    explicação e um passo a passo em linguagem simples."""
    if not license_allows("ia"):
        return jsonify({"error": "Assistente de IA não incluído no seu plano de licença."}), 402
    items = _diag_load_incidents()
    inc = next((i for i in items if i.get("id") == incident_id), None)
    if not inc:
        return jsonify({"error": "Incidente não encontrado"}), 404

    cfg = load_config()
    ai = get_ai_assistant_config("admin")
    if not ai.get("api_key"):
        return jsonify({"error": "Configure uma chave de IA em Configurações > Assistente de IA antes de usar isso."}), 400

    diagnostico = inc.get("diagnostico") or {}
    if inc.get("causa_tipo") == "ameaca_seguranca":
        # Item: contexto dedicado pra incidente de segurança -- os campos
        # são bem diferentes de um "serviço caiu" (processo/PID/hash em
        # vez de systemd/log), então usa o vocabulário certo pra IA
        # entender que é um caso de neutralização de ameaça, não um bug.
        contexto = (
            f"O autodiagnóstico do painel detectou e neutralizou AUTOMATICAMENTE uma ameaça de "
            f"segurança (sem esperar aprovação, por política definida pelo administrador pra esse "
            f"tipo específico de incidente).\n\n"
            f"O que foi encontrado:\n"
            f"- Processo: \"{diagnostico.get('processo')}\" (PID {diagnostico.get('pid')})\n"
            f"- Motivo da suspeita: {diagnostico.get('motivo_deteccao')}\n"
            f"- Caminho do executável: {diagnostico.get('caminho_executavel') or '(não identificado)'}\n"
            f"- Hash SHA-256 do binário (antes de ser apagado): {diagnostico.get('sha256_binario') or '(não coletado)'}\n"
            f"- Usuário Linux dono do processo: {diagnostico.get('usuario_dono')}\n"
            f"- Linha de comando completa: {diagnostico.get('linha_de_comando') or '(vazia)'}\n\n"
            f"Ações que o painel já tomou sozinho:\n"
            + "\n".join(f"- {a}" for a in (diagnostico.get('acoes_tomadas') or []))
        )
    else:
        contexto = (
            f"Causa detectada pelo autodiagnóstico do painel: {inc.get('causa_detalhe')}\n"
            f"Status atual do incidente: {inc.get('status')}\n"
            f"Correção que o painel tentou aplicar: {inc.get('correcao') or 'nenhuma / não se aplica'}\n\n"
            f"Evidência técnica coletada do servidor:\n"
            f"- Status do systemd:\n{diagnostico.get('systemctl_status', '(não coletado)')}\n\n"
            f"- Últimas linhas do log do serviço ({diagnostico.get('log_path') or 'sem log dedicado'}):\n"
            f"{diagnostico.get('log_tail') or '(sem log disponível)'}\n\n"
            f"- Saída do último comando de reinício tentado:\n{diagnostico.get('saida_comando') or '(vazio)'}\n"
            f"- Erro do último comando de reinício tentado:\n{diagnostico.get('erro_comando') or '(vazio)'}"
        )
    # Item: BUG CORRIGIDO — essa chamada usava o mesmo limite padrão de
    # 400 tokens do bot do WhatsApp (pensado pra respostas curtas de
    # atendimento). Um diagnóstico técnico de verdade — causa provável +
    # por que a correção automática falhou + passo a passo com comandos —
    # não cabe nisso, e o modelo "pensando" por baixo dos panos consumia
    # esse orçamento inteiro antes de escrever qualquer coisa visível, daí
    # a resposta sempre saía cortada logo no início. Aqui a IA tem
    # bastante espaço reservado pro raciocínio (thinking_budget) E ainda
    # sobra bastante margem garantida pra resposta completa em si.
    ok, resposta = _call_gemini(
        ai, DIAG_AI_SYSTEM_PROMPT, [], contexto,
        max_tokens=3072, thinking_budget=1024
    )
    if not ok:
        return jsonify({"error": resposta}), 400

    inc.setdefault("ia_respostas", []).append({
        "em": datetime.datetime.now().isoformat(), "resposta": resposta
    })
    _diag_save_incidents(items)
    return jsonify({"ok": True, "resposta": resposta})

@app.route("/api/diagnostics/settings", methods=["GET"])
@auth_required(roles=["admin"])
def diag_get_settings():
    return jsonify(_diag_load_settings())

@app.route("/api/diagnostics/settings", methods=["POST"])
@auth_required(roles=["admin"])
def diag_set_settings():
    """Troca o modo de automação (manual/parcial/automatico). É o
    interruptor de emergência: trocar pra "manual" já desativa toda ação
    automática do autodiagnóstico na hora, sem precisar reiniciar nada."""
    data = request.get_json() or {}
    modo = data.get("modo")
    if modo not in DIAG_MODES:
        return jsonify({"error": f"modo inválido — use um de: {', '.join(DIAG_MODES)}"}), 400
    settings = _diag_load_settings()
    settings["modo"] = modo
    _diag_save_settings(settings)
    system_log_write(f"DIAG — modo de automação alterado para: {modo}")
    return jsonify({"ok": True, "modo": modo})


# ══════════════════════════════════════════════════════════════════
#  ADMIN — Configurações gerais
# ══════════════════════════════════════════════════════════════════

@app.route("/api/admin/password", methods=["POST"])
@auth_required(roles=["admin"])
def change_password():
    data = request.get_json() or {}
    new_pw = data.get("password", "").strip()
    if len(new_pw) < 6:
        return jsonify({"error": "Senha muito curta (mínimo 6 caracteres)"}), 400
    cfg = load_config()
    cfg["admin"]["password"] = hashlib.sha256(new_pw.encode()).hexdigest()
    save_config(cfg)
    return jsonify({"ok": True})

# blocked.db (BLOCKED) é UM arquivo só, mas escrito por fontes bem
# diferentes: register_block() do limit.sh (Limiter — conexão simultânea
# de verdade), o watchdog de expirado, _suspend_login (suspensão manual)
# e block_reseller_client (cascata de revendedor suspenso). A tela
# "Bloqueios do Limiter" promete mostrar só o resultado do Limiter, então
# filtramos pelo motivo — só o register_block() do limit.sh escreve com
# esses prefixos, os outros têm texto próprio (ver cada um deles).
_LIMITER_REASON_PREFIXES = ("SSH duplicado", "UUID compartilhado", "SSH+Xray simultâneos")

def _is_limiter_block(motivo):
    return motivo.startswith(_LIMITER_REASON_PREFIXES)

@app.route("/api/admin/blocked", methods=["GET"])
@auth_required(roles=["admin"])
def list_blocked():
    blocked = []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 3 and _is_limiter_block(parts[2]):
                    blocked.append({"login": parts[0], "data": parts[1], "motivo": parts[2]})
    return jsonify(blocked)

@app.route("/api/admin/blocked", methods=["DELETE"])
@auth_required(roles=["admin"])
def clear_blocked():
    logins, keep_lines = [], []
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            for line in f:
                stripped = line.strip()
                parts = stripped.split("|")
                if len(parts) >= 3 and _is_limiter_block(parts[2]):
                    logins.append(parts[0])
                elif stripped:
                    keep_lines.append(line if line.endswith("\n") else line + "\n")
    # Só desbloqueia/limpa o que é bloqueio do Limiter — bloqueios por
    # expiração, suspensão manual ou suspensão de revendedor NÃO são
    # tocados aqui (reativar essas contas não é papel deste botão; o
    # admin faz isso explicitamente pelo botão Desbloquear/Renovar de
    # cada uma). Antes, isso só zerava o arquivo — a "tela de bloqueados"
    # achava que tinha desbloqueado todo mundo, mas o Xray nunca era
    # re-adicionado pra ninguém, então o acesso continuava fora do ar
    # de verdade.
    for login in logins:
        _unblock_login(login)
    with open(BLOCKED, "w") as f:
        f.writelines(keep_lines)
    device_log_write(f"BLOCKED (Limiter) — limpeza em massa pelo admin: {len(logins)} usuário(s) desbloqueado(s) ({', '.join(logins[:20])})")
    return jsonify({"ok": True, "desbloqueados": len(logins)})

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok", "version": "1.0"})

# ══════════════════════════════════════════════════════════════════
#  DEVICE CHECK — Bloqueio por dispositivo (100% LOCAL)
#  Porta o comportamento de device_check.php + reset_user.php para
#  cá, resolvendo o usuário direto em /etc/painel/usuarios.db
#  (login OU uuid, case-insensitive) em vez de consultar um painel
#  remoto. Chamado pelo APP CLIENTE a cada conexão.
# ══════════════════════════════════════════════════════════════════

def _load_checkuser_token():
    if os.path.exists(CHECKUSER_TOKEN_F):
        try:
            with open(CHECKUSER_TOKEN_F) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def load_device_token():
    if os.path.exists(DEVICE_TOKEN_F):
        try:
            with open(DEVICE_TOKEN_F) as f:
                return f.read().strip()
        except Exception:
            return ""
    return ""

def device_token_required(f):
    def wrapper(*args, **kwargs):
        expected = load_device_token()
        got = request.headers.get("X-Device-Token") or request.form.get("device_token", "")
        if not expected or got != expected:
            return jsonify({"status": "error", "message": "token inválido"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def get_device_db():
    os.makedirs(os.path.dirname(DEVICE_DB), exist_ok=True)
    conn = sqlite3.connect(DEVICE_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS devices (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        device_hash TEXT NOT NULL,
        phone       TEXT,
        ip          TEXT,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        UNIQUE(username, device_hash)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS device_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        device_hash TEXT NOT NULL,
        phone       TEXT,
        ip          TEXT,
        action      TEXT NOT NULL,
        reason      TEXT,
        created_at  TEXT NOT NULL
    )""")
    conn.commit()
    return conn

def _device_client_ip():
    """IP real do cliente pro bloqueio por dispositivo. Tenta
    request.remote_addr (já com ProxyFix), depois lê X-Forwarded-For na
    unha (pega o primeiro IP da cadeia, cobre caso haja mais de um proxy
    na frente), e por último aceita um campo 'ip' enviado pelo próprio
    app cliente — sem isso, toda checagem que não chegasse via Nginx
    exatamente como o ProxyFix espera aparecia como 127.0.0.1 na lista
    de Dispositivos."""
    addr = (request.remote_addr or "").strip()
    if addr and addr not in ("127.0.0.1", "::1", "localhost"):
        return addr
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first and first not in ("127.0.0.1", "::1"):
            return first
    client_ip = (request.form.get("ip") or request.args.get("ip") or "").strip()
    if client_ip:
        return client_ip
    return addr or "unknown"

def device_log_write(line):
    try:
        with open(DEVICE_LOG, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {line}\n")
    except Exception:
        pass

def system_log_write(line):
    """Log sistêmico dedicado — serviços subindo/caindo, config
    corrompido/recuperado, exceções não tratadas. Ver comentário em
    SYSTEM_LOG acima do porquê disso ser separado do device_log_write."""
    try:
        with open(SYSTEM_LOG, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {line}\n")
    except Exception:
        pass

def resolve_user_local(identifier):
    """Resolve por login OU uuid (case-insensitive) direto no usuarios.db local."""
    ident = identifier.strip().lower()
    for u in read_users():
        if u["login"].lower() == ident or u["uuid"].lower() == ident:
            return u
    return None

def _device_check_core(username, device_hash, phone, ip):
    """
    Lógica central do bloqueio por dispositivo. Usada tanto pelo endpoint
    seguro (/api/device/check, exige X-Device-Token) quanto pelo endpoint
    de compatibilidade (/device_check.php, formato idêntico ao que o app
    cliente Painel Netsimon já envia hoje — sem exigir header extra, preservando
    o comportamento original do app sem precisar recompilar a lógica dele).
    Retorna um dict pronto para jsonify.
    """
    if not username or not device_hash:
        return {"status": "error", "message": "Parâmetros inválidos"}, 400

    user = resolve_user_local(username)
    if not user:
        return {"status": "error", "message": "Usuário não encontrado"}, 404

    uuid_val = user["uuid"]
    limite   = int(user["limite"]) if str(user["limite"]).isdigit() else 1
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block_on = device_block_enabled()

    # BUGFIX: esta função é a porta de entrada real chamada pelo app antes
    # de abrir o túnel — antes ela só checava limite de dispositivo e NUNCA
    # expiração. Resultado: um usuário vencido passava por aqui como
    # "allowed" e só era derrubado depois, reativamente, pelo limit.sh (até
    # 8s de janela livre, e só se já estivesse conectado). Agora expiração
    # é checada aqui primeiro, então uma conexão nova de usuário vencido já
    # nasce bloqueada — independente do limiter estar rodando ou não.
    if is_expired(user["expira"]):
        device_log_write(f"BLOCKED (expirado) | user={user['login']}({uuid_val}) | hash={device_hash} | ip={ip} | exp={user['expira']}")
        run_cmd(f"sed -i '/^{user['login']}|/d' {BLOCKED}")
        with open(BLOCKED, "a") as f:
            f.write(f"{user['login']}|{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}|Usuário expirado ({user['expira']})\n")
        xray_kick_live(user["login"])
        run_cmd(f"""
            bash -c '
            pkill -KILL -u "{user['login']}" 2>/dev/null
            source /etc/painel/xray_lib.sh
            xray_remove_client_safe "{user['login']}"
            passwd -l "{user['login']}" 2>/dev/null
            '
        """)
        result = {"status": "expired", "message": "Acesso expirado.", "expira": user["expira"]}
        return result, 200

    conn = get_device_db()
    cur  = conn.cursor()

    cur.execute("UPDATE devices SET username=? WHERE LOWER(username)=LOWER(?) AND username!=?",
                (uuid_val, uuid_val, uuid_val))

    cur.execute("SELECT device_hash FROM devices WHERE username=?", (uuid_val,))
    registered = [r[0] for r in cur.fetchall()]
    is_registered = device_hash in registered
    count = len(registered)

    # Se o admin desligou o bloqueio por dispositivo (interruptor próprio,
    # separado do Limiter), a checagem nunca bloqueia — mas o dispositivo
    # continua sendo registrado logo abaixo, pra lista/contagem na tela
    # ficarem corretas e o histórico já estar certo se for reativado depois.
    if block_on and not is_registered and count >= limite:
        cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (uuid_val, device_hash, phone, ip, "BLOCKED",
                     f"Limite de {limite} dispositivo(s) atingido. Registrados: {count}", now))
        conn.commit(); conn.close()
        device_log_write(f"BLOCKED | user={user['login']}({uuid_val}) | hash={device_hash} | ip={ip} | limite={limite} | registrados={count}")

        # CORREÇÃO CRÍTICA (07/08): a versão anterior aplicava aqui a MESMA
        # trilha de enforcement usada para expirado/suspensão/limiter —
        # derrubava SSH+Xray e travava a senha da conta INTEIRA (passwd -l),
        # exigindo desbloqueio manual do admin. Isso causava bloqueio total
        # indevido sempre que o PRÓPRIO device_hash do app mudava entre
        # conexões (ex.: atualização do app), mesmo sem nenhuma duplicidade
        # real — o dispositivo 1, já registrado, ficava sem acesso junto.
        #
        # device_check é uma checagem PRÉ-túnel (roda antes do túnel abrir).
        # Pra um cliente que respeita "status":"blocked" (o app oficial),
        # simplesmente NÃO abrir o túnel já é suficiente — não precisa
        # derrubar sessão nem remover o client do Xray nem travar a conta.
        # Duplicidade REAL (2 conexões simultâneas de fato, inclusive de
        # cliente que ignora essa checagem) é papel do Limiter (limit.sh),
        # que não depende de device_hash e já cobre esse caso. Aqui só
        # recusamos ESTA tentativa específica — a conta e o dispositivo já
        # registrado continuam intactos e funcionando normalmente.
        result = {"status": "blocked", "message": "Acesso bloqueado: limite de dispositivos atingido.",
                  "limit": limite, "devices": count}
        return result, 200

    if not is_registered:
        cur.execute("""INSERT OR IGNORE INTO devices (username, device_hash, phone, ip, first_seen, last_seen)
                        VALUES (?,?,?,?,?,?)""", (uuid_val, device_hash, phone, ip, now, now))
        cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                        VALUES (?,?,?,?,?,?,?)""",
                    (uuid_val, device_hash, phone, ip, "NEW_DEVICE", f"Novo dispositivo (login={user['login']})", now))
        device_log_write(f"NEW_DEVICE | user={user['login']}({uuid_val}) | hash={device_hash} | ip={ip}")
        count += 1
    else:
        cur.execute("UPDATE devices SET last_seen=?, ip=? WHERE username=? AND device_hash=?",
                    (now, ip, uuid_val, device_hash))

    conn.commit(); conn.close()
    photos = read_photos()
    foto = photos.get(user["login"])
    result = {"status": "allowed", "message": "Dispositivo autorizado.",
              "limit": limite, "devices": count,
              "foto_url": build_public_url(f"/fotos/{foto}") if foto else ""}
    return result, 200

def _build_api_keys_block():
    """Monta o bloco api_keys (versão + chaves por revendedor) que o app
    cliente cacheia localmente e usa depois para consultar o CheckUser
    (/api/checkuser/list) de cada revendedor. Tudo nativo do painel."""
    cfg = load_config()
    keys = {name: data.get("api_key", "") for name, data in cfg.get("resellers", {}).items() if data.get("api_key")}
    return {"version": int(cfg.get("api_keys_version", 0)), "keys": keys}

@app.route("/api/device/check", methods=["POST"])
@device_token_required
def device_check():
    """Endpoint seguro (exige X-Device-Token) — recomendado para novas integrações."""
    username    = request.form.get("username", "").strip()
    device_hash = request.form.get("device_hash", "").strip()
    phone       = request.form.get("phone", "").strip()
    ip          = _device_client_ip()

    result, status_code = _device_check_core(username, device_hash, phone, ip)
    if status_code == 200:
        result["api_keys"] = _build_api_keys_block()
    return jsonify(result), status_code

@app.route("/device_check.php", methods=["POST"])
def device_check_compat():
    """
    Endpoint de COMPATIBILIDADE — mesmo path e mesmo formato de requisição
    que o app cliente Painel Netsimon já usa hoje (username, device_hash, phone,
    keys_version via form-data, sem header de autenticação). Existe para
    que o app converse com o painel apenas trocando o host, sem precisar
    reescrever a lógica Kotlin de device check.

    ⚠️ Por não exigir token, esse endpoint é mais exposto que o
    /api/device/check. Considere restringir por firewall/rate-limit se
    o painel estiver publicamente acessível.
    """
    username    = request.form.get("username", "").strip()
    device_hash = request.form.get("device_hash", "").strip()
    phone       = request.form.get("phone", "").strip()
    ip          = _device_client_ip()

    result, status_code = _device_check_core(username, device_hash, phone, ip)
    if status_code == 200:
        result["api_keys"] = _build_api_keys_block()
    return jsonify(result), status_code

@app.route("/api/checkuser/list", methods=["POST"])
def checkuser_list():
    """
    Endpoint nativo de CheckUser em lote, usado pelo app cliente Painel Netsimon
    (mesmo contrato de sempre: form-data passapi + module=userget,
    resposta em array JSON). O app já faz parsing tolerante de vários
    nomes de campo; aqui usamos os nomes principais (login, expira,
    limite, count_connections). Comunicação 100% direta entre o app e
    este painel — nenhum sistema externo envolvido.

    passapi pode ser:
      - o token mestre do CheckUser (/etc/painel/checkuser.token)
        → retorna TODOS os usuários
      - o api_key de um revendedor específico (gerado ao criar o
        revendedor) → retorna só os usuários daquele revendedor
    """
    passapi = request.form.get("passapi", "").strip()
    module  = request.form.get("module", "").strip()

    if module != "userget" or not passapi:
        return jsonify({"error": "requisição inválida"}), 400

    master_token = _load_checkuser_token()

    cfg = load_config()
    scope_users = None  # None = todos (admin/master)

    if passapi == master_token:
        scope_users = None
    else:
        matched_reseller = None
        for name, data in cfg.get("resellers", {}).items():
            if data.get("api_key") == passapi:
                matched_reseller = name
                break
        if not matched_reseller:
            return jsonify([])  # chave não reconhecida — array vazio, app tenta a próxima
        scope_users = set(cfg["resellers"][matched_reseller].get("users", []))

    online = set(get_online_users())
    photos = read_photos()
    result = []
    for u in read_users():
        if scope_users is not None and u["login"] not in scope_users:
            continue
        foto = photos.get(u["login"])
        result.append({
            "login":            u["login"],
            "expira":           u["expira"],
            "limite":           int(u["limite"]) if str(u["limite"]).isdigit() else 1,
            "count_connections": 1 if u["login"] in online else 0,
            "foto_url":         build_public_url(f"/fotos/{foto}") if foto else ""
        })
    return jsonify(result)

@app.route("/api/device/list", methods=["GET"])
@auth_required()
def device_list():
    """Lista dispositivos registrados. Revendedor só vê os seus usuários."""
    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()

    users = {u["uuid"]: u["login"] for u in read_users()}
    s = request.ns_session
    owned = None
    if s["role"] == "reseller":
        cfg = load_config()
        owned = set(cfg["resellers"].get(s["user"], {}).get("users", []))

    result = []
    for r in rows:
        uuid_val, dhash, phone, ip, first_seen, last_seen = r
        login = users.get(uuid_val, uuid_val)
        if owned is not None and login not in owned:
            continue
        result.append({
            "login": login, "uuid": uuid_val, "device_hash": dhash,
            "phone": phone, "ip": ip, "first_seen": first_seen, "last_seen": last_seen
        })
    return jsonify(result)

def _recent_device_blocked_logins():
    """Logins com bloqueio REAL por dispositivo (device_hash) ativo agora
    — mesma fonte/janela de /api/device/blocked-attempts (device_log,
    ação=BLOCKED, últimas DEVICE_BLOCK_WINDOW_HOURS), só que aqui devolve
    um set() de logins em vez da lista completa pra UI. Existe porque o
    card "Bloqueados" do dashboard (e o Block: do menu SSH) misturavam
    esse número com dispositivos apenas REGISTRADOS (nunca bloqueados) ou
    com o total de blocked.db (que também tem expirado/suspensão manual —
    ver _is_limiter_block). Reaproveita a mesma limpeza de >48h pra não
    deixar tentativas antigas inflando a contagem."""
    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=DEVICE_BLOCK_WINDOW_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM device_log WHERE action='BLOCKED' AND created_at < ?", (cutoff,))
    conn.commit()
    cur.execute("SELECT DISTINCT username FROM device_log WHERE action='BLOCKED'")
    uuids = {r[0] for r in cur.fetchall()}
    conn.close()
    users = {u["uuid"]: u["login"] for u in read_users()}
    return {users.get(u, u) for u in uuids}

@app.route("/api/device/blocked-attempts", methods=["GET"])
@auth_required()
def device_blocked_attempts():
    """Lista as tentativas REAIS de acesso bloqueadas pelo Bloqueio por
    Dispositivo (device_hash) — diferente de /api/device/list, que só
    mostra os dispositivos JÁ REGISTRADOS/liberados. Essa distinção
    importa: um aparelho aparece na lista de "Dispositivos" assim que
    consegue se conectar pela primeira vez (registro, não bloqueio); só
    aparece AQUI se ele tentou conectar e foi recusado por já existir
    outro aparelho ocupando o limite daquele usuário. Os dados sempre
    existiram no banco (tabela device_log, ação=BLOCKED), só nunca
    tinham uma tela própria pra mostrar isso.

    Item CORREÇÃO: a lista crescia pra sempre (só limitada pelo LIMIT 100
    do SELECT), então tentativas de meses atrás continuavam aparecendo.
    Agora, a cada consulta, qualquer registro BLOCKED com mais de 48h é
    apagado do banco antes de montar a resposta — a lista sempre reflete
    só as últimas DEVICE_BLOCK_WINDOW_HOURS horas."""
    cutoff_48h = (datetime.datetime.now() - datetime.timedelta(hours=DEVICE_BLOCK_WINDOW_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM device_log WHERE action='BLOCKED' AND created_at < ?", (cutoff_48h,))
    conn.commit()
    cur.execute("""SELECT username, device_hash, phone, ip, reason, created_at
                   FROM device_log WHERE action='BLOCKED'
                   ORDER BY created_at DESC LIMIT 100""")
    rows = cur.fetchall()
    conn.close()

    users = {u["uuid"]: u["login"] for u in read_users()}
    s = request.ns_session
    owned = None
    if s["role"] == "reseller":
        cfg = load_config()
        owned = set(cfg["resellers"].get(s["user"], {}).get("users", []))

    result = []
    for uuid_val, dhash, phone, ip, reason, created_at in rows:
        login = users.get(uuid_val, uuid_val)
        if owned is not None and login not in owned:
            continue
        result.append({"login": login, "device_hash": dhash, "phone": phone,
                        "ip": ip, "reason": reason, "created_at": created_at})
    return jsonify(result)

@app.route("/api/device/reset/<login>", methods=["POST"])
@auth_required()
def device_reset(login):
    """Remove todos os dispositivos de um usuário, liberando para novo
    aparelho. Se o usuário estiver bloqueado (ex: bateu no limite de
    conexões simultâneas), também desbloqueia — antes essa rota só
    limpava as impressões digitais dos aparelhos e deixava o bloqueio
    intacto, então o usuário continuava aparecendo "bloqueado" nas telas
    de Usuários mesmo depois do admin achar que tinha liberado o acesso
    por aqui (o texto de confirmação já dizia "poderá conectar de novo",
    então o comportamento esperado sempre foi esse).

    Também funciona em registros "órfãos" — dispositivos de um usuário
    que já foi apagado do painel. Antes, como a rota exigia achar um
    usuário vivo com aquele login/uuid, resetar um órfão sempre dava
    "Usuário não encontrado", e o registro ficava preso pra sempre na
    lista de Dispositivos sem nenhuma forma de limpar pela tela."""
    s = request.ns_session
    user = resolve_user_local(login)

    if s["role"] == "reseller":
        cfg = load_config()
        owned = cfg["resellers"].get(s["user"], {}).get("users", [])
        if login not in owned:
            return jsonify({"error": "forbidden"}), 403

    # Se o usuário ainda existe, o identificador salvo na tabela devices
    # é o uuid dele; se não existe mais, o próprio "login" recebido JÁ É
    # o identificador cru gravado (uuid de um usuário apagado).
    device_key = user["uuid"] if user else login

    conn = get_device_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices WHERE username=?", (device_key,))
    changed = cur.rowcount

    if changed == 0 and not user:
        conn.close()
        return jsonify({"error": "Nenhum dispositivo encontrado para esse identificador"}), 404

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""INSERT INTO device_log (username, device_hash, phone, ip, action, reason, created_at)
                    VALUES (?,?,?,?,?,?,?)""",
                (device_key, "-", "-", "-", "RESET_BY_ADMIN",
                 f"Reset manual via painel ({s['user']})" + ("" if user else " [usuário já removido do painel]"), now))
    conn.commit(); conn.close()

    estava_bloqueado = False
    if os.path.exists(BLOCKED):
        with open(BLOCKED) as f:
            estava_bloqueado = any(line.split("|")[0] == login for line in f)
    if estava_bloqueado:
        _unblock_login(login)

    device_log_write(f"RESET_BY_ADMIN | user={login} | uuid={device_key} | devices_removidos={changed}"
                      + (" | desbloqueado=sim" if estava_bloqueado else "")
                      + ("" if user else " | usuario_ja_removido=sim"))
    return jsonify({"ok": True, "removed": changed, "desbloqueado": estava_bloqueado})

@app.route("/api/device/block/status", methods=["GET"])
@auth_required()
def device_block_status_route():
    """Estado do interruptor do bloqueio por dispositivo (device_hash).
    100% independente do Limiter — ver /api/services/limiter/status para
    o outro sistema (conexões simultâneas por IP/SSH)."""
    return jsonify({"enabled": device_block_enabled()})

@app.route("/api/device/block/enable", methods=["POST"])
@auth_required(roles=["admin"])
def device_block_enable_route():
    set_device_block_enabled(True)
    device_log_write(f"DEVICE_BLOCK ATIVADO via painel por {request.ns_session['user']}")
    return jsonify({"enabled": True})

@app.route("/api/device/block/disable", methods=["POST"])
@auth_required(roles=["admin"])
def device_block_disable_route():
    set_device_block_enabled(False)
    device_log_write(f"DEVICE_BLOCK DESATIVADO via painel por {request.ns_session['user']}")
    return jsonify({"enabled": False})

# ══════════════════════════════════════════════════════════════════
#  APP RELEASES — Upload/Download de versões do aplicativo cliente
#  Admin sobe o APK; revendedores baixam pelo próprio painel deles;
#  link direto é gerado para enviar ao cliente final. Serve de base
#  para o futuro sistema de auto-update do app (via /api/app/latest).
# ══════════════════════════════════════════════════════════════════

ALLOWED_APP_EXT = {"apk"}

def load_app_releases():
    if not os.path.exists(APP_META):
        return []
    try:
        with open(APP_META) as f:
            return json.load(f)
    except Exception:
        return []

def save_app_releases(data):
    os.makedirs(APP_DIR, exist_ok=True)
    _atomic_write_json(APP_META, data, indent=2)

@app.route("/api/app/versions", methods=["GET"])
@auth_required()
def app_list_versions():
    releases = load_app_releases()
    releases.sort(key=lambda r: r.get("uploaded_at", ""), reverse=True)
    return jsonify(releases)

@app.route("/api/app/upload", methods=["POST"])
@auth_required(roles=["admin"])
def app_upload():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    version   = request.form.get("version", "").strip()
    changelog = request.form.get("changelog", "").strip()

    if not version or not re.match(r'^[a-zA-Z0-9._-]{1,30}$', version):
        return jsonify({"error": "Versão inválida"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_APP_EXT:
        return jsonify({"error": "Apenas arquivos .apk são aceitos"}), 400

    os.makedirs(APP_DIR, exist_ok=True)
    filename = secure_filename(f"netsimon-{version}.apk")
    filepath = os.path.join(APP_DIR, filename)
    file.save(filepath)
    size = os.path.getsize(filepath)

    releases = load_app_releases()
    releases = [r for r in releases if r["version"] != version]  # substitui se já existir
    releases.append({
        "version":     version,
        "filename":    filename,
        "changelog":   changelog,
        "size":        size,
        "uploaded_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uploaded_by": request.ns_session["user"],
        "latest":      False,
        "url":         f"{APP_PUBLIC_URL}/{filename}"
    })
    save_app_releases(releases)
    return jsonify({"ok": True, "version": version, "url": f"{APP_PUBLIC_URL}/{filename}"}), 201

@app.route("/api/app/versions/<version>/latest", methods=["POST"])
@auth_required(roles=["admin"])
def app_set_latest(version):
    releases = load_app_releases()
    found = False
    for r in releases:
        if r["version"] == version:
            r["latest"] = True
            found = True
        else:
            r["latest"] = False
    if not found:
        return jsonify({"error": "Versão não encontrada"}), 404
    save_app_releases(releases)
    return jsonify({"ok": True})

@app.route("/api/app/versions/<version>", methods=["DELETE"])
@auth_required(roles=["admin"])
def app_delete_version(version):
    releases = load_app_releases()
    target = next((r for r in releases if r["version"] == version), None)
    if not target:
        return jsonify({"error": "Versão não encontrada"}), 404
    filepath = os.path.join(APP_DIR, target["filename"])
    if os.path.exists(filepath):
        os.remove(filepath)
    releases = [r for r in releases if r["version"] != version]
    save_app_releases(releases)
    return jsonify({"ok": True})

@app.route("/api/ai-assistant/config", methods=["GET"])
@auth_required()
def get_ai_assistant_config_route():
    # Item 3: cada painel (admin ou revendedor) só vê/edita a PRÓPRIA
    # config — nunca a de outro revendedor nem a do admin.
    owner = _owner_key(request.ns_session)
    ai = get_ai_assistant_config(owner)
    ai = dict(ai)
    ai["has_key"] = bool(ai.get("api_key"))
    ai["api_key"] = _ai_mask_key(ai.get("api_key", "")) if ai.get("api_key") else ""
    return jsonify(ai)

@app.route("/api/ai-assistant/config", methods=["PUT"])
@auth_required()
def save_ai_assistant_config_route():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    ai = get_ai_assistant_config(owner)

    if "enabled" in data:
        ai["enabled"] = bool(data["enabled"])
    if "model" in data and data["model"]:
        ai["model"] = data["model"].strip()
    if "system_prompt" in data:
        ai["system_prompt"] = data["system_prompt"].strip()
    if "log_conversations" in data:
        ai["log_conversations"] = bool(data["log_conversations"])
    if "max_history_turns" in data:
        try:
            ai["max_history_turns"] = max(0, min(30, int(data["max_history_turns"])))
        except (TypeError, ValueError):
            pass
    # a chave só é sobrescrita se vier um valor novo de verdade — assim
    # salvar o resto do formulário não apaga a chave já configurada
    # (o campo no frontend chega mascarado/vazio quando não foi alterado)
    new_key = (data.get("api_key") or "").strip()
    if new_key and "•" not in new_key:
        ai["api_key"] = new_key

    save_ai_assistant_config(owner, ai)

    out = dict(ai)
    out["has_key"] = bool(out.get("api_key"))
    out["api_key"] = _ai_mask_key(out.get("api_key", "")) if out.get("api_key") else ""
    return jsonify(out)

@app.route("/api/ai-assistant/test", methods=["POST"])
@auth_required()
def test_ai_assistant_route():
    """Manda uma mensagem de teste pra Gemini com a chave/modelo já
    salvos (ou os que vieram no corpo, pra poder testar antes de salvar)."""
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    ai = get_ai_assistant_config(owner)
    if data.get("api_key") and "•" not in data["api_key"]:
        ai["api_key"] = data["api_key"].strip()
    if data.get("model"):
        ai["model"] = data["model"].strip()

    if not ai.get("api_key"):
        return jsonify({"ok": False, "error": "Configure e salve uma chave de API antes de testar"}), 400

    wa = get_owner_wa_config(owner)
    prompt = _ai_system_prompt(ai, wa)
    ok, reply = _call_gemini(ai, prompt, [], "Oi, esse é um teste de conexão. Responda em uma frase curta confirmando que está tudo funcionando.")
    if not ok:
        return jsonify({"ok": False, "error": reply}), 400
    return jsonify({"ok": True, "reply": reply})

# ── "Treinar a IA" — conhecimento persistente (ver _ai_load_training) ──
@app.route("/api/ai-assistant/training", methods=["GET"])
@auth_required(roles=["admin"])
def ai_training_list():
    return jsonify({"itens": list(reversed(_ai_load_training()))})

@app.route("/api/ai-assistant/training", methods=["POST"])
@auth_required(roles=["admin"])
def ai_training_add():
    data = request.get_json() or {}
    texto = (data.get("texto") or "").strip()
    if not texto:
        return jsonify({"error": "Escreva o que a IA deve aprender antes de salvar"}), 400
    items = _ai_load_training()
    items.append({
        "id": uuidlib.uuid4().hex[:12],
        "texto": texto,
        "criado_em": datetime.datetime.now().isoformat(),
    })
    _ai_save_training(items)
    system_log_write(f"IA — novo treinamento adicionado: {texto[:80]}")
    return jsonify({"ok": True, "itens": list(reversed(items))})

@app.route("/api/ai-assistant/training/<item_id>", methods=["DELETE"])
@auth_required(roles=["admin"])
def ai_training_delete(item_id):
    items = _ai_load_training()
    novos = [i for i in items if i.get("id") != item_id]
    if len(novos) == len(items):
        return jsonify({"error": "Item não encontrado"}), 404
    _ai_save_training(novos)
    return jsonify({"ok": True, "itens": list(reversed(novos))})

# ── COMANDOS PERSONALIZADOS DO BOT — pares palavra(s)-chave -> resposta
# fixa, cadastráveis pelo admin sem precisar mexer em código nem pedir
# correção pra cada palavra nova. Fica salvo em
# /etc/painel/whatsapp_custom_commands.json (mesmo padrão do
# ai_training.json — arquivo solto DENTRO de /etc/painel, então já
# entra automaticamente no backup completo existente e volta sozinho
# num restore/reinstalação).
#
# Diferente de "Treinar a IA": aqui a resposta é DETERMINÍSTICA (roda
# antes do fallback de IA, sempre a mesma resposta pra mesma palavra,
# não depende da IA estar ligada nem de interpretação) — é o lugar
# certo pra "quando o cliente digitar X, responda Y" ao pé da letra.
CUSTOM_CMDS_F = os.path.join(BASE, "whatsapp_custom_commands.json")

def _load_custom_commands():
    if not os.path.exists(CUSTOM_CMDS_F):
        return []
    try:
        with open(CUSTOM_CMDS_F) as f:
            return json.load(f)
    except Exception:
        return []

def _save_custom_commands(items):
    _atomic_write_json(CUSTOM_CMDS_F, items, indent=2)

def _match_custom_command(owner, text):
    """Primeira regra cadastrada (por esse owner) cuja(s) palavra(s)-chave
    batem como substring do texto (mesmo estilo dos comandos fixos do
    bot, ex: "apk" in text) vence — ordem de cadastro, a mais antiga
    primeiro."""
    for item in _load_custom_commands():
        if item.get("owner") != owner:
            continue
        for kw in item.get("keywords", []):
            if kw and kw in text:
                return item.get("reply", "")
    return None

@app.route("/api/whatsapp/custom-commands", methods=["GET"])
@auth_required(roles=["admin"])
def custom_commands_list():
    owner = _owner_key(request.ns_session)
    items = [i for i in _load_custom_commands() if i.get("owner") == owner]
    return jsonify({"itens": list(reversed(items))})

@app.route("/api/whatsapp/custom-commands", methods=["POST"])
@auth_required(roles=["admin"])
def custom_commands_add():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    keywords_raw = (data.get("keywords") or "").strip()
    reply = (data.get("reply") or "").strip()
    if not keywords_raw:
        return jsonify({"error": "Informe pelo menos uma palavra-chave"}), 400
    if not reply:
        return jsonify({"error": "Escreva a resposta que o bot deve enviar"}), 400
    keywords = [k.strip().lower() for k in keywords_raw.split(",") if k.strip()]
    if not keywords:
        return jsonify({"error": "Informe pelo menos uma palavra-chave válida"}), 400
    items = _load_custom_commands()
    items.append({
        "id": uuidlib.uuid4().hex[:12],
        "owner": owner,
        "keywords": keywords,
        "reply": reply,
        "criado_em": datetime.datetime.now().isoformat(),
    })
    _save_custom_commands(items)
    system_log_write(f"BOT — novo comando personalizado adicionado ({owner}): {', '.join(keywords)}")
    return jsonify({"ok": True, "itens": list(reversed([i for i in items if i.get("owner") == owner]))})

@app.route("/api/whatsapp/custom-commands/<item_id>", methods=["DELETE"])
@auth_required(roles=["admin"])
def custom_commands_delete(item_id):
    owner = _owner_key(request.ns_session)
    items = _load_custom_commands()
    novos = [i for i in items if not (i.get("id") == item_id and i.get("owner") == owner)]
    if len(novos) == len(items):
        return jsonify({"error": "Item não encontrado"}), 404
    _save_custom_commands(novos)
    return jsonify({"ok": True, "itens": list(reversed([i for i in novos if i.get("owner") == owner]))})

# ── Contatos ignorados pela automação (bloqueio determinístico — ver
# _wa_is_ignored). Por owner: cada painel (admin ou revendedor) só
# enxerga/gerencia os números ignorados do PRÓPRIO bot de WhatsApp.
@app.route("/api/whatsapp/ignored-contacts", methods=["GET"])
@auth_required()
def wa_ignored_contacts_list():
    owner = _owner_key(request.ns_session)
    itens = _wa_load_ignored().get(owner, [])
    return jsonify({"itens": list(reversed(itens))})

@app.route("/api/whatsapp/ignored-contacts", methods=["POST"])
@auth_required()
def wa_ignored_contacts_add():
    owner = _owner_key(request.ns_session)
    data = request.get_json() or {}
    phone = re.sub(r"\D", "", data.get("phone", ""))
    nota = (data.get("nota") or "").strip()
    if not phone:
        return jsonify({"error": "Informe um número de telefone válido"}), 400
    todos = _wa_load_ignored()
    itens = todos.setdefault(owner, [])
    if any(it.get("phone") == phone for it in itens):
        return jsonify({"error": "Esse número já está na lista de ignorados"}), 400
    itens.append({
        "id": uuidlib.uuid4().hex[:12],
        "phone": phone,
        "nota": nota,
        "criado_em": datetime.datetime.now().isoformat(),
    })
    _wa_save_ignored(todos)
    system_log_write(f"WhatsApp ({owner}): contato {phone} adicionado à lista de ignorados pela automação")
    return jsonify({"ok": True, "itens": list(reversed(itens))})

@app.route("/api/whatsapp/ignored-contacts/<item_id>", methods=["DELETE"])
@auth_required()
def wa_ignored_contacts_delete(item_id):
    owner = _owner_key(request.ns_session)
    todos = _wa_load_ignored()
    itens = todos.get(owner, [])
    novos = [i for i in itens if i.get("id") != item_id]
    if len(novos) == len(itens):
        return jsonify({"error": "Item não encontrado"}), 404
    todos[owner] = novos
    _wa_save_ignored(todos)
    system_log_write(f"WhatsApp ({owner}): contato removido da lista de ignorados pela automação")
    return jsonify({"ok": True, "itens": list(reversed(novos))})

# ── Relatório de situação geral (item pedido: um botão que resume o
# estado do painel — vencimentos, serviços, o que o autodiagnóstico já
# corrigiu sozinho e o que ainda precisa de atenção) ──────────────────
AI_REPORT_SYSTEM_PROMPT = (
    "Você é o assistente de operações do Painel Netsimon (painel de revenda de acesso VPN/WebSocket). "
    "Você vai receber um resumo técnico BRUTO já coletado do servidor (não invente nada além disso) e deve "
    "devolver um relatório curto em português claro, para o administrador ler em poucos segundos. "
    "Estruture em tópicos com emojis, nesta ordem, PULANDO qualquer tópico que não tenha dado nenhuma "
    "pra reportar: 1) Situação geral (uma linha: está tudo bem ou não), 2) Usuários vencendo em breve "
    "(se houver — cite quantos e, se poucos, os nomes), 3) O que o autodiagnóstico corrigiu sozinho nas "
    "últimas 24h (se houver), 4) O que precisa da atenção do administrador agora (se houver — serviços "
    "fora do ar, incidentes que falharam). Seja direto, sem saudação nem despedida, sem inventar números "
    "que não foram te passados no resumo."
)

AI_REPORT_SYSTEM_PROMPT = (
    "Você é o assistente de operações do Painel Netsimon (painel de revenda de acesso VPN/WebSocket). "
    "Você vai receber um resumo técnico BRUTO já coletado do servidor (não invente nada além disso) e deve "
    "devolver um relatório curto em português claro, para o administrador ler em poucos segundos. "
    "Estruture em tópicos com emojis, nesta ordem, PULANDO qualquer tópico que não tenha dado nenhuma "
    "pra reportar: 1) Situação geral (uma linha: está tudo bem ou não), 2) Usuários vencendo em breve "
    "(se houver — cite quantos e, se poucos, os nomes), 3) O que o autodiagnóstico corrigiu sozinho nas "
    "últimas 24h (se houver), 4) O que precisa da atenção do administrador agora (se houver — serviços "
    "fora do ar, incidentes que falharam). Seja direto, sem saudação nem despedida, sem inventar números "
    "que não foram te passados no resumo."
)

# ══════════════════════════════════════════════════════════════════
#  Itens 5 e 7 — chat livre "Perguntar à IA" com memória de 72h e
#  ferramentas sob demanda (a IA decide quando puxar mais log).
# ══════════════════════════════════════════════════════════════════

# Item 5: histórico de conversa por dono (admin/revendedor), separado
# do log de transcript do WhatsApp (que é auditoria, não memória de
# conversa). Mesmo padrão de arquivo-JSON-por-owner do resto do painel.
AI_CHAT_HISTORY_FILE = "/etc/painel/ai_chat_history.json"
AI_CHAT_HISTORY_HOURS = 72

def _ai_chat_load_all():
    if not os.path.exists(AI_CHAT_HISTORY_FILE):
        return {}
    try:
        with open(AI_CHAT_HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _ai_chat_save_all(all_hist):
    _atomic_write_json(AI_CHAT_HISTORY_FILE, all_hist, indent=2)

def _ai_chat_get_history(owner):
    """Devolve o histórico do dono já podado pra só as últimas
    AI_CHAT_HISTORY_HOURS horas — turnos mais velhos são descartados
    aqui mesmo (na leitura), então uma conversa parada por mais de 72h
    reseta sozinha, exatamente como pedido, sem precisar de um job
    separado de limpeza."""
    all_hist = _ai_chat_load_all()
    turnos = all_hist.get(owner, [])
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=AI_CHAT_HISTORY_HOURS)
    vivos = []
    for t in turnos:
        try:
            if datetime.datetime.strptime(t["ts"], "%Y-%m-%d %H:%M:%S") >= cutoff:
                vivos.append(t)
        except Exception:
            continue
    if len(vivos) != len(turnos):
        all_hist[owner] = vivos
        _ai_chat_save_all(all_hist)
    return vivos

def _ai_chat_append(owner, role, text):
    all_hist = _ai_chat_load_all()
    turnos = all_hist.get(owner, [])
    turnos.append({"role": role, "text": text, "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    all_hist[owner] = turnos
    _ai_chat_save_all(all_hist)

def _ai_chat_clear(owner):
    all_hist = _ai_chat_load_all()
    all_hist[owner] = []
    _ai_chat_save_all(all_hist)

# Item 7: o README do projeto vira contexto fixo desse chat especificamente
# (não do bot de atendimento ao cliente no WhatsApp — o cliente final não
# precisa, nem deve, saber como o painel é montado por dentro). Lido uma
# vez e cacheado em memória; se o arquivo mudar, precisa só reiniciar o
# serviço (mesmo comportamento de qualquer outra constante carregada de
# disco no boot deste arquivo).
README_PATH = "/etc/painel/README.md"
def _readme_content():
    try:
        with open(README_PATH, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""
_README_CACHE = _readme_content()

AI_CHAT_SYSTEM_PROMPT = (
    "Você é o assistente técnico do PRÓPRIO administrador (ou revendedor) do Painel Netsimon — não é o "
    "atendimento ao cliente final, é uma ferramenta de trabalho pra quem opera o painel. Responda só com "
    "base em dados reais: o contexto que te passamos a cada pergunta (usuários, serviços, incidentes) e, "
    "quando fizer sentido, as ferramentas disponíveis (consultar_log_servico, consultar_incidente) pra "
    "investigar mais fundo antes de responder — use-as sempre que a pergunta exigir detalhe que você ainda "
    "não tem, não hesite em chamar mais de uma se precisar. Nunca invente número, log ou causa técnica que "
    "não veio de um desses dois lugares. Seja direto e prático, em português, como um colega técnico "
    "responderia — sem saudação nem despedida.\n\n"
    "Abaixo está o README do próprio projeto, pra você conhecer a arquitetura, os serviços e os recursos "
    "do sistema (use como conhecimento de fundo, não repita ele de volta a menos que perguntem):\n\n"
    f"{_README_CACHE}"
)

def _service_log_tail(key, linhas=60):
    """Últimas N linhas do log de um serviço — do arquivo dedicado
    quando existe (ver SERVICE_DIAG_INFO), ou do journalctl quando o
    serviço não tem log próprio em arquivo (ex: SlowDNS, BadVPN)."""
    info = SERVICE_DIAG_INFO.get(key)
    if not info:
        return f"(serviço '{key}' não reconhecido — use um de: {', '.join(SERVICE_DIAG_INFO)})"
    log_path = info.get("log")
    if log_path and os.path.exists(log_path):
        out, err, _ = run_cmd_full(f"tail -n {linhas} {log_path}")
        return out or err or "(arquivo de log existe mas está vazio)"
    out, err, _ = run_cmd_full(f"journalctl -u {info['unit']} -n {linhas} --no-pager")
    return out or err or "(journalctl não retornou nada — serviço pode nunca ter rodado nesta máquina)"

# Especificação das ferramentas no formato de function-calling da Gemini.
# Restritas ao painel ADMIN (ver _ai_chat_tool_executor) — são dados de
# infraestrutura do servidor inteiro, não de um revendedor específico.
AI_CHAT_TOOLS = [
    {
        "name": "consultar_log_servico",
        "description": "Lê as últimas linhas de log de um serviço do servidor (xray, proxy, limiter, "
                        "checkuser, badvpn ou slowdns) pra investigar por que ele caiu ou está com erro.",
        "parameters": {
            "type": "object",
            "properties": {
                "servico": {"type": "string", "enum": list(SERVICE_DIAG_INFO.keys())},
                "linhas": {"type": "integer", "description": "Quantas linhas finais do log ler (padrão 60, máx 200)"},
            },
            "required": ["servico"],
        },
    },
    {
        "name": "consultar_incidente",
        "description": "Lê os detalhes completos e a evidência técnica coletada de um incidente do "
                        "autodiagnóstico — use principalmente pra incidentes 'sem correção conhecida', que "
                        "precisam de análise manual e não têm causa óbvia no resumo padrão.",
        "parameters": {
            "type": "object",
            "properties": {"incidente_id": {"type": "string"}},
            "required": ["incidente_id"],
        },
    },
]

def _ai_chat_tool_executor(owner, name, args):
    if owner != "admin":
        return {"erro": "essas ferramentas de diagnóstico de infraestrutura são exclusivas do painel admin"}
    if name == "consultar_log_servico":
        servico = (args.get("servico") or "").strip()
        try:
            linhas = min(200, max(1, int(args.get("linhas") or 60)))
        except (TypeError, ValueError):
            linhas = 60
        return {"log": _service_log_tail(servico, linhas)}
    if name == "consultar_incidente":
        inc_id = (args.get("incidente_id") or "").strip()
        items = _diag_load_incidents()
        inc = next((i for i in items if i.get("id") == inc_id), None)
        if not inc:
            return {"erro": "incidente não encontrado — confira o id"}
        return {"incidente": inc}
    return {"erro": f"ferramenta desconhecida: {name}"}

def _call_gemini_chat(ai_cfg, system_prompt, history, user_text, tools_spec=None, tool_executor=None,
                       max_tokens=700, thinking_budget=300, max_tool_rounds=3):
    """Como _call_gemini, mas com suporte a function-calling — a IA pode
    pedir pra rodar uma ferramenta (ver AI_CHAT_TOOLS), a gente executa
    localmente e manda o resultado de volta, até ela decidir que já tem
    o que precisa pra responder em texto (ou até max_tool_rounds, pra
    nunca ficar num loop infinito gastando cota de API)."""
    api_key = (ai_cfg.get("api_key") or "").strip()
    if not api_key:
        return False, "Chave de API da Gemini não configurada"
    model = (ai_cfg.get("model") or "gemini-3-flash-preview").strip()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    system_prompt = (system_prompt or "") + _ai_training_as_prompt_block()

    contents = []
    for turn in history or []:
        role = "model" if turn.get("role") == "model" else "user"
        txt = (turn.get("text") or "").strip()
        if txt:
            contents.append({"role": role, "parts": [{"text": txt}]})
    contents.append({"role": "user", "parts": [{"text": user_text}]})

    payload_base = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": {"temperature": 0.6, "maxOutputTokens": max_tokens,
                              **({"thinkingConfig": {"thinkingBudget": thinking_budget}} if thinking_budget is not None else {})},
    }
    if tools_spec:
        payload_base["tools"] = [{"functionDeclarations": tools_spec}]

    for _ in range(max_tool_rounds + 1):
        payload = dict(payload_base)
        payload["contents"] = contents
        try:
            r = requests.post(url, json=payload, timeout=40)
        except requests.exceptions.RequestException as e:
            return False, f"Falha de conexão com a Gemini: {e}"
        if r.status_code == 429:
            return False, "Cota gratuita da Gemini esgotada no momento (erro 429)"
        if r.status_code != 200:
            return False, f"Erro Gemini (HTTP {r.status_code}): {r.text[:200]}"
        try:
            parts = r.json()["candidates"][0]["content"]["parts"]
        except Exception:
            return False, "Resposta inesperada da Gemini"

        function_calls = [p["functionCall"] for p in parts if "functionCall" in p]
        if function_calls and tool_executor:
            contents.append({"role": "model", "parts": parts})
            for fc in function_calls:
                resultado = tool_executor(fc.get("name"), fc.get("args") or {})
                contents.append({"role": "function",
                                  "parts": [{"functionResponse": {"name": fc.get("name"), "response": resultado}}]})
            continue  # manda de novo já com o resultado da ferramenta

        texto = "".join(p.get("text", "") for p in parts).strip()
        if not texto:
            return False, "A IA não retornou nenhum texto"
        return True, texto

    return False, "A IA tentou usar ferramentas demais numa única pergunta — tente reformular de forma mais direta."

@app.route("/api/ai-assistant/chat", methods=["GET"])
@auth_required()
def ai_chat_get_history():
    """Item 5: usado quando a tela de IA carrega — devolve a conversa
    de onde parou (últimas 72h), em vez de sempre começar vazia."""
    owner = _owner_key(request.ns_session)
    return jsonify({"historico": _ai_chat_get_history(owner)})

@app.route("/api/ai-assistant/chat", methods=["POST"])
@auth_required()
def ai_chat():
    owner = _owner_key(request.ns_session)
    ai = get_ai_assistant_config(owner)
    if not ai.get("api_key"):
        return jsonify({"error": "Configure uma chave de IA em Configurações > Assistente de IA antes de usar isso."}), 400

    data = request.get_json(silent=True) or {}
    pergunta = (data.get("pergunta") or "").strip()
    if not pergunta:
        return jsonify({"error": "Escreva uma pergunta"}), 400

    contexto, _ = _ai_build_status_context(request.ns_session)
    historico = _ai_chat_get_history(owner)

    # Item 7: ferramentas sob demanda e o README só entram pro painel
    # ADMIN — pro revendedor o chat continua só com o contexto já
    # escopado a ele (mesma isolação que já vale pro resto da IA dele).
    if owner == "admin":
        system_prompt = AI_CHAT_SYSTEM_PROMPT
        tools, executor = AI_CHAT_TOOLS, lambda name, args: _ai_chat_tool_executor(owner, name, args)
    else:
        system_prompt = AI_CHAT_SYSTEM_PROMPT.split("\n\nAbaixo está o README")[0]  # sem README nem menção a ferramentas
        tools, executor = None, None

    pergunta_com_contexto = f"[Dados atuais do painel]\n{contexto}\n\n[Pergunta do administrador]\n{pergunta}"
    ok, resposta = _call_gemini_chat(ai, system_prompt, historico, pergunta_com_contexto,
                                      tools_spec=tools, tool_executor=executor,
                                      max_tokens=900, thinking_budget=400)
    if not ok:
        return jsonify({"error": resposta}), 400

    _ai_chat_append(owner, "user", pergunta)
    _ai_chat_append(owner, "model", resposta)
    return jsonify({"ok": True, "resposta": resposta})

@app.route("/api/ai-assistant/chat", methods=["DELETE"])
@auth_required()
def ai_chat_clear():
    """Item 5: botão 'Limpar conversa' — reseta de verdade, sem memória
    nenhuma da conversa anterior pro próximo turno."""
    owner = _owner_key(request.ns_session)
    _ai_chat_clear(owner)
    return jsonify({"ok": True})

# ══════════════════════════════════════════════════════════════════
#  Item 4 — "Material": notas + arquivos guardados no disco do
#  servidor, exclusivo do admin (não é um recurso por revendedor).
# ══════════════════════════════════════════════════════════════════
MATERIAL_DIR       = "/etc/painel/material"
MATERIAL_FILES_DIR = f"{MATERIAL_DIR}/arquivos"
MATERIAL_NOTES_FILE = f"{MATERIAL_DIR}/notas.json"

def _material_load_notas():
    if not os.path.exists(MATERIAL_NOTES_FILE):
        return []
    try:
        with open(MATERIAL_NOTES_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def _material_save_notas(notas):
    _atomic_write_json(MATERIAL_NOTES_FILE, notas, indent=2)

@app.route("/api/material/notas", methods=["GET"])
@auth_required(roles=["admin"])
def material_list_notas():
    notas = sorted(_material_load_notas(), key=lambda n: n.get("atualizado_em", ""), reverse=True)
    return jsonify(notas)

@app.route("/api/material/notas", methods=["POST"])
@auth_required(roles=["admin"])
def material_create_nota():
    data = request.get_json() or {}
    titulo = (data.get("titulo") or "").strip() or "Sem título"
    conteudo = data.get("conteudo") or ""
    agora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    nota = {"id": uuidlib.uuid4().hex[:12], "titulo": titulo, "conteudo": conteudo,
            "criado_em": agora, "atualizado_em": agora}
    notas = _material_load_notas()
    notas.append(nota)
    _material_save_notas(notas)
    return jsonify(nota), 201

@app.route("/api/material/notas/<nota_id>", methods=["PUT"])
@auth_required(roles=["admin"])
def material_update_nota(nota_id):
    data = request.get_json() or {}
    notas = _material_load_notas()
    nota = next((n for n in notas if n["id"] == nota_id), None)
    if not nota:
        return jsonify({"error": "Nota não encontrada"}), 404
    if "titulo" in data:
        nota["titulo"] = (data["titulo"] or "").strip() or "Sem título"
    if "conteudo" in data:
        nota["conteudo"] = data["conteudo"] or ""
    nota["atualizado_em"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _material_save_notas(notas)
    return jsonify(nota)

@app.route("/api/material/notas/<nota_id>", methods=["DELETE"])
@auth_required(roles=["admin"])
def material_delete_nota(nota_id):
    notas = _material_load_notas()
    restantes = [n for n in notas if n["id"] != nota_id]
    if len(restantes) == len(notas):
        return jsonify({"error": "Nota não encontrada"}), 404
    _material_save_notas(restantes)
    return jsonify({"ok": True})

def _material_safe_path(filename):
    """Garante que o caminho final continua DENTRO de MATERIAL_FILES_DIR
    — sem isso, um filename tipo '../../etc/passwd' (mesmo depois do
    secure_filename, que já barra a maioria, mas não custa nada ter as
    duas camadas) poderia escapar da pasta de material."""
    os.makedirs(MATERIAL_FILES_DIR, exist_ok=True)
    safe = secure_filename(filename)
    full = os.path.realpath(os.path.join(MATERIAL_FILES_DIR, safe))
    if not full.startswith(os.path.realpath(MATERIAL_FILES_DIR) + os.sep):
        return None
    return full

@app.route("/api/material/arquivos", methods=["GET"])
@auth_required(roles=["admin"])
def material_list_arquivos():
    os.makedirs(MATERIAL_FILES_DIR, exist_ok=True)
    out = []
    for nome in sorted(os.listdir(MATERIAL_FILES_DIR)):
        full = os.path.join(MATERIAL_FILES_DIR, nome)
        if not os.path.isfile(full):
            continue
        st = os.stat(full)
        out.append({
            "nome": nome, "tamanho": st.st_size,
            "modificado_em": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    out.sort(key=lambda f: f["modificado_em"], reverse=True)
    return jsonify(out)

@app.route("/api/material/arquivos", methods=["POST"])
@auth_required(roles=["admin"])
def material_upload_arquivo():
    # Sem limite de tamanho/tipo (decisão do dono do projeto) — só o
    # admin tem acesso a essa área, então não há por que restringir.
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Nome de arquivo vazio"}), 400

    base = secure_filename(file.filename) or f"arquivo_{uuidlib.uuid4().hex[:8]}"
    dest = _material_safe_path(base)
    if dest is None:
        return jsonify({"error": "Nome de arquivo inválido"}), 400

    # Evita sobrescrever silenciosamente um arquivo já existente com o
    # mesmo nome — acrescenta "(2)", "(3)"... antes da extensão.
    if os.path.exists(dest):
        raiz, ext = os.path.splitext(dest)
        n = 2
        while os.path.exists(f"{raiz} ({n}){ext}"):
            n += 1
        dest = f"{raiz} ({n}){ext}"

    file.save(dest)
    st = os.stat(dest)
    return jsonify({"ok": True, "nome": os.path.basename(dest), "tamanho": st.st_size}), 201

@app.route("/api/material/arquivos/<path:nome>", methods=["GET"])
@auth_required(roles=["admin"])
def material_download_arquivo(nome):
    full = _material_safe_path(nome)
    if not full or not os.path.isfile(full):
        return jsonify({"error": "Arquivo não encontrado"}), 404
    return send_file(full, as_attachment=True, download_name=os.path.basename(full))

@app.route("/api/material/arquivos/<path:nome>", methods=["DELETE"])
@auth_required(roles=["admin"])
def material_delete_arquivo(nome):
    full = _material_safe_path(nome)
    if not full or not os.path.isfile(full):
        return jsonify({"error": "Arquivo não encontrado"}), 404
    os.remove(full)
    return jsonify({"ok": True})

def _ai_build_status_context(session):
    """Coleta os mesmos dados que já alimentam a central de notificações
    (usuários vencendo, serviços parados, incidentes do autodiagnóstico)
    num texto compacto pra IA transformar em relatório — não duplica a
    lógica de detecção, só formata pra leitura corrida."""
    users = read_users()
    online = get_online_users()
    now = datetime.datetime.now()

    if session.get("role") == "reseller":
        cfg0 = load_config()
        owned = set(cfg0["resellers"].get(session["user"], {}).get("users", []))
        users = [u for u in users if u["login"] in owned]

    venc = []
    for u in users:
        dt = _parse_dt(u["expira"])
        if dt:
            dias = (dt - now).total_seconds() / 86400
            if 0 <= dias <= 3:
                venc.append((u["login"], round(dias, 1)))
    venc.sort(key=lambda x: x[1])

    linhas = [f"Total de usuários visíveis: {len(users)} | Online agora: {len(online)}."]

    servicos_caidos = []
    if session.get("role") == "admin":
        svc_labels = {"xray": "Xray", "proxy": "WebSocket Proxy", "limiter": "Limiter",
                      "slowdns": "SlowDNS", "checkuser": "CheckUser API", "badvpn": "BadVPN"}
        for key, label in svc_labels.items():
            if not service_status(key):
                servicos_caidos.append(label)
        linhas.append("Serviços fora do ar agora: " + (", ".join(servicos_caidos) if servicos_caidos else "nenhum — todos os serviços monitorados estão ativos."))

    if venc:
        linhas.append(f"{len(venc)} usuário(s) vencendo nos próximos 3 dias: " +
                       "; ".join(f"{n} ({d}d)" for n, d in venc[:15]))
    else:
        linhas.append("Nenhum usuário vencendo nos próximos 3 dias.")

    corrigidos_24h, precisam_atencao = [], []
    if session.get("role") == "admin":
        incidentes = _diag_load_incidents()
        cutoff = now - datetime.timedelta(hours=24)
        for inc in incidentes:
            try:
                inc_dt = datetime.datetime.fromisoformat(inc.get("criado_em", ""))
            except Exception:
                continue
            status = inc.get("status")
            if status == "corrigido" and inc_dt >= cutoff:
                corrigidos_24h.append(inc)
            elif status in ("falhou", "sem_correcao_conhecida", "pendente_aprovacao"):
                precisam_atencao.append(inc)
        if corrigidos_24h:
            linhas.append(f"{len(corrigidos_24h)} incidente(s) corrigido(s) automaticamente pelo autodiagnóstico nas últimas 24h: " +
                           "; ".join(i.get("causa_detalhe", "") for i in corrigidos_24h[:10]))
        else:
            linhas.append("Nenhum incidente precisou de correção automática nas últimas 24h.")
        if precisam_atencao:
            linhas.append(f"{len(precisam_atencao)} incidente(s) aguardando atenção do administrador: " +
                           "; ".join(i.get("causa_detalhe", "") for i in precisam_atencao[:10]))
        else:
            linhas.append("Nenhum incidente pendente de atenção no momento.")

    resumo = {
        "servicos_caidos": servicos_caidos, "vencendo": [{"login": n, "dias": d} for n, d in venc],
        "corrigidos_24h": len(corrigidos_24h), "precisam_atencao": len(precisam_atencao),
    }
    return "\n".join(linhas), resumo

@app.route("/api/ai-assistant/relatorio", methods=["POST"])
@auth_required()
def ai_status_report():
    owner = _owner_key(request.ns_session)
    ai = get_ai_assistant_config(owner)
    if not ai.get("api_key"):
        return jsonify({"error": "Configure uma chave de IA em Configurações > Assistente de IA antes de usar isso."}), 400

    contexto, resumo = _ai_build_status_context(request.ns_session)
    ok, resposta = _call_gemini(ai, AI_REPORT_SYSTEM_PROMPT, [], contexto, max_tokens=1024, thinking_budget=512)
    if not ok:
        return jsonify({"error": resposta}), 400
    return jsonify({"ok": True, "resposta": resposta, "resumo": resumo, "gerado_em": datetime.datetime.now().isoformat()})

@app.route("/api/ai-assistant/transcripts", methods=["GET"])
@auth_required(roles=["admin"])
def ai_assistant_transcripts():
    """Últimas conversas registradas (mais recentes primeiro) — usado
    pra revisar o que a IA/bot andou respondendo e ajustar o prompt."""
    limit = int(request.args.get("limit", 100))
    limit = max(1, min(1000, limit))
    lines = []
    if os.path.exists(AI_TRANSCRIPT_LOG):
        with open(AI_TRANSCRIPT_LOG) as f:
            lines = f.readlines()
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    out.reverse()
    return jsonify(out)

@app.route("/api/ai-assistant/transcripts/download", methods=["GET"])
@auth_required(roles=["admin"])
def ai_assistant_transcripts_download():
    if not os.path.exists(AI_TRANSCRIPT_LOG):
        return jsonify({"error": "Nenhuma conversa registrada ainda"}), 404
    return send_file(AI_TRANSCRIPT_LOG, as_attachment=True, download_name="conversas_whatsapp.jsonl")

@app.route("/api/settings", methods=["GET"])
@auth_required(roles=["admin"])
def get_settings():
    cfg = load_config()
    return jsonify({"public_domain": cfg.get("public_domain", "")})

@app.route("/api/settings", methods=["PUT"])
@auth_required(roles=["admin"])
def save_settings():
    data = request.get_json() or {}
    cfg = load_config()
    if "public_domain" in data:
        # aceita tanto "painel.netsimon.fun" quanto "https://painel.netsimon.fun"
        domain = data["public_domain"].strip()
        domain = re.sub(r'^https?://', '', domain).rstrip('/')
        cfg["public_domain"] = domain
    save_config(cfg)
    return jsonify({"ok": True, "public_domain": cfg.get("public_domain", "")})

def build_public_url(path):
    """Monta uma URL absoluta pública. Usa o domínio configurado quando
    existir (fica clicável no WhatsApp/Telegram); cai para o IP:porta
    da própria requisição quando não há domínio configurado (funciona,
    mas pode não virar link clicável em alguns apps de mensagem)."""
    cfg = load_config()
    domain = cfg.get("public_domain", "")
    if domain:
        return f"https://{domain}{path}"
    return request.host_url.rstrip("/") + path

@app.route("/api/app/latest", methods=["GET"])
def app_latest_public():
    """Endpoint público (sem auth) para o app cliente checar atualização."""
    releases = load_app_releases()
    latest = next((r for r in releases if r.get("latest")), None)
    if not latest and releases:
        releases.sort(key=lambda r: r.get("uploaded_at", ""), reverse=True)
        latest = releases[0]
    if not latest:
        return jsonify({"available": False})
    return jsonify({
        "available": True,
        "version":   latest["version"],
        "changelog": latest.get("changelog", ""),
        "url":       build_public_url(latest["url"]),
        "size":      latest.get("size", 0)
    })

# ══════════════════════════════════════════════════════════════════
#  BACKUP — SQL (dados) e Completo (tudo), + auto-backup via Telegram
# ══════════════════════════════════════════════════════════════════

BACKUP_CFG_F = "/etc/painel/backup_config.json"

def load_backup_config():
    default = {"enabled": False, "chat_id": "", "interval_hours": 24,
               "type": "sql", "last_backup_at": ""}
    if not os.path.exists(BACKUP_CFG_F):
        return default
    try:
        with open(BACKUP_CFG_F) as f:
            cfg = json.load(f)
        default.update(cfg)
        return default
    except Exception:
        return default

def save_backup_config(cfg):
    _atomic_write_json(BACKUP_CFG_F, cfg, indent=2)

def build_sql_dump_bytes():
    """Usa sqlite3.iterdump() (escaping seguro nativo) para gerar um
    .sql portável. Cobre usuarios/revendedores/dispositivos (dados
    originais) MAIS os itens abaixo, adicionados porque o backup "leve"
    era o único configurado em vários painéis e não levava nada disso —
    então uma restauração em servidor novo vinha sem WhatsApp, sem
    campanhas, sem a chave de IA configurada e sem as fotos dos
    clientes, obrigando reconfigurar tudo na mão:
    - whatsapp_contacts (nome + telefone + tags + última interação)
    - whatsapp_campaigns (config e resultados de cada campanha já rodada)
    - ai_assistant_config (chave de API e prompt da IA)
    - conversas do bot (ai_conversations.jsonl, pra manter o histórico)
    - fotos_map (login -> nome do arquivo) E fotos_arquivos (o arquivo
      de imagem em si, em base64) — sem isso a referência à foto
      sobrevivia mas a imagem em si se perdia, porque os arquivos ficam
      fora de /etc/painel (em /var/www/html/fotos)."""
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()

    cur.execute("CREATE TABLE usuarios (login TEXT, uuid TEXT, expira TEXT, senha TEXT, limite TEXT)")
    for u in read_users():
        cur.execute("INSERT INTO usuarios VALUES (?,?,?,?,?)",
                    (u["login"], u["uuid"], u["expira"], u["senha"], u["limite"]))

    cfg = load_config()
    cur.execute("CREATE TABLE resellers (username TEXT, password_hash TEXT, quota INTEGER, api_key TEXT, created TEXT, users_json TEXT)")
    for name, r in cfg.get("resellers", {}).items():
        cur.execute("INSERT INTO resellers VALUES (?,?,?,?,?,?)",
                    (name, r.get("password", ""), r.get("quota", 0), r.get("api_key", ""),
                     r.get("created", ""), json.dumps(r.get("users", []))))

    cur.execute("CREATE TABLE admin (username TEXT, password_hash TEXT)")
    cur.execute("INSERT INTO admin VALUES (?,?)", (cfg["admin"]["username"], cfg["admin"]["password"]))

    try:
        dconn = get_device_db()
        dcur = dconn.cursor()
        dcur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices")
        rows = dcur.fetchall()
        dconn.close()
    except Exception:
        rows = []
    cur.execute("CREATE TABLE devices (username TEXT, device_hash TEXT, phone TEXT, ip TEXT, first_seen TEXT, last_seen TEXT)")
    for row in rows:
        cur.execute("INSERT INTO devices VALUES (?,?,?,?,?,?)", row)

    # ── WhatsApp: contatos (nome + telefone + tags + última interação) ──
    cur.execute("CREATE TABLE whatsapp_contacts (owner TEXT, phone TEXT, name TEXT, tags_json TEXT, last_seen REAL)")
    for key, entry in _load_wa_contacts().items():
        owner_k, _, phone_k = key.partition("|")
        cur.execute("INSERT INTO whatsapp_contacts VALUES (?,?,?,?,?)",
                     (owner_k, phone_k, entry.get("name", ""),
                      json.dumps(entry.get("tags", []), ensure_ascii=False),
                      entry.get("last_seen")))

    # ── WhatsApp: campanhas (config + resultados por contato, inteiro) ──
    cur.execute("CREATE TABLE whatsapp_campaigns (id TEXT, owner TEXT, name TEXT, status TEXT, json_blob TEXT)")
    for c in _load_campaigns():
        cur.execute("INSERT INTO whatsapp_campaigns VALUES (?,?,?,?,?)",
                     (c.get("id"), c.get("owner"), c.get("name"), c.get("status"),
                      json.dumps(c, ensure_ascii=False)))

    # ── WhatsApp: lista mestre de sucessos (contatos confirmados) ──
    cur.execute("CREATE TABLE whatsapp_success_contacts (owner_phone_key TEXT, json_blob TEXT)")
    for key, entry in _load_success_contacts().items():
        cur.execute("INSERT INTO whatsapp_success_contacts VALUES (?,?)",
                     (key, json.dumps(entry, ensure_ascii=False)))

    # ── Assistente de IA: preferências e CHAVE DE API — agora por dono
    # (admin + cada revendedor tem a própria, ver item 3) ──
    cur.execute("CREATE TABLE ai_assistant_config (json_blob TEXT)")
    cur.execute("INSERT INTO ai_assistant_config VALUES (?)", (json.dumps(load_ai_assistant_all(), ensure_ascii=False),))

    # ── Conversas do bot já registradas (histórico bruto, uma linha JSONL por linha) ──
    cur.execute("CREATE TABLE ai_conversations_log (linha TEXT)")
    if os.path.exists(AI_TRANSCRIPT_LOG):
        try:
            with open(AI_TRANSCRIPT_LOG, encoding="utf-8", errors="ignore") as f:
                for linha in f:
                    linha = linha.rstrip("\n")
                    if linha:
                        cur.execute("INSERT INTO ai_conversations_log VALUES (?)", (linha,))
        except Exception as e:
            device_log_write(f"BACKUP SQL — não consegui incluir ai_conversations.jsonl: {e}")

    # ── Fotos: mapa login->arquivo E o arquivo em si (base64), pra sobreviver
    # mesmo indo só pelo backup leve, já que os arquivos ficam fora de /etc/painel
    cur.execute("CREATE TABLE fotos_map (login TEXT, filename TEXT)")
    cur.execute("CREATE TABLE fotos_arquivos (filename TEXT, conteudo_base64 TEXT)")
    photos_map = read_photos()
    for login, filename in photos_map.items():
        cur.execute("INSERT INTO fotos_map VALUES (?,?)", (login, filename))
    incluidas, puladas = 0, 0
    for filename in set(photos_map.values()):
        full = os.path.join(FOTOS_DIR, filename)
        try:
            with open(full, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            cur.execute("INSERT INTO fotos_arquivos VALUES (?,?)", (filename, b64))
            incluidas += 1
        except Exception as e:
            puladas += 1
            device_log_write(f"BACKUP SQL — foto '{filename}' pulada ({e})")
    if puladas:
        device_log_write(f"BACKUP SQL — fotos incluídas: {incluidas}, puladas: {puladas}")

    conn.commit()
    dump_text = "-- Painel Netsimon — Backup SQL\n"
    dump_text += f"-- Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    for line in conn.iterdump():
        dump_text += line + "\n"
    conn.close()
    return dump_text.encode("utf-8")

def provision_missing_users(rows):
    """Para cada usuário restaurado do dump SQL (login, uuid, expira, senha, limite),
    garante que ele existe DE FATO no servidor de destino: conta Linux (se ainda não
    existir) e client no Xray com o MESMO uuid do dump (nunca gera um novo — o app do
    cliente já está configurado com aquele valor).

    Idempotente: nunca sobrescreve usuário/senha/uuid já existentes. xray_add_client_safe
    já ignora duplicados por conta própria (via flock + checagem de email).

    Segurança: login e uuid são validados por regex antes de qualquer uso. A senha (que
    vem de um dump possivelmente gerado por outro sistema, portanto menos confiável) é
    passada para o shell via variável de ambiente, nunca interpolada na string do
    comando — assim nenhum caractere especial na senha pode ser interpretado pelo shell.
    """
    login_re = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,29}$')
    uuid_re  = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

    result = {"linux_criados": 0, "xray_adicionados": 0, "ja_existiam": 0, "pulados": []}

    script = '''
source /etc/painel/xray_lib.sh
if ! id "$NS_LOGIN" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$NS_LOGIN"
    echo "$NS_LOGIN:$NS_SENHA" | chpasswd
    mkdir -p "/home/$NS_LOGIN/.ssh"
    chmod 700 "/home/$NS_LOGIN/.ssh"
    chown -R "$NS_LOGIN:$NS_LOGIN" "/home/$NS_LOGIN"
    if [ -n "$NS_EXP" ]; then chage -E "$NS_EXP" "$NS_LOGIN"; fi
    echo "LINUX_NEW"
else
    echo "LINUX_EXISTS"
fi
xray_add_client_safe "$NS_LOGIN" "$NS_UUID" 443
echo "XRAY_RC:$?"
'''

    xray_touched = False
    for login, uuid_v, expira, senha, limite in rows:
        if not login_re.match(login or ""):
            result["pulados"].append(login or "(vazio)")
            device_log_write(f"BACKUP IMPORT — login inválido ignorado no provisionamento: {login}")
            continue
        if not uuid_re.match(uuid_v or ""):
            result["pulados"].append(login)
            device_log_write(f"BACKUP IMPORT — uuid inválido/ausente para {login}, client Xray não adicionado")
            continue

        exp_chage = ""
        try:
            exp_chage = (datetime.datetime.strptime((expira or "").split(" ")[0], "%Y-%m-%d") + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        except Exception:
            pass

        env = os.environ.copy()
        env["NS_LOGIN"] = login
        env["NS_UUID"]  = uuid_v
        env["NS_SENHA"] = senha or "1234"
        env["NS_EXP"]   = exp_chage

        try:
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env=env)
            out = r.stdout
        except Exception as e:
            device_log_write(f"BACKUP IMPORT — falha ao provisionar {login}: {e}")
            continue

        if "LINUX_NEW" in out:
            result["linux_criados"] += 1
        elif "LINUX_EXISTS" in out:
            result["ja_existiam"] += 1
        if "XRAY_RC:0" in out:
            result["xray_adicionados"] += 1
            xray_touched = True

    if xray_touched:
        run_cmd("systemctl restart xray >/dev/null 2>&1")

    return result

def restore_from_sql_dump(sql_text):
    """Carrega o .sql num banco temporário em memória (usando o próprio
    motor SQLite pra validar/escapar) e regrava usuarios.db, resellers
    e devices a partir dele."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(sql_text)
    cur = conn.cursor()

    restored = {"usuarios": 0, "resellers": 0, "devices": 0}

    try:
        cur.execute("SELECT login, uuid, expira, senha, limite FROM usuarios")
        rows = cur.fetchall()
        with open(USERDB, "w") as f:
            for login, uuid_v, expira, senha, limite in rows:
                f.write(f"{login}|{uuid_v}|{expira}|{senha}|{limite}\n")
        restored["usuarios"] = len(rows)
        # Item novo: o dump só regrava o registro do painel — sem isso, o
        # usuário fica "cadastrado" mas nunca autentica de verdade, porque
        # não existe conta Linux nem client no Xray no servidor de destino.
        restored["provisionados"] = provision_missing_users(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela usuarios ausente/erro: {e}")

    try:
        cur.execute("SELECT username, password_hash, quota, api_key, created, users_json FROM resellers")
        rows = cur.fetchall()
        cfg = load_config()
        cfg.setdefault("resellers", {})
        for username, pw_hash, quota, api_key, created, users_json in rows:
            cfg["resellers"][username] = {
                "password": pw_hash, "quota": quota, "api_key": api_key,
                "created": created, "users": json.loads(users_json or "[]")
            }
        save_config(cfg)
        restored["resellers"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela resellers ausente/erro: {e}")

    try:
        cur.execute("SELECT username, device_hash, phone, ip, first_seen, last_seen FROM devices")
        rows = cur.fetchall()
        dconn = get_device_db()
        dcur = dconn.cursor()
        for row in rows:
            dcur.execute("""INSERT OR REPLACE INTO devices
                (username, device_hash, phone, ip, first_seen, last_seen) VALUES (?,?,?,?,?,?)""", row)
        dconn.commit(); dconn.close()
        restored["devices"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela devices ausente/erro: {e}")

    # ── WhatsApp: contatos — mescla com o que já existir (backup manda
    # em caso de conflito, é uma restauração intencional) ──
    try:
        cur.execute("SELECT owner, phone, name, tags_json, last_seen FROM whatsapp_contacts")
        rows = cur.fetchall()
        contacts = _load_wa_contacts()
        for owner_k, phone_k, name, tags_json, last_seen in rows:
            key = f"{owner_k}|{phone_k}"
            entry = contacts.setdefault(key, {})
            entry["name"] = name or entry.get("name", "")
            try:
                entry["tags"] = json.loads(tags_json) if tags_json else entry.get("tags", [])
            except Exception:
                pass
            if last_seen is not None:
                entry["last_seen"] = last_seen
        if rows:
            _save_wa_contacts(contacts)
        restored["whatsapp_contacts"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela whatsapp_contacts ausente/erro: {e}")

    # ── WhatsApp: campanhas — restaura cada uma (substitui se já existir
    # o mesmo id, adiciona se for nova) ──
    try:
        cur.execute("SELECT json_blob FROM whatsapp_campaigns")
        rows = cur.fetchall()
        campaigns = _load_campaigns()
        by_id = {c["id"]: i for i, c in enumerate(campaigns)}
        count = 0
        for (blob,) in rows:
            try:
                c = json.loads(blob)
            except Exception:
                continue
            if c.get("id") in by_id:
                campaigns[by_id[c["id"]]] = c
            else:
                campaigns.append(c)
            count += 1
        if count:
            _save_campaigns(campaigns)
        restored["whatsapp_campaigns"] = count
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela whatsapp_campaigns ausente/erro: {e}")

    # ── WhatsApp: lista mestre de sucessos ──
    try:
        cur.execute("SELECT owner_phone_key, json_blob FROM whatsapp_success_contacts")
        rows = cur.fetchall()
        success = _load_success_contacts()
        for key, blob in rows:
            try:
                success[key] = json.loads(blob)
            except Exception:
                continue
        if rows:
            _save_success_contacts(success)
        restored["whatsapp_success_contacts"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela whatsapp_success_contacts ausente/erro: {e}")

    # ── Assistente de IA: preferências e chave de API (por dono) ──
    try:
        cur.execute("SELECT json_blob FROM ai_assistant_config LIMIT 1")
        row = cur.fetchone()
        if row:
            blob = json.loads(row[0])
            # Compat: backup gerado ANTES do item 3 (IA por revendedor)
            # guardava um único config global aqui, não {owner: config}.
            # Detecta pelo formato: "api_key" na raiz = formato antigo,
            # migra pro admin.
            if isinstance(blob, dict) and "api_key" in blob:
                all_ai_cfg = {"admin": blob}
            else:
                all_ai_cfg = blob if isinstance(blob, dict) else {}
            save_ai_assistant_all(all_ai_cfg)
            restored["ai_assistant_config"] = True
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela ai_assistant_config ausente/erro: {e}")

    # ── Conversas do bot já registradas — acrescenta ao log atual (nunca
    # sobrescreve o arquivo inteiro, só soma o que veio no backup) ──
    try:
        cur.execute("SELECT linha FROM ai_conversations_log")
        rows = cur.fetchall()
        if rows:
            with open(AI_TRANSCRIPT_LOG, "a", encoding="utf-8") as f:
                for (linha,) in rows:
                    f.write(linha + "\n")
        restored["ai_conversations_log"] = len(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabela ai_conversations_log ausente/erro: {e}")

    # ── Fotos: mapa + arquivos de verdade (decodifica o base64 de volta
    # pro disco em /var/www/html/fotos) ──
    try:
        cur.execute("SELECT filename, conteudo_base64 FROM fotos_arquivos")
        rows = cur.fetchall()
        os.makedirs(FOTOS_DIR, exist_ok=True)
        gravadas = 0
        for filename, b64 in rows:
            try:
                with open(os.path.join(FOTOS_DIR, filename), "wb") as f:
                    f.write(base64.b64decode(b64))
                gravadas += 1
            except Exception as e:
                device_log_write(f"BACKUP IMPORT — foto '{filename}' não pôde ser gravada: {e}")
        restored["fotos_arquivos"] = gravadas

        cur.execute("SELECT login, filename FROM fotos_map")
        map_rows = cur.fetchall()
        photos = read_photos()
        for login, filename in map_rows:
            photos[login] = filename
        if map_rows:
            save_photos(photos)
        restored["fotos_map"] = len(map_rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT — tabelas de fotos ausentes/erro: {e}")

    conn.close()
    return restored

# Arquivos que são CÓDIGO/ATIVO ESTÁTICO do próprio painel (chegam de
# novo em qualquer instalação/atualização a partir do pacote — nunca
# são dado de cliente) e por isso ficam FORA do backup completo. Ver
# comentário dentro de build_full_backup_path().
FULL_BACKUP_SKIP_EXT = {".html", ".css", ".js", ".mp4", ".png", ".service", ".md", ".sh"}
FULL_BACKUP_SKIP_FILES = {
    "painel_api.py", "bot_telegram.py", "checkuser.py", "proxy.py", "wss.py", "wss_security.py",
    "package.json", "requirements.txt", "config.json.template",
}

def build_full_backup_path():
    """tar.gz com /etc/painel (scripts+configs+dbs, sem os APKs — eles
    podem ser reenviados) + config.json do Xray + certificados SSL.

    BUGFIX (exportar tudo "não fazia nada"): antes, se qualquer arquivo
    dentro de /etc/painel desse problema no meio da compactação (ex: um
    arquivo temporário de escrita atômica ".tmpNNNN" que existia no
    listdir() mas já tinha sido removido pelo os.replace() um instante
    depois, ou um arquivo sem permissão de leitura), a função inteira
    estourava uma exceção sem tratamento — o backup não era gerado, e
    dependendo do timing a conexão caía sem devolver resposta HTTP
    nenhuma (por isso não aparecia nem mensagem de erro). Agora cada
    item é adicionado individualmente: se um item específico falhar, ele
    é pulado (e fica registrado no log Sistema) e o backup continua com
    o resto — sempre gera alguma coisa em vez de nada.

    BUGFIX (backup completo estourava o limite de 50MB do Telegram):
    o código antigo jogava TUDO que existe dentro de /etc/painel no
    tar, inclusive os arquivos do próprio painel (dashboard.html,
    painel.js, os scripts .sh, painel_bg.mp4 sozinho já são ~9MB
    etc.) — que não são dado nenhum de cliente, são código/mídia
    estática que já vem de novo em qualquer instalação/atualização a
    partir do pacote do painel. Isso inflava o arquivo sem necessidade
    e foi o que fez o backup completo passar dos 83MB e o Telegram
    recusar com "Request Entity Too Large" (limite de 50MB por arquivo
    pra upload via bot — é da própria API do Telegram, não dá pra
    contornar mandando o arquivo inteiro de outro jeito por aqui).
    Agora só entram no tar os arquivos de DADO de verdade (bancos
    .db, .json/.jsonl de config e histórico, tokens, logs, pastas de
    mídia geradas pelo uso do painel como fotos/campanhas/diagnóstico)
    — o código do painel em si fica de fora."""
    tmp_path = tempfile.mktemp(suffix=".tar.gz")
    pulados = []
    with tarfile.open(tmp_path, "w:gz") as tar:
        for item in os.listdir(BASE):
            if item == "app_releases":
                continue
            # arquivos temporários de escrita atômica (.tmp<pid>) podem
            # existir e desaparecer entre o listdir() e o tar.add() —
            # nunca fazem sentido dentro de um backup de qualquer forma.
            if ".tmp" in item:
                continue
            full = os.path.join(BASE, item)
            if os.path.isfile(full):
                ext = os.path.splitext(item)[1].lower()
                if ext in FULL_BACKUP_SKIP_EXT or item in FULL_BACKUP_SKIP_FILES:
                    continue
            try:
                tar.add(full, arcname=f"painel/{item}")
            except Exception as e:
                pulados.append(item)
                system_log_write(f"BACKUP export-all — item '{item}' pulado ({e})")
        if os.path.exists(XRAY_CONF):
            try:
                tar.add(XRAY_CONF, arcname="xray/config.json")
            except Exception as e:
                system_log_write(f"BACKUP export-all — config.json do Xray pulado ({e})")
        ssl_dir = "/etc/xray-manager/ssl"
        if os.path.isdir(ssl_dir):
            try:
                tar.add(ssl_dir, arcname="xray-manager/ssl")
            except Exception as e:
                system_log_write(f"BACKUP export-all — pasta SSL pulada ({e})")
        # Item: os arquivos de foto ficam em /var/www/html/fotos, FORA de
        # /etc/painel — sem isso, o mapa login->arquivo (fotos.db) era
        # levado mas as imagens em si nunca eram, e o restore mostrava
        # foto quebrada.
        if os.path.isdir(FOTOS_DIR):
            try:
                tar.add(FOTOS_DIR, arcname="fotos")
            except Exception as e:
                system_log_write(f"BACKUP export-all — pasta de fotos pulada ({e})")
    if pulados:
        system_log_write(f"BACKUP export-all concluído com {len(pulados)} item(ns) pulado(s): {', '.join(pulados)}")
    return tmp_path

def restore_full_backup(filepath):
    extract_dir = tempfile.mkdtemp()
    with tarfile.open(filepath, "r:gz") as tar:
        tar.extractall(extract_dir)

    painel_src = os.path.join(extract_dir, "painel")
    if os.path.isdir(painel_src):
        for item in os.listdir(painel_src):
            src = os.path.join(painel_src, item)
            dst = os.path.join(BASE, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)

    xray_src = os.path.join(extract_dir, "xray", "config.json")
    if os.path.exists(xray_src):
        shutil.copy2(xray_src, XRAY_CONF)

    ssl_src = os.path.join(extract_dir, "xray-manager", "ssl")
    if os.path.isdir(ssl_src):
        shutil.copytree(ssl_src, "/etc/xray-manager/ssl", dirs_exist_ok=True)

    fotos_src = os.path.join(extract_dir, "fotos")
    if os.path.isdir(fotos_src):
        os.makedirs(FOTOS_DIR, exist_ok=True)
        shutil.copytree(fotos_src, FOTOS_DIR, dirs_exist_ok=True)

    # Mesma lacuna do import-sql: nada aqui recria contas Linux (não fazem
    # parte do tar), e se o restore for num servidor novo, o config.json do
    # Xray só terá os clients que já existiam no backup de origem — não
    # cobre o caso de o backup ter sido feito antes de algum usuário ser
    # criado. Reaproveita a mesma checagem idempotente do import-sql.
    provisionados = None
    try:
        if os.path.exists(USERDB):
            rows = []
            with open(USERDB) as f:
                for line in f:
                    parts = line.rstrip("\n").split("|")
                    if len(parts) == 5:
                        rows.append(tuple(parts))
            provisionados = provision_missing_users(rows)
    except Exception as e:
        device_log_write(f"BACKUP IMPORT (full) — falha no provisionamento pós-restore: {e}")

    shutil.rmtree(extract_dir, ignore_errors=True)
    run_cmd("systemctl restart xray netsimon-painel")
    return {"ok": True, "provisionados": provisionados}

def send_telegram_document(bot_token, chat_id, filepath, caption=""):
    """Item BUG CORRIGIDO: a resposta do requests.post() nunca era checada.
    requests NÃO levanta exceção sozinho quando o Telegram responde com erro
    HTTP (400/403/413 etc) — só levanta em falha de rede/timeout. Resultado:
    se o Telegram rejeitasse o arquivo (maior que 50MB, chat_id errado, bot
    bloqueado/sem /start, token de outro bot, etc), a função voltava 'True'
    do mesmo jeito, sem logar nada, e o chamador marcava o backup como
    concluído mesmo o Telegram nunca tendo recebido o arquivo de verdade.
    Agora confere o campo "ok" da resposta e loga o motivo real do Telegram
    quando falhar, e só devolve True quando o Telegram confirmou o envio."""
    try:
        with open(filepath, "rb") as f:
            resp = requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendDocument",
                data={"chat_id": chat_id, "caption": caption},
                files={"document": (os.path.basename(filepath), f)},
                timeout=120
            )
        try:
            body = resp.json()
        except Exception:
            body = {}
        if resp.status_code == 200 and body.get("ok"):
            return True
        motivo = body.get("description") or f"HTTP {resp.status_code}"
        device_log_write(f"BACKUP TELEGRAM falhou: {motivo} (chat_id={chat_id})")
        return False
    except Exception as e:
        device_log_write(f"BACKUP TELEGRAM falhou: {e}")
        return False

TELEGRAM_MAX_UPLOAD_BYTES = 49 * 1024 * 1024  # margem de segurança abaixo do limite real de 50MB do Telegram pra upload via bot

def split_file_for_telegram(path, max_bytes=TELEGRAM_MAX_UPLOAD_BYTES):
    """Se o arquivo já estiver dentro do limite do Telegram, devolve
    [path] sem tocar nele. Se ainda estiver maior mesmo depois do corte
    dos arquivos estáticos em build_full_backup_path() (ex: painel com
    muita foto de cliente ou muita mídia de campanha do WhatsApp),
    quebra em pedaços binários de até max_bytes cada — <path>.part001,
    <path>.part002 etc. Reconstrução é só concatenar de volta:
    cat arquivo.tar.gz.part* > arquivo.tar.gz (funciona porque split é
    bruto, sem reprocessar o conteúdo)."""
    size = os.path.getsize(path)
    if size <= max_bytes:
        return [path]
    partes = []
    with open(path, "rb") as f:
        idx = 1
        while True:
            chunk = f.read(max_bytes)
            if not chunk:
                break
            part_path = f"{path}.part{idx:03d}"
            with open(part_path, "wb") as pf:
                pf.write(chunk)
            partes.append(part_path)
            idx += 1
    return partes

def send_backup_to_telegram(bot_token, chat_id, path, caption_base):
    """Envia o arquivo de backup pro Telegram. Item novo: se o arquivo
    passar dos 50MB que o Telegram aceita via bot (limite da própria
    API deles, sendDocument recusa com "Request Entity Too Large" —
    não existe jeito de mandar o arquivo inteiro de uma vez só por
    aqui), quebra automaticamente em partes e manda uma mensagem por
    parte, com a legenda explicando como juntar de novo. Só marca como
    sucesso se TODAS as partes forem confirmadas pelo Telegram.
    Devolve (sucesso, tamanho_mb do arquivo original, nº de partes)."""
    tamanho_mb = round(os.path.getsize(path) / (1024 * 1024), 1)
    partes = split_file_for_telegram(path)
    total = len(partes)
    try:
        if total == 1:
            ok = send_telegram_document(bot_token, chat_id, path, caption_base)
            return ok, tamanho_mb, 1
        nome_final = os.path.basename(path)
        ok_all = True
        for i, part_path in enumerate(partes, start=1):
            cap = (f"{caption_base}\nParte {i}/{total} (arquivo de {tamanho_mb}MB passou do limite de "
                   f"50MB do Telegram pra bots). Baixe todas as {total} partes e junte no servidor com:\n"
                   f"cat {nome_final}.part* > {nome_final}")
            if not send_telegram_document(bot_token, chat_id, part_path, cap):
                ok_all = False
                break
        return ok_all, tamanho_mb, total
    finally:
        if total > 1:
            for p in partes:
                try:
                    os.remove(p)
                except Exception:
                    pass

def backup_scheduler_loop():
    """Roda em background. A cada hora, checa se já passou o intervalo
    configurado e, se sim, gera e envia o backup automático via Telegram."""
    while True:
        try:
            bcfg = load_backup_config()
            if bcfg.get("enabled") and bcfg.get("chat_id"):
                last = bcfg.get("last_backup_at", "")
                interval = int(bcfg.get("interval_hours", 24))
                due = True
                if last:
                    try:
                        last_dt = datetime.datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
                        due = (datetime.datetime.now() - last_dt).total_seconds() >= interval * 3600
                    except Exception:
                        due = True
                if due:
                    bot_cfg = load_bot_config()
                    bot_token = bot_cfg.get("token", "")
                    if bot_token:
                        if bcfg.get("type") == "all":
                            path = build_full_backup_path()
                            caption = "💾 Backup automático completo — Painel Netsimon"
                        else:
                            path = tempfile.mktemp(suffix=".sql")
                            with open(path, "wb") as f:
                                f.write(build_sql_dump_bytes())
                            caption = "💾 Backup automático (SQL) — Painel Netsimon"
                        # Item BUG CORRIGIDO: antes o "last_backup_at" era
                        # gravado incondicionalmente, mesmo quando o envio
                        # ao Telegram falhava (ver comentário em
                        # send_telegram_document) — o agendador achava que
                        # já tinha cumprido o backup do dia e só ia tentar
                        # de novo depois do próximo intervalo inteiro
                        # (24h+), enquanto na real nenhum arquivo chegava.
                        # Agora só marca como feito se o Telegram confirmou
                        # o recebimento; se falhar, tenta de novo na
                        # próxima checagem (1h). Também usa
                        # send_backup_to_telegram (em vez de chamar o
                        # Telegram direto) pra quebrar em partes
                        # automaticamente se o arquivo passar de 50MB.
                        enviado, _tam, _partes = send_backup_to_telegram(bot_token, bcfg["chat_id"], path, caption)
                        try:
                            os.remove(path)
                        except Exception:
                            pass
                        if enviado:
                            bcfg["last_backup_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            save_backup_config(bcfg)
        except Exception as e:
            device_log_write(f"BACKUP SCHEDULER erro: {e}")
        time.sleep(3600)

@app.route("/api/backup/export-sql", methods=["GET"])
@auth_required(roles=["admin"])
def backup_export_sql():
    # BUGFIX: antes essa rota não tinha try/except -- qualquer exceção
    # dentro de build_sql_dump_bytes() caía no handler global genérico
    # ("Ocorreu um erro interno..."), que esconde a causa real e nem
    # sempre grava o traceback completo antes de responder. Agora a
    # causa exata (tipo + mensagem) fica tanto no toast quanto no log
    # do sistema, com traceback completo, pra dar pra diagnosticar sem
    # precisar reproduzir de novo às cegas.
    try:
        data = build_sql_dump_bytes()
    except Exception as e:
        tb = traceback.format_exc()
        system_log_write(f"BACKUP export-sql FALHOU: {type(e).__name__}: {e}\n{tb}")
        return jsonify({"error": f"Falha ao gerar o backup SQL: {type(e).__name__}: {e}"}), 500
    fname = f"netsimon_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
    return send_file(io.BytesIO(data), mimetype="application/sql",
                      as_attachment=True, download_name=fname)

@app.route("/api/backup/import-sql", methods=["POST"])
@auth_required(roles=["admin"])
def backup_import_sql():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    try:
        sql_text = file.read().decode("utf-8")
        restored = restore_from_sql_dump(sql_text)
    except Exception as e:
        return jsonify({"error": f"Falha ao processar o arquivo: {e}"}), 400
    return jsonify({"ok": True, "restored": restored})

@app.route("/api/backup/export-all", methods=["GET"])
@auth_required(roles=["admin"])
def backup_export_all():
    try:
        path = build_full_backup_path()
    except Exception as e:
        # BUGFIX: só logava str(e) (ex: "[Errno 13] Permission denied:
        # '/etc/painel/x'"), sem o traceback -- suficiente pra ver O QUE
        # falhou mas não ONDE dentro da função. Agora grava o traceback
        # completo também, mesma lógica aplicada ao export-sql acima.
        tb = traceback.format_exc()
        system_log_write(f"BACKUP export-all FALHOU: {type(e).__name__}: {e}\n{tb}")
        return jsonify({"error": f"Falha ao gerar o backup completo: {type(e).__name__}: {e}"}), 500
    fname = f"netsimon_backup_completo_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
    return send_file(path, mimetype="application/gzip",
                      as_attachment=True, download_name=fname)

@app.route("/api/backup/import-all", methods=["POST"])
@auth_required(roles=["admin"])
def backup_import_all():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400
    file = request.files["file"]
    tmp_path = tempfile.mktemp(suffix=".tar.gz")
    file.save(tmp_path)
    try:
        resultado = restore_full_backup(tmp_path)
    except Exception as e:
        return jsonify({"error": f"Falha ao restaurar backup: {e}"}), 400
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return jsonify(resultado)

@app.route("/api/backup/config", methods=["GET"])
@auth_required(roles=["admin"])
def backup_get_config():
    return jsonify(load_backup_config())

@app.route("/api/backup/config", methods=["POST"])
@auth_required(roles=["admin"])
def backup_save_config():
    data = request.get_json() or {}
    cfg = load_backup_config()
    cfg["enabled"] = bool(data.get("enabled", cfg["enabled"]))
    cfg["chat_id"] = data.get("chat_id", cfg["chat_id"]).strip()
    cfg["interval_hours"] = int(data.get("interval_hours", cfg["interval_hours"]))
    cfg["type"] = data.get("type", cfg["type"])
    save_backup_config(cfg)
    return jsonify({"ok": True})

_send_now_lock = threading.Lock()
_send_now_status = {"running": False, "result": None}

def _run_send_now_backup():
    """Roda em thread separada — ver comentário em backup_send_now()
    sobre o motivo (Erro 504)."""
    global _send_now_status
    try:
        bcfg = load_backup_config()
        bot_cfg = load_bot_config()
        bot_token = bot_cfg.get("token", "")

        if bcfg.get("type") == "all":
            path = build_full_backup_path()
            caption = "💾 Backup manual completo — Painel Netsimon"
        else:
            path = tempfile.mktemp(suffix=".sql")
            with open(path, "wb") as f:
                f.write(build_sql_dump_bytes())
            caption = "💾 Backup manual (SQL) — Painel Netsimon"

        enviado, tamanho_mb, partes = send_backup_to_telegram(bot_token, bcfg["chat_id"], path, caption)
        try:
            os.remove(path)
        except Exception:
            pass

        if enviado:
            bcfg["last_backup_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_backup_config(bcfg)
            with _send_now_lock:
                _send_now_status = {"running": False,
                                     "result": {"ok": True, "tamanho_mb": tamanho_mb, "partes": partes}}
            return

        ultimo_erro = ""
        try:
            with open(DEVICE_LOG) as f:
                linhas = [l for l in f.readlines() if "BACKUP TELEGRAM falhou" in l]
                if linhas:
                    ultimo_erro = linhas[-1].strip()
        except Exception:
            pass
        msg = ultimo_erro.split(" | ", 1)[-1] if ultimo_erro else "Telegram recusou o envio (ver log do sistema)."
        with _send_now_lock:
            _send_now_status = {"running": False,
                                 "result": {"ok": False, "error": f"{msg} (arquivo tinha {tamanho_mb}MB)"}}
    except Exception as e:
        device_log_write(f"BACKUP send-now — erro inesperado: {e}")
        with _send_now_lock:
            _send_now_status = {"running": False, "result": {"ok": False, "error": f"Erro inesperado: {e}"}}

@app.route("/api/backup/send-now", methods=["POST"])
@auth_required(roles=["admin"])
def backup_send_now():
    """Dispara um backup pro Telegram na hora (não espera a checagem
    horária do agendador), usando o Chat ID e tipo salvos em
    /api/backup/config.

    BUG CORRIGIDO (Erro 504): antes essa rota gerava o backup inteiro
    (o que já pode demorar) E esperava o Telegram confirmar o
    recebimento — tudo DENTRO do mesmo request HTTP. Se isso levasse
    mais do que o timeout do proxy na frente do painel (Nginx e,
    se o domínio passa pela Cloudflare, o limite de borda dela também
    — esse nem dá pra configurar por aqui), a conexão caía com 504 pro
    navegador mesmo que o backup continuasse sendo processado (ou já
    tivesse sido enviado) no servidor por trás.

    Agora a rota só confere se dá pra tentar (Chat ID e token
    salvos), dispara o trabalho de verdade numa thread em segundo
    plano, e devolve na hora — sem ficar presa esperando. O navegador
    consulta o resultado em /api/backup/send-now/status."""
    global _send_now_status
    bcfg = load_backup_config()
    if not bcfg.get("chat_id"):
        return jsonify({"error": "Configure e salve um Chat ID antes de testar."}), 400
    bot_cfg = load_bot_config()
    if not bot_cfg.get("token", ""):
        return jsonify({"error": "Nenhum token salvo em Bot Telegram."}), 400

    with _send_now_lock:
        if _send_now_status["running"]:
            return jsonify({"error": "Já tem um backup sendo enviado, aguarde terminar."}), 409
        _send_now_status = {"running": True, "result": None}

    threading.Thread(target=_run_send_now_backup, daemon=True).start()
    return jsonify({"ok": True, "status": "started"})

@app.route("/api/backup/send-now/status", methods=["GET"])
@auth_required(roles=["admin"])
def backup_send_now_status():
    """O front consulta essa rota (a cada ~2s) depois de chamar
    /api/backup/send-now, até 'running' voltar false. Ver comentário em
    backup_send_now() sobre o motivo dela existir (Erro 504)."""
    with _send_now_lock:
        return jsonify(dict(_send_now_status))

# ══════════════════════════════════════════════════════════════════
#  LOGS DE CONEXAO (Xray access.log via log_watcher.py)
#
#  Somente leitura -- os dados vem do netsimon_logs.db escrito pelo
#  log_watcher.py (rodando como serviço systemd separado). Se esse
#  serviço ainda não foi instalado no servidor, o arquivo do banco não
#  existe ainda -- devolve lista vazia em vez de erro 500, pra não
#  quebrar o dashboard em servidores sem o watcher configurado.
# ══════════════════════════════════════════════════════════════════

@app.route("/api/logs/connection_attempts", methods=["GET"])
@auth_required(roles=["admin"])
def api_connection_attempts():
    if not os.path.isfile(LOGS_DB_PATH):
        return jsonify([])
    user_id = request.args.get("user_id")
    period_days = int(request.args.get("period", "7").replace("d", ""))

    conn = get_logs_db()
    query = "SELECT * FROM connection_attempts WHERE timestamp >= datetime('now', ?)"
    params = [f"-{period_days} days"]
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    query += " ORDER BY timestamp DESC LIMIT 500"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/logs/sessions", methods=["GET"])
@auth_required(roles=["admin"])
def api_sessions():
    if not os.path.isfile(LOGS_DB_PATH):
        return jsonify([])
    user_id = request.args.get("user_id")
    period_days = int(request.args.get("period", "7").replace("d", ""))

    conn = get_logs_db()
    query = "SELECT * FROM connection_sessions WHERE connect_at >= datetime('now', ?)"
    params = [f"-{period_days} days"]
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    query += " ORDER BY connect_at DESC LIMIT 500"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/logs/sessions/summary", methods=["GET"])
@auth_required(roles=["admin"])
def api_sessions_summary():
    if not os.path.isfile(LOGS_DB_PATH):
        return jsonify([])
    period_days = int(request.args.get("period", "7").replace("d", ""))

    conn = get_logs_db()
    rows = conn.execute(
        """
        SELECT user_id,
               SUM(COALESCE(duration_seconds, 0)) AS total_seconds,
               COUNT(*) AS session_count
        FROM connection_sessions
        WHERE connect_at >= datetime('now', ?)
        GROUP BY user_id
        ORDER BY total_seconds ASC
        """,
        [f"-{period_days} days"],
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    threading.Thread(target=backup_scheduler_loop, daemon=True).start()
    threading.Thread(target=reseller_expiry_scheduler_loop, daemon=True).start()
    threading.Thread(target=expired_user_kick_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_notify_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_reengage_scheduler_loop, daemon=True).start()
    threading.Thread(target=bot_handoff_auto_resume_loop, daemon=True).start()
    threading.Thread(target=whatsapp_campaign_scheduler_loop, daemon=True).start()
    threading.Thread(target=whatsapp_random_message_scheduler_loop, daemon=True).start()
    threading.Thread(target=server_health_scheduler_loop, daemon=True).start()
    threading.Thread(target=security_watchdog_loop, daemon=True).start()

    # Item: se o painel reiniciar com uma campanha no meio do envio
    # (status "enviando"), o worker dela morreu junto com o processo
    # antigo — retoma sozinho a partir do cursor salvo, sem repetir
    # quem já recebeu.
    for c in _load_campaigns():
        if c.get("status") == "enviando" and not c.get("paused"):
            _start_campaign_thread(c["id"])
    # Item de segurança: escuta só em loopback — o Nginx (proxy reverso,
    # com TLS/Cloudflare na frente) é o único que deve falar com o Flask
    # diretamente. Antes disso era 0.0.0.0, ou seja, a API inteira (login
    # incluso) ficava acessível direto por http://SEU-IP:5001/api/..., sem
    # TLS e pulando completamente o Nginx.
    app.run(host="127.0.0.1", port=5001, debug=False)