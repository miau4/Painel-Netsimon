#!/usr/bin/env python3
# ==========================================
#   PAINEL NETSIMON - CHECKUSER API
#   Porta 5000 — consulta por login/UUID
# ==========================================

from flask import Flask, jsonify, request
import subprocess
import datetime
import os

app = Flask(__name__)

USERDB   = "/etc/painel/usuarios.db"

# Foto de usuário — mesmo arquivo/formato ("login|nome_do_arquivo") já usado
# pelo painel_api.py (read_photos()/save_photos()), pra manter os dois
# sistemas consistentes sem duplicar upload/armazenamento.
FOTOS_DB = "/etc/painel/fotos.db"

# Domínio público onde as fotos ficam servidas (confirmado funcionando via
# curl -I https://painel.netsimon.fun/fotos/netsimon.jpg -> HTTP/2 200).
# Se o domínio público mudar no futuro, atualize aqui também.
PUBLIC_DOMAIN = "https://painel.netsimon.fun"

# BUG4 FIX: token de autenticação lido do ambiente ou do arquivo
# Para configurar: export CHECKUSER_TOKEN="seu-token-secreto"
# ou grave o token em /etc/painel/checkuser.token
def _load_token():
    env_tok = os.environ.get("CHECKUSER_TOKEN", "")
    if env_tok:
        return env_tok
    try:
        with open("/etc/painel/checkuser.token") as f:
            return f.read().strip()
    except Exception:
        return ""

API_TOKEN = _load_token()

def check_token():
    """Retorna resposta de erro 401 se o token for inválido, None se OK."""
    if not API_TOKEN:
        # Token não configurado — bloqueia tudo por segurança
        return jsonify({"error": "API token not configured on server"}), 403
    token = request.headers.get("X-Token") or request.args.get("token", "")
    if token != API_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    return None

def get_user_from_db(username):
    """Lê o banco local e retorna os dados do usuário."""
    if not os.path.exists(USERDB):
        return None
    with open(USERDB, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[0] == username:
                return {
                    "login": parts[0],
                    "uuid": parts[1],
                    "expira": parts[2],
                    "senha": parts[3],
                    "limite": parts[4]
                }
    return None

def get_user_by_uuid(uuid):
    """Busca usuário pelo UUID."""
    if not os.path.exists(USERDB):
        return None
    with open(USERDB, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5 and parts[1] == uuid:
                return {
                    "login": parts[0],
                    "uuid": parts[1],
                    "expira": parts[2],
                    "senha": parts[3],
                    "limite": parts[4]
                }
    return None

def get_photo_url(login):
    """Lê /etc/painel/fotos.db (mesmo formato do painel_api.py) e devolve a
    URL pública absoluta da foto do usuário, ou "" se não tiver foto."""
    if not os.path.exists(FOTOS_DB):
        return ""
    try:
        with open(FOTOS_DB) as f:
            for line in f:
                parts = line.strip().split("|", 1)
                if len(parts) == 2 and parts[0] == login and parts[1]:
                    return f"{PUBLIC_DOMAIN}/fotos/{parts[1]}"
    except Exception:
        pass
    return ""

def is_expired(expira_str):
    """Verifica se a data de expiração já passou."""
    try:
        expira = datetime.datetime.strptime(expira_str, "%Y-%m-%d %H:%M:%S")
        return datetime.datetime.now() > expira
    except Exception:
        try:
            expira = datetime.datetime.strptime(expira_str, "%Y-%m-%d")
            return datetime.datetime.now().date() > expira.date()
        except Exception:
            return False

def is_online_ssh(username):
    """Verifica se usuário tem sessão SSH ativa."""
    try:
        result = subprocess.check_output(
            ["who"], text=True, stderr=subprocess.DEVNULL
        )
        return any(line.split()[0] == username for line in result.splitlines() if line)
    except Exception:
        return False

# ── Endpoints ───────────────────────────────────────────────────

@app.route('/check/<username>', methods=['GET'])
def check_user(username):
    """Verifica status de um usuário por login."""
    err = check_token()
    if err: return err

    data = get_user_from_db(username)
    if not data:
        return jsonify({"status": "not_found", "user": username}), 404

    expired = is_expired(data["expira"])
    online  = is_online_ssh(username)

    return jsonify({
        "status":   "expired" if expired else "active",
        "user":     username,
        "uuid":     data["uuid"],
        "expira":   data["expira"],
        "limite":   data["limite"],
        "online":   online,
        "foto_url": get_photo_url(data["login"])
    })

@app.route('/check/uuid/<uuid>', methods=['GET'])
def check_uuid(uuid):
    """Verifica status de um usuário pelo UUID Xray."""
    err = check_token()
    if err: return err

    data = get_user_by_uuid(uuid)
    if not data:
        return jsonify({"status": "not_found", "uuid": uuid}), 404

    expired = is_expired(data["expira"])

    return jsonify({
        "status":   "expired" if expired else "active",
        "user":     data["login"],
        "uuid":     uuid,
        "expira":   data["expira"],
        "limite":   data["limite"],
        "foto_url": get_photo_url(data["login"])
    })

@app.route('/users', methods=['GET'])
def list_users():
    """Lista todos os usuários cadastrados (sem senha)."""
    err = check_token()
    if err: return err

    users = []
    if os.path.exists(USERDB):
        with open(USERDB, "r") as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 5:
                    expired = is_expired(parts[2])
                    users.append({
                        "login":  parts[0],
                        "uuid":   parts[1],
                        "expira": parts[2],
                        "limite": parts[4],
                        "status": "expired" if expired else "active"
                    })
    return jsonify({"total": len(users), "users": users})

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "version": "1.0"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
