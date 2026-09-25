#!/usr/bin/env python3
# ==========================================
#   PAINEL NETSIMON - BOT TELEGRAM
#   Venda automática via PIX (Mercado Pago)
# ==========================================

import os
import json
import time
import uuid
import hashlib
import datetime
import threading
import subprocess
import requests
import logging

logging.basicConfig(
    filename="/var/log/netsimon_bot.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger("netsimon_bot")

BOT_CFG   = "/etc/painel/bot_config.json"
USERDB    = "/etc/painel/usuarios.db"
BASE      = "/etc/painel"

# ── Aguarda PIX pendentes em memória ────────────────────────────
_pending_payments = {}   # payment_id -> {chat_id, login, senha, dias, limite, preco, expires}

def load_cfg():
    with open(BOT_CFG) as f:
        return json.load(f)

def send_msg(token, chat_id, text, reply_markup=None, parse_mode="Markdown"):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        log.error(f"send_msg: {e}")

def answer_callback(token, callback_query_id, text=""):
    url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
    try:
        requests.post(url, json={"callback_query_id": callback_query_id, "text": text}, timeout=10)
    except Exception:
        pass

def edit_msg(token, chat_id, message_id, text, reply_markup=None, parse_mode="Markdown"):
    url = f"https://api.telegram.org/bot{token}/editMessageText"
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup)
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception:
        pass

# ── Mercado Pago — gera PIX copia-e-cola ────────────────────────
def create_pix(mp_token, valor, descricao, external_ref):
    url = "https://api.mercadopago.com/v1/payments"
    headers = {
        "Authorization": f"Bearer {mp_token}",
        "Content-Type": "application/json",
        "X-Idempotency-Key": external_ref
    }
    body = {
        "transaction_amount": float(valor),
        "description": descricao,
        "payment_method_id": "pix",
        "payer": {"email": f"cliente_{external_ref[:8]}@netsimon.app"}
    }
    try:
        r = requests.post(url, headers=headers, json=body, timeout=15)
        data = r.json()
        if r.status_code in (200, 201):
            qr = data["point_of_interaction"]["transaction_data"]["qr_code"]
            pid = str(data["id"])
            return pid, qr
        log.error(f"MP create_pix error: {data}")
    except Exception as e:
        log.error(f"create_pix: {e}")
    return None, None

def check_pix_paid(mp_token, payment_id):
    url = f"https://api.mercadopago.com/v1/payments/{payment_id}"
    headers = {"Authorization": f"Bearer {mp_token}"}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        return data.get("status") == "approved"
    except Exception:
        return False

# ── Cria conta no servidor ────────────────────────────────────────
def criar_conta(login, senha, dias, limite):
    cmd = f"""
bash -c '
source /etc/painel/xray_lib.sh
useradd -m -s /bin/bash "{login}" 2>/dev/null
echo "{login}:{senha}" | chpasswd
mkdir -p /home/{login}/.ssh
chmod 700 /home/{login}/.ssh
chown -R {login}:{login} /home/{login}
exp=$(date -d "+{dias} days" +"%Y-%m-%d 23:59:59")
exp_chage=$(date -d "+{dias} days" +"%Y-%m-%d")
chage -E "$exp_chage" "{login}" 2>/dev/null
uuid=$(cat /proc/sys/kernel/random/uuid)
xray_add_client_safe "{login}" "$uuid" 443 2>/dev/null
echo "{login}|$uuid|$exp|{senha}|{limite}" >> /etc/painel/usuarios.db
systemctl restart xray >/dev/null 2>&1
echo "OK:$uuid:$exp"
'
"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        out = r.stdout.strip()
        if "OK:" in out:
            parts = out.split("OK:")[-1].split(":")
            return parts[0], ":".join(parts[1:])
    except Exception as e:
        log.error(f"criar_conta: {e}")
    return None, None

def get_xray_info():
    """Retorna IP, porta e host configurado do Xray para montar link VLESS."""
    ip = ""
    porta = 443
    host = ""
    try:
        ip = subprocess.check_output(
            "wget -qO- --timeout=3 ipv4.icanhazip.com", shell=True, text=True
        ).strip()
        with open("/usr/local/etc/xray/config.json") as f:
            cfg = json.load(f)
        for ib in cfg.get("inbounds", []):
            if ib.get("protocol") != "dokodemo-door":
                porta = ib.get("port", 443)
                host = ib.get("streamSettings", {}).get("xhttpSettings", {}).get("host", "")
    except Exception:
        pass
    return ip, porta, host

# ── Monitoramento de pagamentos pendentes ────────────────────────
def payment_watcher():
    while True:
        try:
            cfg = load_cfg()
            mp_token = cfg.get("mp_token", "")
            token = cfg.get("token", "")
            now = time.time()
            expired_keys = []

            for pid, info in list(_pending_payments.items()):
                if now > info["expires"]:
                    expired_keys.append(pid)
                    send_msg(token, info["chat_id"],
                             "⏰ *Tempo expirado!*\nO PIX não foi confirmado. Use /start para tentar novamente.")
                    continue

                if mp_token and check_pix_paid(mp_token, pid):
                    expired_keys.append(pid)
                    # Cria a conta
                    uuid_val, exp = criar_conta(
                        info["login"], info["senha"],
                        info["dias"], info["limite"]
                    )
                    if uuid_val:
                        ip, porta, host = get_xray_info()
                        host_param = f"&host={host}" if host else ""
                        vless = (f"vless://{uuid_val}@{ip}:{porta}"
                                 f"?encryption=none&flow=none&type=xhttp"
                                 f"&path=%2F{host_param}&security=tls&sni=www.tim.com.br#{info['login']}")
                        msg = (
                            f"✅ *Pagamento confirmado!*\n\n"
                            f"👤 *Usuário:* `{info['login']}`\n"
                            f"🔑 *Senha SSH:* `{info['senha']}`\n"
                            f"📅 *Validade:* {exp[:10] if exp else '–'}\n"
                            f"🔢 *Limite:* {info['limite']} acesso(s)\n\n"
                            f"*Link VLESS:*\n`{vless}`\n\n"
                            f"_Importe o link no v2rayNG, Hiddify ou app compatível._"
                        )
                        send_msg(token, info["chat_id"], msg)
                        # Notifica admin
                        admin_id = cfg.get("admin_chat_id", "")
                        if admin_id:
                            send_msg(token, admin_id,
                                     f"💰 *Venda realizada!*\nUsuário: `{info['login']}`\nPlano: {info['plano_nome']}\nValor: R$ {info['preco']:.2f}")
                    else:
                        send_msg(token, info["chat_id"],
                                 "❌ Pagamento confirmado, mas houve erro ao criar a conta. Entre em contato com o suporte.")

            for k in expired_keys:
                _pending_payments.pop(k, None)

        except Exception as e:
            log.error(f"payment_watcher: {e}")

        time.sleep(15)

# ── Estados de conversa ──────────────────────────────────────────
_user_state = {}   # chat_id -> {"step": ..., "data": {...}}

def handle_update(update, cfg):
    token = cfg["token"]

    # Callback (botão inline)
    if "callback_query" in update:
        cq = update["callback_query"]
        chat_id = str(cq["message"]["chat"]["id"])
        msg_id = cq["message"]["message_id"]
        data = cq.get("data", "")
        answer_callback(token, cq["id"])

        if data.startswith("plano:"):
            idx = int(data.split(":")[1])
            planos = cfg.get("planos", [])
            if idx >= len(planos):
                return
            plano = planos[idx]
            _user_state[chat_id] = {
                "step": "aguarda_usuario",
                "data": {"plano": plano}
            }
            edit_msg(token, chat_id, msg_id,
                     f"📦 *{plano['nome']}*\n"
                     f"💰 R$ {plano['preco']:.2f} | {plano['dias']} dias | {plano['limite']} acesso(s)\n\n"
                     f"Digite o nome de usuário desejado:\n_(3-20 letras/números, sem espaços)_")
        return

    # Mensagem de texto
    msg = update.get("message", {})
    if not msg:
        return
    chat_id = str(msg["chat"]["id"])
    text = msg.get("text", "").strip()

    state = _user_state.get(chat_id, {})
    step = state.get("step", "")

    # /start
    if text in ("/start", "/menu"):
        _user_state.pop(chat_id, None)
        planos = cfg.get("planos", [])
        buttons = []
        for i, p in enumerate(planos):
            buttons.append([{"text": f"📦 {p['nome']} — R$ {p['preco']:.2f}", "callback_data": f"plano:{i}"}])
        buttons.append([{"text": "📞 Suporte", "url": f"https://t.me/{cfg.get('suporte_user', 'suporte')}"}])
        send_msg(token, chat_id,
                 "🚀 *Bem-vindo ao Painel Netsimon!*\n\nEscolha um plano:",
                 reply_markup={"inline_keyboard": buttons})
        return

    # Fluxo de compra
    if step == "aguarda_usuario":
        import re
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{2,19}$', text):
            send_msg(token, chat_id, "❌ Nome inválido. Use 3-20 letras/números, começando com letra.")
            return
        # Verifica se já existe
        try:
            with open(USERDB) as f:
                logins = [l.split("|")[0] for l in f if l.strip()]
            if text in logins:
                send_msg(token, chat_id, f"❌ Usuário `{text}` já existe. Escolha outro nome.")
                return
        except Exception:
            pass
        state["data"]["login"] = text
        state["step"] = "aguarda_senha"
        _user_state[chat_id] = state
        send_msg(token, chat_id, f"✅ Usuário: `{text}`\n\nAgora escolha uma senha:")
        return

    if step == "aguarda_senha":
        if len(text) < 4:
            send_msg(token, chat_id, "❌ Senha muito curta (mínimo 4 caracteres).")
            return
        state["data"]["senha"] = text
        state["step"] = "confirma_pagamento"
        _user_state[chat_id] = state
        plano = state["data"]["plano"]
        send_msg(token, chat_id,
                 f"📋 *Resumo do pedido:*\n\n"
                 f"👤 Usuário: `{state['data']['login']}`\n"
                 f"📦 Plano: {plano['nome']}\n"
                 f"💰 Valor: R$ {plano['preco']:.2f}\n\n"
                 f"Confirmar e gerar PIX?",
                 reply_markup={"inline_keyboard": [
                     [{"text": "✅ Confirmar e Pagar", "callback_data": "confirmar_pix"}],
                     [{"text": "❌ Cancelar", "callback_data": "cancelar"}]
                 ]})
        return

    # Confirmar PIX via callback
    if text == "" and "callback_query" in update:
        return

    # Comandos de admin
    if text == "/vendas" and str(chat_id) == str(cfg.get("admin_chat_id", "")):
        pendentes = len(_pending_payments)
        send_msg(token, chat_id, f"📊 *Pagamentos pendentes:* {pendentes}")
        return

    # Fallback
    if step == "":
        send_msg(token, chat_id, "Use /start para ver os planos disponíveis.")

def handle_callback_confirmar(update, cfg):
    """Chamado quando o usuário clica em Confirmar e Pagar."""
    if "callback_query" not in update:
        return
    cq = update["callback_query"]
    if cq.get("data") != "confirmar_pix":
        return
    chat_id = str(cq["message"]["chat"]["id"])
    msg_id = cq["message"]["message_id"]
    token = cfg["token"]
    mp_token = cfg.get("mp_token", "")
    answer_callback(token, cq["id"])

    state = _user_state.get(chat_id, {})
    if state.get("step") != "confirma_pagamento":
        return

    plano = state["data"]["plano"]
    login = state["data"]["login"]
    senha = state["data"]["senha"]
    external_ref = f"ns7-{chat_id}-{int(time.time())}"

    if mp_token:
        pid, qr = create_pix(mp_token, plano["preco"],
                              f"Painel Netsimon - {plano['nome']}", external_ref)
        if not pid:
            send_msg(token, chat_id, "❌ Erro ao gerar PIX. Tente novamente ou contate o suporte.")
            return

        _pending_payments[pid] = {
            "chat_id":    chat_id,
            "login":      login,
            "senha":      senha,
            "dias":       plano["dias"],
            "limite":     plano["limite"],
            "preco":      plano["preco"],
            "plano_nome": plano["nome"],
            "expires":    time.time() + 1800  # 30 min
        }
        _user_state.pop(chat_id, None)
        edit_msg(token, chat_id, msg_id,
                 f"💳 *PIX gerado!* Válido por 30 minutos.\n\n"
                 f"Copie o código abaixo e cole no seu banco:\n\n"
                 f"`{qr}`\n\n"
                 f"⏳ Aguardando confirmação automática...")
    else:
        # Sem MP configurado — entrega manual (apenas para testes)
        _user_state.pop(chat_id, None)
        edit_msg(token, chat_id, msg_id,
                 "⚠️ *Pagamento manual*\n\nEntre em contato com o suporte para finalizar o pagamento.")

    if cq.get("data") == "cancelar":
        _user_state.pop(chat_id, None)
        send_msg(token, cfg["token"], chat_id, "❌ Pedido cancelado. Use /start para recomeçar.")

# ── Loop principal de polling ────────────────────────────────────
def run_bot():
    cfg = load_cfg()
    token = cfg.get("token", "")
    if not token:
        log.error("Token do bot não configurado!")
        return

    log.info("Bot Telegram Painel Netsimon iniciado (polling)")
    offset = 0

    # Inicia watcher de pagamentos
    t = threading.Thread(target=payment_watcher, daemon=True)
    t.start()

    while True:
        try:
            url = f"https://api.telegram.org/bot{token}/getUpdates"
            r = requests.get(url, params={"offset": offset, "timeout": 30}, timeout=40)
            data = r.json()

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                try:
                    cfg = load_cfg()  # recarrega config a cada update (permite editar em tempo real)
                    # Trata callbacks especiais antes do handler genérico
                    if "callback_query" in update:
                        cq_data = update["callback_query"].get("data", "")
                        if cq_data == "confirmar_pix":
                            handle_callback_confirmar(update, cfg)
                            continue
                        if cq_data == "cancelar":
                            chat_id = str(update["callback_query"]["message"]["chat"]["id"])
                            _user_state.pop(chat_id, None)
                            answer_callback(cfg["token"], update["callback_query"]["id"])
                            send_msg(cfg["token"], chat_id, "❌ Pedido cancelado. Use /start para recomeçar.")
                            continue
                    handle_update(update, cfg)
                except Exception as e:
                    log.error(f"handle_update: {e}")

        except Exception as e:
            log.error(f"polling loop: {e}")
            time.sleep(5)

if __name__ == "__main__":
    run_bot()
