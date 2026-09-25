#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==========================================
#   PAINEL NETSIMON - WEBSOCKET/SSH PROXY
#   Suporta WebSocket Upgrade + pass-through
# ==========================================

import socket
import threading
import sys
import os
import datetime

SSH_HOST    = '127.0.0.1'
SSH_PORT    = 22
BUFFER_SIZE = 65536   # 8.0: aumentado de 8192 para reduzir syscalls e melhorar throughput
STATUS_MSG  = "netsimon"
LOG_FILE    = "/var/log/netsimon_proxy.log"

# ── Logging simples ──────────────────────────────────────────────

def log(msg):
    ts = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    line = f"{ts} {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        pass

# ── Keepalive TCP (BUGFIX: usuário SSH "online" fantasma) ─────────
# client_socket.settimeout(None) é usado depois do handshake, então o
# recv() em forward() fica bloqueado indefinidamente esperando dado.
# Se o app do cliente (celular) cair "sujo" (troca de torre, app
# morto, sem FIN/RST), esse recv() nunca retorna e o par de sockets
# (client_socket <-> target_socket, ou seja, proxy<->sshd local) nunca
# é fechado - o sshd continua vendo uma conexão de verdade, ativa, e
# o painel web (que valida via `ss` ESTABLISHED) continua marcando o
# usuário como online bem depois de ele já ter sumido de verdade,
# mesmo com ClientAliveInterval configurado no sshd_config (porque do
# ponto de vista do sshd quem responde é o proxy, não o celular).
# Ativar SO_KEEPALIVE com intervalos curtos faz o próprio kernel
# sondar o peer e derrubar a conexão (recv() levanta erro) se ele não
# responder - sem depender de nenhum timeout de aplicação.
def _harden_socket(sock, idle=15, interval=10, count=3):
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except Exception:
        pass

# ── Forward bidirecional ─────────────────────────────────────────

def forward(src, dst):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try: s.close()
            except Exception: pass

# ── Handler por cliente ──────────────────────────────────────────

def handle_client(client_socket, client_addr):
    target_socket = None
    try:
        _harden_socket(client_socket)
        client_socket.settimeout(10)
        request = client_socket.recv(BUFFER_SIZE)
        client_socket.settimeout(None)

        if not request:
            return

        # Otimização TCP: desativa algoritmo de Nagle para menor latência
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        header       = request.decode('utf-8', errors='ignore')
        header_lower = header.lower()

        is_ws = (
            "upgrade: websocket" in header_lower or
            "connection: upgrade" in header_lower
        )

        if is_ws:
            response = (
                f"HTTP/1.1 101 {STATUS_MSG}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n\r\n"
            )
            client_socket.sendall(response.encode())

        # Conecta ao SSH
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Otimização TCP no socket de destino também
        target_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        target_socket.settimeout(8)
        target_socket.connect((SSH_HOST, SSH_PORT))
        target_socket.settimeout(None)
        _harden_socket(target_socket)

        # Pass-through para conexões não-WS (ex: cliente SSH direto)
        if not is_ws:
            target_socket.sendall(request)

        log(f"CONN {client_addr[0]}:{client_addr[1]} | WS={is_ws}")

        t1 = threading.Thread(target=forward, args=(client_socket, target_socket), daemon=True)
        t2 = threading.Thread(target=forward, args=(target_socket, client_socket), daemon=True)
        t1.start()
        t2.start()

    except ConnectionRefusedError:
        log(f"SSH recusou conexão de {client_addr}")
    except socket.timeout:
        log(f"Timeout de {client_addr}")
    except Exception as e:
        log(f"ERRO handle_client {client_addr}: {e}")
    finally:
        if target_socket and not (
            hasattr(target_socket, '_closed') and not target_socket._closed
        ):
            pass  # threads gerenciam o fechamento

# ── Main ─────────────────────────────────────────────────────────

def main(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Aumenta buffer de recepção do socket servidor
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
    try:
        server.bind(('0.0.0.0', port))
    except OSError as e:
        print(f"[ERRO] Bind na porta {port} falhou: {e}")
        sys.exit(1)

    server.listen(500)
    log(f"=== Proxy Painel Netsimon iniciado na porta {port} ===")
    print(f"[OK] Proxy escutando na porta {port}")

    while True:
        try:
            client, addr = server.accept()
            threading.Thread(
                target=handle_client, args=(client, addr), daemon=True
            ).start()
        except KeyboardInterrupt:
            log("Proxy encerrado pelo operador.")
            break
        except Exception:
            pass

if __name__ == "__main__":
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    main(listen_port)
