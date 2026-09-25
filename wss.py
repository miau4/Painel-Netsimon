#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wss.py - NetSimon WebSocket Security (WSS)
Substitui o antigo security.py (nunca abria socket TLS de fato — só o
nome "Security" enganava). Este aqui é TLS real (ssl.SSLContext) por
cima do mesmo modelo de "WebSocket Proxy" do proxy.py: handshake HTTP
RFC 6455 com Sec-WebSocket-Accept calculado de verdade (não fixo),
seguido de passthrough cru pro destino (SSH local, por padrão).

Uso: wss.py <porta> [--dest host:porta] [--cert caminho] [--key caminho]
Rodado via systemd (wss@<porta>.service) — nunca direto em produção.
"""

import argparse
import base64
import hashlib
import logging
import select
import socket
import ssl
import threading

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
BUFFER_SIZE = 65536
LOG_FILE = "/var/log/netsimon_wss.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [wss] %(message)s",
)


def compute_accept(key):
    sha1 = hashlib.sha1((key + WS_MAGIC).encode()).digest()
    return base64.b64encode(sha1).decode()


def extract_ws_key(request):
    for line in request.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            return line.split(":", 1)[1].strip()
    return None


def handle_client(client_socket, addr, dest_host, dest_port):
    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.settimeout(10)
        request = client_socket.recv(BUFFER_SIZE).decode(errors="ignore")
        client_socket.settimeout(None)
        if not request:
            return

        ws_key = extract_ws_key(request)
        if ws_key:
            # Handshake real (RFC 6455) — corrige o "Sec-WebSocket-Accept"
            # fixo/"foo" que outros scripts desse nicho usam.
            accept_val = compute_accept(ws_key)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
            )
        else:
            # Fallback pra apps que só esperam ver o 101 e já mandar
            # bytes crus, sem validar o handshake WS de verdade.
            response = "HTTP/1.1 101 Switching Protocols\r\n\r\n"

        client_socket.sendall(response.encode())

        target_socket.connect((dest_host, dest_port))
        target_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        while True:
            r, _, _ = select.select([client_socket, target_socket], [], [], 120)
            if not r:
                break
            if client_socket in r:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                target_socket.sendall(data)
            if target_socket in r:
                data = target_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                client_socket.sendall(data)
    except Exception as e:
        logging.info(f"{addr}: encerrado ({e})")
    finally:
        client_socket.close()
        target_socket.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--dest", default="127.0.0.1:22")
    parser.add_argument("--cert", default="/etc/painel/wss/cert.pem")
    parser.add_argument("--key", default="/etc/painel/wss/key.pem")
    args = parser.parse_args()

    dest_host, dest_port_str = args.dest.rsplit(":", 1)
    dest_port = int(dest_port_str)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", args.port))
    server.listen(200)
    logging.info(f"WSS escutando na porta {args.port} -> destino {args.dest}")

    while True:
        raw_client, addr = server.accept()
        try:
            tls_client = context.wrap_socket(raw_client, server_side=True)
        except Exception as e:
            logging.info(f"{addr}: falha no handshake TLS ({e})")
            raw_client.close()
            continue
        t = threading.Thread(
            target=handle_client,
            args=(tls_client, addr, dest_host, dest_port),
            daemon=True,
        )
        t.start()


if __name__ == "__main__":
    main()
