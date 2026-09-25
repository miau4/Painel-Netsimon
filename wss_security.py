#!/usr/bin/env python3
"""
WSS (WebSocket Security) - proxy de camuflagem WebSocket -> SSH local

Como funciona (ordem confirmada por captura de rede real, comparando
com o script original em produção):
1. Escuta na porta escolhida pelo usuário (ex: 80, 8880, 443).
2. Assim que a conexão TCP é aceita, responde IMEDIATAMENTE com o
   status HTTP (ex: "101 SECURITY"), SEM esperar nenhum dado do
   cliente antes disso. Essa é a ordem que apps como HTTP Injector
   esperam: servidor fala primeiro.
3. Só DEPOIS de responder, lê (e descarta) o cabeçalho HTTP que o
   cliente manda em seguida (o "payload" de disfarce) - isso nunca
   deve ir pro SSH local, senão o sshd rejeita como identificação
   inválida e derruba a conexão.
4. A partir daí vira um túnel bruto: tudo que chega de um lado é
   copiado pro outro lado (cliente <-> SSH local), sem inspecionar
   o conteúdo.

Uso:
    python3 wss_security.py
    (vai perguntar a porta, igual à tela "WEBSOCKET SECURITY")

    ou direto:
    python3 wss_security.py --port 80 --target 127.0.0.1:22 --msg SECURITY
"""

import argparse
import asyncio
import sys

BUFFER_SIZE = 65536


def build_response(msg: str) -> bytes:
    # Formato mínimo, igual ao observado na captura de rede do script
    # original: "HTTP/1.1 101 <MSG>\r\n\r\n", sem headers extras
    # (Upgrade/Connection) - manter isso curto reduz a chance de
    # inspeção de tráfego reconhecer palavras-chave como "websocket".
    return f"HTTP/1.1 101 {msg}\r\n\r\n".encode()


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Copia bytes crus de um lado da conexão para o outro, sem tocar no conteúdo."""
    try:
        while True:
            data = await reader.read(BUFFER_SIZE)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def read_and_discard_handshake(client_reader) -> bytes:
    """
    Lê do cliente até encontrar o fim do cabeçalho HTTP (\\r\\n\\r\\n) e
    descarta o cabeçalho em si. Retorna só o que vier DEPOIS desse fim
    de cabeçalho (dado real do túnel, se vier colado no mesmo pacote).

    Chamada SÓ DEPOIS de já termos respondido ao cliente - essa é a
    correção do bug de ordem: antes líamos isso antes de responder,
    e o app/rede esperava o servidor falar primeiro.
    """
    buffer = b""
    try:
        while b"\r\n\r\n" not in buffer:
            chunk = await asyncio.wait_for(client_reader.read(BUFFER_SIZE), timeout=5)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > BUFFER_SIZE * 4:
                break
    except asyncio.TimeoutError:
        pass

    if b"\r\n\r\n" in buffer:
        _headers, _sep, remainder = buffer.partition(b"\r\n\r\n")
        return remainder
    return b""


async def handle_client(client_reader, client_writer, target_host, target_port, response: bytes):
    peer = client_writer.get_extra_info("peername")
    try:
        # PASSO 1 (CORRIGIDO): responde IMEDIATAMENTE ao aceitar a conexão,
        # antes de ler qualquer coisa do cliente. É essa ordem que o app
        # e a rede esperam - confirmado pela captura de tráfego real.
        client_writer.write(response)
        await client_writer.drain()

        # PASSO 2: só agora lemos o payload/cabeçalho que o cliente manda,
        # e descartamos - ele nunca deve ir pro SSH local.
        leftover = await read_and_discard_handshake(client_reader)

        # PASSO 3: conecta no serviço real (SSH local, dropbear, etc.)
        try:
            target_reader, target_writer = await asyncio.open_connection(
                target_host, target_port
            )
        except OSError as e:
            print(f"[WSS] Falha ao conectar no destino {target_host}:{target_port} -> {e}")
            client_writer.close()
            return

        # Se sobrou dado real (além do cabeçalho HTTP) no mesmo pacote,
        # repassa pro backend.
        if leftover:
            target_writer.write(leftover)
            await target_writer.drain()

        # A partir daqui é só um túnel bidirecional cru.
        await asyncio.gather(
            pipe(client_reader, target_writer),
            pipe(target_reader, client_writer),
        )
    except Exception as e:
        print(f"[WSS] Erro na conexão {peer}: {e}")
    finally:
        client_writer.close()


async def main(listen_port: int, target_host: str, target_port: int, msg: str):
    response = build_response(msg)

    async def _handler(r, w):
        await handle_client(r, w, target_host, target_port, response)

    server = await asyncio.start_server(_handler, "0.0.0.0", listen_port)
    addr = server.sockets[0].getsockname()
    print(f"[WSS] WEBSOCKET SECURITY ativo em {addr[0]}:{addr[1]} -> encaminhando para {target_host}:{target_port} (msg={msg})")
    async with server:
        await server.serve_forever()


def ask_port_interactively() -> int:
    print("=" * 40)
    print(" " * 10 + "WEBSOCKET SECURITY")
    print("=" * 40)
    while True:
        raw = input("Qual porta deseja utilizar? ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
        print("Porta inválida, tente novamente.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WSS - WebSocket Security proxy")
    parser.add_argument("--port", type=int, help="Porta de escuta (ex: 80)")
    parser.add_argument(
        "--target",
        type=str,
        default="127.0.0.1:22",
        help="Destino no formato host:porta (padrão: 127.0.0.1:22, o SSH local)",
    )
    parser.add_argument(
        "--msg",
        type=str,
        default="SECURITY",
        help="Texto do status HTTP 101 (padrão: SECURITY, igual à tela do menu)",
    )
    args = parser.parse_args()

    port = args.port if args.port else ask_port_interactively()

    try:
        target_host, target_port_str = args.target.split(":")
        target_port = int(target_port_str)
    except ValueError:
        print("Formato de --target inválido. Use host:porta, ex: 127.0.0.1:22")
        sys.exit(1)

    try:
        asyncio.run(main(port, target_host, target_port, args.msg))
    except KeyboardInterrupt:
        print("\n[WSS] Encerrado.")
