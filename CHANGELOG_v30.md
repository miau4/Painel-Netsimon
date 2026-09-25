# Painel Netsimon — v30 — changelog desta rodada

## 1. Porta 8080 deixa de ser vulnerável — security.py vira serviço fixo
- **Causa raiz do risco:** a porta 8080 rodava `proxy.py`, que aceita
  qualquer handshake WebSocket sem autenticação e faz passthrough cru
  até o SSH local (`127.0.0.1:22`). Como o `sshd` só via a conexão vindo
  de `127.0.0.1` (o próprio `proxy.py`), o `fail2ban` nunca enxergava o
  IP real de quem tentava — abrindo caminho pra brute-force de SSH
  ilimitado e invisível.
- **Correção:** a porta 80 continua com o `proxy.py` simples, sem
  mudanças. A porta 8080 agora é sempre o `security.py`, subindo como
  serviço systemd de verdade (`netsimon-security.service`,
  `Restart=always`, igual ao `xray`). Ele exige um token compartilhado
  (`X-Auth-Token`, gerado em `/etc/painel/security.token`, `chmod 600`)
  no handshake — quem não manda o token certo é rejeitado e logado em
  formato que o `fail2ban` reconhece, banindo o IP real de origem.
- Atualizado em conjunto: `install.sh`, `boot_check.sh`, `repair.sh`,
  `uninstall.sh`, `migrate_ssh_xhttp.sh`, `monitor.sh`, `websocket.sh`,
  `painel_api.py` (`MONITORED_SERVICES`, status/start/stop/restart do
  serviço "security" separado do "proxy", endpoints
  `/api/websocket/*` e `/api/wssecurity/*`) e `websocket.html`.
- O menu do painel (`websocket.sh` e a tela WebSocket Manager) nunca
  mais mata/sobe a porta 8080 via `screen`/`kill -9` — sempre via
  `systemctl`, pra não brigar com o `Restart=always`. Portas extras de
  Security fora de 80/8080 continuam disponíveis via `screen`, para
  testes.

## 2. Versão do painel agora aparece discretamente na interface
- Pequeno indicador de versão (`v30`) injetado automaticamente no
  rodapé da barra lateral (via `painel.js`, sem precisar editar cada
  uma das páginas) e no rodapé da tela de login.

## 3. Padronização de fixes — "modelo de fix"
- `aplicar_fix_device_block.sh` renomeado para `modelo_de_fix.sh`,
  agora documentado como modelo de referência para o formato que
  qualquer fix aplicado ao painel deve seguir.
