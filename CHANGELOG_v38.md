# Changelog v38

Este pacote é a **junção** entre o v37 (gerado neste chat, com as
correções abaixo) e o `Painel-Netsimon-v36.zip` que você enviou.

## Comparação feita
Diff recursivo, arquivo por arquivo, entre o seu zip enviado e o v36
original que eu já tinha aqui: **só 1 divergência** — todo o resto
(incluindo `painel_api.py`, `campanhas.html`, `whatsapp.html` na forma
como estavam no v36) batia byte a byte.

## O que veio do seu zip (mesclado)
- `recriar_usuarios_linux.sh` — script novo, não existia nas versões
  anteriores. Lê `/etc/painel/usuarios.db` e recria no sistema
  operacional todo usuário que existe no banco do painel mas sumiu
  como usuário Linux (útil depois de reconstruir/restaurar um
  servidor). Não conflita com nada — arquivo independente, adicionado
  como está.

## O que já vinha do v37 (mantido)
- Correção: sincronia entre servidores falhava em silêncio
  (`propagate_to_servers` agora loga qualquer erro HTTP, não só falha
  de rede).
- Correção: bot não reconhecia a palavra "app" (comando de
  APK/aplicativo).
- Novo recurso: "🔧 Comandos Personalizados" no bot do WhatsApp.

Ver `CHANGELOG_v37.md` e `CHANGELOG_v36.md` neste mesmo zip pros
detalhes completos de cada um.
