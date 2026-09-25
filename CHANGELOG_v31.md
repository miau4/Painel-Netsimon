# Painel Netsimon — v31 — changelog desta rodada

## 1. Limiter religando sozinho depois de "Desativar"
- **Causa raiz #1:** o `install.sh` cria uma unit systemd `limiter` com
  `Restart=always` (pensada pra outro fim), mas o Limiter de verdade
  sempre foi gerenciado via `screen`/`pgrep`, nunca via systemd. O botão
  "Desativar Limiter" só matava o processo (`pkill`/`screen quit`) — e
  como a unit systemd tinha `Restart=always`, o próprio systemd subia
  outro processo sozinho em ~3s, sem passar pelo painel e sem gerar log
  nenhum. Resultado: o botão "desligava" por um instante e voltava
  ligado sozinho quase na hora.
- **Causa raiz #2:** `"limiter"` estava na lista `MONITORED_SERVICES` do
  autodiagnóstico, checada a cada 10 minutos. Como um "Desativar" manual
  e uma queda de verdade são indistinguíveis pra esse watchdog, em modo
  de automação "parcial" ou "automático" ele tratava o limiter desligado
  como incidente e reaplicava `systemctl restart limiter` sozinho outra
  vez, minutos depois.
- **Correção:** `service_action()` (start/stop/restart do limiter) agora
  também para e desabilita a unit systemd `limiter` antes de
  ligar/desligar o processo real via `screen`. `"limiter"` saiu de
  `MONITORED_SERVICES` — desligar o limiter pela tela Dispositivos
  nunca mais é tratado como incidente pelo autodiagnóstico.
- Arquivo afetado: `painel_api.py`.

## 2. "Exportar SQL" / "Exportar Tudo" (Backup) enviando pro Telegram
- Versões de `backup.html` anteriores à v30/v31 tinham os botões
  "Exportar SQL" e "Exportar Tudo" da tela Backup enviando o arquivo
  pro Telegram, em vez de só baixar localmente pelo navegador.
- **Correção (confirmada):** `Exportar SQL`/`Exportar Tudo` fazem
  SEMPRE download local no navegador (rotas `/api/backup/export-sql` e
  `/api/backup/export-all`, via `send_file` + download por blob no
  front). O envio pro Telegram fica restrito a exatamente dois
  caminhos: o toggle "Ativar backup automático" (agendador próprio) e o
  botão "Testar envio agora" (`/api/backup/send-now`), que dispara o
  envio imediato pra validar a configuração.
- Arquivo afetado: `backup.html`.

## 3. Novo formato padrão de fix pontual
- `modelo_de_fix.sh` reescrito: o formato antigo (copiar um arquivo
  inteiro por cima do outro, `cp SRC DEST`) foi descontinuado.
- Novo padrão: um único `.sh` autocontido por fix, com patch por
  `diff -ru` real (embutido em base64, com SHA-256 de integridade,
  aplicado por um applier Python que faz substituição exata de bloco de
  texto — nunca por número de linha, e nunca aborta os demais arquivos
  se um deles não bater) para arquivos onde dá pra gerar um diff seguro,
  e restauração completa (também em base64 com SHA-256, mas
  explicitamente rotulada como tal) só quando não dá. Sempre com
  validação de sintaxe antes de aplicar, backup com timestamp,
  reinício só do(s) serviço(s) afetado(s), confirmação de status com
  rollback automático se algo não subir, e resumo final com rollback
  manual.
- `fixes_aplicados/aplicar_correcoes_limiter_backup_telegram.sh` (o fix
  dos itens 1 e 2 acima) fica no pacote como exemplo de referência
  desse formato, já testado ponta a ponta.

## 4. Indicador de versão
- Rodapé da sidebar (`painel.js`) e rodapé da tela de login
  (`login.html`) atualizados de `v30` para `v31`.
