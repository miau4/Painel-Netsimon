# Changelog v33

## 1. Correção: sincronização multi-servidor não cobria todos os fluxos de criação/renovação
- **Causa raiz:** a sincronização entre servidores (aba "Servidores",
  `propagate_to_servers()`) só era disparada pela rota `/api/users`
  (criação de usuário completo, com dias de validade). Os outros três
  fluxos que também criam ou renovam usuário de verdade nunca chamavam
  `propagate_to_servers()`, então ficavam de fora da réplica:
  - **Criar Teste** / **Criar Teste Automático** (`create_test_internal`,
    usada tanto pelo botão quanto pelo autoatendimento do bot de
    WhatsApp)
  - **Acesso pago via bot** — cliente novo que manda comprovante PIX
    (`create_paid_access_internal`)
  - **Renovação via bot** — cliente já existente que manda comprovante
    PIX (chamada de `renew_access_internal` dentro do webhook do bot;
    as renovações manuais pelo botão ♻️ e pela ação em lote já
    propagavam corretamente e continuam funcionando como antes)
- **Correção:** as três chamadas passam a propagar para os servidores
  sincronizados, reaproveitando os mesmos endpoints (`/api/users/test`,
  `/api/users`, `/api/users/<login>/renovar`) que a sincronização normal
  já usava. A propagação da renovação via bot foi colocada no ponto de
  chamada (dentro do webhook), e não dentro de `renew_access_internal()`,
  para não duplicar a propagação já feita por `renovar_user()` e
  `bulk_action_users()` — o que somaria os dias em dobro no servidor
  remoto.
- Arquivo afetado: `painel_api.py`.

## 2. Indicador de versão
- Rodapé da sidebar (`painel.js`) e rodapé da tela de login
  (`login.html`) atualizados de `v31` para `v33`.

## 3. Backup local (Exportar SQL / Exportar Tudo) — erro sem causa visível
  + corrida no download
- **Causa raiz 1 (visibilidade do erro):** a rota `/api/backup/export-sql`
  não tinha `try/except` ao redor de `build_sql_dump_bytes()` — qualquer
  exceção ali caía no handler global genérico ("Ocorreu um erro
  interno..."), escondendo a causa real tanto do toast quanto do log
  de sistema. `/api/backup/export-all` já tinha `try/except`, mas só
  logava `str(e)`, sem traceback.
- **Correção 1:** as duas rotas agora logam tipo + mensagem + traceback
  completo em `/var/log/netsimon_system.log`, e devolvem o erro real
  (tipo + mensagem) no toast — se o backup falhar por qualquer motivo,
  a causa aparece na hora, sem precisar reproduzir às cegas de novo.
- **Causa raiz 2 (corrida no download):** em `exportSql()`/`exportAll()`
  (`backup.html`), o `<a>` de download nunca era anexado ao DOM, e a
  blob URL era revogada imediatamente após `a.click()` — em downloads
  maiores isso pode abortar o download em silêncio no Chromium.
- **Correção 2:** o `<a>` passa a ser anexado ao DOM antes do click e
  removido depois, e a blob URL só é revogada 1s após o click.
- **Nota:** se o download aparecer como "não seguro" e for bloqueado
  pelo próprio navegador (aviso "Download não seguro bloqueado",
  `net::ERR_FAILED` mesmo com a requisição em 200 OK), isso **não é bug
  do painel** — é o Chrome bloqueando downloads de páginas servidas em
  HTTP puro (sem TLS). A correção nesse caso é publicar o painel via
  HTTPS (ver `setup_https_domain.sh`), não um patch de código.
- Arquivos afetados: `painel_api.py`, `backup.html`.
