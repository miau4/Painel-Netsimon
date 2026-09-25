# Changelog v37

## 1. Correção: sincronia entre servidores falhava em silêncio
- **Problema relatado:** quando o bot renovava um usuário no servidor 1,
  o servidor 2 não recebia a informação, e não sobrava nenhum rastro em
  log em lugar nenhum.
- **Causa raiz:** `propagate_to_servers()` só registrava log de falha
  quando havia erro de **rede** (timeout, conexão recusada) —
  `requests.post()`/`requests.delete()` não levantam exceção por causa
  do status code da resposta. Uma resposta HTTP de erro do servidor
  remoto (401 de token de sincronização inválido/desatualizado, 404,
  500 etc.) passava batido, sem nenhum log, dando a falsa impressão de
  que "não aconteceu nada".
- **Correção:** toda resposta com status `>= 400` agora é tratada como
  falha e logada com o motivo, o nome do servidor remoto e o caminho
  da chamada — aparece na tela de Logs do painel, junto das mensagens
  "SYNC FALHOU" que já existiam por falha de rede.
- Arquivo afetado: `painel_api.py` (função `propagate_to_servers`).

## 2. Correção: bot não reconhecia a palavra "app"
- **Problema relatado:** cliente digitava "app" pedindo o link do
  aplicativo, e o bot não respondia com o link (nem batendo o comando
  fixo, nem através de treinamento na IA).
- **Causa raiz:** o menu mostra o comando oficial como "apk", e o
  código só reconhecia as palavras `apk`, `aplicativo`, `baixar`,
  `download`, `link` — `app` não é substring de nenhuma delas
  (`aplicativo` não contém `app`, só tem um "p"). Sem bater em nenhuma
  palavra-chave fixa, a mensagem caía no fallback de IA, que só tinha
  o texto treinado como dica e não o link real (isso só o código busca
  dinamicamente, via `_get_app_links_internal()`).
- **Correção:** adicionada a palavra `app` na lista de palavras-chave
  reconhecidas desse comando, que já busca e envia o link real.
- Arquivo afetado: `painel_api.py` (1 linha, comando APK).

## 3. Novo recurso: "🔧 Comandos Personalizados" no bot do WhatsApp
- **Objetivo:** dar ao admin um jeito de cadastrar novas
  palavras-chave + resposta fixa do bot, direto no painel, sem
  precisar de correção de código a cada palavra nova.
- **O que foi criado:**
  - Armazenamento em `/etc/painel/whatsapp_custom_commands.json`
    (mesmo padrão do `ai_training.json` que já existe — arquivo solto
    dentro de `/etc/painel`, entra automático no backup completo e
    volta sozinho num restore, sem precisar recadastrar).
  - Endpoints novos: `GET/POST /api/whatsapp/custom-commands`,
    `DELETE /api/whatsapp/custom-commands/<id>`.
  - Bloco novo em `whatsapp.html`, "🔧 Comandos Personalizados" (logo
    abaixo de "APK / Link do Aplicativo"): cadastra palavra(s)-chave
    (separadas por vírgula) + a resposta fixa, lista os cadastrados,
    apaga com um clique. Já vale na hora, sem restart.
  - No fluxo do bot: a checagem roda **depois** dos comandos oficiais
    fixos (teste/vencimento/apk/mensal/renovar) — um cadastro novo
    nunca sobrescreve esses por acidente — e **antes** do suporte/IA —
    pra ser sempre determinístico (mesma pergunta, mesma resposta, não
    depende da IA estar ligada).
  - Diferença importante pro "Treinar a IA" que já existe: aquele é só
    uma sugestão de contexto pra IA decidir o que responder. Isto aqui
    é literal — a palavra bate, a resposta cadastrada é enviada,
    sempre a mesma, sem IA no meio.
- Arquivos afetados: `painel_api.py`, `whatsapp.html`.

---
**Observação sobre este pacote:** as mudanças deste changelog tocam
só `painel_api.py` e `whatsapp.html` — nenhum outro arquivo do
projeto (incluindo os blocos de Campanhas do v36) foi alterado.
