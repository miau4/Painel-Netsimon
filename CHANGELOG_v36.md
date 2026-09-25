# Changelog v36

## 1. Novo bloco "🎲 Mensagem Aleatória Programável" em Campanhas
- **Objetivo:** permitir um envio avulso (fora do fluxo de campanha em
  lote) — número do contato e mensagem digitados na mão, mídia
  opcional, com agendamento de data/hora exata do disparo (ou fila de
  envio imediato se não agendar).
- **O que foi criado:**
  - Armazenamento próprio em `/etc/painel/whatsapp_random_messages.json`
    e mídia em `/etc/painel/wa_random_msg_media/<id>/`.
  - Endpoints novos: `GET/POST /api/whatsapp/random-messages`,
    `POST /api/whatsapp/random-messages/<id>/media`,
    `DELETE /api/whatsapp/random-messages/<id>` (cancelamento, só
    permitido enquanto a mensagem estiver "pendente").
  - Scheduler novo em background (`whatsapp_random_message_scheduler_loop`,
    checa a cada 30s) que dispara sozinho assim que o horário agendado
    chega, sem precisar do painel aberto na hora.
  - Bloco novo em `campanhas.html`, aparecendo como o **primeiro** da
    tela, com lista de mensagens (status: pendente/enviada/falhou) e
    botão de cancelar.
- Arquivos afetados: `painel_api.py`, `campanhas.html`.

## 2. Novo bloco "🗂️ Modelos de Mensagens" em Campanhas
- **Objetivo:** guardar mensagens prontas (texto + mídia opcional)
  reaproveitáveis com um clique em qualquer tela de envio, sem
  precisar redigitar/reanexar tudo de novo a cada campanha/mensagem.
- **O que foi criado:**
  - Armazenamento próprio em `/etc/painel/whatsapp_message_templates.json`
    e mídia em `/etc/painel/wa_template_media/<id>/`.
  - Endpoints novos: `GET/POST /api/whatsapp/message-templates`,
    `POST /api/whatsapp/message-templates/<id>/media`,
    `DELETE /api/whatsapp/message-templates/<id>`.
  - Botão "🗂️ Adicionar modelo" adicionado nas telas de **Nova
    Campanha Manual** e **Mensagem Aleatória Programável** — abre um
    modal com os modelos salvos e aplica o texto (e a mídia, se
    houver) no formulário com um clique.
  - Quando um modelo com mídia é usado numa campanha/mensagem, o
    arquivo é **copiado direto no servidor** para o novo registro
    (`template_id` no payload de criação) — o navegador não precisa
    reanexar o arquivo, já que um `<input type="file">` não aceita
    valor setado por script a partir de um caminho salvo.
  - Bloco novo em `campanhas.html`, terceiro da lista (salvar/listar/
    apagar modelos).
- Arquivos afetados: `painel_api.py`, `campanhas.html`.

## 3. Reordenação dos blocos de Campanhas
- Ordem anterior: Disparo Automático → Nova Campanha Manual →
  Importar Contatos → ...
- Ordem nova: **Mensagem Aleatória Programável** → **Nova Campanha
  Manual** → **Modelos de Mensagens** → Disparo Automático → Importar
  Contatos → ... (resto do painel sem alteração de posição).
- Arquivo afetado: `campanhas.html`.

---
**Observação sobre este pacote:** as mudanças deste changelog tocam
só `painel_api.py` e `campanhas.html` — nenhum outro arquivo do
projeto foi alterado.
