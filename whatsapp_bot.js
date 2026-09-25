// ==========================================
//   PAINEL NETSIMON - WHATSAPP MICROSERVICE
//   Pareamento multi-dispositivo (QR Code) via Baileys v7.
//   Roda local na porta 5055 e é chamado pelo painel_api.py
//   (Flask), nunca é exposto publicamente.
//
//   Instalação no servidor:
//     cd /etc/painel && npm install
//     node whatsapp_bot.js
//   (ou registre como serviço systemd — ver whatsapp-bot.service)
//
//   Cada "owner" (admin ou um username de revendedor) tem sua própria
//   sessão/pareamento, guardada em ./wa_sessions/<owner>/, então cada
//   painel manda mensagens do SEU PRÓPRIO número de WhatsApp.
//
//   Item: migrado pra Baileys v7 (ESM-only) — o import da lib é
//   dinâmico (await import) porque o resto do arquivo é CommonJS.
//   Item: WhatsApp mudou pra endereçamento "LID" (Linked ID) em vez
//   do número de telefone direto — extraímos o telefone real via
//   msg.key.remoteJidAlt quando o remoteJid vem como "...@lid".
//   Item: trava de 3 minutos no loop de geração de QR — depois disso
//   o sistema para de tentar sozinho e espera um pedido manual via
//   POST /pair/:owner (botão "Parear / Gerar novo QR Code" no painel).
//   Item: bot de autoatendimento ampliado — agora também baixa
//   IMAGENS recebidas (comprovante de PIX, print da tela inicial do
//   app) e encaminha pro painel junto com o texto/legenda, pra
//   permitir fluxos em etapas (ex: "me manda o comprovante").
// ==========================================

const express = require("express");
const QRCode = require("qrcode");
const path = require("path");
const fs = require("fs");
const P = require("pino");

const app = express();
app.use(express.json());

if (typeof fetch !== "function") {
  console.error("=".repeat(70));
  console.error("[whatsapp] ERRO FATAL: fetch() nativo não disponível nesta versão do Node.");
  console.error(`[whatsapp] Versão atual: ${process.version}. Requer Node.js 20 ou superior.`);
  console.error("[whatsapp] Atualize com: curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt install -y nodejs");
  console.error("=".repeat(70));
  process.exit(1);
}

const PORT = 5055;
const FLASK_URL = "http://127.0.0.1:5001"; // painel_api.py — só tráfego local
const SESSIONS_DIR = path.join(__dirname, "wa_sessions");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// Item de segurança: token interno compartilhado com o painel_api.py
// (mesmo arquivo já usado pro X-Sync-Token entre servidores) — sem isso,
// o Flask só sabia dizer que a chamada "veio do localhost", o que nunca
// é uma prova real de quem originou a chamada nesse tipo de arquitetura
// com proxy reverso na frente.
const INTERNAL_TOKEN_PATH = "/etc/painel/sync_token.txt";
function _internalToken() {
  try { return fs.readFileSync(INTERNAL_TOKEN_PATH, "utf8").trim(); }
  catch { return ""; }
}
function _internalHeaders() {
  return { "Content-Type": "application/json", "X-Internal-Token": _internalToken() };
}

// Item: pasta onde ficam salvas as imagens recebidas dos clientes
// (comprovante de PIX, print da tela inicial etc.), organizadas por
// owner. O painel (painel_api.py) só recebe o caminho do arquivo —
// como os dois processos rodam no mesmo servidor, não precisa subir
// o binário da imagem por HTTP.
const MEDIA_DIR = path.join(__dirname, "wa_media");
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

const PAIR_TIMEOUT_MS = 3 * 60 * 1000; // 3 minutos sem leitura do QR

// owner -> { sock, qr, connected, phone, pairStartedAt, everConnected, qrTimedOut }
const instances = {};

function sanitizeOwner(owner) {
  return String(owner).replace(/[^a-zA-Z0-9_-]/g, "");
}

async function main() {
  // Baileys 7.x é ESM-only — import dinâmico dentro de um arquivo CJS.
  const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    downloadMediaMessage,
  } = await import("@whiskeysockets/baileys");

  async function startSession(owner, isManualRetry = false) {
    owner = sanitizeOwner(owner);

    if (instances[owner] && instances[owner].sock) {
      return instances[owner];
    }

    // Se está em timeout (3min sem leitura) e ninguém pediu retry manual,
    // não tenta de novo sozinho — só devolve o estado parado.
    if (instances[owner] && instances[owner].qrTimedOut && !isManualRetry) {
      return instances[owner];
    }

    instances[owner] = instances[owner] || {};
    instances[owner].sock = "pending"; // trava síncrona, antes de qualquer await
    instances[owner].qrTimedOut = false;
    if (!instances[owner].pairStartedAt || isManualRetry) {
      instances[owner].pairStartedAt = Date.now();
    }
    console.log(`[whatsapp] iniciando sessão para "${owner}"...`);

    try {
      const sessionPath = path.join(SESSIONS_DIR, owner);
      const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
      const { version, isLatest } = await fetchLatestBaileysVersion();
      console.log(`[whatsapp] usando Baileys/WA version ${version.join(".")} (isLatest=${isLatest})`);

      const sock = makeWASocket({
        version,
        auth: state,
        logger: P({ level: "silent" }),
        browser: ["Painel Netsimon", "Chrome", "9.0"],
        getMessage: async () => undefined,
        // Item: sincronização de histórico real de conversas — sem isso
        // o painel só "aprendia" a última interação de um contato quando
        // uma mensagem chegava ao vivo (não tinha nenhum jeito de saber
        // a data real de conversas anteriores ao bot estar rodando).
        syncFullHistory: true,
      });

      instances[owner].sock = sock;
      instances[owner].connected = false;
      instances[owner].qr = null;

      sock.ev.on("creds.update", saveCreds);

      // Item: bot de autoatendimento — encaminha mensagens recebidas
      // (de conversas individuais, nunca de grupo/canal) pro painel
      // decidir a resposta.
      sock.ev.on("messages.upsert", async ({ messages, type }) => {
        // Item BUG CORRIGIDO: só processava type "notify" (mensagem nova,
        // ao vivo). Depois de qualquer instabilidade de rede/reconexão, o
        // Baileys reentrega mensagens perdidas — inclusive fromMe, ou
        // seja, respostas MANUAIS do atendente — com type "append"
        // durante o catch-up, e isso caía direto no "return" abaixo sem
        // nunca avisar o painel. Resultado: o bot continuava respondendo
        // por cima do atendente, sem motivo aparente. Agora também
        // processa "append", mas só quando a mensagem é recente (< 2 min)
        // — um catch-up de histórico ANTIGO não deve reabrir/alterar
        // nenhuma conversa já encerrada há dias.
        if (type !== "notify" && type !== "append") return;
        for (const msg of messages) {
          try {
            if (!msg.message) continue;
            if (type === "append") {
              const ts = Number(msg.messageTimestamp) || 0;
              if (!ts || (Date.now() / 1000 - ts) > 120) continue;
            }

            if (msg.key.fromMe) {
              // "fromMe" pode ser: (a) o eco da própria mensagem que O BOT
              // acabou de enviar via POST /send (esperado, ignora), ou
              // (b) você digitando e respondendo manualmente pelo
              // WhatsApp/celular — nesse caso avisa o painel pra ele
              // silenciar o bot (inclusive a IA) nesse número, já que um
              // humano acabou de assumir a conversa de verdade.
              // Item BUG CORRIGIDO: usava a variável "inst", nunca
              // definida nesse escopo (ReferenceError engolido pelo
              // catch abaixo) — o correto é instances[owner], mesmo
              // objeto onde /send guarda os IDs em botSentIds.
              const isBotEcho = instances[owner].botSentIds && msg.key.id && instances[owner].botSentIds.has(msg.key.id);
              if (isBotEcho) {
                instances[owner].botSentIds.delete(msg.key.id);
                continue;
              }
              const jidOut = msg.key.remoteJid;
              if (!jidOut || jidOut.endsWith("@g.us") || jidOut.endsWith("@broadcast") || jidOut.endsWith("@newsletter")) continue;
              let phoneOut;
              if (jidOut.endsWith("@lid")) {
                const realJidOut = msg.key.remoteJidAlt || msg.key.participantAlt || msg.key.senderPn || msg.key.participantPn || "";
                if (!realJidOut) continue;
                phoneOut = realJidOut.split("@")[0];
              } else {
                phoneOut = jidOut.split("@")[0];
              }
              console.log(`[whatsapp] resposta manual detectada (${owner}) pra ${phoneOut} — silenciando bot nesse número`);
              fetch(`${FLASK_URL}/api/whatsapp/human-activity`, {
                method: "POST",
                headers: _internalHeaders(),
                body: JSON.stringify({ owner, phone: phoneOut })
              }).catch(e => console.error("[whatsapp] falha ao avisar o painel sobre resposta manual:", e.message));
              continue;
            }

            const jid = msg.key.remoteJid;
            if (!jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast") || jid.endsWith("@newsletter")) continue;

            // Item BUG CORRIGIDO (mensagens repetidas): o WhatsApp/Baileys
            // pode reentregar a MESMA mensagem do cliente mais de uma vez —
            // ex: uma reconexão rápida logo após a entrega "ao vivo" (evento
            // "notify") faz o catch-up de sincronização ("append") repassar
            // a mesma mensagem de novo, dentro da mesma janela de 2min já
            // aceita acima. Sem checagem de duplicidade por ID, cada
            // reentrega virava uma nova chamada a /api/whatsapp/inbound, e o
            // painel processava (e respondia — bot ou IA) a MESMA mensagem
            // do cliente mais de uma vez, o que aparecia na conversa como o
            // bot "repetindo" respostas (inclusive o menu) sem motivo.
            // Guarda os últimos IDs de mensagem já encaminhados ao painel
            // (por owner, expira sozinho depois de 10min — mesmo padrão já
            // usado em botSentIds acima) e ignora silenciosamente uma
            // repetição exata do mesmo ID.
            if (msg.key.id) {
              if (!instances[owner].inboundForwardedIds) instances[owner].inboundForwardedIds = new Set();
              if (instances[owner].inboundForwardedIds.has(msg.key.id)) continue;
              instances[owner].inboundForwardedIds.add(msg.key.id);
              setTimeout(() => {
                if (instances[owner] && instances[owner].inboundForwardedIds) {
                  instances[owner].inboundForwardedIds.delete(msg.key.id);
                }
              }, 10 * 60 * 1000);
            }

            // Item: WhatsApp agora usa "LID" em vez do número de telefone
            // direto no remoteJid pra alguns contatos — na verdade já é o
            // modo PADRÃO, não uma exceção rara. O número real vem no
            // campo remoteJidAlt (participantAlt em mensagens de grupo);
            // os campos senderPn/participantPn ficam mantidos só como
            // fallback pra caso uma versão diferente do Baileys volte a
            // preenchê-los — na 7.0.0-rc13 eles vêm sempre vazios, e como
            // não tinha nenhum log nesse ponto, praticamente toda mensagem
            // de cliente real estava sendo descartada em silêncio aqui.
            let phone;
            if (jid.endsWith("@lid")) {
              const realJid = msg.key.remoteJidAlt || msg.key.participantAlt || msg.key.senderPn || msg.key.participantPn || "";
              if (!realJid) {
                console.error(`[whatsapp] mensagem @lid sem telefone real resolvível (${owner}): ${JSON.stringify(msg.key)}`);
                continue; // sem telefone real disponível, ignora
              }
              phone = realJid.split("@")[0];
            } else {
              phone = jid.split("@")[0];
            }

            const text = msg.message.conversation
              || (msg.message.extendedTextMessage && msg.message.extendedTextMessage.text)
              || (msg.message.buttonsResponseMessage && msg.message.buttonsResponseMessage.selectedButtonId)
              || (msg.message.imageMessage && msg.message.imageMessage.caption)
              || "";

            // Item: imagem recebida (comprovante de PIX, print da tela
            // inicial etc.) — baixa e salva em disco; o texto (se houver)
            // é a legenda da própria imagem.
            let hasImage = false;
            let imagePath = "";
            if (msg.message.imageMessage) {
              try {
                const buffer = await downloadMediaMessage(msg, "buffer", {});
                const ownerDir = path.join(MEDIA_DIR, owner);
                if (!fs.existsSync(ownerDir)) fs.mkdirSync(ownerDir, { recursive: true });
                imagePath = path.join(ownerDir, `${phone}_${Date.now()}.jpg`);
                fs.writeFileSync(imagePath, buffer);
                hasImage = true;
              } catch (e) {
                console.error(`[whatsapp] falha ao baixar imagem de ${phone} (${owner}):`, e.message);
              }
            }

            // Item: comprovante em PDF — bem comum quando o cliente
            // exporta o recibo direto do app do banco em vez de mandar
            // print. Baixa e salva igual à imagem; o painel decide o que
            // fazer com ele (aceita como comprovante sem precisar ler o
            // conteúdo — ver painel_api.py / _looks_like_payment_proof).
            let hasPdf = false;
            let pdfPath = "";
            const docMsg = msg.message.documentMessage || msg.message.documentWithCaptionMessage?.message?.documentMessage;
            if (docMsg && (docMsg.mimetype || "").toLowerCase().includes("pdf")) {
              try {
                const buffer = await downloadMediaMessage(msg, "buffer", {});
                const ownerDir = path.join(MEDIA_DIR, owner);
                if (!fs.existsSync(ownerDir)) fs.mkdirSync(ownerDir, { recursive: true });
                pdfPath = path.join(ownerDir, `${phone}_${Date.now()}.pdf`);
                fs.writeFileSync(pdfPath, buffer);
                hasPdf = true;
              } catch (e) {
                console.error(`[whatsapp] falha ao baixar PDF de ${phone} (${owner}):`, e.message);
              }
            }

            if (!text && !hasImage && !hasPdf) continue;
            const pushName = msg.pushName || "";
            console.log(`[whatsapp] mensagem recebida (${owner}) de ${phone}: "${text.substring(0, 60)}"${hasImage ? " [+imagem]" : ""}${hasPdf ? " [+pdf]" : ""}`);
            const resp = await fetch(`${FLASK_URL}/api/whatsapp/inbound`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, phone, text, hasImage, imagePath, hasPdf, pdfPath, name: pushName })
            }).catch(e => { console.error("[whatsapp] falha de rede ao encaminhar mensagem pro painel:", e.message); return null; });
            if (resp && !resp.ok) {
              const body = await resp.text().catch(() => "");
              console.error(`[whatsapp] painel recusou a mensagem (${owner}/${phone}): HTTP ${resp.status} — ${body.substring(0, 300)}`);
            }
          } catch (e) {
            console.error("[whatsapp] erro processando mensagem recebida:", e);
          }
        }
      });

      // Item: rastreamento de status pras campanhas de reengajamento —
      // Baileys reporta a evolução de cada mensagem ENVIADA por nós
      // (fromMe) através desse evento: 2=enviado ao servidor,
      // 3=entregue no aparelho (2 tracinhos cinza), 4=visualizado
      // (tracinhos azuis). Encaminha pro painel casar com a campanha.
      //
      // Item BUG CORRIGIDO: faltava o status 0 (ERROR) do Baileys nesse
      // mapa. O /send responde "ok:true" assim que sock.sendMessage()
      // resolve a Promise (ou seja, a mensagem foi aceita pra ENVIO),
      // mas isso não garante que o WhatsApp vai aceitar ela de fato —
      // se o número não existe/não tem WhatsApp mais, se a sessão cair
      // no meio do envio, etc, o servidor devolve um update.status=0
      // (ERROR) alguns instantes depois. Como statusMap[0] não existia,
      // "if (!status) continue" descartava esse evento silenciosamente
      // e o relatório da campanha ficava PRESO em "enviado" pra sempre,
      // mesmo a mensagem nunca tendo chegado de verdade no destino.
      // Agora reporta como "falhou", e o painel_api.py sabe rebaixar
      // "enviado" -> "falhou" quando recebe esse status (ver
      // whatsapp_status_update em painel_api.py).
      // Item BUG CORRIGIDO #2: o telefone usado pra casar o status com a
      // campanha vinha direto de key.remoteJid.split("@")[0] — mas pra
      // conversas endereçadas por "@lid" (que é o modo PADRÃO hoje, não
      // exceção — ver o mesmo problema resolvido lá em cima, no handler
      // de mensagens recebidas) isso retorna o identificador LID, não o
      // telefone de verdade. Resultado: o /status-update chegava no
      // painel com um "phone" que nunca bate com nenhum resultado salvo
      // na campanha (que é indexada pelo telefone real), então a
      // atualização de status (entregue/visualizado/falhou) era
      // descartada em silêncio pra praticamente todo mundo — é por isso
      // que o relatório ficava PRESO em "enviado" mesmo com o fix do
      // status=0 já aplicado. Resolve com a MESMA lógica já usada pras
      // mensagens recebidas: usa remoteJidAlt (ou os fallbacks) quando o
      // jid é @lid.
      sock.ev.on("messages.update", async (updates) => {
        for (const { key, update } of updates) {
          try {
            if (!key.fromMe || update.status === undefined || update.status === null) continue;
            const jid = key.remoteJid || "";
            let phone;
            if (jid.endsWith("@lid")) {
              const realJid = key.remoteJidAlt || key.participantAlt || key.senderPn || key.participantPn || "";
              if (!realJid) continue; // sem telefone real resolvível, não dá pra casar com a campanha
              phone = realJid.split("@")[0];
            } else {
              phone = jid.split("@")[0];
            }
            const statusMap = { 0: "falhou", 2: "enviado", 3: "entregue", 4: "visualizado" };
            const status = statusMap[update.status];
            if (!status) continue;
            await fetch(`${FLASK_URL}/api/whatsapp/status-update`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, phone, msgId: key.id, status })
            }).catch(() => {});
          } catch (e) {
            console.error("[whatsapp] erro processando status de mensagem:", e);
          }
        }
      });

      // Item: sincronização do histórico real de conversas (ver
      // syncFullHistory acima) — o WhatsApp entrega, na conexão, todos
      // os chats existentes na conta com a data/hora VERDADEIRA da
      // última mensagem de cada um (chat.conversationTimestamp). Cruza
      // com o array "contacts" do mesmo evento pra resolver o telefone
      // real de chats endereçados por LID (ver nota sobre LID acima).
      //
      // Item: o evento "messaging-history.set" dispara em VÁRIAS ONDAS
      // distintas (não pacotes picotados de um único envio — são fases
      // reais da sincronização, às vezes com mais de 4s de intervalo
      // entre elas). Um debounce simples que limpa o buffer inteiro a
      // cada flush perde os chats cujo mapeamento LID->telefone só chega
      // numa onda POSTERIOR à onda em que o chat apareceu (foi o que
      // aconteceu em produção: 2ª onda trouxe 215 chats mas 29 ficaram
      // sem LID, e o buffer era limpo antes da 3ª onda poder resolvê-los).
      //
      // Correção: o buffer de contatos NUNCA é limpo (só cresce, custo
      // desprezível) e chats não resolvidos ficam retidos no buffer —
      // não são descartados — pra serem tentados de novo no próximo
      // flush ou quando um contato novo chegar (inclusive fora da
      // sincronização inicial, via "contacts.upsert" em uso normal do
      // WhatsApp). Só removemos do buffer os chats que efetivamente
      // conseguimos resolver e sincronizar.
      instances[owner].historySync = instances[owner].historySync || {
        contacts: new Map(), // lid/phone -> dados brutos do contato (nunca limpo)
        chats: new Map(),    // jid -> chat (só remove quando resolvido com sucesso)
        timer: null
      };
      const HISTORY_SYNC_DEBOUNCE_MS = 6000;

      const flushHistorySync = async () => {
        const buf = instances[owner].historySync;
        buf.timer = null;
        try {
          const phoneByLid = new Map();
          const nameByPhone = new Map();
          for (const c of buf.contacts.values()) {
            const num = c.phoneNumber || (c.id && c.id.endsWith("@s.whatsapp.net") ? c.id : null);
            const phoneFromId = num ? num.split("@")[0] : null;
            if (c.lid && phoneFromId) phoneByLid.set(c.lid.split("@")[0], phoneFromId);

            // Item: nome real do contato (agenda salva no WhatsApp) — vem
            // nesse array "contacts", não em "chats". Prioriza o nome que
            // o próprio dono salvou (name), cai pro nome verificado de
            // empresa (verifiedName) e por último o nome que o contato
            // definiu no próprio perfil (notify), na ausência dos outros.
            const savedName = (c.name || c.verifiedName || c.notify || "").trim();
            if (phoneFromId && savedName) nameByPhone.set(phoneFromId, savedName);
          }

          const synced = [];
          const resolvedJids = [];
          for (const [jid, chat] of buf.chats.entries()) {
            if (!jid || jid.endsWith("@g.us") || jid.endsWith("@broadcast") || jid.endsWith("@newsletter")) {
              resolvedJids.push(jid); // lixo, não é chat individual — descarta
              continue;
            }
            if (!chat.conversationTimestamp) {
              resolvedJids.push(jid); // nunca vai ter timestamp, não adianta reter
              continue;
            }

            let phone;
            if (jid.endsWith("@lid")) {
              phone = phoneByLid.get(jid.split("@")[0]);
              if (!phone) continue; // ainda sem mapeamento — MANTÉM no buffer pra tentar de novo depois
            } else {
              phone = jid.split("@")[0];
            }

            const ts = typeof chat.conversationTimestamp === "object" && chat.conversationTimestamp.toNumber
              ? chat.conversationTimestamp.toNumber()
              : Number(chat.conversationTimestamp);
            if (!ts) { resolvedJids.push(jid); continue; }

            const name = chat.name || nameByPhone.get(phone) || "";
            synced.push({ phone, name, last_seen: ts });
            resolvedJids.push(jid);
          }

          // Só remove do buffer o que foi de fato resolvido/descartado —
          // o que ficou sem LID continua lá pra próxima tentativa.
          for (const jid of resolvedJids) buf.chats.delete(jid);

          if (synced.length) {
            await fetch(`${FLASK_URL}/api/whatsapp/contacts/sync-history`, {
              method: "POST",
              headers: _internalHeaders(),
              body: JSON.stringify({ owner, contacts: synced })
            }).catch(e => console.error(`[whatsapp] falha ao sincronizar histórico (${owner}):`, e.message));
          }
          const pending = buf.chats.size;
          console.log(`[whatsapp] histórico sincronizado (${owner}): ${synced.length} chat(s)` +
            (pending ? `, ${pending} ainda pendente(s) de mapeamento LID (retido no buffer)` : ""));
        } catch (e) {
          console.error(`[whatsapp] erro processando sincronização de histórico (${owner}):`, e);
        }
      };

      sock.ev.on("messaging-history.set", ({ chats, contacts }) => {
        const buf = instances[owner].historySync;

        for (const c of contacts || []) {
          const key = c.lid || c.id || c.phoneNumber;
          if (key) buf.contacts.set(key, c);
        }
        for (const chat of chats || []) {
          if (chat.id) buf.chats.set(chat.id, chat);
        }

        // Reinicia o debounce a cada onda nova — só processa quando
        // parar de chegar onda por HISTORY_SYNC_DEBOUNCE_MS seguidos.
        // Mesmo assim chats não resolvidos não são perdidos (ver acima).
        if (buf.timer) clearTimeout(buf.timer);
        buf.timer = setTimeout(flushHistorySync, HISTORY_SYNC_DEBOUNCE_MS);
      });

      // Item: fora da sincronização inicial, o WhatsApp também manda
      // atualizações de contato em uso normal via "contacts.upsert" (ex:
      // quando o app resolve o LID de alguém em segundo plano). Aproveita
      // esse evento pra tentar resolver retroativamente qualquer chat que
      // ficou pendente no buffer por falta de mapeamento LID — sem isso,
      // um chat pendente só seria resolvido se aquele número mandasse
      // mensagem ao vivo.
      sock.ev.on("contacts.upsert", (contacts) => {
        const buf = instances[owner].historySync;
        if (!buf) return;
        let gotNewLid = false;
        for (const c of contacts || []) {
          const key = c.lid || c.id || c.phoneNumber;
          if (key) buf.contacts.set(key, c);
          if (c.lid) gotNewLid = true;
        }
        if (gotNewLid && buf.chats.size) {
          if (buf.timer) clearTimeout(buf.timer);
          buf.timer = setTimeout(flushHistorySync, 1500);
        }
      });

      sock.ev.on("connection.update", async (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
          console.log(`[whatsapp] QR gerado para "${owner}" — aguardando leitura...`);
          instances[owner].qr = await QRCode.toDataURL(qr);
        }

        if (connection === "open") {
          instances[owner].connected = true;
          instances[owner].everConnected = true;
          instances[owner].qr = null;
          instances[owner].phone = sock.user && sock.user.id ? sock.user.id.split(":")[0] : "";
          console.log(`[whatsapp] ${owner} conectado como ${instances[owner].phone}`);
        }

        if (connection === "close") {
          instances[owner].connected = false;
          instances[owner].sock = null; // libera a trava para permitir reconexão
          const statusCode = lastDisconnect && lastDisconnect.error &&
            lastDisconnect.error.output && lastDisconnect.error.output.statusCode;
          console.log(`[whatsapp] ${owner} conexão fechada. statusCode=${statusCode} motivo=${lastDisconnect && lastDisconnect.error ? lastDisconnect.error.message : "?"}`);
          const shouldReconnect = statusCode !== DisconnectReason.loggedOut;

          if (!shouldReconnect) {
            console.log(`[whatsapp] ${owner} deslogado (logout manual).`);
            // Item CORREÇÃO: quando o WhatsApp derruba a sessão de verdade
            // (loggedOut — ex: usuário removeu o "dispositivo conectado"
            // pelo celular), os arquivos de credenciais em wa_sessions/<owner>
            // ficam em disco só que agora INVÁLIDOS. Antes só apagávamos a
            // instância da memória e mantínhamos esses arquivos — na próxima
            // vez que o painel chamava /qr/:owner, o Baileys reaproveitava
            // esse creds.json morto e nunca mais emitia um QR novo (ficava
            // preso em "Gerando QR, tente novamente em alguns segundos..."
            // pra sempre). Agora limpamos a sessão em disco também, então a
            // próxima chamada a /qr/:owner (ou o próximo autoStart) já nasce
            // do zero e gera QR normalmente.
            try {
              fs.rmSync(path.join(SESSIONS_DIR, owner), { recursive: true, force: true });
              console.log(`[whatsapp] sessão de "${owner}" removida do disco após logout — pronta para novo pareamento.`);
            } catch (e) {
              console.error(`[whatsapp] falha ao limpar sessão de ${owner} após logout:`, e.message);
            }
            delete instances[owner];
            return;
          }

          // Item: trava de 3 minutos — só se aplica enquanto o pareamento
          // NUNCA foi concluído com sucesso (evita cortar reconexões
          // normais de uma sessão já pareada há dias que caiu por
          // instabilidade de rede).
          if (!instances[owner].everConnected) {
            const elapsedMs = Date.now() - (instances[owner].pairStartedAt || Date.now());
            if (elapsedMs >= PAIR_TIMEOUT_MS) {
              instances[owner].qrTimedOut = true;
              instances[owner].qr = null;
              console.log(`[whatsapp] ${owner}: 3 minutos sem leitura do QR — parado. Aguardando pedido manual de pareamento.`);
              return;
            }
          }

          console.log(`[whatsapp] ${owner} tentando reconectar em 3s...`);
          setTimeout(() => startSession(owner).catch(e => console.error(`[whatsapp] erro ao reconectar ${owner}:`, e)), 3000);
        }
      });
    } catch (e) {
      console.error(`[whatsapp] falha ao iniciar sessão de "${owner}":`, e && e.message || e);
      instances[owner].sock = null;
      throw e;
    }

    return instances[owner];
  }

  // ── Rotas ──────────────────────────────────────────────────────────

  app.get("/qr/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const existing = instances[owner];
    if (existing && existing.qrTimedOut) {
      return res.json({
        connected: false, qr: null, timedOut: true,
        message: "Tempo de leitura do QR esgotado. Clique em \"Parear / Gerar novo QR Code\"."
      });
    }
    try {
      const inst = await startSession(owner);
      if (inst.connected) {
        return res.json({ connected: true, phone: inst.phone || "" });
      }
      if (inst.qrTimedOut) {
        return res.json({
          connected: false, qr: null, timedOut: true,
          message: "Tempo de leitura do QR esgotado. Clique em \"Parear / Gerar novo QR Code\"."
        });
      }
      if (inst.qr) {
        return res.json({ connected: false, qr: inst.qr });
      }
      return res.json({ connected: false, qr: null, message: "Gerando QR, tente novamente em alguns segundos..." });
    } catch (e) {
      console.error(`[whatsapp] erro em /qr/${owner}:`, e);
      return res.status(500).json({ connected: false, qr: null, error: String(e && e.message || e) });
    }
  });

  // Item: pareamento manual — usado pelo botão "Parear / Gerar novo QR
  // Code" quando a tentativa automática expirou (3min) ou pra forçar
  // um pareamento novo do zero.
  app.post("/pair/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    try {
      const prev = instances[owner];
      // Item CRÍTICO: se a tentativa anterior nunca chegou a parear de
      // verdade (ex: os 3 minutos do QR expiraram sem leitura), os
      // arquivos de autenticação em disco (wa_sessions/<owner>/) ficam
      // num estado parcial/travado — o Baileys não consegue gerar um QR
      // novo reaproveitando esse handshake incompleto, e a sessão fica
      // permanentemente travada (nem reiniciar o servidor resolve,
      // porque o problema está em disco, não em memória). Só limpamos a
      // sessão em disco quando NUNCA houve pareamento bem-sucedido —
      // isso nunca derruba uma sessão já conectada de verdade.
      if (!prev || !prev.everConnected) {
        try {
          fs.rmSync(path.join(SESSIONS_DIR, owner), { recursive: true, force: true });
          console.log(`[whatsapp] sessão travada de "${owner}" limpa em disco antes de reparear.`);
        } catch (e) {
          console.error(`[whatsapp] falha ao limpar sessão travada de ${owner} antes de reparear:`, e.message);
        }
      }
      delete instances[owner];
      const inst = await startSession(owner, true);
      res.json({ ok: true, qr: inst.qr || null, connected: !!inst.connected });
    } catch (e) {
      res.status(500).json({ error: String(e && e.message || e) });
    }
  });

  app.get("/status/:owner", (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const inst = instances[owner];
    if (!inst) return res.json({ connected: false });
    return res.json({ connected: !!inst.connected, phone: inst.phone || "" });
  });

  app.post("/logout/:owner", async (req, res) => {
    const owner = sanitizeOwner(req.params.owner);
    const inst = instances[owner];
    try {
      if (inst && inst.sock && inst.sock !== "pending") {
        await inst.sock.logout().catch(e =>
          console.error(`[whatsapp] logout() falhou pra ${owner}, seguindo com limpeza local:`, e.message)
        );
      }
    } finally {
      // Item: essa limpeza agora SEMPRE roda, mesmo se sock.logout()
      // falhar acima (sessão já corrompida) — antes, uma exceção ali
      // impedia o rmSync de rodar e deixava a pasta de sessão velha
      // (com chaves de criptografia quebradas) presa no disco.
      try {
        fs.rmSync(path.join(SESSIONS_DIR, owner), { recursive: true, force: true });
      } catch (e) {
        console.error(`[whatsapp] falha ao remover pasta de sessão de ${owner}:`, e.message);
      }
      delete instances[owner];
    }
    res.json({ ok: true });
  });

  app.post("/send", async (req, res) => {
    const { owner, phone, message, mediaType, mediaPath, mediaFilename } = req.body || {};
    if (!owner || !phone || (!message && !mediaType)) {
      return res.status(400).json({ error: "owner, phone e message (ou mídia) são obrigatórios" });
    }
    const inst = instances[sanitizeOwner(owner)];
    if (!inst || !inst.connected) {
      return res.status(409).json({ error: "Este painel ainda não está conectado ao WhatsApp" });
    }
    try {
      const rawJid = phone.replace(/\D/g, "") + "@s.whatsapp.net";
      // Item CRÍTICO (Bug: campanha reportava "enviado" pra número que
      // nunca recebeu nada): sock.sendMessage() sempre resolvia com
      // sucesso (devolvendo um key.id) assim que o Baileys entregava a
      // mensagem PRA RELAY do WhatsApp — mesmo quando o número de
      // destino não existe/não tem WhatsApp ativo, porque o Baileys não
      // valida o destinatário sozinho antes de mandar. Isso fazia o
      // relatório de campanha contar como "enviado" um monte de contato
      // que na real nunca recebeu a mensagem (o "envio" só existia no
      // nosso lado). A doc oficial do Baileys recomenda checar
      // sock.onWhatsApp(jid) ANTES de enviar e usar o JID canônico que
      // ele devolve (que pode ser um @lid em vez do @s.whatsapp.net
      // construído na mão, já que o WhatsApp migrou o endereçamento
      // padrão pra LID — ver o resto deste arquivo sobre LID).
      let jid = rawJid;
      try {
        const [lookup] = await inst.sock.onWhatsApp(rawJid);
        if (!lookup || !lookup.exists) {
          return res.json({ ok: false, error: "Esse número não está registrado no WhatsApp (ou não pôde ser verificado)" });
        }
        jid = lookup.jid || rawJid;
      } catch (lookupErr) {
        // Item: se a própria checagem falhar (ex: instabilidade
        // momentânea do WhatsApp), não trava o envio inteiro — segue
        // com o JID construído na mão como fallback, que era o
        // comportamento antigo (melhor tentar do que travar a campanha
        // inteira por causa de uma falha pontual na verificação).
        console.error(`[whatsapp] onWhatsApp() falhou pra ${phone} (${owner}), enviando sem checagem prévia:`, lookupErr.message);
      }
      let content;
      // Item: campanhas de reengajamento podem anexar imagem, vídeo ou
      // arquivo (ex: o próprio APK) além do texto — mediaPath é sempre
      // um caminho local no mesmo servidor (não precisa ser uma URL
      // pública, o Baileys lê o arquivo direto do disco).
      if (mediaType === "image" && mediaPath) {
        content = { image: { url: mediaPath }, caption: message || "" };
      } else if (mediaType === "video" && mediaPath) {
        content = { video: { url: mediaPath }, caption: message || "" };
      } else if (mediaType === "document" && mediaPath) {
        content = {
          document: { url: mediaPath },
          fileName: mediaFilename || path.basename(mediaPath),
          mimetype: "application/octet-stream",
          caption: message || "",
        };
      } else {
        content = { text: message };
      }
      const sent = await inst.sock.sendMessage(jid, content);
      // Item: log de auditoria de todo envio (sucesso), pro caso de um
      // contato aparecer como "enviado" no relatório da campanha mas o
      // destinatário nunca receber nada de fato (ex: conta do WhatsApp
      // existe mas está com bloqueio/spam-flag do lado do WhatsApp,
      // fora do nosso controle) — com isso dá pra confirmar que a
      // tentativa de fato saiu daqui com esse ID de mensagem específico.
      console.log(`[whatsapp][send] OK owner=${owner} phone=${phone} jid=${jid} msgId=${sent && sent.key ? sent.key.id : "?"}`);
      // Item: guarda o ID da mensagem que O PRÓPRIO BOT acabou de mandar —
      // usado logo abaixo (listener messages.upsert) pra diferenciar uma
      // mensagem "fromMe" que é só o eco do bot de uma mensagem "fromMe"
      // que foi você digitando e mandando manualmente pelo WhatsApp.
      if (sent && sent.key && sent.key.id) {
        if (!inst.botSentIds) inst.botSentIds = new Set();
        inst.botSentIds.add(sent.key.id);
        // evita crescer pra sempre: some sozinho depois de 10 min
        setTimeout(() => inst.botSentIds && inst.botSentIds.delete(sent.key.id), 10 * 60 * 1000);
      }
      res.json({ ok: true, id: sent && sent.key ? sent.key.id : null });
    } catch (e) {
      console.error(`[whatsapp][send] ERRO owner=${owner} phone=${phone}:`, e && e.message || e);
      res.status(500).json({ error: String(e) });
    }
  });

  // Item CRÍTICO (Bug #2): reconecta automaticamente todas as sessões já
  // pareadas em disco assim que o processo sobe — sem isso, qualquer
  // restart do serviço (ou reboot do servidor) derrubava TODAS as
  // sessões da memória (admin + revendedores), e elas só voltavam se
  // alguém abrisse manualmente a tela de WhatsApp daquele painel
  // específico. Só reconecta pastas que têm creds.json de verdade — uma
  // pasta sem isso é de um pareamento que nunca terminou (QR nunca
  // escaneado), e tentar reconectar não geraria nada útil.
  try {
    const ownersSalvos = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory() && fs.existsSync(path.join(SESSIONS_DIR, d.name, "creds.json")))
      .map(d => d.name);
    if (ownersSalvos.length) {
      console.log(`[whatsapp] reconectando ${ownersSalvos.length} sessão(ões) já pareada(s) em disco: ${ownersSalvos.join(", ")}`);
    }
    for (const owner of ownersSalvos) {
      startSession(owner).catch(e =>
        console.error(`[whatsapp] falha ao reconectar "${owner}" automaticamente no boot:`, e.message)
      );
    }
  } catch (e) {
    console.error("[whatsapp] falha ao listar sessões salvas para reconexão automática:", e.message);
  }

  process.on("unhandledRejection", (reason) => {
    console.error("[whatsapp] unhandledRejection:", reason);
  });
  process.on("uncaughtException", (err) => {
    console.error("[whatsapp] uncaughtException:", err);
  });

  app.listen(PORT, "127.0.0.1", () => {
    console.log(`[whatsapp] microserviço rodando em http://127.0.0.1:${PORT}`);
  });
}

main().catch(e => {
  console.error("[whatsapp] falha fatal ao iniciar o microserviço:", e);
  process.exit(1);
});