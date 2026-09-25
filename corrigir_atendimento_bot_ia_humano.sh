#!/usr/bin/env bash
# ============================================================================
# Painel Netsimon — corrige o atendimento via bot/IA (WhatsApp) "atropelando"
# o atendente humano e repetindo mensagens (menu) sem necessidade.
#
# CAUSA RAIZ (uma só, por trás dos dois sintomas relatados):
#   O sistema já tinha um mecanismo de handoff pra humano (contact["human"]),
#   que desliga bot e IA nesse contato até: (a) o atendente clicar
#   "Reativar bot" no painel, ou (b) 12h se passarem sem atividade — pra
#   nenhum contato ficar "esquecido" pra sempre. O problema é COMO essas
#   12h eram contadas: a partir de "human_since", um timestamp gravado
#   *uma única vez*, na primeira transferência pra humano — nunca
#   atualizado depois disso, mesmo que o atendente respondesse manualmente
#   várias vezes pelo WhatsApp.
#   Resultado real: qualquer conversa em atendimento humano ATIVO por mais
#   de 12h corridas (fila grande, caso mais demorado, fim de semana) tinha
#   o bot_handoff_auto_resume_loop (roda a cada 10min) REATIVANDO o bot/IA
#   sozinho NO MEIO da conversa — mesmo com o atendente respondendo
#   normalmente o tempo todo. Na próxima mensagem do cliente, o bot (sem
#   saber que já tinha um humano cuidando daquilo) reentra no fluxo normal:
#   se nada bate com nenhum comando, ele reenvia o bot_menu_message (que só
#   tem cooldown de 12h — e já tinham se passado 12h+ desde a transferência
#   original), e/ou a IA volta a responder por cima do atendente. É esse o
#   caso real por trás de "o bot fica repetindo o menu" e "a IA continua
#   respondendo mesmo com o humano na conversa".
#   Corrigido gravando também "human_last_activity", atualizado a CADA
#   resposta manual detectada (não só na primeira) — o auto-resume passa a
#   contar a partir da ÚLTIMA atividade humana, não da primeira transferência.
#   Enquanto o atendente estiver ativo na conversa, o relógio das 12h nunca
#   estoura; só volta pro bot sozinho depois de 12h de SILÊNCIO humano de
#   verdade (ou se o atendente clicar "Reativar bot" manualmente, como já
#   era antes). Contatos já existentes no arquivo de estado (sem esse campo
#   ainda) caem automaticamente no comportamento antigo até a próxima
#   atividade humana nesse contato — não perdem nem travam nada.
#   Arquivo afetado: painel_api.py (funções whatsapp_human_activity e
#   bot_handoff_auto_resume_loop).
#
#   Segunda causa, contribuindo pro mesmo sintoma de "mensagem repetida":
#   o whatsapp_bot.js (microserviço Node/Baileys) não tinha NENHUMA
#   deduplicação de mensagens recebidas por ID — só as mensagens que o
#   PRÓPRIO bot manda (botSentIds) eram controladas contra eco. O WhatsApp/
#   Baileys pode reentregar a MESMA mensagem do cliente mais de uma vez
#   (ex: uma reconexão rápida logo após a entrega ao vivo faz o catch-up de
#   sincronização — "append", já tratado no arquivo pra esse mesmo tipo de
#   instabilidade do lado "fromMe" — repassar de novo uma mensagem do
#   CLIENTE que já tinha chegado segundos antes via "notify"). Sem checagem
#   de duplicidade, cada reentrega virava uma nova chamada a
#   /api/whatsapp/inbound, e o painel processava (e respondia) a MESMA
#   mensagem do cliente mais de uma vez. Corrigido guardando os IDs de
#   mensagem já encaminhados ao painel (por owner, expira sozinho em
#   10min — mesmo padrão já usado em botSentIds) e ignorando repetição
#   exata do mesmo ID.
#   Arquivo afetado: whatsapp_bot.js.
#
# O QUE ESSE FIX NÃO FAZ (leia o resumo final depois de rodar também):
#   - Não muda o prazo de 12h de auto-reativação em si (BOT_HANDOFF_AUTO_
#     RESUME_HOURS continua 12) — só corrige A PARTIR DE QUANDO ele conta.
#   - Não adiciona nenhum lock/trava de concorrência no arquivo de estado
#     do bot (/etc/painel/whatsapp_bot_state.json) contra escrita
#     simultânea do processo principal com os loops de fundo — existe uma
#     janela de corrida residual, rara (o processo principal e o loop de
#     auto-resume raramente escrevem no MESMO instante), fora do escopo
#     deste fix pontual por exigir mexer em muitos pontos do arquivo de
#     uma vez. Se depois de aplicado isso o problema persistir com muita
#     frequência, é o próximo passo a investigar.
#   - Não muda o texto de nenhuma mensagem do bot, nem o cooldown de 12h do
#     menu (bot_menu_message) em si — só corrige o gatilho que fazia o bot
#     "acordar" cedo demais no meio de um atendimento humano em andamento.
#
# Método usado nos dois arquivos: PATCH POR DIFF (bloco a bloco, resiliente
# a pequenas divergências — um bloco que não bater é PULADO sem abortar os
# demais).
#
# Uso no servidor:
#   sudo bash corrigir_atendimento_bot_ia_humano.sh
# ============================================================================
set -u

C='\033[0;36m'; G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; W='\033[1;37m'; NC='\033[0m'

echo -e "${C}== Painel Netsimon — corrigindo atendimento bot/IA x atendimento humano ==${NC}"

if [ "$(id -u)" != "0" ]; then
    echo -e "${R}Rode como root (sudo bash corrigir_atendimento_bot_ia_humano.sh).${NC}"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${R}python3 nao encontrado -- necessario pra aplicar as correcoes com seguranca. Abortando.${NC}"
    exit 1
fi

BASE="/etc/painel"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$BASE/backups/correcoes_atendimento_humano_$STAMP"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$BACKUP_DIR/etc-painel"

# ── PARTE 1: decodifica o patch (painel_api.py + whatsapp_bot.js) e confere integridade (SHA-256) ──
echo -e "${W}[1/5] Decodificando patch e conferindo integridade (SHA-256)...${NC}"
PATCH_FILE="$TMP_DIR/correcoes.patch"
base64 -d > "$PATCH_FILE" << 'B64_CORRECOES_EOF'
LS0tIHByb2pfb3JpZy9wYWluZWxfYXBpLnB5CTIwMjYtMDktMjQgMDE6Mzk6NTguNzEzMDUxODk4
ICswMDAwCisrKyBwcm9qL3BhaW5lbF9hcGkucHkJMjAyNi0wOS0yNCAwMTo0MDoyNy41ODA1NDg2
MjkgKzAwMDAKQEAgLTYyMjIsNiArNjIyMiwyMCBAQAogICAgIGNvbnRhY3RbImh1bWFuIl0gPSBU
cnVlCiAgICAgY29udGFjdFsiaHVtYW5fcmVwbGllZF9tYW51YWxseSJdID0gVHJ1ZQogICAgIGNv
bnRhY3Quc2V0ZGVmYXVsdCgiaHVtYW5fc2luY2UiLCB0aW1lLnRpbWUoKSkKKyAgICAjIEl0ZW0g
QlVHIENPUlJJR0lETyAoSUEvYm90IHZvbHRhbmRvIGEgcmVzcG9uZGVyIGNvbSBodW1hbm8gbmEK
KyAgICAjIGNvbnZlcnNhKTogImh1bWFuX3NpbmNlIiBzw7Mgw6kgZ3JhdmFkbyBVTUEgVkVaIChz
ZXRkZWZhdWx0LCBhY2ltYSkg4oCUCisgICAgIyBtYXJjYSBxdWFuZG8gYSBjb252ZXJzYSBmb2kg
dHJhbnNmZXJpZGEgcHJhIGh1bWFubyBwZWxhIFBSSU1FSVJBIHZleiwKKyAgICAjIGUgw6kgaXNz
byBxdWUgYm90X2hhbmRvZmZfYXV0b19yZXN1bWVfbG9vcCB1c2F2YSBwcmEgZGVjaWRpciBxdWFu
ZG8KKyAgICAjIHJlYXRpdmFyIG8gYm90IHNvemluaG8gKDEyaCBkZXBvaXMpLiBTw7MgcXVlIG51
bWEgY29udmVyc2EgZW0KKyAgICAjIGF0ZW5kaW1lbnRvIGh1bWFubyBBVElWTyBwb3IgbWFpcyBk
ZSAxMmggKGZpbGEgZ3JhbmRlLCBjYXNvIG1haXMKKyAgICAjIGRlbW9yYWRvLCBmaW0gZGUgc2Vt
YW5hKSwgbyBhdGVuZGVudGUgcG9kZSByZXNwb25kZXIgdsOhcmlhcyB2ZXplcworICAgICMgbWFu
dWFsbWVudGUgc2VtIGlzc28gbnVuY2EgInJlbm92YXIiIGVzc2UgcmVsw7NnaW8g4oCUIGRhw60s
IDEyaCBhcMOzcyBhCisgICAgIyB0cmFuc2ZlcsOqbmNpYSBPUklHSU5BTCwgbyBsb29wIHJlYXRp
dmF2YSBvIGJvdC9JQSBzb3ppbmhvIE5PIE1FSU8gZGEKKyAgICAjIGNvbnZlcnNhLCBtZXNtbyBj
b20gbyBhdGVuZGVudGUgYWluZGEgcmVzcG9uZGVuZG8gbm9ybWFsbWVudGUuIEFnb3JhCisgICAg
IyBncmF2YSB0YW1iw6ltIGEgZGF0YSBkYSDDmkxUSU1BIGF0aXZpZGFkZSBodW1hbmEsIGF0dWFs
aXphZGEgQSBDQURBCisgICAgIyByZXNwb3N0YSBtYW51YWwg4oCUIG8gYXV0by1yZXN1bWUgKHZl
ciBib3RfaGFuZG9mZl9hdXRvX3Jlc3VtZV9sb29wKQorICAgICMgcGFzc2EgYSBjb250YXIgYSBw
YXJ0aXIgZGVsYSwgbsOjbyBkYSBwcmltZWlyYSB0cmFuc2ZlcsOqbmNpYS4KKyAgICBjb250YWN0
WyJodW1hbl9sYXN0X2FjdGl2aXR5Il0gPSB0aW1lLnRpbWUoKQogICAgIGNvbnRhY3RbInN0ZXAi
XSA9IE5vbmUKICAgICBzdGF0ZVtrZXldID0gY29udGFjdAogICAgIF9zYXZlX2JvdF9zdGF0ZShz
dGF0ZSkKQEAgLTYyODgsMTAgKzYzMDIsMjAgQEAKIAogZGVmIGJvdF9oYW5kb2ZmX2F1dG9fcmVz
dW1lX2xvb3AoKToKICAgICAiIiJSb2RhIGVtIGJhY2tncm91bmQ6IGRlcG9pcyBkZSBCT1RfSEFO
RE9GRl9BVVRPX1JFU1VNRV9IT1VSUyBob3JhcwotICAgIGRlc2RlIGEgw7psdGltYSB0cmFuc2Zl
csOqbmNpYSBwcmEgYXRlbmRpbWVudG8gaHVtYW5vLCBvIGJvdCB2b2x0YSBhCi0gICAgcmVzcG9u
ZGVyIGVzc2UgY29udGF0byBzb3ppbmhvIGF1dG9tYXRpY2FtZW50ZSDigJQgbWVzbW8gcXVlIG5p
bmd1w6ltCi0gICAgY2xpcXVlIGVtICdSZWF0aXZhciBib3QnIG5vIHBhaW5lbC4gRXZpdGEgY29u
dGF0byAiZXNxdWVjaWRvIiBwcmVzbwotICAgIGVtIHNpbMOqbmNpbyBwcmEgc2VtcHJlIGNhc28g
byBhdGVuZGVudGUgbsOjbyByZWF0aXZlIG1hbnVhbG1lbnRlLiIiIgorICAgIFNFTSBORU5IVU1B
IGF0aXZpZGFkZSBodW1hbmEgbm92YSBuZXNzZSBjb250YXRvLCBvIGJvdCB2b2x0YSBhCisgICAg
cmVzcG9uZGVyIHNvemluaG8gYXV0b21hdGljYW1lbnRlIOKAlCBtZXNtbyBxdWUgbmluZ3XDqW0g
Y2xpcXVlIGVtCisgICAgJ1JlYXRpdmFyIGJvdCcgbm8gcGFpbmVsLiBFdml0YSBjb250YXRvICJl
c3F1ZWNpZG8iIHByZXNvIGVtIHNpbMOqbmNpbworICAgIHByYSBzZW1wcmUgY2FzbyBvIGF0ZW5k
ZW50ZSBuw6NvIHJlYXRpdmUgbWFudWFsbWVudGUuCisgICAgSXRlbSBCVUcgQ09SUklHSURPOiBh
bnRlcyBjb250YXZhIGEgcGFydGlyIGRlICJodW1hbl9zaW5jZSIgKGEKKyAgICBQUklNRUlSQSB0
cmFuc2ZlcsOqbmNpYSBwcmEgaHVtYW5vLCBncmF2YWRhIHVtYSDDum5pY2EgdmV6KSwgZW50w6Nv
IHVtYQorICAgIGNvbnZlcnNhIGVtIGF0ZW5kaW1lbnRvIGh1bWFubyBBVElWTyBwb3IgbWFpcyBk
ZSAxMmggKGZpbGEgZ3JhbmRlLAorICAgIGNhc28gbWFpcyBkZW1vcmFkbywgZmltIGRlIHNlbWFu
YSkgdGluaGEgbyBib3QvSUEgcmVhdGl2YWRvIHNvemluaG8gTk8KKyAgICBNRUlPIGRhIGNvbnZl
cnNhLCBtZXNtbyBjb20gbyBhdGVuZGVudGUgcmVzcG9uZGVuZG8gbm9ybWFsbWVudGUgbworICAg
IHRlbXBvIHRvZG8g4oCUIGEgY2F1c2EgcmVhbCBwb3IgdHLDoXMgZGUgImEgSUEgdm9sdGEgYSBy
ZXNwb25kZXIgbworICAgIGNsaWVudGUgbWVzbW8gY29tIG8gaHVtYW5vIG5hIGNvbnZlcnNhIi4g
QWdvcmEgY29udGEgYSBwYXJ0aXIgZGUKKyAgICAiaHVtYW5fbGFzdF9hY3Rpdml0eSIsIGF0dWFs
aXphZG8gYSBjYWRhIHJlc3Bvc3RhIG1hbnVhbCAodmVyCisgICAgd2hhdHNhcHBfaHVtYW5fYWN0
aXZpdHkpIOKAlCBzw7MgcmVhdGl2YSBzb3ppbmhvIGRlcG9pcyBkZSAxMmggZGUKKyAgICBTSUzD
ik5DSU8gaHVtYW5vIGRlIHZlcmRhZGUuIiIiCiAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgdHJ5
OgogICAgICAgICAgICAgc3RhdGUgPSBfbG9hZF9ib3Rfc3RhdGUoKQpAQCAtNjMwMCw3ICs2MzI0
LDEyIEBACiAgICAgICAgICAgICBmb3Iga2V5LCBjb250YWN0IGluIHN0YXRlLml0ZW1zKCk6CiAg
ICAgICAgICAgICAgICAgaWYgbm90IGNvbnRhY3QuZ2V0KCJodW1hbiIpOgogICAgICAgICAgICAg
ICAgICAgICBjb250aW51ZQotICAgICAgICAgICAgICAgIHNpbmNlID0gY29udGFjdC5nZXQoImh1
bWFuX3NpbmNlIiwgMCkgb3IgMAorICAgICAgICAgICAgICAgICMgQ29udGF0b3MgYW50aWdvcyAo
Z3JhdmFkb3MgYW50ZXMgZGVzc2EgY29ycmXDp8OjbykgYWluZGEgbsOjbworICAgICAgICAgICAg
ICAgICMgdMOqbSAiaHVtYW5fbGFzdF9hY3Rpdml0eSIg4oCUIGNhaSBubyBmYWxsYmFjayBwcmEK
KyAgICAgICAgICAgICAgICAjICJodW1hbl9zaW5jZSIgKGNvbXBvcnRhbWVudG8gYW50aWdvLCBz
w7MgcHJhIGVzc2VzIGNhc29zCisgICAgICAgICAgICAgICAgIyBsZWdhZG9zOyBzb21lIHNvemlu
aG8gYXNzaW0gcXVlIGVzc2UgY29udGF0byByZWNlYmVyCisgICAgICAgICAgICAgICAgIyBxdWFs
cXVlciBhdGl2aWRhZGUgaHVtYW5hIG5vdmEpLgorICAgICAgICAgICAgICAgIHNpbmNlID0gY29u
dGFjdC5nZXQoImh1bWFuX2xhc3RfYWN0aXZpdHkiKSBvciBjb250YWN0LmdldCgiaHVtYW5fc2lu
Y2UiLCAwKSBvciAwCiAgICAgICAgICAgICAgICAgaWYgc2luY2UgYW5kIHNpbmNlIDw9IGxpbWl0
ZToKICAgICAgICAgICAgICAgICAgICAgY29udGFjdFsiaHVtYW4iXSA9IEZhbHNlCiAgICAgICAg
ICAgICAgICAgICAgIGNvbnRhY3RbInN0ZXAiXSA9IE5vbmUKLS0tIHByb2pfb3JpZy93aGF0c2Fw
cF9ib3QuanMJMjAyNi0wOS0yNCAwMTozOTo1OC43MTQ1MjUwMDAgKzAwMDAKKysrIHByb2ovd2hh
dHNhcHBfYm90LmpzCTIwMjYtMDktMjQgMDE6NDA6MDkuMDMxMDE4OTc0ICswMDAwCkBAIC0xOTgs
NiArMTk4LDMxIEBACiAgICAgICAgICAgICBjb25zdCBqaWQgPSBtc2cua2V5LnJlbW90ZUppZDsK
ICAgICAgICAgICAgIGlmICghamlkIHx8IGppZC5lbmRzV2l0aCgiQGcudXMiKSB8fCBqaWQuZW5k
c1dpdGgoIkBicm9hZGNhc3QiKSB8fCBqaWQuZW5kc1dpdGgoIkBuZXdzbGV0dGVyIikpIGNvbnRp
bnVlOwogCisgICAgICAgICAgICAvLyBJdGVtIEJVRyBDT1JSSUdJRE8gKG1lbnNhZ2VucyByZXBl
dGlkYXMpOiBvIFdoYXRzQXBwL0JhaWxleXMKKyAgICAgICAgICAgIC8vIHBvZGUgcmVlbnRyZWdh
ciBhIE1FU01BIG1lbnNhZ2VtIGRvIGNsaWVudGUgbWFpcyBkZSB1bWEgdmV6IOKAlAorICAgICAg
ICAgICAgLy8gZXg6IHVtYSByZWNvbmV4w6NvIHLDoXBpZGEgbG9nbyBhcMOzcyBhIGVudHJlZ2Eg
ImFvIHZpdm8iIChldmVudG8KKyAgICAgICAgICAgIC8vICJub3RpZnkiKSBmYXogbyBjYXRjaC11
cCBkZSBzaW5jcm9uaXphw6fDo28gKCJhcHBlbmQiKSByZXBhc3NhcgorICAgICAgICAgICAgLy8g
YSBtZXNtYSBtZW5zYWdlbSBkZSBub3ZvLCBkZW50cm8gZGEgbWVzbWEgamFuZWxhIGRlIDJtaW4g
asOhCisgICAgICAgICAgICAvLyBhY2VpdGEgYWNpbWEuIFNlbSBjaGVjYWdlbSBkZSBkdXBsaWNp
ZGFkZSBwb3IgSUQsIGNhZGEKKyAgICAgICAgICAgIC8vIHJlZW50cmVnYSB2aXJhdmEgdW1hIG5v
dmEgY2hhbWFkYSBhIC9hcGkvd2hhdHNhcHAvaW5ib3VuZCwgZSBvCisgICAgICAgICAgICAvLyBw
YWluZWwgcHJvY2Vzc2F2YSAoZSByZXNwb25kaWEg4oCUIGJvdCBvdSBJQSkgYSBNRVNNQSBtZW5z
YWdlbQorICAgICAgICAgICAgLy8gZG8gY2xpZW50ZSBtYWlzIGRlIHVtYSB2ZXosIG8gcXVlIGFw
YXJlY2lhIG5hIGNvbnZlcnNhIGNvbW8gbworICAgICAgICAgICAgLy8gYm90ICJyZXBldGluZG8i
IHJlc3Bvc3RhcyAoaW5jbHVzaXZlIG8gbWVudSkgc2VtIG1vdGl2by4KKyAgICAgICAgICAgIC8v
IEd1YXJkYSBvcyDDumx0aW1vcyBJRHMgZGUgbWVuc2FnZW0gasOhIGVuY2FtaW5oYWRvcyBhbyBw
YWluZWwKKyAgICAgICAgICAgIC8vIChwb3Igb3duZXIsIGV4cGlyYSBzb3ppbmhvIGRlcG9pcyBk
ZSAxMG1pbiDigJQgbWVzbW8gcGFkcsOjbyBqw6EKKyAgICAgICAgICAgIC8vIHVzYWRvIGVtIGJv
dFNlbnRJZHMgYWNpbWEpIGUgaWdub3JhIHNpbGVuY2lvc2FtZW50ZSB1bWEKKyAgICAgICAgICAg
IC8vIHJlcGV0acOnw6NvIGV4YXRhIGRvIG1lc21vIElELgorICAgICAgICAgICAgaWYgKG1zZy5r
ZXkuaWQpIHsKKyAgICAgICAgICAgICAgaWYgKCFpbnN0YW5jZXNbb3duZXJdLmluYm91bmRGb3J3
YXJkZWRJZHMpIGluc3RhbmNlc1tvd25lcl0uaW5ib3VuZEZvcndhcmRlZElkcyA9IG5ldyBTZXQo
KTsKKyAgICAgICAgICAgICAgaWYgKGluc3RhbmNlc1tvd25lcl0uaW5ib3VuZEZvcndhcmRlZElk
cy5oYXMobXNnLmtleS5pZCkpIGNvbnRpbnVlOworICAgICAgICAgICAgICBpbnN0YW5jZXNbb3du
ZXJdLmluYm91bmRGb3J3YXJkZWRJZHMuYWRkKG1zZy5rZXkuaWQpOworICAgICAgICAgICAgICBz
ZXRUaW1lb3V0KCgpID0+IHsKKyAgICAgICAgICAgICAgICBpZiAoaW5zdGFuY2VzW293bmVyXSAm
JiBpbnN0YW5jZXNbb3duZXJdLmluYm91bmRGb3J3YXJkZWRJZHMpIHsKKyAgICAgICAgICAgICAg
ICAgIGluc3RhbmNlc1tvd25lcl0uaW5ib3VuZEZvcndhcmRlZElkcy5kZWxldGUobXNnLmtleS5p
ZCk7CisgICAgICAgICAgICAgICAgfQorICAgICAgICAgICAgICB9LCAxMCAqIDYwICogMTAwMCk7
CisgICAgICAgICAgICB9CisKICAgICAgICAgICAgIC8vIEl0ZW06IFdoYXRzQXBwIGFnb3JhIHVz
YSAiTElEIiBlbSB2ZXogZG8gbsO6bWVybyBkZSB0ZWxlZm9uZQogICAgICAgICAgICAgLy8gZGly
ZXRvIG5vIHJlbW90ZUppZCBwcmEgYWxndW5zIGNvbnRhdG9zIOKAlCBuYSB2ZXJkYWRlIGrDoSDD
qSBvCiAgICAgICAgICAgICAvLyBtb2RvIFBBRFLDg08sIG7Do28gdW1hIGV4Y2XDp8OjbyByYXJh
LiBPIG7Dum1lcm8gcmVhbCB2ZW0gbm8K
B64_CORRECOES_EOF

EXPECTED_SHA256="aaf08da256b8e5ae095901b4de1788e61b7fffa2b386f72bb0b5cf42a129ea00"
GOT_SHA256="$(sha256sum "$PATCH_FILE" | awk '{print $1}')"
if [ "$GOT_SHA256" != "$EXPECTED_SHA256" ]; then
    echo -e "${R}  -> patch corrompido no download/copia (SHA-256 nao bate). Abortando, nada foi tocado.${NC}"
    echo "     esperado: $EXPECTED_SHA256"
    echo "     recebido: $GOT_SHA256"
    exit 1
fi
echo -e "${G}  -> patch integro ($GOT_SHA256)${NC}"

for f in painel_api.py whatsapp_bot.js; do
    if [ ! -f "$BASE/$f" ]; then
        echo -e "${R}  -> $BASE/$f nao encontrado. Abortando.${NC}"
        exit 1
    fi
done

echo -e "${W}[2/5] Aplicando patch (substituicao exata por bloco, resiliente a pequenas divergencias)...${NC}"
APPLIER="$TMP_DIR/apply_corrections.py"
cat > "$APPLIER" << 'APPLIER_EOF'
#!/usr/bin/env python3
"""Aplica um diff -ru (multi-arquivo) usando substituicao exata de blocos de
texto por hunk, em vez de numero de linha -- resiliente a arquivos que ja
sofreram pequenas alteracoes desde que o diff foi gerado. Cada arquivo e
tratado de forma independente e atomica: ou TODOS os hunks dele batem e o
arquivo novo e escrito, ou NENHUMA alteracao e feita nesse arquivo (e ele
entra na lista de pulados, sem afetar os demais)."""
import re, sys, os

def parse_unified_diff(text):
    files = {}
    current_file = None
    lines = text.split('\n')
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.startswith('+++ '):
            m = re.match(r'\+\+\+ proj/(.+?)\t', line)
            if m:
                current_file = m.group(1)
                files.setdefault(current_file, [])
            i += 1
            continue
        if line.startswith('@@'):
            i += 1
            old_lines, new_lines = [], []
            while i < n and not lines[i].startswith('@@') and not lines[i].startswith('diff -ru') and not lines[i].startswith('--- '):
                l = lines[i]
                if l.startswith('\\'):
                    i += 1
                    continue
                if l == '':
                    old_lines.append(''); new_lines.append(''); i += 1
                    continue
                tag, content = l[0], l[1:]
                if tag == ' ':
                    old_lines.append(content); new_lines.append(content)
                elif tag == '-':
                    old_lines.append(content)
                elif tag == '+':
                    new_lines.append(content)
                i += 1
            files[current_file].append(('\n'.join(old_lines), '\n'.join(new_lines)))
            continue
        i += 1
    return files

def apply_file(content, hunks):
    """Retorna (novo_conteudo_ou_None, status_msg)."""
    for idx, (old_block, new_block) in enumerate(hunks, start=1):
        count_old = content.count(old_block)
        if count_old == 1:
            content = content.replace(old_block, new_block, 1)
            continue
        count_new = content.count(new_block)
        if count_old == 0 and count_new >= 1:
            continue
        if count_old > 1:
            return None, f"hunk #{idx} ambiguo (texto original aparece {count_old}x no arquivo)"
        return None, f"hunk #{idx} nao encontrado (arquivo ja diverge do esperado nesse trecho)"
    return content, "ok"

def main():
    diff_file, source_dir, dest_dir, manifest_path = sys.argv[1:5]
    target_files = sys.argv[5:]
    with open(diff_file, encoding='utf-8') as f:
        all_hunks = parse_unified_diff(f.read())

    ok, skipped, missing = [], [], []
    os.makedirs(dest_dir, exist_ok=True)
    for fn in target_files:
        src_path = os.path.join(source_dir, fn)
        if not os.path.isfile(src_path):
            missing.append(fn)
            continue
        hunks = all_hunks.get(fn, [])
        with open(src_path, encoding='utf-8') as f:
            content = f.read()
        new_content, status = apply_file(content, hunks)
        if new_content is None:
            skipped.append((fn, status))
            print(f"PULADO  {fn}: {status}")
            continue
        with open(os.path.join(dest_dir, fn), 'w', encoding='utf-8') as f:
            f.write(new_content)
        ok.append(fn)
        print(f"OK      {fn}")

    with open(manifest_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(ok) + ('\n' if ok else ''))

    if missing:
        print("AVISO -- nao encontrados no servidor (ignorados): " + ", ".join(missing))
    print(f"RESUMO: {len(ok)} ok, {len(skipped)} pulado(s), {len(missing)} ausente(s)")
    sys.exit(1 if skipped else 0)

if __name__ == '__main__':
    main()
APPLIER_EOF

SCRATCH="$TMP_DIR/scratch"
MANIFEST="$TMP_DIR/manifest_ok.txt"
python3 "$APPLIER" "$PATCH_FILE" "$BASE" "$SCRATCH" "$MANIFEST" painel_api.py whatsapp_bot.js
mapfile -t OK_FILES < "$MANIFEST" 2>/dev/null || OK_FILES=()

PY_APPLIED=0
JS_APPLIED=0

# ── painel_api.py: valida sintaxe Python antes de tocar em producao ──────
if printf '%s\n' "${OK_FILES[@]:-}" | grep -qx "painel_api.py"; then
    echo -e "${W}  -> validando sintaxe de painel_api.py...${NC}"
    if python3 -m py_compile "$SCRATCH/painel_api.py" 2>"$TMP_DIR/err_painel_api.txt"; then
        echo -e "${G}  -> sintaxe OK${NC}"
        cp -a "$BASE/painel_api.py" "$BACKUP_DIR/etc-painel/painel_api.py"
        cp "$SCRATCH/painel_api.py" "$BASE/painel_api.py"
        PY_APPLIED=1
        echo -e "${G}  -> painel_api.py corrigido e aplicado (backup em $BACKUP_DIR)${NC}"
    else
        echo -e "${R}  -> erro de sintaxe apos o patch, NADA foi alterado nesse arquivo:${NC}"
        cat "$TMP_DIR/err_painel_api.txt"
    fi
else
    echo -e "${Y}  -> painel_api.py PULADO (patch nao bateu com o esperado). Arquivo ficou intocado.${NC}"
    echo -e "${Y}     Me manda o conteudo atual dele que eu gero a correcao certa.${NC}"
fi

# ── whatsapp_bot.js: valida sintaxe JS (se o node estiver disponivel) ────
if printf '%s\n' "${OK_FILES[@]:-}" | grep -qx "whatsapp_bot.js"; then
    JS_OK=1
    if command -v node >/dev/null 2>&1; then
        echo -e "${W}  -> validando sintaxe de whatsapp_bot.js...${NC}"
        if node --check "$SCRATCH/whatsapp_bot.js" 2>"$TMP_DIR/err_whatsapp_bot.txt"; then
            echo -e "${G}  -> sintaxe OK${NC}"
        else
            echo -e "${R}  -> erro de sintaxe apos o patch, NADA foi alterado nesse arquivo:${NC}"
            cat "$TMP_DIR/err_whatsapp_bot.txt"
            JS_OK=0
        fi
    else
        echo -e "${Y}  -> node nao encontrado no PATH -- pulando checagem de sintaxe (nao bloqueia a aplicacao).${NC}"
    fi
    if [ "$JS_OK" = "1" ]; then
        cp -a "$BASE/whatsapp_bot.js" "$BACKUP_DIR/etc-painel/whatsapp_bot.js"
        cp "$SCRATCH/whatsapp_bot.js" "$BASE/whatsapp_bot.js"
        JS_APPLIED=1
        echo -e "${G}  -> whatsapp_bot.js corrigido e aplicado (backup em $BACKUP_DIR)${NC}"
    fi
else
    echo -e "${Y}  -> whatsapp_bot.js PULADO (patch nao bateu com o esperado). Arquivo ficou intocado.${NC}"
    echo -e "${Y}     Me manda o conteudo atual dele que eu gero a correcao certa.${NC}"
fi

if [ "$PY_APPLIED" = "0" ] && [ "$JS_APPLIED" = "0" ]; then
    echo -e "${R}Nenhum dos dois arquivos pode ser aplicado -- nada a fazer. Abortando sem reiniciar nada.${NC}"
    exit 1
fi

# ── PARTE 3: reinicia so o(s) servico(s) dos arquivo(s) realmente alterados, com rollback automatico se algo nao subir ──
echo -e "${W}[4/5] Reiniciando servico(s) afetado(s) e conferindo se subiram...${NC}"
RESTARTED=()
detect_and_restart() {
    # $1: lista de nomes candidatos de unit systemd, em ordem de preferencia
    for cand in $1; do
        if systemctl list-unit-files --type=service 2>/dev/null | grep -qiE "^${cand}\.service"; then
            systemctl restart "$cand"
            RESTARTED+=("$cand")
            return 0
        fi
    done
    return 1
}
if [ "$PY_APPLIED" = "1" ]; then
    detect_and_restart "netsimon-painel painel-netsimon painel" || \
        echo -e "${Y}  -> nenhuma unit systemd conhecida encontrada pro painel_api.py -- reinicie manualmente.${NC}"
fi
if [ "$JS_APPLIED" = "1" ]; then
    detect_and_restart "whatsapp-bot whatsapp_bot painel-whatsapp" || \
        echo -e "${Y}  -> nenhuma unit systemd conhecida encontrada pro whatsapp_bot.js -- reinicie manualmente.${NC}"
fi

sleep 3
OK=1
for svc in "${RESTARTED[@]:-}"; do
    [ -z "$svc" ] && continue
    if ! systemctl is-active --quiet "$svc"; then
        echo -e "${R}  -> $svc NAO esta ativo depois do restart!${NC}"
        journalctl -u "$svc" -n 30 --no-pager 2>/dev/null
        OK=0
    else
        echo -e "${G}  -> $svc ativo${NC}"
    fi
done
if [ "${#RESTARTED[@]}" = "0" ]; then
    echo -e "${Y}  -> nenhum servico foi reiniciado automaticamente (confira manualmente se necessario).${NC}"
fi

if [ "$OK" = "0" ]; then
    echo -e "${R}Algum servico nao subiu -- fazendo ROLLBACK AUTOMATICO pro backup em $BACKUP_DIR ...${NC}"
    [ -f "$BACKUP_DIR/etc-painel/painel_api.py" ] && cp -a "$BACKUP_DIR/etc-painel/painel_api.py" "$BASE/painel_api.py"
    [ -f "$BACKUP_DIR/etc-painel/whatsapp_bot.js" ] && cp -a "$BACKUP_DIR/etc-painel/whatsapp_bot.js" "$BASE/whatsapp_bot.js"
    for svc in "${RESTARTED[@]:-}"; do
        [ -z "$svc" ] && continue
        systemctl restart "$svc"
    done
    sleep 2
    echo -e "${Y}Rollback feito -- os dois arquivos voltaram ao estado anterior.${NC}"
    exit 1
fi

echo -e "${W}[5/5] Resumo${NC}"
echo -e "${G}"
echo "============================================================================"
echo " Correcoes aplicadas!"
echo "   - Backup do estado anterior em: $BACKUP_DIR"
[ "$PY_APPLIED" = "1" ] && echo "   - painel_api.py: fix do auto-resume (human_last_activity) aplicado (patch)"
[ "$PY_APPLIED" = "0" ] && echo "   - painel_api.py: PULADO (nao bateu com o esperado)"
[ "$JS_APPLIED" = "1" ] && echo "   - whatsapp_bot.js: dedup de mensagens recebidas por ID aplicado (patch)"
[ "$JS_APPLIED" = "0" ] && echo "   - whatsapp_bot.js: PULADO (nao bateu com o esperado)"
echo "============================================================================"
echo -e "${NC}"
echo -e "${W}Servicos reiniciados:${NC} ${RESTARTED[*]:-nenhum}"
echo ""
echo -e "${W}O que cada correcao faz de fato:${NC}"
echo "  - painel_api.py: enquanto o atendente estiver respondendo manualmente"
echo "    pelo WhatsApp, o 'relogio' de 12h do auto-resume agora e renovado a"
echo "    cada resposta dele -- o bot/IA so volta sozinho depois de 12h de"
echo "    SILENCIO humano de verdade (ou se alguem clicar 'Reativar bot')."
echo "  - whatsapp_bot.js: se o WhatsApp reentregar a mesma mensagem do cliente"
echo "    (reconexao/instabilidade), ela e ignorada na segunda vez -- o painel"
echo "    nao processa/responde a mesma mensagem duas vezes."
echo ""
echo -e "${W}O que isso NAO faz (ver cabecalho do script para mais detalhes):${NC}"
echo "  - Nao muda o prazo de 12h em si, nem os textos das mensagens do bot."
echo "  - Nao adiciona lock contra escrita concorrente no arquivo de estado"
echo "    do bot -- janela de corrida residual e rara, fora do escopo deste"
echo "    fix pontual; me avise se o problema persistir com frequencia."
echo "  - Contatos JA presos em atendimento humano no momento do restart"
echo "    continuam sem 'human_last_activity' ate a PROXIMA resposta manual"
echo "    detectada nesse contato -- ate la, valem pelo campo antigo"
echo "    (human_since), sem quebrar nem travar nada."
echo ""
echo -e "${W}Reverter manualmente, se precisar:${NC}"
echo "  cp -a $BACKUP_DIR/etc-painel/. $BASE/ && systemctl restart netsimon-painel whatsapp-bot"
