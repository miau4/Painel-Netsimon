#!/usr/bin/env bash
# ============================================================================
#   PAINEL NETSIMON - MODELO DE FIX (formato padrão a partir da v31)
#
#   Este arquivo é um MODELO/TEMPLATE. Não é pra rodar direto — é a
#   referência de formato/estrutura que TODO fix pontual do Painel
#   Netsimon deve seguir a partir de agora, gerado sob demanda quando um
#   fix pontual precisar ser aplicado manualmente num servidor (fora do
#   fluxo normal de instalação/reinstalação via install.sh).
#
#   INSTRUÇÃO PRA QUEM (ou o assistente) FOR GERAR UM NOVO FIX:
#   ------------------------------------------------------------------
#   Sempre que eu pedir um "fix" pro Painel Netsimon, o resultado deve
#   ser UM ÚNICO arquivo .sh autocontido, seguindo EXATAMENTE esta
#   estrutura (não o formato antigo de "cp arquivo por cima do outro" —
#   esse foi descontinuado a partir da v31):
#
#   1. Cabeçalho com comentário explicando CADA correção incluída no
#      arquivo (pode ser mais de uma), a causa raiz de cada uma, e o(s)
#      arquivo(s) afetado(s) por cada uma. Deixar explícito qual método
#      foi usado em cada arquivo (patch por diff OU restauração
#      completa — ver item 2).
#
#   2. Pra cada arquivo corrigido, escolher o método certo:
#      a) PATCH POR DIFF (preferido sempre que der): gerar um
#         `diff -ru nome_orig/ARQUIVO nome_novo/ARQUIVO` real, de verdade
#         (nunca inventado/escrito à mão), embutir esse diff como bloco
#         base64 dentro do próprio .sh (delimitador único tipo
#         B64_CORRECOES_EOF), e conferir a integridade dele com
#         SHA-256 (EXPECTED_SHA256 fixo no script, comparado com o hash
#         real do que foi decodificado) antes de qualquer coisa. Um
#         applier em Python (embutido no mesmo .sh, ver função
#         apply_file) aplica cada hunk por SUBSTITUIÇÃO EXATA DE BLOCO
#         DE TEXTO (nunca por número de linha) — se o bloco "antigo" não
#         bater 100% com o que está no servidor, aquele arquivo
#         específico é PULADO (fica intocado) sem abortar os demais
#         arquivos do mesmo fix, e isso é reportado no resumo final.
#      b) RESTAURAÇÃO COMPLETA (só quando não der pra gerar um diff
#         seguro — ex: não se sabe o conteúdo exato/atual do arquivo no
#         servidor de destino): embutir o arquivo NOVO inteiro como
#         bloco base64 próprio, com seu próprio SHA-256 de integridade,
#         e SEMPRE deixar isso escrito claramente no cabeçalho do script
#         ("RESTAURAÇÃO COMPLETA, não é patch") — nunca disfarçar uma
#         restauração completa de patch cirúrgico.
#
#   3. Validação antes de tocar em produção: sintaxe Python
#      (`python3 -m py_compile` ou `ast.parse`) pra .py, `node --check`
#      pra .js (se node existir), checagem básica de tags (ex:
#      <script>/</script> balanceados) pra .html. Um arquivo que falhar
#      na validação NÃO é aplicado — fica intocado.
#
#   4. Backup automático de CADA arquivo antes de sobrescrever, com
#      timestamp único da rodada (pasta tipo
#      /etc/painel/backups/correcoes_NOME_YYYYMMDD_HHMMSS/), nunca
#      sobrescrevendo backup antigo.
#
#   5. Reiniciar só o(s) serviço(s) realmente afetado(s) pelo(s)
#      arquivo(s) corrigido(s) — nunca mais que isso, e detectar a unit
#      systemd certa dinamicamente (não assumir um nome fixo só).
#
#   6. Conferir se o serviço realmente subiu depois do restart
#      (`systemctl is-active`). Se QUALQUER serviço não subir, fazer
#      ROLLBACK AUTOMÁTICO pro backup do passo 4 e sair com erro — nunca
#      deixar o servidor num estado pior do que estava.
#
#   7. Resumo final obrigatório, em texto simples, com:
#        - quais arquivos foram aplicados / pulados / ausentes
#        - o que cada correção faz de fato
#        - o que ela NÃO faz (efeitos colaterais que precisam de ação
#          manual do admin, dados antigos que não são desfeitos, etc)
#        - o comando exato de rollback manual (usando os backups do
#          passo 4), mesmo já tendo rollback automático no passo 6
#
#   Ver `aplicar_correcoes_limiter_backup_telegram.sh` (fix da v31: unit
#   systemd "limiter" religando sozinho + Exportar SQL/Tudo indo pro
#   Telegram) como EXEMPLO DE REFERÊNCIA completo e já testado ponta a
#   ponta desse formato — inclusive com os dois métodos (2a e 2b) juntos
#   no mesmo arquivo.
# ============================================================================
set -u

C='\033[0;36m'; G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; W='\033[1;37m'; NC='\033[0m'

echo -e "${C}== Painel Netsimon — aplicando correcao MODELO (troque pelo nome real do fix) ==${NC}"

if [ "$(id -u)" != "0" ]; then
    echo -e "${R}Rode como root (sudo bash NOME_DO_FIX.sh).${NC}"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${R}python3 nao encontrado -- necessario pra aplicar as correcoes com seguranca. Abortando.${NC}"
    exit 1
fi

BASE="/etc/painel"
WEBROOT="/var/www/html"
STAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$BASE/backups/correcoes_MODELO_$STAMP"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$BACKUP_DIR/etc-painel" "$BACKUP_DIR/var-www-html"

# ── A PARTIR DAQUI: repetir, para cada arquivo corrigido, o padrão 2a
#    (patch por diff + SHA-256 + applier Python) ou 2b (restauração
#    completa + SHA-256), seguido de validação (3), backup (4), reinício
#    do(s) serviço(s) afetado(s) (5), confirmação + rollback automático
#    (6) e resumo final (7) — ver o arquivo de referência citado acima
#    pro código completo e já testado de cada uma dessas etapas.
