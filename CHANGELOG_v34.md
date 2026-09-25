# Changelog v34

## 1. Correção: era possível cadastrar dois usuários com o mesmo nome (diferindo só em maiúsculas/minúsculas)
- **Causa raiz:** tanto a criação de usuário pelo painel web (rota
  `POST /api/users`, em `painel_api.py`) quanto pelo menu no terminal
  (`adduser.sh`) comparavam o nome digitado com os já existentes usando
  comparação **exata** (case-sensitive). Era possível cadastrar
  `yndaiara` e depois `Yndaiara` como se fossem usuários diferentes —
  os dois entravam normalmente no `usuarios.db`. O Xray, porém, trata o
  campo interno de identificação do cliente sem diferenciar
  maiúsculas/minúsculas, então o segundo nome sempre falhava ao ser
  carregado no `config.json` (o processo chegava a recusar subir,
  com erro `User X already exists`), ficando "fantasma": existe no
  banco, mas nunca funciona de verdade.
- **Correção:** as duas checagens agora comparam os nomes ignorando
  maiúsculas/minúsculas e bloqueiam a criação **antes** de tocar em
  qualquer coisa (Linux, Xray, `usuarios.db`), com mensagem de erro
  clara (exibida como popup no painel web).
- Arquivos afetados: `painel_api.py`, `adduser.sh`.

## 2. Correção: autodiagnóstico ficava tentando baixar arquivo da internet e nunca conseguia
- **Causa raiz:** quando o autodiagnóstico detectava um arquivo de
  código ausente (varredura proativa a cada 10 min, ou em resposta a
  um erro real), ele tentava restaurar baixando de novo direto do
  repositório oficial no GitHub via `wget`. Se o repositório estivesse
  fora do ar, sem internet no servidor, ou o nome do arquivo não
  existisse mais lá (caso real observado: `config.json.template`,
  resíduo de uma versão antiga que nunca existiu no repositório
  oficial), a correção automática ficava tentando e falhando sozinha a
  cada 10 minutos, empilhando incidente atrás de incidente na tela de
  Diagnóstico sem nunca resolver nada.
- **Correção:** o autodiagnóstico nunca mais acessa a internet para
  restaurar arquivo de código. Agora ele só repara se já existir uma
  cópia **local** desse arquivo no próprio servidor — procurando (nessa
  ordem) nos backups que o próprio autodiagnóstico já fez antes
  (`/etc/painel/diag_backups`) e nos backups de correções manuais já
  aplicadas (`/etc/painel/backups/correcoes_*/`). Sem cópia local, o
  incidente fica marcado como pendente (sem tentar nada externo) para
  correção manual.
- Arquivo afetado: `painel_api.py` (nova função
  `_diag_find_local_restore_source()`; `_diag_fix_missing_file()`
  reescrita).
- **Nota:** o `repair.sh` (ferramenta manual, acionada por você no
  menu) continua baixando do GitHub quando você o roda explicitamente —
  isso não foi alterado, pois é uma ação deliberada do admin, não o
  sistema agindo sozinho.

## 3. Confirmação: sincronização de usuário de teste entre servidores
- Item já corrigido na v33 (ver Changelog v33, item 1) — validado
  nesta versão em ambiente real: "Criar Teste"/"Criar Teste
  Automático" (painel web e bot do WhatsApp) replicam corretamente
  para os servidores sincronizados. Nenhuma mudança de código nova
  nesta versão; incluído aqui apenas como confirmação de que o fix já
  embarcado está funcionando.

## 4. Indicador de versão
- Rodapé da sidebar (`painel.js`) e rodapé da tela de login
  (`login.html`) atualizados de `v33` para `v34`.
