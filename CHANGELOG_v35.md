# Changelog v35

## 1. Nova infraestrutura: logs de conexão real por cliente (Xray → banco → painel)
- **Objetivo:** o painel não tinha nenhuma forma de saber quem
  conectou, quando, ou por quanto tempo — só o estado "online agora".
- **O que foi criado:**
  - `log_watcher.py` (novo, roda como serviço systemd separado,
    `/opt/netsimon/log_watcher.py`): lê o `access.log` do Xray em
    tempo real e grava cada conexão aceita/rejeitada em
    `/opt/netsimon/netsimon_logs.db` (banco separado do
    `usuarios.db`, para não gerar risco no banco principal).
  - Unidade systemd `netsimon-log-watcher.service` — sobe sozinha no
    boot, reinicia automaticamente se cair.
  - 3 endpoints novos e somente-leitura em `painel_api.py`:
    `/api/logs/connection_attempts`, `/api/logs/sessions`,
    `/api/logs/sessions/summary`.
- **Limitação conhecida:** o Xray só loga o evento de conexão aceita
  (`accepted`), nunca o de desconexão — então a duração de sessão
  **não vem** dessa fonte (ver item 2).
- Arquivos afetados: `painel_api.py`, `log_watcher.py` (novo),
  `netsimon-log-watcher.service` (novo).

## 2. Tempo real de conexão por cliente, aproveitando o rastreamento de "online" que já existia
- **Causa raiz do problema:** sem evento de desconexão no Xray, não
  havia como medir duração de sessão de jeito nenhum a partir do log.
- **Solução:** o painel já tinha um mecanismo de fundo
  (`update_online_since`, rodando a cada ~20s dentro do loop de
  expiração de usuários que já existia) que marca desde quando cada
  login está online. Ele só não guardava histórico — a marcação era
  apagada assim que o usuário caía. Agora, no exato momento em que o
  painel detecta a queda, a sessão completa (login, desde quando, até
  quando, duração) é gravada em `connection_sessions` no mesmo banco
  do `log_watcher.py`. Flutuações de rede muito curtas (< 20s) são
  ignoradas para não sujar a métrica.
- **Resultado:** `/api/logs/sessions/summary` agora devolve, por
  cliente, tempo total conectado (`total_seconds`) **e** quantidade de
  sessões (`session_count`) no período.
- Arquivo afetado: `painel_api.py` (nova função
  `_record_completed_session`, ajuste em `update_online_since`, ajuste
  na query de `api_sessions_summary`).

## 3. Card "Uso por Cliente (7 dias)" no dashboard
- Novo painel no `dashboard.html` (admin-only), mostrando por cliente
  o tempo total conectado e a quantidade de conexões no período,
  atualizado a cada 30s.
- Arquivo afetado: `dashboard.html`.

## 4. Correção: `/api/logs/sessions/summary` retornava erro 500
- **Causa raiz:** a primeira versão da query somava a coluna
  `duration_seconds`, mas ela existe só na tabela
  `connection_sessions` — a query original lia de
  `connection_attempts`, que não tem essa coluna.
- **Correção:** query ajustada para ler de `connection_sessions`
  (que é de fato a fonte de duração — ver item 2).
- Arquivo afetado: `painel_api.py`.

## 5. Correção: falso incidente de "queda" no SlowDNS
- **Causa raiz:** o mesmo padrão de bug já corrigido antes no
  `limiter` (v31/v33) também existia no `slowdns`: o watchdog
  considera o serviço "fora do ar" sempre que o processo
  `dnstt-server` não está rodando — mas isso é normal e esperado
  quando o SlowDNS nunca foi configurado (é um recurso opcional,
  ativado só quando o admin roda o setup). Isso gerava um incidente
  falso a cada ~10 minutos, indefinidamente.
- **Correção:** o watchdog agora verifica se o SlowDNS foi
  configurado (mesma checagem que `/api/slowdns/status` já usa —
  existência de `/etc/slowdns/domain`) antes de considerar o processo
  parado como uma queda real. Sem configuração, o serviço é
  simplesmente ignorado pelo autodiagnóstico.
- Arquivo afetado: `painel_api.py`.

---
**Observação sobre este pacote:** os arquivos `log_watcher.py` e
`netsimon-log-watcher.service` estão nas pastas `opt-netsimon/` e
`etc-systemd-system/` só para deixar claro pra onde cada um vai no
servidor (`/opt/netsimon/log_watcher.py` e
`/etc/systemd/system/netsimon-log-watcher.service`, respectivamente)
— não é a estrutura real de pastas do zip original.
